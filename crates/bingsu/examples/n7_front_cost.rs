//! Test/measurement entry only. Uses the exact shipped prefilter reader and
//! decoder; no additional effects or fault switches in the installed binary.
#![allow(
    dead_code,
    reason = "shares production adapters and the complete wire fixture"
)]
#[cfg(all(unix, not(test)))]
#[path = "../../bingsu-core-tests/src/snapshot_fixture.rs"]
mod fixture;
#[cfg(all(unix, not(test)))]
#[path = "../src/prompt_io.rs"]
mod prompt_io;
#[cfg(all(unix, not(test)))]
#[path = "../src/prompt_read.rs"]
mod prompt_read;
#[cfg(all(unix, not(test)))]
#[path = "../src/prompt_spawn.rs"]
mod prompt_spawn;

#[cfg(all(unix, not(test)))]
fn main() {
    use bingsu_core::{
        bands::Band,
        snapshot::{self, FrontDecoder, Identity, Marker, Snapshot},
    };
    use std::{
        fs,
        hint::black_box,
        io::Read,
        os::unix::fs::{MetadataExt, PermissionsExt},
        time::Instant,
    };
    let mut args = std::env::args_os().skip(1);
    let first = args
        .next()
        .expect("private fixture directory or --helper-spawn");
    if first == "--helper-spawn" {
        return helper_spawn(args.next().expect("product binary"), args.collect());
    }
    let base = std::path::PathBuf::from(first);
    fs::create_dir_all(&base).unwrap();
    fs::set_permissions(&base, fs::Permissions::from_mode(0o700)).unwrap();
    let base = fs::canonicalize(base).unwrap();
    let mut store = base.clone();
    for part in snapshot::context_components(b"/c", b"/s").unwrap() {
        store.push(part);
        fs::create_dir_all(&store).unwrap();
        fs::set_permissions(&store, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let native = prompt_io::observe_clock();
    let native_available = native.is_ok();
    eprintln!("native_clock_available={native_available}");
    // A denied native boot observation still permits a wire/decode measurement.
    // It does NOT permit a successful native prefilter/render claim.
    let clock = native.unwrap_or(snapshot::Clock {
        boot: [1; 16],
        kind: 1,
        domain: [2; 16],
        resume: 0,
        now: prompt_io::monotonic_ns().unwrap(),
    });
    let mut ordinary = fixture::compile("");
    // Same 4096-band forest used by the N1 boundary fixture, including both palettes.
    let mut boundary = ordinary.clone();
    let n = bingsu_core::bands::MAX_BANDS;
    boundary.bands = (0..n)
        .map(|i| Band {
            min_cols: Some(i as u16),
            max_cols: Some(10000),
            order: None,
        })
        .collect();
    boundary.band_names = (0..n).map(|i| format!("b{i}")).collect();
    boundary.band_order = (0..n).rev().collect();
    boundary.variants = vec![ordinary.variants[0].clone(); n + 1];
    boundary.widths.clear();
    let md = fs::metadata(&base).unwrap();
    let argv = [
        "--ctx".to_owned(),
        "1".into(),
        "--record".into(),
        "B1".into(),
        "--shell".into(),
        "bash".into(),
        "--width".into(),
        "120".into(),
        "--config-root=/c".into(),
        "--state-root=/s".into(),
        format!(
            "--runtime-root={}:{}:{}",
            md.dev(),
            md.ino(),
            base.display()
        ),
    ];
    let raw = argv.iter().map(|s| s.as_bytes()).collect::<Vec<_>>();
    println!(
        "fixture\titeration\tcompiled_bytes\tprefilter_ns\tstaged_file_read_decode_ns\trespond_render_ns\tread_ns\tchecksum_decode_ns"
    );
    for (name, config) in [("normal", &mut ordinary), ("4096-band", &mut boundary)] {
        let s = Snapshot {
            id: Identity {
                boot: clock.boot,
                epoch: [3; 16],
                context: snapshot::context_crc(b"/c", b"/s").unwrap(),
                generation: 1,
                source: [4; 4],
            },
            config: config.clone(),
            metadata: snapshot::encode_metadata(b"metadata stays unread").unwrap(),
        };
        let wire = s.encode(clock.kind, clock.resume).unwrap();
        let compiled_len = snapshot::lengths(&wire).unwrap().0;
        let marker = Marker {
            id: s.id,
            seq: 1,
            verified_at: clock.now,
            kind: clock.kind,
            domain: clock.domain,
            resume: clock.resume,
            invalid: false,
        };
        for (name, bytes) in [
            ("snapshot", wire.as_slice()),
            ("last-good", wire.as_slice()),
            ("marker", &marker.encode()),
        ] {
            fs::write(store.join(name), bytes).unwrap();
            fs::set_permissions(store.join(name), fs::Permissions::from_mode(0o600)).unwrap();
        }
        for iteration in 0..260 {
            // Descriptor setup is outside the staged read/decode measurement.
            let mut fd = fs::File::open(store.join("snapshot")).unwrap();
            let start = Instant::now();
            let mut decoder = FrontDecoder::new(wire.len() as u64).unwrap();
            let mut buffer = [0; snapshot::READ_CHUNK];
            while decoder.read_len() != 0 {
                let len = decoder.read_len();
                fd.read_exact(&mut buffer[..len]).unwrap();
                decoder.push(&buffer[..len]).unwrap();
            }
            let read_ns = start.elapsed().as_nanos();
            let decode_start = Instant::now();
            // The envelope's width (--width 120 above) selects the decoded variant.
            let decoded = decoder.finish_for(120).unwrap();
            let decode_ns = decode_start.elapsed().as_nanos();
            let staged_ns = start.elapsed().as_nanos();
            black_box(&decoded);
            assert_eq!(decoded.config.bands().len(), config.bands.len());
            let deadline = prompt_io::entry_deadline().unwrap();
            let start = Instant::now();
            let respond = prompt_read::prepare(&raw, deadline);
            let prefilter_ns = start.elapsed().as_nanos();
            let respond_ns = if native_available {
                let start = Instant::now();
                let record = respond();
                let ns = start.elapsed().as_nanos();
                assert!(record.windows(7).any(|w| w == b"ok:none"), "{record:?}");
                ns.to_string()
            } else {
                drop(respond);
                "NA-native-clock-denied".into()
            };
            if iteration >= 20 {
                println!(
                    "{name}\t{}\t{compiled_len}\t{prefilter_ns}\t{staged_ns}\t{respond_ns}\t{read_ns}\t{decode_ns}",
                    iteration - 20
                );
            }
        }
    }
}
/// One refresh-helper spawn, as `bingsu prompt` does it, in a fresh process:
/// `exe` is the product binary and `words` the product prompt's argv after
/// `prompt` (bench/n7_measure.py takes them from a real `init`). The interval
/// holds the shipped `bootstrap` only: its fd-table walk, CLOEXEC marking and
/// posix_spawn. The helper's own work runs after it, outside the interval.
#[cfg(all(unix, not(test)))]
fn helper_spawn(exe: std::ffi::OsString, words: Vec<std::ffi::OsString>) {
    use std::os::unix::ffi::OsStrExt;
    let stamp = || prompt_io::monotonic_ns().unwrap();
    let raw: Vec<&[u8]> = words.iter().map(|w| w.as_bytes()).collect();
    let deadline = prompt_io::entry_deadline();
    let args_ready = stamp();
    let bootstrap_enter = stamp();
    prompt_spawn::bootstrap(&exe, &raw, deadline);
    let bootstrap_return = stamp();
    let spawned = children();
    // bootstrap set SIGCHLD to SA_NOCLDWAIT: wait blocks until every child has
    // exited, then fails with ECHILD. No helper outlives the sample.
    let reaped = loop {
        // SAFETY: a null status pointer is allowed.
        if unsafe { libc::wait(std::ptr::null_mut()) } == -1 {
            match std::io::Error::last_os_error().raw_os_error() {
                Some(libc::EINTR) => continue,
                errno => break errno == Some(libc::ECHILD),
            }
        }
    };
    let helpers_gone = stamp();
    println!(
        "{{\"events\":{{\"args_ready\":{args_ready},\"bootstrap_enter\":{bootstrap_enter},\"bootstrap_return\":{bootstrap_return},\"helpers_gone\":{helpers_gone}}},\"helpers_reaped\":{reaped},\"children_after_spawn\":{spawned}}}"
    );
}

/// Live children of this process, observed after the interval: the helper is
/// still running (it takes milliseconds), so 1 proves bootstrap spawned it.
#[cfg(all(target_os = "macos", not(test)))]
fn children() -> i32 {
    let mut pids = [0 as libc::pid_t; 64];
    let me = std::process::id() as libc::pid_t;
    // SAFETY: a writable buffer of the stated size.
    let n = unsafe {
        libc::proc_listchildpids(
            me,
            pids.as_mut_ptr().cast(),
            std::mem::size_of_val(&pids) as i32,
        )
    };
    pids[..n.clamp(0, 64) as usize]
        .iter()
        .filter(|&&p| p > 0)
        .count() as i32
}
#[cfg(all(target_os = "linux", not(test)))]
fn children() -> i32 {
    let pid = std::process::id();
    std::fs::read_to_string(format!("/proc/self/task/{pid}/children"))
        .map_or(-1, |s| s.split_whitespace().count() as i32)
}
#[cfg(all(unix, not(any(target_os = "macos", target_os = "linux")), not(test)))]
fn children() -> i32 {
    -1
}
// The shipped readers exist only on Unix; elsewhere this entry is empty.
#[cfg(not(all(unix, not(test))))]
fn main() {}
