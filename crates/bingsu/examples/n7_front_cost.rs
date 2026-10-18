//! Test/measurement entry only. Uses the exact shipped prefilter reader and
//! decoder; no additional effects or fault switches in the installed binary.
#![allow(
    dead_code,
    reason = "shares production adapters and the complete wire fixture"
)]
#[cfg(not(test))]
#[path = "../../bingsu-core-tests/src/snapshot_fixture.rs"]
mod fixture;
#[cfg(not(test))]
#[path = "../src/prompt_io.rs"]
mod prompt_io;
#[cfg(not(test))]
#[path = "../src/prompt_read.rs"]
mod prompt_read;

#[cfg(not(test))]
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
    let base = std::path::PathBuf::from(
        std::env::args_os()
            .nth(1)
            .expect("private fixture directory"),
    );
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
            let decoded = decoder.finish().unwrap();
            let decode_ns = decode_start.elapsed().as_nanos();
            let staged_ns = start.elapsed().as_nanos();
            black_box(&decoded);
            assert_eq!(decoded.config.bands.len(), config.bands.len());
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
#[cfg(test)]
fn main() {}
