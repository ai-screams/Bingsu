//! Fixed product entry and one bounded request. Every startup error precedes
//! Ready and the first request read. Both Linux filters precede collection.
// Keep the sink binary-local. The startup integration target includes worker.rs
// directly and therefore exercises the same sink without linking it into lib.rs.
#[cfg(unix)]
#[path = "update_sink.rs"]
mod update_sink;
#[cfg(unix)]
use crate::{limits, sys};
#[cfg(unix)]
use bingsu_core::collection::{
    self,
    selection::PRODUCT,
    wire::{self, Frame, Kind, M3B_REQUEST_ID, RequestDecoder},
};
#[cfg(unix)]
pub(crate) use update_sink::UpdateSink;
#[cfg(unix)]
use update_sink::WireSink;

pub fn run() -> i32 {
    std::panic::set_hook(Box::new(|_| {}));
    let mut arguments = std::env::args_os().skip(1);
    if arguments.next().as_deref() != Some(std::ffi::OsStr::new("__collect-v1"))
        || arguments.next().is_some()
    {
        return 2;
    }
    #[cfg(unix)]
    {
        execute().map_or(1, |()| 0)
    }
    #[cfg(not(unix))]
    {
        1
    }
}

#[cfg(unix)]
fn execute() -> std::io::Result<()> {
    sys::orphan_guard()?;
    // Warm the allocator and the only frame buffer before baseline measurement.
    let mut buffer = Box::new([0; wire::FRAME_MAX]);
    std::hint::black_box(&mut buffer);
    let mut fds = sys::validate_worker_fds()?;
    sys::hygiene()?;
    let (installed, landlock) = protected()?;
    #[cfg(target_os = "macos")]
    let _access = probe_before_ready(&mut fds)?;
    exchange(
        &mut fds,
        &mut buffer,
        installed.baseline_bytes,
        landlock,
        &PRODUCT,
        crate::build_id(),
        |_, _: &mut dyn UpdateSink| Err(std::io::Error::other("no product workers")),
    )
}

#[cfg(target_os = "macos")]
fn probe_before_ready(fds: &mut sys::WorkerFds) -> std::io::Result<crate::safe_read::Access> {
    use std::time::{Duration, Instant};
    let probe = fds.take_probe();
    let mut meter = crate::meter::Meter::new(Instant::now() + Duration::from_millis(100));
    let result = crate::safe_read::macos::probe(probe.as_ref().map(|p| p.fixture()), &mut meter);
    // Close fd 6 and every probe-owned temporary before Ready/request IO.
    drop(probe);
    result.map_err(|_| std::io::Error::other("collector capability probe"))
}

// The shipped and fixture entries share this exact installation sequence.
#[cfg(unix)]
fn protected() -> std::io::Result<(limits::InstalledLimits, u32)> {
    protect(
        limits::install_base,
        limits::drop_capabilities,
        sys::no_new_privs,
        sys::initial_filter,
        limits::lower_as_under_filter,
        sys::final_filter,
    )
}

#[cfg(unix)]
fn protect(
    base: impl FnOnce() -> std::io::Result<()>,
    caps: impl FnOnce() -> std::io::Result<()>,
    nnp: impl FnOnce() -> std::io::Result<()>,
    initial: impl FnOnce() -> std::io::Result<u32>,
    baseline: impl FnOnce() -> std::io::Result<limits::InstalledLimits>,
    final_filter: impl FnOnce() -> std::io::Result<()>,
) -> std::io::Result<(limits::InstalledLimits, u32)> {
    base()?;
    caps()?;
    nnp()?;
    let landlock = initial()?;
    let installed = baseline()?;
    final_filter()?;
    Ok((installed, landlock))
}

#[cfg(unix)]
fn exchange(
    fds: &mut sys::WorkerFds,
    buffer: &mut [u8; wire::FRAME_MAX],
    baseline: u64,
    landlock: u32,
    catalog: &collection::selection::Catalog<'_>,
    build_id: wire::BuildId,
    collect: impl FnOnce(&wire::Request, &mut dyn UpdateSink) -> std::io::Result<()>,
) -> std::io::Result<()> {
    exchange_with_sink(
        fds,
        buffer,
        baseline,
        landlock,
        catalog,
        build_id,
        |request, sink| collect(request, sink),
    )
}

#[cfg(unix)]
fn exchange_with_sink(
    fds: &mut sys::WorkerFds,
    buffer: &mut [u8; wire::FRAME_MAX],
    baseline: u64,
    landlock: u32,
    catalog: &collection::selection::Catalog<'_>,
    build_id: wire::BuildId,
    collect: impl FnOnce(&wire::Request, &mut WireSink<'_>) -> std::io::Result<()>,
) -> std::io::Result<()> {
    let bad = |_| std::io::Error::other("worker protocol");
    let mut payload = [0; 24];
    payload[..8].copy_from_slice(&wire::FEATURES.to_le_bytes());
    payload[8..12].copy_from_slice(&catalog.workers.to_le_bytes());
    payload[12..16].copy_from_slice(&landlock.to_le_bytes());
    payload[16..].copy_from_slice(&baseline.to_le_bytes());
    let ready = Frame {
        kind: Kind::Ready,
        build_id,
        request_id: M3B_REQUEST_ID,
        payload: &payload,
    };
    let n = wire::encode_frame(ready, buffer).map_err(bad)?;
    fds.write_all(&buffer[..n])?;
    let mut decoder = RequestDecoder::new();
    decoder.accept(ready).map_err(bad)?;
    loop {
        fds.read_exact(&mut buffer[..wire::HEADER])?;
        let len = wire::frame_len(&buffer[..wire::HEADER]).map_err(bad)?;
        fds.read_exact(&mut buffer[wire::HEADER..len])?;
        let frame = wire::decode_frame(&buffer[..len]).map_err(bad)?;
        if let Some(request) = decoder.accept(frame).map_err(bad)? {
            // Second product policy boundary, even after wire validation. A
            // catalog is explicit; no argv, feature or environment selects it.
            let selected = collection::request(
                catalog,
                request.binding.clone(),
                request.request_id,
                request.budget_ms,
            )
            .map_err(bad)?;
            let mut write = |bytes: &[u8]| fds.write_all(bytes);
            let mut sink = WireSink::new(&request, catalog.segments, &payload, buffer, &mut write)?;
            if let Some(request) = selected {
                collect(&request, &mut sink)?;
            }
            return sink.complete();
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::{cell::RefCell, io};

    // 이것을 실패시키는 것: 최종 필터 전에 Ready·요청·스레드를 허용하거나 seal 생략.
    #[test]
    fn filter_installed_before_threads_and_ready() {
        for failure in 0..=7 {
            let trace = RefCell::new(Vec::new());
            let stage = |n| {
                trace.borrow_mut().push(n);
                if n == failure {
                    Err(io::Error::other("injected"))
                } else {
                    Ok(())
                }
            };
            let result = protect(
                || stage(1),
                || stage(2),
                || stage(3),
                || {
                    stage(4)?;
                    stage(5)?;
                    Ok(3)
                },
                || {
                    stage(6)?;
                    Ok(limits::InstalledLimits {
                        baseline_bytes: 1,
                        memory_limit_bytes: 2,
                    })
                },
                || stage(7),
            );
            if result.is_ok() {
                for event in [8, 9, 10] {
                    stage(event).unwrap();
                } // Ready, request, thread
            }
            assert_eq!(result.is_ok(), failure == 0);
            assert_eq!(
                *trace.borrow(),
                (1..=if failure == 0 { 10 } else { failure }).collect::<Vec<_>>()
            );
        }
    }

    // 이것을 실패시키는 것: 보호 단계의 순서를 바꾸거나 실패 뒤 단계를 실행하는 것.
    #[test]
    fn startup_baseline_is_read_under_filter_before_ready() {
        for failure in 0..=6 {
            let trace = RefCell::new(Vec::new());
            let stage = |n| {
                trace.borrow_mut().push(n);
                if failure == n {
                    Err(io::Error::other("injected"))
                } else {
                    Ok(())
                }
            };
            let result = protect(
                || stage(1),
                || stage(2),
                || stage(3),
                || stage(4).map(|()| 0),
                || {
                    stage(5).map(|()| limits::InstalledLimits {
                        baseline_bytes: 1,
                        memory_limit_bytes: 2,
                    })
                },
                || stage(6),
            );
            assert_eq!(result.is_ok(), failure == 0);
            assert_eq!(
                *trace.borrow(),
                (1..=if failure == 0 { 6 } else { failure }).collect::<Vec<_>>()
            );
        }
    }
}

/// Test target only, with a distinct build identity and a fixed deterministic
/// catalog. No product feature, argv or environment switch reaches this entry.
#[cfg(all(test, unix))]
#[allow(
    dead_code,
    reason = "called by the startup integration target, never shipped"
)]
pub(crate) fn fixture_entry() -> std::io::Result<()> {
    use bingsu_core::field::SegmentDecl;
    sys::orphan_guard()?;
    let mut buffer = Box::new([0; wire::FRAME_MAX]);
    let mut fds = sys::validate_worker_fds()?;
    sys::hygiene()?;
    let (installed, landlock) = protected()?;
    #[cfg(target_os = "macos")]
    let _access = probe_before_ready(&mut fds)?;
    let catalog = collection::selection::Catalog {
        segments: &[const {
            SegmentDecl {
                id: "fixture",
                role: "fg",
                fields: &[],
            }
        }; 32],
        workers: 1 << 31,
    };
    let test_id = wire::BuildId(bingsu_core::collection::cwd_hash::sha256(
        &[crate::build_id().0.as_slice(), b"test-worker"].concat(),
    ));
    exchange_with_sink(
        &mut fds,
        &mut buffer,
        installed.baseline_bytes,
        landlock,
        &catalog,
        test_id,
        |_, sink| {
            let mut payload = vec![31, 0, 1];
            payload.extend(7u32.to_le_bytes());
            payload.extend(b"fixture");
            payload.extend(0u16.to_le_bytes());
            payload.push(0);
            sink.fixture_update(&payload)
        },
    )
}
