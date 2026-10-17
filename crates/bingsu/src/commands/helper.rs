//! Detached fixed refresh command. All NSS, source I/O and publication live here.
use super::{
    clock::SystemClock,
    collector,
    group_policy::SystemGroups,
    helper_filter, helper_limits, log,
    refresh::{self, RefreshRequest, RefreshResult},
    sys,
};
use bingsu_core::{collection, envelope::LogLevel, snapshot::ClockSource};
use std::{
    ffi::{OsStr, OsString},
    os::unix::ffi::OsStrExt,
    path::Path,
    process::ExitCode,
    time::Instant,
};

pub fn run(exe: &OsStr, args: &[OsString]) -> ExitCode {
    let started = Instant::now();
    std::panic::set_hook(Box::new(|_| {}));
    if detach().is_err() {
        return ExitCode::from(1);
    }
    let Ok(_watchdog) = helper_limits::start(started) else {
        return ExitCode::from(1);
    };
    if helper_limits::install(&_watchdog).is_err() {
        return ExitCode::from(1);
    }
    let raw: Vec<_> = args.iter().map(|a| a.as_bytes()).collect();
    let Ok(e) = bingsu_core::helper::validate(&raw) else {
        return ExitCode::from(1);
    };
    // Capture clock identity before the first trust observation (including NSS).
    let mut clock = SystemClock;
    let process_started = clock.observe();
    let Some(user) = sys::passwd_entry(sys::current_uid()) else {
        return ExitCode::from(1);
    };
    let mut groups = SystemGroups::new(&user.name);
    let log_root = e
        .log_root
        .as_deref()
        .map(|b| Path::new(OsStr::from_bytes(b)));
    let report = |groups: &mut SystemGroups, severity, text| {
        log::event(
            e.log_level,
            log_root,
            sys::current_uid(),
            groups,
            severity,
            text,
        )
    };
    let Ok(process_started) = process_started else {
        report(
            &mut groups,
            LogLevel::Error,
            "refresh incomplete: clock observation",
        );
        return ExitCode::from(1);
    };
    let version = bingsu_core::VERSION
        .split('.')
        .take(3)
        .map(|n| n.parse().unwrap_or(0))
        .collect::<Vec<_>>();
    let Some(request) = RefreshRequest::from_envelope(
        &e,
        &user,
        process_started,
        [version[0], version[1], version[2]],
    ) else {
        return ExitCode::from(1);
    };
    let mut filter_failed = false;
    let result = refresh::refresh_broker(request, &mut clock, &mut |context, display, now| {
        let request = if let (Some((config, id)), Some(cwd)) = (display, e.pwd.as_deref()) {
            collection::Request::new(
                id,
                now,
                e.config_root.as_deref().unwrap_or(b""),
                e.state_root.as_deref().unwrap_or(b""),
                cwd,
                config.collect_mask,
            )?
        } else {
            None
        };
        before_filter(
            request,
            |request| {
                // Collection failure keeps the last completed result and does not
                // change independently validated configuration publication.
                let _ = collector::spawn(exe, context, &request, sys::current_uid());
            },
            || {
                if let Err(error) = helper_filter::install() {
                    filter_failed = true;
                    return Err(error.into());
                }
                Ok(())
            },
        )
    });
    if filter_failed {
        report(
            &mut groups,
            LogLevel::Error,
            "refresh incomplete: helper TSYNC filter unavailable",
        );
    }
    match result {
        RefreshResult::Published { .. } => report(&mut groups, LogLevel::Info, "refresh published"),
        RefreshResult::Revalidated { .. } => {
            report(&mut groups, LogLevel::DebugLog, "refresh revalidated")
        }
        RefreshResult::Busy => report(&mut groups, LogLevel::DebugLog, "refresh busy"),
        RefreshResult::Invalid => report(&mut groups, LogLevel::Error, "refresh invalid"),
        RefreshResult::Incomplete => report(&mut groups, LogLevel::Error, "refresh incomplete"),
    }
    if matches!(result, RefreshResult::Incomplete | RefreshResult::Invalid) {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

pub(super) fn detach() -> Result<(), ()> {
    // SAFETY: own fresh child process; no pointers. Failure aborts before NSS/I/O.
    if unsafe { libc::setsid() } < 0 {
        Err(())
    } else {
        // SAFETY: helper-local creation policy; never changes the prompt/shell.
        unsafe { libc::umask(0o077) };
        Ok(())
    }
}

fn before_filter(
    request: Option<collection::Request>,
    spawn: impl FnOnce(collection::Request),
    filter: impl FnOnce() -> Result<(), super::snapshot_store::StoreError>,
) -> Result<(), super::snapshot_store::StoreError> {
    if let Some(request) = request {
        spawn(request);
    }
    filter()
}
#[cfg(test)]
mod tests {
    use super::*;
    // 이것을 실패시키는 것: 수집 전에 필터를 설치하거나 필요 없는 worker를 생성하거나 필터 실패를 무시하는 것.
    #[test]
    fn collection_precedes_filter_only_when_needed() {
        let events = std::cell::RefCell::new(Vec::new());
        let id = bingsu_core::snapshot::Identity {
            boot: [1; 16],
            epoch: [2; 16],
            generation: 1,
            source: [3; 4],
            context: bingsu_core::snapshot::context_crc(b"/c", b"/s").unwrap(),
        };
        let now = bingsu_core::snapshot::Clock {
            boot: id.boot,
            kind: 1,
            domain: [0; 16],
            resume: 0,
            now: 1,
        };
        let request = collection::Request::new(id, now, b"/c", b"/s", b"/r", u32::MAX).unwrap();
        before_filter(
            request,
            |_| events.borrow_mut().push("spawn"),
            || {
                events.borrow_mut().push("filter");
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(*events.borrow(), ["spawn", "filter"]);
        events.borrow_mut().clear();
        before_filter(
            None,
            |_| panic!("unexpected spawn"),
            || {
                events.borrow_mut().push("filter");
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(*events.borrow(), ["filter"]);
        assert!(
            before_filter(
                None,
                |_| {},
                || Err(super::super::snapshot_store::StoreError::Unsafe)
            )
            .is_err()
        );
    }
}
