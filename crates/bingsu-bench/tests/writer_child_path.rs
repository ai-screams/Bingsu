//! The exact spawn path the writer-order benchmark times: the child holds no
//! fd above 2 (a leaked non-CLOEXEC fd at >= 100 is present in the parent,
//! and a control child without the close sees it) and runs in its own session.
#![cfg(any(target_os = "linux", target_os = "macos"))]
use std::process::Command;

// 이것을 실패시키는 것: SETSID를 빼는 것(같은 세션), 자식 쪽 fd 닫기를 빼는 것(유출 fd가 보임),
// 저장한 fd 1·2를 close-on-exec 없이 두는 것, fd 목록을 낮은 번호까지만 보는 것(대조 자식이 유출을 못 봄),
// fd 1을 파이프로 옮기지 않는 것(자식 출력이 "CHILD " 줄로 오지 않음).
#[test]
fn writer_child_has_only_stdio_and_own_session() {
    let out = Command::new(env!("CARGO_BIN_EXE_m1-writer-child"))
        .args(["--probe-child", env!("CARGO_BIN_EXE_m1-fd-report")])
        .output()
        .unwrap();
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(
        out.status.success(),
        "{text}{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let field = |k: &str| {
        text.lines()
            .find_map(|l| l.strip_prefix(k))
            .unwrap_or_else(|| panic!("no {k:?} in {text}"))
            .to_string()
    };
    let leak = field("LEAK ");
    assert!(
        leak.parse::<i32>().unwrap() >= 100,
        "leak not planted high: {text}"
    );
    let control = field("CONTROL_FDS ");
    assert!(
        control.split(',').any(|f| f == leak),
        "report cannot see fd {leak}: {text}"
    );
    for s in field("SAVED ").split(',') {
        assert!(
            !control.split(',').any(|f| f == s),
            "saved copy {s} is inheritable: {text}"
        );
    }
    assert_eq!(field("CHILD FDS "), "-", "child inherited fds: {text}");
    assert_eq!(field("CHILD_STATUS "), "0", "child failed: {text}");
    assert_ne!(
        field("CHILD SID "),
        field("PARENT_SID "),
        "child shares the parent's session: {text}"
    );
}
