//! The helper's I/O caps (user decision U2) through `bingsu reload`, which
//! publishes with the refresh engine: a config exactly at a cap publishes,
//! one unit past it ends "not finished" (3) with the context files unchanged.
//! Here: R, E_n and B, whose exact boundaries do not depend on the platform.
//! E_b, P and L boundaries depend on record sizes and path depth and are not
//! exercised here at the real caps; F cannot cross before R (each file is a
//! candidate), D is 1 with the one conf.d, and M needs 17 mounts. The in-crate
//! refresh tests cross all nine with lowered caps.
#![cfg(unix)]

#[path = "support/user_env.rs"]
mod user_env;
use user_env::{Env, quiet, text};

const COMMAND: &str = "[segment.\"custom/probe\"]\nkind = \"command\"\ncommand = [\"printf\", \"NEVER_EXECUTE\"]\n[layout.line1]\nleft = [\"custom/probe\", \"char\"]\n";
const KIB256: usize = 256 * 1024;

fn reload(e: &Env) -> (Option<i32>, String) {
    let o = e.run(&["reload"]);
    (
        o.status.code(),
        format!("{}{}", text(&o.stdout), quiet(&o.stderr)),
    )
}

/// The bytes a refresh may write: snapshot, last-good, marker, sequence.
fn context(e: &Env) -> Vec<Vec<u8>> {
    let dir = e.context_dir();
    ["snapshot", "last-good", "marker", "sequence"]
        .iter()
        .map(|n| std::fs::read(dir.join(n)).unwrap())
        .collect()
}

fn extends(refs: &[String], body: &str) -> String {
    let list: Vec<String> = refs.iter().map(|r| format!("{r:?}")).collect();
    format!("extends = [{}]\n{body}", list.join(", "))
}

/// `n` bytes that do not parse: core drops the file alone and publishes.
fn unparsable(n: usize) -> String {
    let mut s = String::from("[style\n");
    s.extend(std::iter::repeat_n('x', n - s.len()));
    s
}

/// `reload` on the real clock: a busy machine can pass the helper's 500 ms
/// work budget, which also ends 3, so a 3 is tried again. A refused cap ends 3
/// on every attempt, so it stays 3 here; one other outcome on any attempt is
/// what comes back. A budget stop cannot turn an over-cap cell into a 0.
fn reload_settled(e: &Env) -> (Option<i32>, String) {
    let mut last = reload(e);
    for _ in 0..4 {
        if last.0 != Some(3) {
            break;
        }
        last = reload(e);
    }
    last
}

/// Publishes `COMMAND`, applies `past`, reloads: the outcome and whether
/// the context files stayed as they were.
fn after(e: &Env, past: impl FnOnce(&Env)) -> (Option<i32>, bool, String) {
    e.put_config("config.toml", COMMAND);
    let (code, out) = reload_settled(e);
    assert_eq!(code, Some(0), "{out}");
    let before = context(e);
    past(e);
    let (code, out) = reload_settled(e);
    (code, context(e) == before, out)
}

// 실제 U2 값에서 R·E_n·B 각각: cap에 딱 맞는 설정은 발행되고(0), 하나 넘으면 3(끝나지 않음)이며
// snapshot·last-good·marker·sequence가 그대로다.
// 이것을 실패시키는 것: 거부된 extends 항목이나 없는 뿌리 후보를 R에서 빼는 것, conf.d의 설정이 아닌 항목을
// 세지 않거나 재검증 목록을 세지 않는 것, 버린 원본의 바이트를 B에서 빼는 것, cap 비교의 하나 차이, 상한
// 초과를 확인한 실패(1, 무효 표식)로 내는 것, sequence를 옮긴 뒤에 상한을 넘는 것, 상한 거부가 시도에 따라
// 풀리는 것(재시도가 그 0을 돌려줘 실패한다).
#[test]
fn reload_publishes_at_cap_and_keeps_the_marker_past_it() {
    let mut seen = Vec::new();
    // R: config.toml, the absent config.local.toml and n refused entries.
    for n in [254, 255] {
        let e = Env::new("helper_axis_caps", &format!("r-{n}"));
        let refs: Vec<String> = (0..n).map(|i| format!("$THEME_{i}")).collect();
        let (code, same, out) = after(&e, |e| {
            e.put_config("config.toml", &extends(&refs, COMMAND));
        });
        seen.push(("R", n, code, same, out));
    }
    // E_n: a.toml, k other entries, `.` and `..`, listed four times a round.
    for k in [253, 254] {
        let e = Env::new("helper_axis_caps", &format!("en-{k}"));
        let (code, same, out) = after(&e, |e| {
            e.put_config("conf.d/a.toml", "");
            for i in 0..k {
                e.put_config(&format!("conf.d/n{i:03}.txt"), "");
            }
        });
        seen.push(("E_n", k, code, same, out));
    }
    // B: the config and eight dropped themes, together exactly 2 MiB, or one more.
    for extra in [0, 1] {
        let e = Env::new("helper_axis_caps", &format!("b-{extra}"));
        let (code, same, out) = after(&e, |e| {
            let refs: Vec<String> = (0..8)
                .map(|i| {
                    e.base
                        .join(format!("themes/t{i}.toml"))
                        .display()
                        .to_string()
                })
                .collect();
            let config = extends(&refs, COMMAND);
            e.put_config("config.toml", &config);
            for (i, r) in refs.iter().enumerate() {
                let n = if i < 7 {
                    KIB256
                } else {
                    KIB256 - config.len() + extra
                };
                e.put(
                    &std::path::Path::new(r)
                        .strip_prefix(&e.base)
                        .unwrap()
                        .display()
                        .to_string(),
                    &unparsable(n),
                );
            }
        });
        seen.push(("B", extra, code, same, out));
    }
    let got: Vec<_> = seen
        .iter()
        .map(|(axis, n, code, same, _)| (*axis, *n, *code, *same))
        .collect();
    assert_eq!(
        got,
        [
            ("R", 254, Some(0), false),
            ("R", 255, Some(3), true),
            ("E_n", 253, Some(0), false),
            ("E_n", 254, Some(3), true),
            ("B", 0, Some(0), false),
            ("B", 1, Some(3), true),
        ],
        "{seen:#?}"
    );
}
