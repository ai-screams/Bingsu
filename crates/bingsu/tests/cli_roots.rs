//! The user's commands act on the roots init pinned (`BINGSU_ROOTS`, the
//! hook's own root words). Only an absent variable permits XDG fallback;
//! an unusable pin stops the command.
#![cfg(unix)]

#[path = "support/user_env.rs"]
mod user_env;
use user_env::{Env, FALLBACK_NOTICE, frame, text};

const VALID: &str = "icons = \"ascii\"\n";

fn notice_line() -> String {
    format!(
        "{FALLBACK_NOTICE}, not from what init pinned in this shell, so they may differ from the ones your prompt uses. Run: eval \"$(bingsu init <shell>)\" again\n"
    )
}

fn env_with_config(tag: &str) -> Env {
    let e = Env::new("cli_roots", tag);
    e.put_config("config.toml", VALID);
    e
}

// reload, config path and config use follow the pinned roots after XDG_* moved: the snapshot lands under the
// pinned runtime root, the record under the pinned state root, nothing is made where XDG_* now points, and
// stderr stays empty.
// 이것을 실패시키는 것: 명령이 변수를 무시하고 지금의 XDG_*로 뿌리를 찾는 것, 변수는 읽고도 안내를 내는 것.
#[test]
fn commands_use_the_pinned_roots_even_when_xdg_moved() {
    let e = env_with_config("moved");
    let var = frame(&e.pinned_words());
    let o = e.cmd_pinned(&["reload"], &var).output().unwrap();
    assert_eq!(o.status.code(), Some(0), "{}", text(&o.stderr));
    assert_eq!(text(&o.stderr), "");
    assert!(e.context_dir().join("snapshot").exists());
    assert!(!e.base.join("elsewhere").exists());
    let o = e.cmd_pinned(&["config", "path"], &var).output().unwrap();
    assert_eq!(text(&o.stderr), "");
    assert!(
        text(&o.stdout).contains("cfg/bingsu/config.toml"),
        "{}",
        text(&o.stdout)
    );
    let chosen = e.put("other/work.toml", VALID);
    let o = e
        .cmd_pinned(&["config", "use", chosen.to_str().unwrap()], &var)
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(0), "{}", text(&o.stderr));
    assert_eq!(text(&o.stderr), "");
    assert!(e.state_dir().join("config-use").exists());
    assert!(!e.base.join("elsewhere").exists());
}

// Without the variable the commands say so exactly once and use the environment.
// 이것을 실패시키는 것: 안내를 빼거나 두 번 내는 것, 안내를 stdout에 내는 것, 환경 폴백을 하지 않는 것.
#[test]
fn without_the_variable_one_notice_and_the_environment() {
    let e = env_with_config("fallback");
    for args in [&["reload"][..], &["config", "check"], &["config", "path"]] {
        let o = e.run(args);
        assert_eq!(o.status.code(), Some(0), "{args:?}: {}", text(&o.stderr));
        assert_eq!(text(&o.stderr), notice_line(), "{args:?}");
        assert!(!text(&o.stdout).contains("init pinned"), "{args:?}");
    }
    assert!(e.context_dir().join("snapshot").exists());
}

// Garbled, forged or stale values stop the command without XDG fallback or writes.
// 이것을 실패시키는 것: 런타임 뿌리의 dev/ino 재확인을 빼는 것, 모르는 낱말·중복 낱말·상대 경로·남는 바이트를 받는 것,
// home이 계정과 다른 값을 받는 것, 설정 뿌리를 다시 검사하지 않는 것.
#[test]
fn forged_or_garbled_values_are_rejected() {
    let e = env_with_config("forged");
    let good = e.pinned_words();
    let evil = e.base.join("evil");
    let swap = |i: usize, f: &dyn Fn(&str) -> String| {
        let mut w = good.clone();
        w[i] = f(&String::from_utf8(w[i].clone()).unwrap()).into_bytes();
        w
    };
    let mut cases: Vec<(&str, Vec<u8>)> = vec![
        ("garbage", b"not a value".to_vec()),
        ("empty", Vec::new()),
        ("length past the end", b"99:--home=/x".to_vec()),
        ("trailing bytes", [frame(&good), b"x".to_vec()].concat()),
        (
            "leading zero length",
            [b"0".to_vec(), frame(&good)].concat(),
        ),
    ];
    let mut dup = good.clone();
    dup.push(good[4].clone());
    cases.push(("duplicate state root", frame(&dup)));
    let mut extra = good.clone();
    extra.push(b"--bogus=1".to_vec());
    cases.push(("unknown word", frame(&extra)));
    cases.push(("missing home", frame(&good[..5])));
    cases.push((
        "wrong inode",
        frame(&swap(0, &|s| {
            let mut p: Vec<&str> = s.splitn(3, ':').collect();
            let ino: u64 = p[1].parse().unwrap();
            let bumped = (ino + 1).to_string();
            p[1] = &bumped;
            p.join(":")
        })),
    ));
    cases.push((
        "relative state root",
        frame(&swap(4, &|_| "--state-root=evil/state".into())),
    ));
    cases.push((
        "other home",
        frame(&swap(5, &|_| "--home=/nonexistent-home".into())),
    ));
    cases.push((
        "config root that does not match its written path",
        frame(&swap(2, &|_| {
            format!("--config-root={}", evil.join("cfg").display())
        })),
    ));
    for (name, var) in cases {
        let o = e.cmd_pinned(&["config", "path"], &var).output().unwrap();
        assert!(
            text(&o.stderr).contains("run bingsu init <shell> again"),
            "{name}: {}",
            text(&o.stderr)
        );
        assert_eq!(o.status.code(), Some(3), "{name}");
        assert!(!evil.exists(), "{name}");
    }
}

#[test]
fn replaced_runtime_and_config_pins_stop_read_commands_without_writes() {
    for replacement in ["runtime", "config"] {
        let e = env_with_config(&format!("replaced-{replacement}"));
        let var = frame(&e.pinned_words());
        if replacement == "runtime" {
            std::fs::rename(e.base.join("run"), e.base.join("old-run")).unwrap();
            std::fs::create_dir(e.base.join("run")).unwrap();
            user_env::chmod(&e.base.join("run"), 0o700);
        } else {
            std::fs::rename(e.config_dir(), e.base.join("old-config")).unwrap();
            std::os::unix::fs::symlink(e.base.join("old-config"), e.config_dir()).unwrap();
        }
        let before = e.tree();
        for args in [vec!["config", "check"], vec!["config", "path"]] {
            let o = e.cmd_pinned(&args, &var).output().unwrap();
            assert_eq!(
                o.status.code(),
                Some(3),
                "{replacement} {args:?}: {}",
                text(&o.stderr)
            );
            assert!(text(&o.stderr).contains("run bingsu init <shell> again"));
            assert_eq!(e.tree(), before, "{replacement} {args:?}");
            assert!(!e.base.join("elsewhere").exists());
        }
    }
}
