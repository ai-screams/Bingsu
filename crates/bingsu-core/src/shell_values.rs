//! Segment values the front end makes from the envelope alone (spec
//! section 4 process table: `status`, `duration`, `jobs`, `char`, and
//! `dir`, `host`, `venv` from display-only hook words, never opened).
//! git and time stay hidden until their tasks land.
use crate::envelope::Envelope;
use crate::field::{BUILTIN, Field, FieldValue, Value, segment, write_duration};
use crate::shorten::{Anchor, MAX_STEPS, PathFacts};
use crate::width::WidthProfile;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

/// Shown from this many milliseconds (spec section 4 "필수 세그먼트":
/// default 2 s). Becomes `[segment.duration] min` with the config.
pub const DURATION_MIN_MS: u64 = 2000;

/// Values and facts per `field::BUILTIN` entry, same index.
pub struct Collected {
    pub values: Vec<Option<Value>>,
    pub facts: Vec<Option<PathFacts>>,
}

fn index(id: &str) -> usize {
    BUILTIN
        .iter()
        .position(|d| d.id == id)
        .unwrap_or(BUILTIN.len())
}

/// A value of `id` with the named fields set and the rest Absent.
fn value(id: &str, text: &[u8], set: &[(&str, Field)]) -> Option<Value> {
    let d = segment(id)?;
    let mut f = vec![Field::ABSENT; d.fields.len()];
    for (name, field) in set {
        if let Some(k) = d.field_index(name) {
            f[k] = field.clone();
        }
    }
    Some(Value::new(text, f))
}

fn put(c: &mut Collected, id: &str, v: Option<Value>) {
    if let Some(slot) = c.values.get_mut(index(id)) {
        *slot = v;
    }
}

/// `~` when `pwd` is `home` or under it; a home of `/` never anchors.
/// Steps are the non-empty parts between `/`: `$PWD` is logical, so `.`
/// and `..` are kept as names, as the shell shows them.
pub fn path_facts(pwd: &[u8], home: Option<&[u8]>) -> PathFacts {
    let home = home.map(|h| h.strip_suffix(b"/").unwrap_or(h));
    let rest = home.filter(|h| !h.is_empty()).and_then(|h| {
        let r = pwd.strip_prefix(h)?;
        (r.is_empty() || r.first() == Some(&b'/')).then_some(r)
    });
    let (anchor, rest) = match rest {
        Some(r) => (Anchor::Home, r),
        None => (Anchor::Root, pwd),
    };
    PathFacts::new(anchor, &last_steps(rest), None, &[])
}

/// The non-empty parts between `/`, at most the last `MAX_STEPS`.
/// `PathFacts::new` keeps only those anyway; cutting here means a 64 KiB
/// `$PWD` of 32,767 steps is not split and collected whole (decision P14).
fn last_steps(rest: &[u8]) -> Vec<&[u8]> {
    let mut steps: Vec<&[u8]> = rest
        .rsplit(|&b| b == b'/')
        .filter(|s| !s.is_empty())
        .take(MAX_STEPS)
        .collect();
    steps.reverse();
    steps
}

fn decimal(n: impl core::fmt::Display) -> Vec<u8> {
    n.to_string().into_bytes()
}

pub fn collect(e: &Envelope) -> Collected {
    collect_with_duration_min(e, DURATION_MIN_MS)
}

/// The threshold is from the validated compiled configuration, in milliseconds.
pub fn collect_with_duration_min(e: &Envelope, duration_min_ms: u64) -> Collected {
    let mut c = Collected {
        values: vec![None; BUILTIN.len()],
        facts: vec![None; BUILTIN.len()],
    };
    let code = e.status.unwrap_or(0);
    let pipe = e.pipestatus.as_deref().unwrap_or(&[]);
    // One verdict for `char` and `status` (spec section 4 "필수 세그먼트":
    // status shows a failure of any pipe stage, so char must too).
    let failed = code != 0 || pipe.iter().any(|&s| s != 0);
    let vicmd = e.keymap.as_deref() == Some(b"vicmd");
    put(
        &mut c,
        "char",
        value(
            "char",
            b"",
            &[
                ("failed", Field::known(FieldValue::Bool(failed))),
                ("vicmd", Field::known(FieldValue::Bool(vicmd))),
            ],
        ),
    );
    if let Some(pwd) = e.pwd.as_deref() {
        put(
            &mut c,
            "dir",
            value(
                "dir",
                b"",
                &[("path", Field::text(pwd, 4096, WidthProfile::DEFAULT))],
            ),
        );
        if let Some(slot) = c.facts.get_mut(index("dir")) {
            *slot = Some(path_facts(pwd, e.home.as_deref()));
        }
    }
    if let Some(host) = e.host.as_deref() {
        put(
            &mut c,
            "host",
            value(
                "host",
                host,
                &[
                    ("name", Field::text(host, 64, WidthProfile::DEFAULT)),
                    ("ssh", Field::known(FieldValue::Bool(e.ssh))),
                ],
            ),
        );
    }
    if let Some(venv) = e.venv.as_deref() {
        let venv = venv
            .rsplit(|b| *b == b'/')
            .find(|p| !p.is_empty())
            .unwrap_or(b"");
        put(
            &mut c,
            "venv",
            value(
                "venv",
                venv,
                &[("name", Field::text(venv, 64, WidthProfile::DEFAULT))],
            ),
        );
    }
    if failed {
        let joined: Vec<u8> = pipe
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>()
            .join("|")
            .into_bytes();
        let text = if pipe.len() > 1 {
            joined.clone()
        } else {
            decimal(code)
        };
        let mut set = vec![("code", Field::known(FieldValue::Int(i64::from(code))))];
        if pipe.len() > 1 {
            set.push((
                "pipestatus",
                Field::text(&joined, 64, WidthProfile::DEFAULT),
            ));
        }
        put(&mut c, "status", value("status", &text, &set));
    }
    if let Some(ms) = e.duration_ms.filter(|&ms| ms >= duration_min_ms) {
        let mut t = String::new();
        write_duration(ms, &mut t);
        put(
            &mut c,
            "duration",
            value(
                "duration",
                t.as_bytes(),
                &[("ms", Field::known(FieldValue::Duration { ms }))],
            ),
        );
    }
    if let Some(n) = e.jobs.filter(|&n| n > 0) {
        put(
            &mut c,
            "jobs",
            value(
                "jobs",
                &decimal(n),
                &[(
                    "count",
                    Field::known(FieldValue::Count {
                        n,
                        saturated: false,
                    }),
                )],
            ),
        );
    }
    c
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::borrow::ToOwned;
    use alloc::format;

    fn blank() -> Envelope {
        Envelope {
            width: 80,
            ..Envelope::default()
        }
    }

    fn shown(c: &Collected, id: &str) -> Option<String> {
        c.values[index(id)].as_ref().map(|v| v.text().to_owned())
    }

    // 이것을 실패시키는 것: 홈 접두사를 글자 단위로 비교하는 것(/home/ub가 ~b가 됨), 홈 `/`로 모든 경로를 ~로 만드는 것,
    // 홈 끝의 `/`를 지우지 않는 것.
    #[test]
    fn home_anchor_is_a_folder_boundary() {
        let d = |p: &[u8], h: Option<&[u8]>| path_facts(p, h).display();
        assert_eq!(d(b"/home/u/src", Some(b"/home/u")), "~/src");
        assert_eq!(d(b"/home/u", Some(b"/home/u/")), "~");
        assert_eq!(d(b"/home/ub", Some(b"/home/u")), "/home/ub");
        assert_eq!(d(b"/etc", Some(b"/")), "/etc");
        assert_eq!(d(b"/", None), "/");
        assert_eq!(d(b"//a///b", None), "/a/b");
    }

    // 이것을 실패시키는 것: host/venv 정제를 빼거나 SSH를 host 존재에서 추론하는 것.
    #[test]
    fn display_words_are_sanitized_and_ssh_is_separate() {
        let mut e = blank();
        e.host = Some(b"host\x1b\n\0name".to_vec());
        e.venv = Some(b"/virtual/env\x1b\r\0name/".to_vec());
        let c = collect(&e);
        assert_eq!(shown(&c, "host").as_deref(), Some("hostname"));
        assert_eq!(shown(&c, "venv").as_deref(), Some("envname"));
        let ssh = segment("host").unwrap().field_index("ssh").unwrap();
        assert_eq!(
            c.values[index("host")].as_ref().unwrap().fields[ssh].value,
            FieldValue::Bool(false)
        );
        e.ssh = true;
        assert_eq!(
            collect(&e).values[index("host")].as_ref().unwrap().fields[ssh].value,
            FieldValue::Bool(true)
        );
        e.host = None;
        assert!(collect(&e).values[index("host")].is_none());
    }

    fn char_failed(c: &Collected) -> FieldValue {
        let ch = c.values[index("char")].as_ref().unwrap();
        let k = segment("char").unwrap().field_index("failed").unwrap();
        ch.fields[k].value.clone()
    }

    // 이것을 실패시키는 것: 뒤에서 MAX_STEPS 단계까지만 자르지 않는 것(`take`를 빼면 길이 단언),
    // 앞이 아니라 뒤를 버리는 것, 순서를 뒤집어 두는 것(표시 단언).
    #[test]
    fn long_paths_keep_the_last_steps_and_draw_the_same() {
        let mut pwd = Vec::new();
        for i in 0..MAX_STEPS + 10 {
            pwd.extend_from_slice(format!("/s{i}").as_bytes());
        }
        let cut = last_steps(&pwd);
        assert_eq!(cut.len(), MAX_STEPS);
        assert_eq!(cut[0], b"s10");
        assert_eq!(cut[MAX_STEPS - 1], format!("s{}", MAX_STEPS + 9).as_bytes());
        let all: Vec<&[u8]> = pwd
            .split(|&b| b == b'/')
            .filter(|s| !s.is_empty())
            .collect();
        let whole = PathFacts::new(Anchor::Root, &all, None, &[]);
        assert_eq!(path_facts(&pwd, None).display(), whole.display());
    }

    // 이것을 실패시키는 것: 성공에서 status를 보이는 것, 파이프 한 단계 실패를 숨기는 것, char의 failed를 뒤집는 것,
    // char가 파이프 실패를 보지 않는 것(`failed = code != 0`), char를 늘 실패로 두는 것.
    #[test]
    fn status_only_on_failure() {
        let mut e = blank();
        e.status = Some(0);
        e.pipestatus = Some(vec![0]);
        let c = collect(&e);
        assert_eq!(shown(&c, "status"), None);
        assert_eq!(char_failed(&c), FieldValue::Bool(false));
        e.pipestatus = Some(vec![1, 0]);
        let c = collect(&e);
        assert_eq!(shown(&c, "status").as_deref(), Some("1|0"));
        assert_eq!(char_failed(&c), FieldValue::Bool(true));
        e.status = Some(130);
        e.pipestatus = Some(vec![130]);
        let c = collect(&e);
        assert_eq!(shown(&c, "status").as_deref(), Some("130"));
        assert_eq!(char_failed(&c), FieldValue::Bool(true));
    }

    // 이것을 실패시키는 것: 기준을 `>`로 바꾸는 것(2000ms가 숨음), 기준을 빼는 것(1999ms가 보임), jobs 0을 보이는 것.
    #[test]
    fn duration_from_two_seconds_and_jobs_from_one() {
        let mut e = blank();
        e.duration_ms = Some(1999);
        e.jobs = Some(0);
        let c = collect(&e);
        assert_eq!((shown(&c, "duration"), shown(&c, "jobs")), (None, None));
        e.duration_ms = Some(2000);
        e.jobs = Some(2);
        let c = collect(&e);
        assert_eq!(shown(&c, "duration").as_deref(), Some("2.0s"));
        assert_eq!(shown(&c, "jobs").as_deref(), Some("2"));
    }

    // 이것을 실패시키는 것: pwd가 없을 때 dir을 빈 경로로 그리는 것, 아직 못 채우는 세그먼트에 값을 넣는 것.
    #[test]
    fn unknown_inputs_hide_segments() {
        let c = collect(&blank());
        for id in ["dir", "git", "host", "venv", "time"] {
            assert!(c.values[index(id)].is_none(), "{id}");
        }
        assert!(c.values[index("char")].is_some());
    }
}
