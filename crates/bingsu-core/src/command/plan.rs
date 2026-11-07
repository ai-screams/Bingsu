//! The helper's side of one round: which config units may go into the grant
//! and in what form, the shell environment the prompt handed over, the target
//! environment built from it, `{dir}` in argv, the units chosen this round
//! and whether a result frame names a place in the grant. Pure; the helper
//! and the supervisor do the I/O.
use super::{
    grant::{KEEP, KEEP_PREFIX},
    wire::{Grant, Outcome, Policy},
};
use crate::{
    config::compile::{ExecPolicy, ExecUnit},
    handoff::{Cwd, Origin},
};
use alloc::string::String;
use alloc::vec::Vec;

/// Config units spawned in one round (U-9d).
pub const CONFIG_MAX: usize = 8;
/// Builtin probes spawned in one round (U-9d): the four languages.
pub const PROBE_MAX: usize = 4;
/// Longest run of one unit (U-9d, 1,000 ms); a longer `timeout` is cut to it.
pub const TIMEOUT_MAX: u64 = 1_000_000_000;
/// `timeout` when the config sets none (spec: 200 ms).
pub const TIMEOUT_DEFAULT: u64 = 200_000_000;
/// The one placeholder M6 replaces, as one whole argv word.
pub const DIR: &[u8] = b"{dir}";

/// A config unit in its grant form.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Runnable {
    pub policy: Policy,
    pub cwd: Cwd,
    /// Nanoseconds, as configured (the supervisor cuts it to `TIMEOUT_MAX`).
    pub timeout: u64,
    pub env_allow: Vec<Vec<u8>>,
    /// A language unit's `detect_files`; empty for a command.
    pub detect: Vec<Vec<u8>>,
}

/// The grant form of a compiled unit, or `None` when it must not run: a
/// `not_run` reason (unreachable band, untrusted file, disabled), no grant
/// policy (plain `shell`, a language unit without `interpreter`), or a `cwd`
/// value outside the two.
pub fn runnable(u: &ExecUnit) -> Option<Runnable> {
    if u.not_run.is_some() {
        return None;
    }
    let policy = Policy::from_config(&u.policy)?;
    let (cwd, env_allow, detect) = match &u.policy {
        ExecPolicy::Command { cwd, env_allow, .. } => (cwd, env_allow, &[][..]),
        ExecPolicy::Language {
            cwd,
            env_allow,
            detect_files,
            ..
        } => (cwd, env_allow, detect_files.as_slice()),
    };
    let cwd = match cwd.as_deref() {
        None | Some("neutral") => Cwd::Neutral,
        Some("untrusted-current") => Cwd::UntrustedCurrent,
        Some(_) => return None,
    };
    let timeout = match u.timeout_ms {
        None => TIMEOUT_DEFAULT,
        Some(ms) => ms.checked_mul(1_000_000)?,
    };
    Some(Runnable {
        policy,
        cwd,
        timeout,
        env_allow: env_allow.iter().map(|n| n.as_bytes().to_vec()).collect(),
        detect: detect.iter().map(|n| n.as_bytes().to_vec()).collect(),
    })
}

/// The policy digest a unit's response entry is bound to: the grant's
/// (`wire::policy_digest`) for a command, and for a language unit that one
/// with its `detect_files` too (D3c-2 ruling Q3), so other files that mark
/// the language never stand for the value decided with these. The grant
/// keeps `policy_digest`, which the supervisor checks the unit against.
pub fn entry_digest(r: &Runnable) -> [u8; 32] {
    let grant = super::wire::policy_digest(&r.policy, r.cwd, r.timeout, &r.env_allow);
    // Fails without it: a_language_digest_binds_its_files.
    if r.detect.is_empty() {
        return grant;
    }
    let mut b = Vec::new();
    b.extend_from_slice(b"bingsu-language-policy-v1\0");
    b.extend_from_slice(&grant);
    b.extend_from_slice(&(r.detect.len() as u64).to_le_bytes());
    for name in &r.detect {
        b.extend_from_slice(&(name.len() as u64).to_le_bytes());
        b.extend_from_slice(name);
    }
    crate::collection::cwd_hash::sha256(&b)
}

/// What `Environ::parse` left out, for the helper's log line.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Dropped {
    /// Entries without `=`, with an empty name, empty, or not ended by NUL.
    pub malformed: usize,
    /// Names that appeared more than once; every copy is left out.
    pub duplicate: usize,
}

/// The shell environment as the prompt passed it (`NAME=VALUE\0` entries,
/// `env_frame` body), sorted by name. A name given twice is dropped as a
/// whole: which copy a program reads depends on how it searches its
/// environment, so neither is passed on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Environ<'a> {
    entries: Vec<(&'a [u8], &'a [u8])>,
    pub dropped: Dropped,
}

impl<'a> Environ<'a> {
    pub fn parse(body: &'a [u8]) -> Self {
        let mut dropped = Dropped::default();
        let mut found = Vec::new();
        let mut rest = body;
        while let Some(end) = rest.iter().position(|&b| b == 0) {
            let entry = &rest[..end];
            rest = &rest[end + 1..];
            match entry.iter().position(|&b| b == b'=') {
                Some(eq) if eq > 0 => found.push((&entry[..eq], &entry[eq + 1..])),
                _ => dropped.malformed += 1,
            }
        }
        // The prompt ends every entry with NUL; a tail without one is not an entry.
        if !rest.is_empty() {
            dropped.malformed += 1;
        }
        found.sort_by(|a, b| a.0.cmp(b.0));
        let mut entries = Vec::with_capacity(found.len());
        let mut i = 0;
        while i < found.len() {
            let same = found[i..].iter().take_while(|e| e.0 == found[i].0).count();
            if same == 1 {
                entries.push(found[i]);
            } else {
                dropped.duplicate += 1;
            }
            i += same;
        }
        Self { entries, dropped }
    }

    pub fn get(&self, name: &[u8]) -> Option<&'a [u8]> {
        self.entries
            .binary_search_by(|e| e.0.cmp(name))
            .ok()
            .map(|i| self.entries[i].1)
    }
}

/// What an env segment draws for variable `name` of this environment (C5):
/// its raw value sanitized up to what the cut reads
/// (`Clean::sanitized_prefix`), never copied whole; nothing when it is unset
/// or named twice (`Environ` drops both). An empty value draws nothing as
/// empty text does.
pub fn env_segment_value(vars: &Environ<'_>, name: &str) -> Option<String> {
    let value = vars.get(name.as_bytes())?;
    Some(crate::field::Clean::sanitized_prefix(
        value,
        crate::field::CUSTOM_TEXT_CELLS,
    ))
}

/// The original environment digest of a config unit (spec section 4
/// "cache", U-16): the keep list (`LC_*` by prefix) and the unit's
/// `env_allow`, as the shell gave them, before any sanitizing. The prompt
/// computes the same from its own environment, so a response is shown only
/// to a shell whose values it ran with. Names in byte order, each once; a
/// name without a value is marked absent, so an empty value differs.
pub fn env_digest(vars: &Environ<'_>, env_allow: &[Vec<u8>]) -> [u8; 32] {
    let mut names: Vec<&[u8]> = KEEP.to_vec();
    names.extend(
        vars.entries
            .iter()
            .map(|e| e.0)
            .filter(|n| n.starts_with(KEEP_PREFIX)),
    );
    names.extend(env_allow.iter().map(|n| n.as_slice()));
    names.sort_unstable();
    names.dedup();
    let mut b = Vec::new();
    b.extend_from_slice(b"bingsu-command-env-v1\0");
    for name in names {
        b.extend_from_slice(&(name.len() as u64).to_le_bytes());
        b.extend_from_slice(name);
        match vars.get(name) {
            Some(v) => {
                b.push(1);
                b.extend_from_slice(&(v.len() as u64).to_le_bytes());
                b.extend_from_slice(v);
            }
            None => b.push(0),
        }
    }
    crate::collection::cwd_hash::sha256(&b)
}

/// The target environment of a config unit: the keep list (`PATH` is the
/// sanitized value, never the shell's), every `LC_*`, then the unit's
/// `env_allow` names, each at most once and only when the shell had it. An
/// empty sanitized `PATH` leaves `PATH` out: `PATH=` would be one empty
/// entry, which a search reads as the working folder.
pub fn target_environment(vars: &Environ<'_>, env_allow: &[Vec<u8>], path: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut push = |name: &[u8], value: &[u8]| {
        out.extend_from_slice(name);
        out.push(b'=');
        out.extend_from_slice(value);
        out.push(0);
    };
    for name in KEEP.iter().filter(|n| **n != b"PATH") {
        if let Some(v) = vars.get(name) {
            push(name, v);
        }
    }
    for (name, value) in vars.entries.iter().filter(|e| e.0.starts_with(KEEP_PREFIX)) {
        push(name, value);
    }
    for (i, name) in env_allow.iter().enumerate() {
        let kept = KEEP.contains(&name.as_slice()) || name.starts_with(KEEP_PREFIX);
        if kept || env_allow[..i].contains(name) {
            continue;
        }
        if let Some(v) = vars.get(name) {
            push(name, v);
        }
    }
    if !path.is_empty() {
        push(b"PATH", path);
    }
    out
}

/// `argv` with every word that is exactly `{dir}` replaced by `dir`. Only a
/// whole word is replaced, so a value with spaces, quotes or a newline stays
/// one argv element (config check refuses `{dir}` inside a word).
pub fn with_dir(argv: &[Vec<u8>], dir: &[u8]) -> Vec<Vec<u8>> {
    argv.iter()
        .map(|w| if w == DIR { dir.to_vec() } else { w.clone() })
        .collect()
}

/// The folder whose identity stands for the repository the shell is in, for
/// the `PATH` and executable rules (C2 ruling J9): the repository root this
/// round's collection reported for `cwd` (component `component` of it, as
/// the collector found it), else `cwd` itself. The fallback misses a root
/// above `cwd` when the shell is in a subfolder of a repository.
pub fn repo_folder(cwd: &[u8], component: Option<u16>) -> Vec<u8> {
    let Some(last) = component else {
        return cwd.to_vec();
    };
    let mut out = Vec::new();
    for name in crate::collection::path_facts::components(cwd).take(usize::from(last) + 1) {
        out.push(b'/');
        out.extend_from_slice(name);
    }
    if out.is_empty() {
        out.push(b'/');
    }
    out
}

/// Indices of the units to run this round, at most `cap`: never tried
/// first, then the oldest last attempt, then by id. N units are each tried
/// within ⌈N / cap⌉ rounds.
pub fn pick(units: &[(&str, Option<u64>)], cap: usize) -> Vec<usize> {
    let mut order: Vec<usize> = (0..units.len()).collect();
    order.sort_by(|&a, &b| {
        let (ia, ta) = units[a];
        let (ib, tb) = units[b];
        ta.cmp(&tb).then(ia.cmp(ib))
    });
    order.truncate(cap);
    order
}

/// Whether a result names a place in the grant's list for its origin and
/// does not end before it was approved.
pub fn result_fits(grant: &Grant, o: &Outcome) -> bool {
    let len = match o.origin {
        Origin::Config => grant.units.len(),
        Origin::Builtin => grant.probes.len(),
    };
    usize::from(o.index) < len && o.approved_at <= o.ended_at
}

/// Whether a result is taken: it fits the grant and is the first one for
/// its place. A second result for the same origin and index is counted as
/// rejected and never published (the first one stands).
pub fn accept(grant: &Grant, taken: &[Outcome], o: &Outcome) -> bool {
    result_fits(grant, o)
        && !taken
            .iter()
            .any(|t| t.origin == o.origin && t.index == o.index)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        command::{
            grant::{Refusal, target_environment_allowed},
            wire::{Probe, Reason, Unit, policy_digest},
        },
        config::compile::NotRun,
        handoff::Permit,
    };
    use alloc::{string::String, vec};

    fn unit(policy: ExecPolicy) -> ExecUnit {
        ExecUnit {
            id: "custom/k".into(),
            policy,
            timeout_ms: None,
            cache_ms: None,
            origins: Vec::new(),
            approved_by: Vec::new(),
            shown_at: Vec::new(),
            not_run: None,
            pattern: None,
        }
    }
    fn command(argv: &[&str], cwd: Option<&str>) -> ExecPolicy {
        ExecPolicy::Command {
            argv: argv.iter().map(|w| String::from(*w)).collect(),
            cwd: cwd.map(String::from),
            env_allow: vec!["KUBECONFIG".into()],
            shell: None,
            unsafe_shell: false,
        }
    }

    fn language(interpreter: Option<&str>, detect: &[&str]) -> ExecPolicy {
        ExecPolicy::Language {
            interpreter: interpreter.map(String::from),
            version_argv: vec!["--version".into()],
            detect_files: detect.iter().map(|w| String::from(*w)).collect(),
            cwd: Some("untrusted-current".into()),
            env_allow: vec!["DENO_DIR".into()],
        }
    }

    // D3c-2: 사용자 정의 language 단위는 argv [interpreter, version…]로, 자기 cwd·env_allow로 실행한다.
    // interpreter가 없거나 비면 실행하지 않는다. 이것을 실패시키는 것: language를 grant 정책으로 바꾸지 않는 것,
    // version 인자를 빼는 것, 빈 interpreter를 받는 것, language의 cwd·env_allow 대신 기본값을 쓰는 것.
    #[test]
    fn a_language_unit_runs_its_interpreter_and_version() {
        let r = runnable(&unit(language(Some("deno"), &["deno.json"]))).unwrap();
        assert_eq!(
            r.policy,
            Policy::Argv {
                argv: vec![b"deno".to_vec(), b"--version".to_vec()]
            }
        );
        assert_eq!(r.cwd, Cwd::UntrustedCurrent);
        assert_eq!(r.env_allow, [b"DENO_DIR".to_vec()]);
        assert_eq!(r.detect, [b"deno.json".to_vec()]);
        assert!(runnable(&unit(language(None, &["deno.json"]))).is_none());
        assert!(runnable(&unit(language(Some(""), &["deno.json"]))).is_none());
    }

    // 항목의 정책 요약값: 명령은 grant 요약값 그대로, language는 detect_files까지 묶는다(D3c-2 Q3). 감지 이름이
    // 다르면 요약값이 다르다. 이것을 실패시키는 것: language에도 grant 요약값만 쓰는 것, 명령의 요약값을 바꾸는 것,
    // 이름마다의 길이 머리를 빼는 것(["ab","c"]와 ["a","bc"]가 같아짐).
    #[test]
    fn a_language_digest_binds_its_files() {
        let cmd = runnable(&unit(command(&["k"], None))).unwrap();
        assert_eq!(
            entry_digest(&cmd),
            policy_digest(&cmd.policy, cmd.cwd, cmd.timeout, &cmd.env_allow)
        );
        let a = runnable(&unit(language(Some("deno"), &["deno.json"]))).unwrap();
        let b = runnable(&unit(language(Some("deno"), &["deno.jsonc"]))).unwrap();
        assert_ne!(
            entry_digest(&a),
            policy_digest(&a.policy, a.cwd, a.timeout, &a.env_allow)
        );
        assert_ne!(entry_digest(&a), entry_digest(&b));
        let ab = runnable(&unit(language(Some("deno"), &["ab", "c"]))).unwrap();
        let a_b = runnable(&unit(language(Some("deno"), &["a", "bc"]))).unwrap();
        assert_ne!(entry_digest(&ab), entry_digest(&a_b));
    }

    // 이것을 실패시키는 것: runnable의 `not_run.is_some()` 거름을 지우는 것(도달할 수 없는 구간·믿을 수
    // 없는 파일의 단위가 허가에 들어감).
    #[test]
    fn runnable_skips_not_run_units() {
        let ok = unit(command(&["kubectl"], None));
        assert!(runnable(&ok).is_some());
        for reason in [
            NotRun::Disabled,
            NotRun::NotInTrustedLayout,
            NotRun::UnknownBand,
            NotRun::UnsafeFile {
                key: "command".into(),
            },
        ] {
            let mut u = ok.clone();
            u.not_run = Some(reason);
            assert_eq!(runnable(&u), None);
        }
    }

    // 이것을 실패시키는 것: cwd 대응에서 `Some(_) => return None`을 Neutral로 바꾸는 것, 또는
    // "untrusted-current"를 Neutral로 읽는 것. 기본 timeout 200 ms, 설정값은 ms → ns.
    #[test]
    fn runnable_maps_cwd_and_timeout() {
        let r = runnable(&unit(command(&["k"], None))).unwrap();
        assert_eq!((r.cwd, r.timeout), (Cwd::Neutral, TIMEOUT_DEFAULT));
        assert_eq!(r.env_allow, vec![b"KUBECONFIG".to_vec()]);
        let r = runnable(&unit(command(&["k"], Some("neutral")))).unwrap();
        assert_eq!(r.cwd, Cwd::Neutral);
        let r = runnable(&unit(command(&["k"], Some("untrusted-current")))).unwrap();
        assert_eq!(r.cwd, Cwd::UntrustedCurrent);
        assert_eq!(runnable(&unit(command(&["k"], Some("repo")))), None);
        let mut u = unit(command(&["k"], None));
        u.timeout_ms = Some(300);
        assert_eq!(runnable(&u).unwrap().timeout, 300_000_000);
        u.timeout_ms = Some(u64::MAX);
        assert_eq!(runnable(&u), None);
    }

    // 이것을 실패시키는 것: Environ::parse에서 `=` 없는 항목이나 빈 이름(`=x`)을 받아들이는 것,
    // NUL로 끝나지 않는 꼬리를 항목으로 읽는 것.
    #[test]
    fn environ_skips_malformed_entries() {
        let e = Environ::parse(b"HOME=/h\0NOEQ\0\0=x\0TERM=xterm\0TAIL=1");
        assert_eq!(e.get(b"HOME"), Some(&b"/h"[..]));
        assert_eq!(e.get(b"TERM"), Some(&b"xterm"[..]));
        assert_eq!(e.get(b"NOEQ"), None);
        assert_eq!(e.get(b""), None);
        assert_eq!(e.get(b"TAIL"), None);
        assert_eq!(
            e.dropped,
            Dropped {
                malformed: 4,
                duplicate: 0
            }
        );
        // A value may hold '=' and be empty.
        let e = Environ::parse(b"A=b=c\0B=\0");
        assert_eq!(e.get(b"A"), Some(&b"b=c"[..]));
        assert_eq!(e.get(b"B"), Some(&b""[..]));
    }

    // 이것을 실패시키는 것: 중복 이름의 첫 사본이나 마지막 사본을 남기는 것(`same == 1` 조건을 지움),
    // 떨어져 있는 같은 이름을 모으는 정렬을 지우는 것.
    #[test]
    fn environ_drops_every_copy_of_a_duplicate_name() {
        let e = Environ::parse(b"PATH=/a\0HOME=/h\0PATH=/b\0");
        assert_eq!(e.get(b"PATH"), None);
        assert_eq!(e.get(b"HOME"), Some(&b"/h"[..]));
        assert_eq!(
            e.dropped,
            Dropped {
                malformed: 0,
                duplicate: 1
            }
        );
        let e = Environ::parse(b"X=1\0X=1\0X=2\0Y=3\0");
        assert_eq!((e.get(b"X"), e.get(b"Y")), (None, Some(&b"3"[..])));
    }

    // 이것을 실패시키는 것: target_environment가 셸의 PATH를 넘기는 것(KEEP 훑기에서 PATH 제외를 지움),
    // LC_* 접두 훑기를 지우는 것, env_allow 이름을 빼는 것, env_allow의 남기기 이름·중복을 다시 넣는 것
    // (같은 이름 두 번이면 감독이 그 단위를 거부한다).
    #[test]
    fn target_environment_keeps_names_once() {
        let vars = Environ::parse(
            b"HOME=/h\0PATH=/repo/bin:/usr/bin\0LC_TIME=ko_KR.UTF-8\0KUBECONFIG=/k\0EDITOR=vi\0TERM=xterm\0",
        );
        let allow = vec![
            b"KUBECONFIG".to_vec(),
            b"HOME".to_vec(),
            b"KUBECONFIG".to_vec(),
            b"LC_TIME".to_vec(),
            b"MISSING".to_vec(),
        ];
        let out = target_environment(&vars, &allow, b"/usr/bin");
        assert_eq!(
            out,
            b"HOME=/h\0TERM=xterm\0LC_TIME=ko_KR.UTF-8\0KUBECONFIG=/k\0PATH=/usr/bin\0".to_vec()
        );
        assert!(target_environment_allowed(&out, &allow));
    }

    // 이것을 실패시키는 것: 정제한 PATH가 비었을 때도 `PATH=`를 넣는 것(빈 항목은 현재 폴더로 읽힘).
    #[test]
    fn empty_sanitized_path_is_left_out() {
        let vars = Environ::parse(b"PATH=/repo/bin\0HOME=/h\0");
        assert_eq!(target_environment(&vars, &[], b""), b"HOME=/h\0".to_vec());
    }

    // 수용 조건(A4): `{dir}` 값에 셸 문자·줄바꿈이 있어도 argv 원소 하나로 남는다. 이것을 실패시키는 것:
    // with_dir가 값을 공백·줄바꿈으로 나누거나 단어 안의 `{dir}`도 바꾸는 것.
    #[test]
    fn dir_value_stays_one_word() {
        let argv = vec![b"ls".to_vec(), DIR.to_vec(), b"x{dir}".to_vec()];
        let dir = b"/tmp/a b;$(rm -rf ~)\n`id`|c";
        let got = with_dir(&argv, dir);
        assert_eq!(got, vec![b"ls".to_vec(), dir.to_vec(), b"x{dir}".to_vec()]);
    }

    // J9: 수집이 알린 저장소 루트가 있으면 그 폴더, 없으면 셸 폴더. 이것을 실패시키는 것: component를
    // 무시하고 늘 cwd를 쓰는 것, take의 `+ 1`을 지우는 것(루트 한 단계 위가 됨).
    #[test]
    fn repo_folder_prefers_the_collected_root() {
        assert_eq!(
            repo_folder(b"/home/u/repo/src/x", Some(2)),
            b"/home/u/repo".to_vec()
        );
        assert_eq!(
            repo_folder(b"/home/u/repo/src/x", Some(0)),
            b"/home".to_vec()
        );
        assert_eq!(repo_folder(b"/home/u/proj", None), b"/home/u/proj".to_vec());
    }

    // 원본 환경 요약값: 남기기 목록·LC_* 접두·env_allow의 값만 보고, 다른 이름은 보지 않으며, 없음과 빈 값을
    // 가린다. 이것을 실패시키는 것: env_allow를 이름 목록에 넣지 않는 것(KUBECONFIG만 다른 두 셸이 같은 값),
    // LC_* 접두 훑기를 지우는 것(LC_TIME만 다른 두 셸이 같은 값), 없음 표시를 빈 값과 같게 쓰는 것.
    #[test]
    fn env_digest_covers_kept_names_lc_and_env_allow_only() {
        let allow = [b"KUBECONFIG".to_vec()];
        let d = |frame: &[u8]| env_digest(&Environ::parse(frame), &allow);
        let base = d(b"HOME=/h\0PATH=/bin\0KUBECONFIG=a\0");
        assert_eq!(base, d(b"PATH=/bin\0HOME=/h\0KUBECONFIG=a\0SECRET=x\0"));
        assert_ne!(base, d(b"HOME=/h\0PATH=/bin\0KUBECONFIG=b\0"));
        assert_ne!(
            base,
            d(b"HOME=/h\0PATH=/bin\0KUBECONFIG=a\0LC_TIME=ko_KR.UTF-8\0")
        );
        assert_ne!(base, d(b"HOME=/h\0PATH=/bin\0KUBECONFIG=a\0TZ=\0"));
        assert_ne!(
            env_digest(&Environ::parse(b"HOME=/h\0KUBECONFIG=a\0"), &[]),
            env_digest(&Environ::parse(b"HOME=/h\0KUBECONFIG=b\0"), &allow)
        );
    }

    // 이것을 실패시키는 것: pick의 시도 시각 정렬을 지우는 것(id 순만), id 동점 처리를 지우는 것,
    // truncate(cap)를 지우는 것.
    #[test]
    fn pick_oldest_attempt_first() {
        let units = [
            ("a", Some(30)),
            ("b", None),
            ("c", Some(10)),
            ("d", Some(10)),
            ("e", None),
        ];
        assert_eq!(pick(&units, 3), vec![1, 4, 2]);
        assert_eq!(pick(&units, 8), vec![1, 4, 2, 3, 0]);
        // 12 units never tried, 8 a round: the 4 left over come first next round.
        let ids: Vec<String> = (0..12).map(|i| alloc::format!("u{i:02}")).collect();
        let first: Vec<(&str, Option<u64>)> = ids.iter().map(|i| (i.as_str(), None)).collect();
        let round1 = pick(&first, CONFIG_MAX);
        let second: Vec<(&str, Option<u64>)> = first
            .iter()
            .enumerate()
            .map(|(i, u)| (u.0, round1.contains(&i).then_some(1)))
            .collect();
        let mut all = round1.clone();
        all.extend(pick(&second, CONFIG_MAX).into_iter().take(4));
        all.sort_unstable();
        assert_eq!(all, (0..12).collect::<Vec<_>>());
    }

    fn grant() -> Grant {
        let policy = Policy::Argv {
            argv: vec![b"k".to_vec()],
        };
        Grant {
            permit: Permit {
                kind: 1,
                deadline: 9,
                boot: [1; 16],
                resume: 0,
                domain: [2; 16],
            },
            helper_deadline: 9,
            cwd: Vec::new(),
            neutral: Vec::new(),
            units: vec![Unit {
                id: "custom/k".into(),
                digest: policy_digest(&policy, Cwd::Neutral, 1, &[]),
                policy,
                cwd: Cwd::Neutral,
                environment: Vec::new(),
                timeout: 1,
                env_allow: Vec::new(),
                executable: b"/usr/bin/k".to_vec(),
                pin: None,
                interpreter: None,
            }],
            probes: Vec::new(),
        }
    }
    fn outcome(origin: Origin, index: u8, approved_at: u64, ended_at: u64) -> Outcome {
        Outcome {
            origin,
            index,
            reason: Reason::Refused(Refusal::Budget),
            approved_at,
            ended_at,
            stdout: Vec::new(),
        }
    }

    // 수용 조건(A3 L-5). 이것을 실패시키는 것: result_fits의 순번 검사를 지우는 것, origin별 목록 대신
    // 두 목록 합을 보는 것, `approved_at <= ended_at`을 지우는 것.
    #[test]
    fn result_must_name_a_grant_place() {
        let mut g = grant();
        assert!(result_fits(&g, &outcome(Origin::Config, 0, 5, 5)));
        assert!(!result_fits(&g, &outcome(Origin::Config, 1, 5, 6)));
        assert!(!result_fits(&g, &outcome(Origin::Builtin, 0, 5, 6)));
        assert!(!result_fits(&g, &outcome(Origin::Config, 0, 6, 5)));
        g.probes.push(Probe {
            profile: 1,
            executable: b"/usr/bin/go".to_vec(),
            pin: None,
            toolchain: None,
        });
        assert!(result_fits(&g, &outcome(Origin::Builtin, 0, 5, 6)));
        assert!(!result_fits(&g, &outcome(Origin::Config, 1, 5, 6)));
    }

    // 같은 자리의 둘째 결과는 받지 않는다(첫 결과가 선다, C4 Q5). 이것을 실패시키는 것: accept의 중복 검사를
    // 지우는 것, origin을 보지 않는 것(같은 index의 다른 origin 결과까지 거부), accept가 result_fits를 건너뛰는 것.
    #[test]
    fn a_second_result_for_one_place_is_rejected() {
        let mut g = grant();
        g.probes.push(Probe {
            profile: 1,
            executable: b"/usr/bin/go".to_vec(),
            pin: None,
            toolchain: None,
        });
        let first = outcome(Origin::Config, 0, 5, 6);
        assert!(accept(&g, &[], &first));
        assert!(!accept(
            &g,
            core::slice::from_ref(&first),
            &outcome(Origin::Config, 0, 7, 8)
        ));
        assert!(accept(
            &g,
            core::slice::from_ref(&first),
            &outcome(Origin::Builtin, 0, 7, 8)
        ));
        assert!(!accept(&g, &[], &outcome(Origin::Config, 0, 9, 8)));
    }
}
