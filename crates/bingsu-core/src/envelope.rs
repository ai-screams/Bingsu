//! Shell input envelope, version `--ctx 1` (spec section 5). Hand-written
//! parser on the prompt fast path (spec section 8 budget table).
use crate::layout::PATH_BYTES_MAX;
use crate::record::RecordVersion;
use crate::root_arg::{
    CONFIG_ROOT_PREFIX, CONFIG_ROOT_SHAPE_ONLY, CONFIG_ROOT_WRITTEN_PREFIX, HOME_PREFIX,
    LOG_ROOT_PREFIX, RUNTIME_ROOT_PREFIX, STATE_ROOT_PREFIX, parse_abs_path, parse_decimal,
    parse_runtime_root,
};
use crate::shell_word::Shell;
use alloc::vec::Vec;

// Fields are parsed and validated now so ctx 1 never changes; M2/M3 read them.
#[derive(Debug, PartialEq, Eq)]
pub struct OwnedRuntimeRoot {
    pub dev: u64,
    pub ino: u64,
    pub path: Vec<u8>,
}

/// Optional ctx 1 field. Unknown values are deliberately quiet.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum LogLevel {
    #[default]
    Off,
    Error,
    Info,
    DebugLog,
}
impl LogLevel {
    pub fn parse(v: &[u8]) -> Self {
        match v {
            b"error" => Self::Error,
            b"info" => Self::Info,
            b"debug" => Self::DebugLog,
            _ => Self::Off,
        }
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Envelope {
    pub record: Option<RecordVersion>,
    /// Terminal width in cells; 0 means unknown (value missing from the
    /// terminal environment, not a malformed argument).
    pub width: u16,
    pub status: Option<u8>,
    pub pipestatus: Option<Vec<u8>>,
    pub duration_ms: Option<u64>,
    pub jobs: Option<u32>,
    pub keymap: Option<Vec<u8>>,
    pub session: Option<Vec<u8>>,
    pub seq: Option<u64>,
    pub redraw: bool,
    pub runtime_root: Option<OwnedRuntimeRoot>,
    pub config_root: Option<Vec<u8>>,
    /// Original spelling whose parent/link/target evidence N2 must rebuild.
    pub config_root_written: Option<Vec<u8>>,
    /// `--config-root-shape-only`: init could not decide the root's safety,
    /// so every file under it is shape-only. A trust ceiling only.
    pub config_root_shape_only: bool,
    pub state_root: Option<Vec<u8>>,
    pub log_root: Option<Vec<u8>>,
    /// `--shell`, a constant word of each shell's hook. `None`: the hook is
    /// older than the renderer, so only the shell-neutral minimal record.
    pub shell: Option<Shell>,
    /// `--pwd "$PWD"`: display only, never opened or stat'ed (spec section
    /// 4 front end). Not absolute or over PATH_BYTES_MAX: unknown (`None`).
    pub pwd: Option<Vec<u8>>,
    /// `--colorterm "$COLORTERM"`: `truecolor` or `24bit` (spec section 3
    /// "색 출력"). Absent or anything else: 256 colors.
    pub truecolor: bool,
    /// Display-only COLORFGBG observation; malformed or absent means dark.
    pub colorfgbg: Option<crate::color::palette::Mode>,
    /// `--home=<path>`, pinned by init from getpwuid.
    pub home: Option<Vec<u8>>,
    /// Init-pinned HOME/XDG_CONFIG_HOME for helper-only Git global config.
    /// Absent fields identify old hooks; explicit empty values stay empty.
    pub git_global_home: Option<Vec<u8>>,
    pub git_global_xdg: Option<Vec<u8>>,
    /// Canonical dedicated sibling pinned by init; never read from environment.
    pub collector_exe: Option<Vec<u8>>,
    pub runtime_groups: Vec<crate::fs_trust::GroupPin>,
    pub log_level: LogLevel,
    pub host: Option<Vec<u8>>,
    pub venv: Option<Vec<u8>>,
    pub ssh: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub enum EnvelopeError {
    /// `--record` missing or outside the compatibility window: empty output.
    NoSupportedRecordVersion,
    /// Record version is valid: minimal record with `error:bad-args`.
    BadArgs(&'static str),
}

const MAX_EXT: usize = 16;
const RESERVED_EXT: [&[u8]; 3] = [b"config-root-id", b"state-root-id", b"log-root-id"];

fn dev_ino_ok(v: &[u8]) -> bool {
    match v.iter().position(|&b| b == b':') {
        Some(c) => parse_decimal(&v[..c]).is_some() && parse_decimal(&v[c + 1..]).is_some(),
        None => false,
    }
}
const MAX_PIPESTATUS: usize = 64;

fn set_once<T>(slot: &mut Option<T>, v: T) -> Result<(), EnvelopeError> {
    if slot.is_some() {
        return Err(EnvelopeError::BadArgs("duplicate field"));
    }
    *slot = Some(v);
    Ok(())
}

fn num<T: TryFrom<u64>>(v: &[u8], what: &'static str) -> Result<T, EnvelopeError> {
    parse_decimal(v)
        .and_then(|n| T::try_from(n).ok())
        .ok_or(EnvelopeError::BadArgs(what))
}

/// `$PWD` comes from the shell, which bingsu does not control: a value that
/// is not an absolute path or is too long to draw means "folder unknown".
fn pwd_or_unknown(v: &[u8]) -> Option<Vec<u8>> {
    (v.first() == Some(&b'/') && v.len() <= PATH_BYTES_MAX).then(|| v.to_vec())
}

/// Width comes from the terminal, which bingsu does not control: anything
/// that is not a `u16` decimal means "width unknown" (0), not a bad argument.
fn display_or_unknown(v: &[u8]) -> Option<Vec<u8>> {
    (!v.is_empty() && v.len() <= PATH_BYTES_MAX).then(|| v.to_vec())
}

// Accept only two ANSI indices, without retaining or rendering hostile bytes.
// A valid word is at most five bytes ("15;15"); parsing cost is bounded too.
fn colorfgbg_mode(v: &[u8]) -> Option<crate::color::palette::Mode> {
    use crate::color::palette::Mode;
    if v.len() > 5 {
        return None;
    }
    let sep = v.iter().position(|&b| b == b';')?;
    let fg = parse_decimal(&v[..sep])?;
    let bg = parse_decimal(&v[sep + 1..])?;
    if fg > 15 {
        return None;
    }
    match bg {
        0..=6 | 8 => Some(Mode::Dark),
        7 | 9..=15 => Some(Mode::Light),
        _ => None,
    }
}

fn width_or_unknown(v: &[u8]) -> u16 {
    parse_decimal(v)
        .and_then(|n| u16::try_from(n).ok())
        .unwrap_or(0)
}

fn ext_name_ok(n: &[u8]) -> bool {
    matches!(n.first(), Some(b'a'..=b'z'))
        && n.len() <= 32
        && n.iter()
            .all(|&b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// Flags that take the next word as their value (the two-word fields).
pub(crate) fn is_value_flag(a: &[u8]) -> bool {
    matches!(
        a,
        b"--record"
            | b"--ctx"
            | b"--width"
            | b"--status"
            | b"--pipestatus"
            | b"--duration-ms"
            | b"--jobs"
            | b"--keymap"
            | b"--session"
            | b"--seq"
            | b"--ctx-ext"
            | b"--shell"
            | b"--pwd"
            | b"--colorterm"
            | b"--colorfgbg"
            | b"--host"
            | b"--venv"
    )
}

/// Record version is settled first so every later error knows which
/// minimal record to print (spec section 5 envelope rules). `--record` is
/// counted in flag position only; two or more is `bad-args` whatever the
/// values are (duplicate check before version check).
pub(crate) fn record_version(args: &[&[u8]]) -> Result<RecordVersion, EnvelopeError> {
    let mut first: Option<Option<&[u8]>> = None;
    let mut count = 0;
    let mut i = 0;
    while i < args.len() {
        let a = args[i];
        if a == b"--record" {
            count += 1;
            first.get_or_insert_with(|| args.get(i + 1).copied());
        }
        // Only known value flags swallow the next word; an unknown flag
        // takes nothing, so it cannot hide a `--record` that follows it.
        i += if is_value_flag(a) { 2 } else { 1 };
    }
    if count > 1 {
        return Err(EnvelopeError::BadArgs("duplicate field"));
    }
    let Some(bytes) = first.flatten() else {
        return Err(EnvelopeError::NoSupportedRecordVersion);
    };
    match RecordVersion::parse(bytes) {
        Some(v) => Ok(v),
        None => Err(EnvelopeError::NoSupportedRecordVersion),
    }
}

fn root_slot<'e, 'a>(
    e: &'e mut Envelope,
    a: &'a [u8],
) -> Option<(&'e mut Option<Vec<u8>>, &'a [u8])> {
    if let Some(v) = a.strip_prefix(CONFIG_ROOT_WRITTEN_PREFIX) {
        return Some((&mut e.config_root_written, v));
    }
    if let Some(v) = a.strip_prefix(CONFIG_ROOT_PREFIX) {
        return Some((&mut e.config_root, v));
    }
    if let Some(v) = a.strip_prefix(STATE_ROOT_PREFIX) {
        return Some((&mut e.state_root, v));
    }
    if let Some(v) = a.strip_prefix(b"--collector-exe=") {
        return Some((&mut e.collector_exe, v));
    }
    if let Some(v) = a.strip_prefix(HOME_PREFIX) {
        return Some((&mut e.home, v));
    }
    a.strip_prefix(LOG_ROOT_PREFIX)
        .map(|v| (&mut e.log_root, v))
}

pub fn parse(args: &[&[u8]]) -> Result<Envelope, EnvelopeError> {
    let record = record_version(args)?;
    let mut e = Envelope {
        record: Some(record),
        ..Envelope::default()
    };
    let (mut ctx, mut width, mut ext) = (None::<()>, None::<u16>, 0usize);
    let (mut pwd, mut colorterm) = (None::<Option<Vec<u8>>>, None::<bool>);
    let (mut log_level, mut ssh, mut groups) = (None, None, None);
    let (mut host, mut venv, mut colorfgbg) = (None, None, None);
    let mut i = 0;
    while i < args.len() {
        let a = args[i];
        if let Some(v) = a.strip_prefix(b"--log-level=") {
            set_once(&mut log_level, LogLevel::parse(v))?;
            i += 1;
            continue;
        }
        if let Some(v) = a.strip_prefix(b"--ssh=") {
            set_once(&mut ssh, v == b"1")?;
            i += 1;
            continue;
        }
        if let Some(v) = a.strip_prefix(b"--runtime-groups=") {
            set_once(&mut groups, v)?;
            i += 1;
            continue;
        }
        let global = a
            .strip_prefix(b"--git-global-home=")
            .map(|v| (&mut e.git_global_home, v))
            .or_else(|| {
                a.strip_prefix(b"--git-global-xdg=")
                    .map(|v| (&mut e.git_global_xdg, v))
            });
        if let Some((slot, value)) = global {
            if value.len() <= 65_536 && value.contains(&0) {
                return Err(EnvelopeError::BadArgs("git global path"));
            }
            // Direct/older callers can still send over-cap values. Degrade
            // without failing the prompt; new hooks validate these at init.
            // Keep Some(empty) so pinned HOME is not revived and duplicate
            // fields still fail closed.
            set_once(
                slot,
                if value.len() > 65_536 {
                    Vec::new()
                } else {
                    value.to_vec()
                },
            )?;
            i += 1;
            continue;
        }
        // One-word fields: `--name=value` (values may hold any byte).
        if let Some(v) = a.strip_prefix(RUNTIME_ROOT_PREFIX) {
            let r = parse_runtime_root(v).map_err(|_| EnvelopeError::BadArgs("runtime root"))?;
            set_once(
                &mut e.runtime_root,
                OwnedRuntimeRoot {
                    dev: r.dev,
                    ino: r.ino,
                    path: r.path.to_vec(),
                },
            )?;
            i += 1;
            continue;
        }
        if let Some((slot, v)) = root_slot(&mut e, a) {
            let p = parse_abs_path(v).map_err(|_| EnvelopeError::BadArgs("root path"))?;
            set_once(slot, p.to_vec())?;
            i += 1;
            continue;
        }
        if a == b"--redraw" {
            if e.redraw {
                return Err(EnvelopeError::BadArgs("duplicate field"));
            }
            e.redraw = true;
            i += 1;
            continue;
        }
        if a == CONFIG_ROOT_SHAPE_ONLY {
            if e.config_root_shape_only {
                return Err(EnvelopeError::BadArgs("duplicate field"));
            }
            e.config_root_shape_only = true;
            i += 1;
            continue;
        }
        // Two-word fields: `--name value`.
        let v = args
            .get(i + 1)
            .copied()
            .ok_or(EnvelopeError::BadArgs("missing value"))?;
        match a {
            b"--record" => {} // settled by record_version
            b"--ctx" => {
                if v != b"1" {
                    return Err(EnvelopeError::BadArgs("ctx version"));
                }
                set_once(&mut ctx, ())?;
            }
            b"--width" => set_once(&mut width, width_or_unknown(v))?,
            b"--status" => set_once(&mut e.status, num(v, "status")?)?,
            b"--duration-ms" => set_once(&mut e.duration_ms, num(v, "duration")?)?,
            b"--jobs" => set_once(&mut e.jobs, num(v, "jobs")?)?,
            b"--seq" => set_once(&mut e.seq, num(v, "seq")?)?,
            b"--shell" => {
                let sh = Shell::parse(v).ok_or(EnvelopeError::BadArgs("shell"))?;
                set_once(&mut e.shell, sh)?;
            }
            b"--host" => set_once(&mut host, display_or_unknown(v))?,
            b"--venv" => set_once(&mut venv, display_or_unknown(v))?,
            b"--pwd" => set_once(&mut pwd, pwd_or_unknown(v))?,
            b"--colorfgbg" => set_once(&mut colorfgbg, colorfgbg_mode(v))?,
            b"--colorterm" => set_once(&mut colorterm, v == b"truecolor" || v == b"24bit")?,
            b"--pipestatus" => {
                let items: Vec<u8> = v
                    .split(|&b| b == b',')
                    .map(|p| num::<u8>(p, "pipestatus"))
                    .collect::<Result<_, _>>()?;
                if items.len() > MAX_PIPESTATUS {
                    return Err(EnvelopeError::BadArgs("pipestatus"));
                }
                set_once(&mut e.pipestatus, items)?;
            }
            b"--keymap" => {
                if v.is_empty()
                    || v.len() > 16
                    || !v.iter().all(|&b| b.is_ascii_lowercase() || b == b'_')
                {
                    return Err(EnvelopeError::BadArgs("keymap"));
                }
                set_once(&mut e.keymap, v.to_vec())?;
            }
            b"--session" => {
                if v.len() != 32
                    || !v
                        .iter()
                        .all(|&b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                {
                    return Err(EnvelopeError::BadArgs("session"));
                }
                set_once(&mut e.session, v.to_vec())?;
            }
            b"--ctx-ext" => {
                let eq = v
                    .iter()
                    .position(|&b| b == b'=')
                    .ok_or(EnvelopeError::BadArgs("ctx-ext"))?;
                ext += 1;
                if !ext_name_ok(&v[..eq]) || ext > MAX_EXT {
                    return Err(EnvelopeError::BadArgs("ctx-ext"));
                }
                // Reserved for the config/state/log root identity (dev:ino),
                // validated now so ctx 1 never changes; other names are ignored.
                let (name, val) = (&v[..eq], &v[eq + 1..]);
                if RESERVED_EXT.contains(&name) && !dev_ino_ok(val) {
                    return Err(EnvelopeError::BadArgs("ctx-ext root id"));
                }
            }
            _ => return Err(EnvelopeError::BadArgs("unknown argument")),
        }
        i += 2;
    }
    ctx.ok_or(EnvelopeError::BadArgs("ctx missing"))?;
    e.width = width.ok_or(EnvelopeError::BadArgs("width missing"))?;
    e.pwd = pwd.flatten();
    e.truecolor = colorterm.unwrap_or(false);
    e.colorfgbg = colorfgbg.flatten();
    e.log_level = log_level.unwrap_or_default();
    e.ssh = ssh.unwrap_or(false);
    e.host = host.flatten();
    e.venv = venv.flatten();
    let components = e.runtime_root.as_ref().map_or(0, |r| {
        r.path
            .split(|b| *b == b'/')
            .filter(|v| !v.is_empty())
            .count()
    });
    e.runtime_groups = crate::helper::decode_groups(groups.unwrap_or(b"1"), components)
        .map_err(|_| EnvelopeError::BadArgs("runtime groups"))?;
    Ok(e)
}

#[cfg(test)]
mod tests {
    // 이것을 실패시키는 것: 작성 경로를 인식하지 않거나 절대 경로 문법을 적용하지 않는 것.
    #[test]
    fn config_root_handoff_parses_both_paths() {
        let e = super::parse(&[
            b"--ctx",
            b"1",
            b"--record",
            b"B1",
            b"--width",
            b"80",
            b"--config-root=/target",
            b"--config-root-written=/home/me/.config/bingsu",
        ])
        .unwrap();
        for bad in [
            b"--config-root-written=relative".as_slice(),
            b"--config-root-written=",
        ] {
            assert!(
                super::parse(&[b"--ctx", b"1", b"--record", b"B1", b"--width", b"80", bad])
                    .is_err()
            );
        }
        assert_eq!(e.config_root.as_deref(), Some(&b"/target"[..]));
        assert_eq!(
            e.config_root_written.as_deref(),
            Some(&b"/home/me/.config/bingsu"[..])
        );
        assert!(!e.config_root_shape_only);
    }

    // 모양 전용 표식은 값 없는 한 단어다. 두 번 오면 거부하고, 값을 붙이거나 접두사처럼 쓰면 모르는 인자다.
    // 이것을 실패시키는 것: 표식을 인식하지 않는 것(모양 전용 init 뒤 모든 프롬프트가 bad-args),
    // 중복을 받아 주는 것, `starts_with`로 비교해 `--config-root-shape-only=/x`를 받아 주는 것.
    #[test]
    fn config_root_shape_only_is_one_flag_word() {
        let base: [&[u8]; 7] = [
            b"--ctx",
            b"1",
            b"--record",
            b"B1",
            b"--width",
            b"80",
            b"--config-root=/c",
        ];
        let with = |extra: &[&'static [u8]]| {
            let mut a = base.to_vec();
            a.extend_from_slice(extra);
            super::parse(&a)
        };
        let e = with(&[b"--config-root-shape-only"]).unwrap();
        assert!(e.config_root_shape_only);
        assert_eq!(e.config_root.as_deref(), Some(&b"/c"[..]));
        assert_eq!(
            with(&[b"--config-root-shape-only", b"--config-root-shape-only"]).err(),
            Some(super::EnvelopeError::BadArgs("duplicate field"))
        );
        for bad in [
            &b"--config-root-shape-only=/x"[..],
            b"--config-root-shape-onl",
            b"--config-root-shape-only-x",
        ] {
            // A trailing word, so the parser reaches the unknown-name check
            // instead of stopping at a missing two-word value.
            assert_eq!(
                with(&[bad, b"x"]).err(),
                Some(super::EnvelopeError::BadArgs("unknown argument")),
                "{bad:?}"
            );
        }
    }

    use super::*;
    use alloc::format;
    use alloc::vec;

    fn base_with_width(w: &'static str) -> Vec<&'static [u8]> {
        vec![b"--ctx", b"1", b"--record", b"B1", b"--width", w.as_bytes()]
    }

    fn parse_strs(a: &[&str]) -> Result<Envelope, EnvelopeError> {
        let v: Vec<&[u8]> = a.iter().map(|x| x.as_bytes()).collect();
        parse(&v)
    }

    // 이것을 실패시키는 것: COLORFGBG 값 소비/중복/문법/상한/배경별 모드 판단 제거.
    #[test]
    fn colorfgbg_is_a_bounded_display_observation() {
        use crate::color::palette::Mode;
        for bg in 0..=15 {
            let value = format!("15;{bg}");
            let mut a = base_with_width("80");
            a.extend([b"--colorfgbg", value.as_bytes()]);
            assert_eq!(
                parse(&a).unwrap().colorfgbg,
                Some(if matches!(bg, 7 | 9..=15) {
                    Mode::Light
                } else {
                    Mode::Dark
                })
            );
            a.extend([b"--colorfgbg".as_slice(), b""]);
            assert_eq!(parse(&a), Err(EnvelopeError::BadArgs("duplicate field")));
        }
        let huge = vec![b'7'; PATH_BYTES_MAX + 1];
        for bad in [
            b"".as_slice(),
            b"7",
            b";7",
            b"0;",
            b"0;16",
            b"16;7",
            b"0;7;0",
            b"0;7\n",
            b"0;7\x1b",
            b"x;7",
            b"0;-1",
            b"--record",
            &huge,
        ] {
            let mut a = base_with_width("80");
            a.extend([b"--colorfgbg", bad]);
            assert_eq!(parse(&a).unwrap().colorfgbg, None, "{bad:?}");
        }
        assert_eq!(parse(&base_with_width("80")).unwrap().colorfgbg, None);
        let mut a = base_with_width("80");
        a.extend([b"--colorfgbg".as_slice(), b"", b"--colorfgbg", b"0;7"]);
        assert_eq!(parse(&a), Err(EnvelopeError::BadArgs("duplicate field")));
    }

    // 이것을 실패시키는 것: 선택 필드 정규화·값 소비·중복·64 KiB 상한을 생략하는 것.
    #[test]
    fn optional_prompt_fields() {
        let base = [
            b"--ctx".as_slice(),
            b"1",
            b"--record",
            b"B1",
            b"--width",
            b"80",
        ];
        let old = parse(&base).unwrap();
        assert_eq!(old.log_level, LogLevel::Off);
        assert!(!old.ssh);
        assert_eq!((old.host, old.venv), (None, None));
        for (word, expected) in [
            (b"--log-level=off".as_slice(), LogLevel::Off),
            (b"--log-level=error", LogLevel::Error),
            (b"--log-level=info", LogLevel::Info),
            (b"--log-level=debug", LogLevel::DebugLog),
            (b"--log-level=/tmp/log", LogLevel::Off),
        ] {
            let mut a = base.to_vec();
            a.extend([
                word,
                b"--log-root=/pinned",
                b"--host",
                b"--record",
                b"--venv",
                b"a b",
                b"--ssh=1",
            ]);
            let e = parse(&a).unwrap();
            assert_eq!(e.log_level, expected);
            assert_eq!(e.log_root.as_deref(), Some(b"/pinned".as_slice()));
            assert_eq!(e.host.as_deref(), Some(b"--record".as_slice()));
            assert_eq!(e.venv.as_deref(), Some(b"a b".as_slice()));
            assert!(e.ssh);
            a.push(word);
            assert!(parse(&a).is_err());
        }
        for flag in [b"--host".as_slice(), b"--venv"] {
            let mut a = base.to_vec();
            a.extend([flag, b"", flag, b"x"]);
            assert!(parse(&a).is_err());
            a.truncate(base.len() + 2);
            let empty = parse(&a).unwrap();
            assert!(empty.host.is_none() && empty.venv.is_none());
        }
        for flag in [b"--host".as_slice(), b"--venv"] {
            let limit = alloc::vec![b'x'; PATH_BYTES_MAX];
            let mut at_limit = base.to_vec();
            at_limit.extend([flag, limit.as_slice()]);
            let accepted = parse(&at_limit).unwrap();
            assert_eq!(
                accepted.host.or(accepted.venv).unwrap().len(),
                PATH_BYTES_MAX
            );
            let huge = alloc::vec![b'x'; PATH_BYTES_MAX + 1];
            let mut a = base.to_vec();
            a.extend([flag, huge.as_slice()]);
            let e = parse(&a).unwrap();
            assert!(e.host.is_none() && e.venv.is_none());
        }
        let mut a = base.to_vec();
        a.extend([b"--ssh=unknown".as_slice()]);
        assert!(!parse(&a).unwrap().ssh);
        a.push(b"--ssh=1");
        assert!(parse(&a).is_err());
    }

    const BASE: [&str; 6] = ["--ctx", "1", "--record", "B1", "--width", "80"];

    fn with(extra: &[&'static str]) -> Result<Envelope, EnvelopeError> {
        let mut a: Vec<&'static str> = BASE.to_vec();
        a.extend_from_slice(extra);
        parse_strs(&a)
    }

    // 이것을 실패시키는 것: 앞자리 0을 허용해 80으로 파싱하는 것.
    #[test]
    fn width_leading_zero_is_unknown() {
        assert_eq!(parse(&base_with_width("080")).unwrap().width, 0);
    }

    // 이것을 실패시키는 것: 중복 검사를 지우거나 버전 검사보다 뒤에 두는 것.
    #[test]
    fn duplicate_record_is_bad_args_whatever_the_values() {
        for pair in [["B1", "B1"], ["B1", "B2"], ["B2", "B1"], ["B2", "B2"]] {
            let a = [
                "--ctx", "1", "--record", pair[0], "--record", pair[1], "--width", "80",
            ];
            assert!(
                matches!(parse_strs(&a), Err(EnvelopeError::BadArgs(_))),
                "{pair:?}"
            );
        }
    }

    #[test]
    fn single_unsupported_record_is_empty_output() {
        let a = ["--ctx", "1", "--record", "B2", "--width", "80"];
        assert_eq!(parse_strs(&a), Err(EnvelopeError::NoSupportedRecordVersion));
    }

    // 이것을 실패시키는 것: 사전 스캔을 인자 쌍 구조 없이 raw 문자열 비교로 하는 것.
    #[test]
    fn record_in_value_position_is_not_negotiated() {
        let r = with(&["--keymap", "--record"]);
        assert!(matches!(r, Err(EnvelopeError::BadArgs(_))), "{r:?}");
    }

    // 이것을 실패시키는 것: 사전 스캔이 값 자리의 `--record`를 플래그로 세는 것(raw 비교).
    #[test]
    fn record_in_value_position_is_not_counted() {
        // width accepts any value, so the value `--record` is not an error.
        let a = ["--ctx", "1", "--record", "B1", "--width", "--record"];
        assert_eq!(parse_strs(&a).unwrap().width, 0);
        // The only `--record` is a value: nothing is negotiated, empty output.
        let a = ["--ctx", "1", "--width", "80", "--keymap", "--record", "B1"];
        assert_eq!(parse_strs(&a), Err(EnvelopeError::NoSupportedRecordVersion));
    }

    // 이것을 실패시키는 것: 모르는 플래그가 다음 낱말을 값으로 먹게 하는 것.
    #[test]
    fn unknown_flag_does_not_hide_record_flag() {
        let a = ["--foo", "--record", "B1", "--ctx", "1", "--width", "80"];
        assert!(matches!(parse_strs(&a), Err(EnvelopeError::BadArgs(_))));
    }

    // 이것을 실패시키는 것: 각 한계 상수를 1 늘리거나 줄이는 것.
    #[test]
    fn limits_pipestatus_64_ok_65_rejected() {
        let ok = vec!["0"; 64].join(",");
        let bad = vec!["0"; 65].join(",");
        let a = [
            "--ctx",
            "1",
            "--record",
            "B1",
            "--width",
            "80",
            "--pipestatus",
            ok.as_str(),
        ];
        assert!(parse_strs(&a).is_ok());
        let a = [
            "--ctx",
            "1",
            "--record",
            "B1",
            "--width",
            "80",
            "--pipestatus",
            bad.as_str(),
        ];
        assert!(parse_strs(&a).is_err());
    }

    #[test]
    fn limits_ctx_ext_16_ok_17_rejected() {
        let mut a: Vec<&str> = BASE.to_vec();
        for _ in 0..16 {
            a.extend(["--ctx-ext", "x=1"]);
        }
        assert!(parse_strs(&a).is_ok());
        a.extend(["--ctx-ext", "x=1"]);
        assert!(parse_strs(&a).is_err());
    }

    #[test]
    fn limits_keymap_16_ok_17_rejected() {
        assert!(with(&["--keymap", "aaaaaaaaaaaaaaaa"]).is_ok());
        assert!(with(&["--keymap", "aaaaaaaaaaaaaaaaa"]).is_err());
    }

    #[test]
    fn limits_session_32_ok_33_rejected() {
        assert!(with(&["--session", "0123456789abcdef0123456789abcdef"]).is_ok());
        assert!(with(&["--session", "0123456789abcdef0123456789abcdef0"]).is_err());
        assert!(with(&["--session", "0123456789abcdef0123456789abcde"]).is_err());
    }

    // 이것을 실패시키는 것: 폭 갈래를 bad-args로 바꾸는 것(width_or_unknown의 unwrap_or(0) 제거).
    #[test]
    fn width_out_of_u16_is_unknown_not_bad_args() {
        let e = parse(&base_with_width("70000")).unwrap();
        assert_eq!(e.width, 0);
    }

    #[test]
    fn width_non_numeric_is_unknown_not_bad_args() {
        let e = parse(&base_with_width("abc")).unwrap();
        assert_eq!(e.width, 0);
    }

    // 이것을 실패시키는 것: 새 값 플래그를 is_value_flag에 넣지 않는 것(값 자리의 `--record`가 협상으로 세어짐).
    #[test]
    fn record_after_new_value_flags_is_a_value() {
        for flag in ["--shell", "--pwd", "--colorterm"] {
            let a = ["--ctx", "1", "--width", "80", flag, "--record", "B1"];
            assert_eq!(
                parse_strs(&a),
                Err(EnvelopeError::NoSupportedRecordVersion),
                "{flag}"
            );
        }
    }

    // 이것을 실패시키는 것: 셸 이름 검사를 빼는 것, 중복을 받는 것, `--shell` 없는 봉투를 거부하는 것(옛 hook).
    #[test]
    fn shell_field() {
        assert_eq!(with(&["--shell", "zsh"]).unwrap().shell, Some(Shell::Zsh));
        assert_eq!(with(&[]).unwrap().shell, None);
        assert!(matches!(
            with(&["--shell", "sh"]),
            Err(EnvelopeError::BadArgs(_))
        ));
        assert!(matches!(
            with(&["--shell", "zsh", "--shell", "zsh"]),
            Err(EnvelopeError::BadArgs(_))
        ));
    }

    // 이것을 실패시키는 것: 상대 경로·빈 값·너무 긴 값을 받는 것, 그것을 bad-args로 만드는 것, 중복을 받는 것.
    #[test]
    fn pwd_is_display_only_and_unknown_when_odd() {
        assert_eq!(
            with(&["--pwd", "/a b/$(x)"]).unwrap().pwd,
            Some(b"/a b/$(x)".to_vec())
        );
        for odd in ["", "rel/x", "~/x"] {
            assert_eq!(with(&["--pwd", odd]).unwrap().pwd, None, "{odd:?}");
        }
        let pwd = |v: &str| {
            let mut a: Vec<&str> = BASE.to_vec();
            a.extend(["--pwd", v]);
            parse_strs(&a).unwrap().pwd
        };
        assert_eq!(pwd(&format!("/{}", "a".repeat(PATH_BYTES_MAX))), None);
        assert!(pwd(&format!("/{}", "a".repeat(PATH_BYTES_MAX - 1))).is_some());
        assert!(matches!(
            with(&["--pwd", "/a", "--pwd", "/b"]),
            Err(EnvelopeError::BadArgs(_))
        ));
    }

    // 이것을 실패시키는 것: truecolor·24bit 말고 다른 값을 truecolor로 받는 것, 없는 경우를 truecolor로 두는 것.
    #[test]
    fn colorterm_field() {
        assert!(with(&["--colorterm", "truecolor"]).unwrap().truecolor);
        assert!(with(&["--colorterm", "24bit"]).unwrap().truecolor);
        assert!(!with(&["--colorterm", "TrueColor"]).unwrap().truecolor);
        assert!(!with(&["--colorterm", ""]).unwrap().truecolor);
        assert!(!with(&[]).unwrap().truecolor);
    }

    // 이것을 실패시키는 것: `--home=`을 상대 경로로 받는 것, 중복을 받는 것.
    #[test]
    fn home_is_pinned_absolute() {
        assert_eq!(
            with(&["--home=/Users/u"]).unwrap().home,
            Some(b"/Users/u".to_vec())
        );
        assert!(matches!(
            with(&["--home=u"]),
            Err(EnvelopeError::BadArgs(_))
        ));
        assert!(matches!(
            with(&["--home=/a", "--home=/b"]),
            Err(EnvelopeError::BadArgs(_))
        ));
    }

    #[test]
    fn width_valid_is_kept() {
        assert_eq!(parse(&base_with_width("65535")).unwrap().width, 65535);
        assert_eq!(parse(&base_with_width("80")).unwrap().width, 80);
    }
}
