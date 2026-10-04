//! Shell input envelope, version `--ctx 1` (spec section 5). Hand-written
//! parser on the prompt fast path (spec section 8 budget table).
use bingsu_core::record::RecordVersion;
use bingsu_core::root_arg::{
    CONFIG_ROOT_PREFIX, LOG_ROOT_PREFIX, RUNTIME_ROOT_PREFIX, STATE_ROOT_PREFIX, parse_abs_path,
    parse_decimal, parse_runtime_root,
};

// Fields are parsed and validated now so ctx 1 never changes; M2/M3 read them.
#[derive(Debug, PartialEq, Eq)]
pub struct OwnedRuntimeRoot {
    pub dev: u64,
    pub ino: u64,
    pub path: Vec<u8>,
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
    pub state_root: Option<Vec<u8>>,
    pub log_root: Option<Vec<u8>>,
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

/// Width comes from the terminal, which bingsu does not control: anything
/// that is not a `u16` decimal means "width unknown" (0), not a bad argument.
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

/// True for fields written as one word (`--name=value`, `--redraw`); the
/// pre-scan and the main loop must step over arguments the same way, or a
/// value that happens to read `--record` would be taken for the flag.
fn is_one_word(a: &[u8]) -> bool {
    a.starts_with(RUNTIME_ROOT_PREFIX)
        || a.starts_with(CONFIG_ROOT_PREFIX)
        || a.starts_with(STATE_ROOT_PREFIX)
        || a.starts_with(LOG_ROOT_PREFIX)
        || a == b"--redraw"
}

/// Record version is settled first so every later error knows which
/// minimal record to print (spec section 5 envelope rules). `--record` is
/// counted in flag position only; two or more is `bad-args` whatever the
/// values are (duplicate check before version check).
fn record_version(args: &[&[u8]]) -> Result<RecordVersion, EnvelopeError> {
    let mut first: Option<Option<&[u8]>> = None;
    let mut count = 0;
    let mut i = 0;
    while i < args.len() {
        if is_one_word(args[i]) {
            i += 1;
            continue;
        }
        if args[i] == b"--record" {
            count += 1;
            first.get_or_insert_with(|| args.get(i + 1).copied());
        }
        i += 2;
    }
    if count > 1 {
        return Err(EnvelopeError::BadArgs("duplicate field"));
    }
    match first.flatten().and_then(RecordVersion::parse) {
        Some(v) => Ok(v),
        None => Err(EnvelopeError::NoSupportedRecordVersion),
    }
}

fn root_slot<'e, 'a>(
    e: &'e mut Envelope,
    a: &'a [u8],
) -> Option<(&'e mut Option<Vec<u8>>, &'a [u8])> {
    if let Some(v) = a.strip_prefix(CONFIG_ROOT_PREFIX) {
        return Some((&mut e.config_root, v));
    }
    if let Some(v) = a.strip_prefix(STATE_ROOT_PREFIX) {
        return Some((&mut e.state_root, v));
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
    let mut i = 0;
    while i < args.len() {
        let a = args[i];
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
    Ok(e)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_with_width(w: &'static str) -> Vec<&'static [u8]> {
        vec![b"--ctx", b"1", b"--record", b"B1", b"--width", w.as_bytes()]
    }

    fn parse_strs(a: &[&str]) -> Result<Envelope, EnvelopeError> {
        let v: Vec<&[u8]> = a.iter().map(|x| x.as_bytes()).collect();
        parse(&v)
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

    #[test]
    fn width_valid_is_kept() {
        assert_eq!(parse(&base_with_width("65535")).unwrap().width, 65535);
        assert_eq!(parse(&base_with_width("80")).unwrap().width, 80);
    }
}
