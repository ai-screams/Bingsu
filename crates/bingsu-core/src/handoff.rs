//! Fixed relay contract: argv, the permit and the exec frame on fd 3.
//! The relay rechecks both with a fresh clock immediately before execution.
use crate::{
    command::{
        Error as FrameError,
        path::{EXEC_PIN_LEN, ExecPin},
    },
    snapshot::{Clock, crc32c},
    snapshot_codec::Error,
};
use alloc::vec::Vec;
/// Reserved M6 entry. No executor or additional spawn path is installed by N4.
pub const ENTRY: &str = "__exec-v2";
pub const PERMIT_ARG: &str = "--permit-fd=3";
pub const PERMIT_FD: u8 = 3;
/// Version word of the relay argv layout (the exec frame carries its own,
/// `EXEC_VERSION`).
pub const RELAY_VERSION: &str = "1";
/// Largest permit plus exec frame on fd 3 (U-9d, 16 KB): the supervisor
/// writes both into an empty pipe in one write before the spawn.
pub const RELAY_INPUT_MAX: usize = 16 * 1024;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Permit {
    pub kind: u8,
    pub deadline: u64,
    pub boot: [u8; 16],
    pub resume: u64,
    pub domain: [u8; 16],
}
impl Permit {
    pub fn encode(self) -> [u8; 96] {
        let mut b = [0; 96];
        b[..8].copy_from_slice(b"BNGEXC02");
        b[8] = 2;
        b[10] = 96;
        b[12] = self.kind;
        b[16..24].copy_from_slice(&self.deadline.to_le_bytes());
        b[24..40].copy_from_slice(&self.boot);
        b[40..48].copy_from_slice(&self.resume.to_le_bytes());
        b[48..64].copy_from_slice(&self.domain);
        let h = crc32c(&[b"bingsu-exec-v2\0", &b[..64]]);
        b[64..68].copy_from_slice(&h);
        b
    }
    pub fn decode(b: &[u8]) -> Result<Self, Error> {
        if b.len() != 96 {
            return Err(Error::Short);
        }
        if &b[..8] != b"BNGEXC02"
            || b[8..12] != [2, 0, 96, 0]
            || ![1, 2].contains(&b[12])
            || b[13..16] != [0, 0, 0]
            || crc32c(&[b"bingsu-exec-v2\0", &b[..64]]) != b[64..68]
            || b[68..96] != [0; 28]
        {
            return Err(Error::Tag);
        }
        Ok(Self {
            kind: b[12],
            deadline: u64::from_le_bytes(b[16..24].try_into().map_err(|_| Error::Short)?),
            boot: b[24..40].try_into().map_err(|_| Error::Short)?,
            resume: u64::from_le_bytes(b[40..48].try_into().map_err(|_| Error::Short)?),
            domain: b[48..64].try_into().map_err(|_| Error::Short)?,
        })
    }
    pub fn allows(self, now: Clock) -> bool {
        self.same_clock(now) && now.now < self.deadline
    }
    /// The permit's absolute times mean something only on this exact clock:
    /// same kind, boot, resume generation and domain (a resume makes a
    /// deadline look later than it is).
    pub fn same_clock(self, now: Clock) -> bool {
        [1, 2].contains(&self.kind)
            && self.boot != [0; 16]
            && self.kind == now.kind
            && self.boot == now.boot
            && self.resume == now.resume
            && self.domain == now.domain
    }
}

/// Where a unit came from. Only config units are bound to the trust deadline.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Origin {
    Config,
    Builtin,
}
impl Origin {
    pub fn tag(self) -> u8 {
        match self {
            Self::Config => 1,
            Self::Builtin => 2,
        }
    }
    pub fn from_tag(b: u8) -> Result<Self, FrameError> {
        match b {
            1 => Ok(Self::Config),
            2 => Ok(Self::Builtin),
            _ => Err(FrameError::Kind),
        }
    }
}

/// Working folder of the target, as the config names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cwd {
    Neutral,
    UntrustedCurrent,
}
impl Cwd {
    pub fn word(self) -> &'static str {
        match self {
            Self::Neutral => "neutral",
            Self::UntrustedCurrent => "untrusted-current",
        }
    }
    pub fn tag(self) -> u8 {
        match self {
            Self::Neutral => 0,
            Self::UntrustedCurrent => 1,
        }
    }
    pub fn from_tag(b: u8) -> Result<Self, FrameError> {
        match b {
            0 => Ok(Self::Neutral),
            1 => Ok(Self::UntrustedCurrent),
            _ => Err(FrameError::Kind),
        }
    }
}

/// Relay arguments after argv[0]:
/// `__exec-v2 --permit-fd=3 <version> <executable> <cwd> -- <argv...>`.
/// Deadlines and the environment never travel in argv.
/// A NUL in the executable or a word is refused: the C string would end
/// there and the bytes after it would become separate words.
pub fn relay_args<'a>(
    executable: &'a [u8],
    cwd: Cwd,
    argv: &[&'a [u8]],
) -> Result<Vec<&'a [u8]>, FrameError> {
    if executable.contains(&0) || argv.iter().any(|w| w.contains(&0)) {
        return Err(FrameError::Utf8);
    }
    let mut out = Vec::with_capacity(6 + argv.len());
    out.extend([
        ENTRY.as_bytes(),
        PERMIT_ARG.as_bytes(),
        RELAY_VERSION.as_bytes(),
        executable,
        cwd.word().as_bytes(),
        b"--",
    ]);
    out.extend_from_slice(argv);
    Ok(out)
}
#[derive(Debug, PartialEq, Eq)]
pub struct RelayArgs<'a> {
    pub executable: &'a [u8],
    pub cwd: Cwd,
    pub argv: &'a [&'a [u8]],
}
/// Fixed positions only: the separator is word 5, so a target argv that
/// contains `--` stays the target's.
pub fn parse_relay_args<'a>(args: &'a [&'a [u8]]) -> Result<RelayArgs<'a>, FrameError> {
    let [
        entry,
        permit,
        version,
        executable,
        cwd,
        separator,
        argv @ ..,
    ] = args
    else {
        return Err(FrameError::Short);
    };
    if *entry != ENTRY.as_bytes() || *permit != PERMIT_ARG.as_bytes() || *separator != b"--" {
        return Err(FrameError::Magic);
    }
    if *version != RELAY_VERSION.as_bytes() {
        return Err(FrameError::Version);
    }
    let cwd = match *cwd {
        b"neutral" => Cwd::Neutral,
        b"untrusted-current" => Cwd::UntrustedCurrent,
        _ => return Err(FrameError::Kind),
    };
    // An empty target argv would give the target argc 0.
    if argv.is_empty() {
        return Err(FrameError::Short);
    }
    Ok(RelayArgs {
        executable,
        cwd,
        argv,
    })
}

const EXEC_MAGIC: &[u8; 8] = b"BNGEXF01";
const EXEC_DOMAIN: &[u8] = b"bingsu-exec-frame-v1\0";
/// Layout version 2 added the target pin, version 3 the script interpreter,
/// version 4 the working folder.
const EXEC_VERSION: u16 = 4;
/// Magic, version, origin, flags, environment length, run deadline, CRC,
/// reserved, target pin, interpreter pin (`EXEC_PIN_LEN` bytes each, all
/// zero for none), interpreter line, path and working folder lengths,
/// reserved.
pub const EXEC_HEADER: usize = 40 + 2 * EXEC_PIN_LEN;
const TARGET_PIN: usize = 32;
const INTERPRETER_PIN: usize = TARGET_PIN + EXEC_PIN_LEN;
const LENGTHS: usize = INTERPRETER_PIN + EXEC_PIN_LEN;
/// Second frame on fd 3, after the 96-byte permit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecFrame {
    pub origin: Origin,
    /// `E`, computed by the supervisor at approval.
    pub run_deadline: u64,
    /// Target envp as `NAME=VALUE\0` entries. Only `execveat` sees it.
    pub environment: Vec<u8>,
    /// The target the helper resolved, when it is group-writable and its
    /// group was cleared (spec section 2 safety row): the relay accepts the
    /// group write only for this exact file, group and mode.
    pub pin: Option<ExecPin>,
    /// The interpreter the helper resolved for a `#!` target; `None` for a
    /// native one.
    pub interpreter: Option<Interpreter>,
    /// The absolute folder the relay enters right before the exec (the
    /// neutral folder, or the shell's folder for `untrusted-current`). The
    /// relay, not the supervisor, changes folder: a folder on a stopped
    /// mount then holds only that one relay, which its deadline ends.
    pub cwd: Vec<u8>,
}
/// A script's interpreter as the helper resolved it (spec section 4 script
/// row). The relay reads the `#!` line itself and runs the script only when
/// the whole line after `#!` (interpreter and argument, untrimmed) is `line`
/// byte for byte; it then opens `path`, which the
/// helper reached by following root's and the user's symlinks (merged-/usr
/// `/bin/sh`), refusing any symlink on the way, and accepts group write only
/// for `pin`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Interpreter {
    pub line: Vec<u8>,
    pub path: Vec<u8>,
    pub pin: Option<ExecPin>,
}
/// CRC over everything but the CRC itself (reserved bytes and pins included).
fn exec_crc(h: &[u8], body: [&[u8]; 4]) -> [u8; 4] {
    let [a, b, c, d] = body;
    crc32c(&[EXEC_DOMAIN, &h[..24], &h[28..EXEC_HEADER], a, b, c, d])
}
fn le16(b: &[u8], at: usize) -> u32 {
    u32::from(u16::from_le_bytes([b[at], b[at + 1]]))
}
fn pin_at(b: &[u8], at: usize) -> Result<Option<ExecPin>, FrameError> {
    let mut pin = [0u8; EXEC_PIN_LEN];
    pin.copy_from_slice(&b[at..at + EXEC_PIN_LEN]);
    ExecPin::from_bytes(&pin)
}
impl ExecFrame {
    /// Config: trust deadline and run deadline; builtin: run deadline only.
    /// Both need the permit's clock, without which `E` means nothing.
    pub fn allows(&self, permit: Permit, now: Clock) -> bool {
        permit.same_clock(now)
            && now.now < self.run_deadline
            && (self.origin == Origin::Builtin || now.now < permit.deadline)
    }
    fn encode_into(&self, out: &mut Vec<u8>) -> Result<(), FrameError> {
        let len = u32::try_from(self.environment.len()).map_err(|_| FrameError::Limit)?;
        // An interpreter with an empty line or path does not decode: the
        // relay refuses the frame.
        let (line, path, pin): (&[u8], &[u8], _) = match &self.interpreter {
            Some(i) => (&i.line, &i.path, i.pin),
            None => (&[], &[], None),
        };
        let line_len = u16::try_from(line.len()).map_err(|_| FrameError::Limit)?;
        let path_len = u16::try_from(path.len()).map_err(|_| FrameError::Limit)?;
        let cwd_len = u16::try_from(self.cwd.len()).map_err(|_| FrameError::Limit)?;
        let mut h = [0u8; EXEC_HEADER];
        h[..8].copy_from_slice(EXEC_MAGIC);
        h[8..10].copy_from_slice(&EXEC_VERSION.to_le_bytes());
        h[10] = self.origin.tag();
        h[12..16].copy_from_slice(&len.to_le_bytes());
        h[16..24].copy_from_slice(&self.run_deadline.to_le_bytes());
        h[TARGET_PIN..INTERPRETER_PIN].copy_from_slice(&ExecPin::to_bytes(self.pin));
        h[INTERPRETER_PIN..LENGTHS].copy_from_slice(&ExecPin::to_bytes(pin));
        h[LENGTHS..LENGTHS + 2].copy_from_slice(&line_len.to_le_bytes());
        h[LENGTHS + 2..LENGTHS + 4].copy_from_slice(&path_len.to_le_bytes());
        h[LENGTHS + 4..LENGTHS + 6].copy_from_slice(&cwd_len.to_le_bytes());
        let crc = exec_crc(&h, [line, path, &self.cwd, &self.environment]);
        h[24..28].copy_from_slice(&crc);
        out.extend_from_slice(&h);
        out.extend_from_slice(line);
        out.extend_from_slice(path);
        out.extend_from_slice(&self.cwd);
        out.extend_from_slice(&self.environment);
        Ok(())
    }
    fn decode(b: &[u8]) -> Result<Self, FrameError> {
        if b.len() < EXEC_HEADER {
            return Err(FrameError::Short);
        }
        let len = u32::from_le_bytes([b[12], b[13], b[14], b[15]]);
        let (line_len, path_len) = (le16(b, LENGTHS), le16(b, LENGTHS + 2));
        let cwd_len = le16(b, LENGTHS + 4);
        let body = &b[EXEC_HEADER..];
        // In u32, so a declared environment near u32::MAX cannot wrap the
        // sum on any target.
        let want = len
            .checked_add(line_len)
            .and_then(|n| n.checked_add(path_len))
            .and_then(|n| n.checked_add(cwd_len))
            .and_then(|n| usize::try_from(n).ok())
            .ok_or(FrameError::Length)?;
        let (line_len, path_len, cwd_len) =
            (line_len as usize, path_len as usize, cwd_len as usize);
        if body.len() < want {
            return Err(FrameError::Short);
        }
        if body.len() > want {
            return Err(FrameError::Trailing);
        }
        if &b[..8] != EXEC_MAGIC {
            return Err(FrameError::Magic);
        }
        if b[8..10] != EXEC_VERSION.to_le_bytes() {
            return Err(FrameError::Version);
        }
        let origin = Origin::from_tag(b[10])?;
        if b[11] != 0 || b[28..32] != [0; 4] || b[LENGTHS + 6..EXEC_HEADER] != [0; 2] {
            return Err(FrameError::Flags);
        }
        if exec_crc(b, [body, &[], &[], &[]]) != b[24..28] {
            return Err(FrameError::Checksum);
        }
        let mut deadline = [0u8; 8];
        deadline.copy_from_slice(&b[16..24]);
        let pin = pin_at(b, TARGET_PIN)?;
        let interpreter_pin = pin_at(b, INTERPRETER_PIN)?;
        let (line, rest) = body.split_at(line_len);
        let (path, rest) = rest.split_at(path_len);
        let (cwd, environment) = rest.split_at(cwd_len);
        // A line names its interpreter's path and only an interpreter has a
        // pin: either all three or none.
        let interpreter = match (line.is_empty(), path.is_empty()) {
            (false, false) => Some(Interpreter {
                line: line.to_vec(),
                path: path.to_vec(),
                pin: interpreter_pin,
            }),
            (true, true) if interpreter_pin.is_none() => None,
            _ => return Err(FrameError::Length),
        };
        // An absolute folder without NUL, or the relay could not enter it.
        if cwd.first() != Some(&b'/') || cwd.contains(&0) {
            return Err(FrameError::Kind);
        }
        Ok(Self {
            origin,
            run_deadline: u64::from_le_bytes(deadline),
            environment: environment.to_vec(),
            pin,
            interpreter,
            cwd: cwd.to_vec(),
        })
    }
}
/// Everything the relay reads from fd 3: permit, then exec frame. Refused
/// above `cap` bytes so the whole input fits one write into an empty pipe.
pub fn relay_input(permit: Permit, frame: &ExecFrame, cap: usize) -> Result<Vec<u8>, FrameError> {
    let interpreter = frame
        .interpreter
        .as_ref()
        .map_or(0, |i| i.line.len().saturating_add(i.path.len()));
    let total = 96usize
        .checked_add(EXEC_HEADER)
        .and_then(|n| n.checked_add(frame.environment.len()))
        .and_then(|n| n.checked_add(interpreter))
        .and_then(|n| n.checked_add(frame.cwd.len()))
        .ok_or(FrameError::Limit)?;
    if total > cap {
        return Err(FrameError::Limit);
    }
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&permit.encode());
    frame.encode_into(&mut out)?;
    Ok(out)
}
/// The cap is checked before anything is copied.
pub fn read_relay_input(b: &[u8], cap: usize) -> Result<(Permit, ExecFrame), FrameError> {
    if b.len() > cap {
        return Err(FrameError::Limit);
    }
    if b.len() < 96 {
        return Err(FrameError::Short);
    }
    let permit = Permit::decode(&b[..96]).map_err(|_| FrameError::Checksum)?;
    Ok((permit, ExecFrame::decode(&b[96..])?))
}

#[cfg(test)]
mod tests {
    use super::*;
    // 이것을 실패시키는 것: 중계의 fresh clock 비교 또는 버전·정체 비교 하나를 제거한다.
    #[test]
    fn relay_checks_fresh_clock() {
        let p = Permit {
            kind: 1,
            deadline: 100,
            boot: [1; 16],
            resume: 0,
            domain: [2; 16],
        };
        let c = Clock {
            kind: 1,
            now: 99,
            boot: p.boot,
            resume: 0,
            domain: p.domain,
        };
        // 이것을 실패시키는 것: 직접 만든 permit의 미지원 시계/영 부팅을 허용하는 것.
        assert!(!Permit { kind: 3, ..p }.allows(Clock { kind: 3, ..c }));
        assert!(!Permit { boot: [0; 16], ..p }.allows(Clock { boot: [0; 16], ..c }));
        assert_eq!(Permit::decode(&p.encode()), Ok(p));
        assert!(p.allows(c));
        let mut x = c;
        x.now = 100;
        assert!(!p.allows(x));
        let mut x = c;
        x.boot[0] ^= 1;
        assert!(!p.allows(x));
        let mut x = c;
        x.kind = 2;
        assert!(!p.allows(x));
        let mut x = c;
        x.resume = 1;
        assert!(!p.allows(x));
        let mut x = c;
        x.domain[0] ^= 1;
        assert!(!p.allows(x));
        for i in 0..96 {
            let mut b = p.encode();
            b[i] ^= 0x80;
            assert!(Permit::decode(&b).is_err())
        }
    }

    fn permit(deadline: u64) -> Permit {
        Permit {
            kind: 1,
            deadline,
            boot: [1; 16],
            resume: 0,
            domain: [2; 16],
        }
    }
    fn clock(now: u64) -> Clock {
        Clock {
            kind: 1,
            now,
            boot: [1; 16],
            resume: 0,
            domain: [2; 16],
        }
    }
    fn frame(origin: Origin) -> ExecFrame {
        ExecFrame {
            origin,
            run_deadline: 50,
            environment: b"HOME=/h\0LANG=C\0".to_vec(),
            pin: None,
            interpreter: None,
            cwd: b"/run/n".to_vec(),
        }
    }

    // 이것을 실패시키는 것: ExecFrame::allows에서 `origin == Builtin ||`를 지우는 것(내장이 신뢰
    // 마감을 받음), `now < permit.deadline`을 지우는 것(설정 단위가 신뢰 만료 뒤 실행), `now <
    // run_deadline`을 지우는 것, same_clock을 지우는 것(깨어남 뒤 실행) 중 하나.
    #[test]
    fn relay_checks_both_deadlines() {
        let config = frame(Origin::Config);
        let builtin = frame(Origin::Builtin);
        // Trust deadline 30 < run deadline 50.
        let p = permit(30);
        assert!(config.allows(p, clock(29)));
        assert!(!config.allows(p, clock(30)));
        assert!(builtin.allows(p, clock(30)));
        assert!(builtin.allows(p, clock(49)));
        assert!(!builtin.allows(p, clock(50)));
        // Trust deadline later than E: E decides for config too.
        assert!(!config.allows(permit(90), clock(50)));
        let mut c = clock(10);
        c.resume = 1;
        assert!(!builtin.allows(p, c));
        assert!(!config.allows(p, c));
    }

    // 이것을 실패시키는 것: parse_relay_args의 고정 위치 구분자 비교를 지우거나 버전 비교를 지우는
    // 것, 또는 빈 대상 argv 거부를 지우는 것(대상 argc 0).
    #[test]
    fn relay_args_fixed_positions() {
        let argv: [&[u8]; 3] = [b"kubectl", b"--", b"--context=x"];
        let args = relay_args(b"/usr/bin/kubectl", Cwd::UntrustedCurrent, &argv).unwrap();
        let parsed = parse_relay_args(&args).unwrap();
        assert_eq!(parsed.executable, b"/usr/bin/kubectl");
        assert_eq!(parsed.cwd, Cwd::UntrustedCurrent);
        assert_eq!(parsed.argv, &argv);
        let mut bad = args.clone();
        bad[2] = b"2";
        assert_eq!(parse_relay_args(&bad), Err(FrameError::Version));
        let mut bad = args.clone();
        bad[5] = b"kubectl";
        assert_eq!(parse_relay_args(&bad), Err(FrameError::Magic));
        let mut bad = args.clone();
        bad[4] = b"current";
        assert_eq!(parse_relay_args(&bad), Err(FrameError::Kind));
        let empty = relay_args(b"/bin/true", Cwd::Neutral, &[]).unwrap();
        assert_eq!(parse_relay_args(&empty), Err(FrameError::Short));
        assert_eq!(parse_relay_args(&args[..5]), Err(FrameError::Short));
    }

    // 이것을 실패시키는 것: relay_args의 NUL 검사(실행 파일 또는 단어) 하나를 지우는 것. C 문자열로
    // 넘기면 NUL에서 끊겨, 실행 파일 안에 숨긴 `neutral`·`--`가 cwd·구분자 자리를 차지하고 나머지가
    // 대상 argv가 된다.
    #[test]
    fn relay_args_refuse_nul() {
        let words: [&[u8]; 1] = [b"kubectl"];
        assert_eq!(
            relay_args(
                b"/bin/sh\0neutral\0--\0-c\0id",
                Cwd::UntrustedCurrent,
                &words
            ),
            Err(FrameError::Utf8)
        );
        let words: [&[u8]; 2] = [b"kubectl", b"ctx\0--evil"];
        assert_eq!(
            relay_args(b"/usr/bin/kubectl", Cwd::Neutral, &words),
            Err(FrameError::Utf8)
        );
    }

    // 이것을 실패시키는 것: relay_input의 `total > cap` 검사를 지우거나 read_relay_input의 cap 검사를
    // 지우는 것, total에서 인터프리터 줄·경로 길이나 작업 폴더 길이를 빼는 것(cap을 넘는 프레임을 만든다).
    #[test]
    fn relay_input_cap() {
        for f in [frame(Origin::Config), scripted(Some(pin()))] {
            let line_path = f
                .interpreter
                .as_ref()
                .map_or(0, |i| i.line.len() + i.path.len());
            let exact = 96 + EXEC_HEADER + f.environment.len() + line_path + f.cwd.len();
            let b = relay_input(permit(30), &f, exact).unwrap();
            assert_eq!(b.len(), exact);
            assert_eq!(read_relay_input(&b, exact), Ok((permit(30), f.clone())));
            assert_eq!(
                relay_input(permit(30), &f, exact - 1),
                Err(FrameError::Limit)
            );
            assert_eq!(read_relay_input(&b, exact - 1), Err(FrameError::Limit));
        }
    }

    // 작업 폴더는 절대 경로이고 NUL이 없다(중계가 chdir한다). 이것을 실패시키는 것: decode의 `/` 시작
    // 검사나 NUL 검사를 지우는 것, encode·decode에서 작업 폴더를 빼는 것(왕복이 달라짐).
    #[test]
    fn exec_frame_cwd_is_absolute() {
        let mut f = frame(Origin::Config);
        f.cwd = b"/home/u/a b".to_vec();
        let b = relay_input(permit(30), &f, 16_384).unwrap();
        assert_eq!(read_relay_input(&b, 16_384), Ok((permit(30), f.clone())));
        for bad in [&b""[..], b"rel/x", b"/a\0b"] {
            f.cwd = bad.to_vec();
            let b = relay_input(permit(30), &f, 16_384).unwrap();
            assert_eq!(
                read_relay_input(&b, 16_384),
                Err(FrameError::Kind),
                "{bad:?}"
            );
        }
    }

    // 이것을 실패시키는 것: ExecFrame::decode의 `body.len() < len` 검사를 지우는 것
    // (잘린 환경이 Short 대신 Checksum으로 거부됨).
    #[test]
    fn exec_frame_rejects_truncated() {
        let b = relay_input(permit(30), &frame(Origin::Builtin), 16_384).unwrap();
        for cut in 0..b.len() {
            assert_eq!(
                read_relay_input(&b[..cut], 16_384),
                Err(FrameError::Short),
                "{cut}"
            );
        }
    }

    // 이것을 실패시키는 것: ExecFrame::decode의 magic·version·origin·flags 검사 하나를 지우는 것.
    // CRC를 다시 계산해 둔 머리라 CRC 비교는 이것을 거부하지 못한다.
    #[test]
    fn exec_header_fields_checked_under_valid_crc() {
        let cases: [(usize, u8, FrameError); 6] = [
            (0, b'X', FrameError::Magic),
            (8, 3, FrameError::Version),
            (8, 5, FrameError::Version),
            (10, 0, FrameError::Kind),
            (10, 3, FrameError::Kind),
            (11, 1, FrameError::Flags),
        ];
        for (at, v, e) in cases {
            let mut b = relay_input(permit(30), &frame(Origin::Config), 16_384).unwrap();
            let f = &mut b[96..];
            f[at] = v;
            let crc = exec_crc(f, [&f[EXEC_HEADER..], &[], &[], &[]]);
            f[24..28].copy_from_slice(&crc);
            assert_eq!(read_relay_input(&b, 16_384), Err(e), "{at}");
        }
    }

    fn pin() -> ExecPin {
        ExecPin {
            group: crate::fs_trust::GroupPin {
                dev: 0x0102_0304_0506_0708,
                ino: 0x1112_1314_1516_1718,
                gid: 1000,
                mode: 0o100_775,
            },
            ctime_sec: 1_700_000_000,
            ctime_nsec: 123,
        }
    }

    // 이것을 실패시키는 것: encode_into가 pin을 쓰지 않거나 decode가 pin을 버리는 것, 또는 pin의
    // 예약 바이트 거부(ExecPin::from_bytes의 Err를 Flags로)를 지우는 것.
    #[test]
    fn exec_frame_carries_pin() {
        let mut f = frame(Origin::Config);
        f.pin = Some(pin());
        let b = relay_input(permit(30), &f, 16_384).unwrap();
        assert_eq!(read_relay_input(&b, 16_384).unwrap().1.pin, Some(pin()));
        let b = relay_input(permit(30), &frame(Origin::Config), 16_384).unwrap();
        assert_eq!(b[96 + TARGET_PIN..96 + INTERPRETER_PIN], [0; EXEC_PIN_LEN]);
        assert_eq!(read_relay_input(&b, 16_384).unwrap().1.pin, None);
        let mut x = relay_input(permit(30), &f, 16_384).unwrap();
        let h = &mut x[96..];
        h[INTERPRETER_PIN - 1] = 1;
        let crc = exec_crc(h, [&h[EXEC_HEADER..], &[], &[], &[]]);
        h[24..28].copy_from_slice(&crc);
        assert_eq!(read_relay_input(&x, 16_384), Err(FrameError::Flags));
    }

    // 이것을 실패시키는 것: ExecFrame::decode의 CRC 비교나 예약 바이트(28..32) 검사를 지우는 것,
    // 또는 CRC 범위에서 pin이나 인터프리터 길이(32..EXEC_HEADER)를 빼는 것.
    #[test]
    fn exec_frame_rejects_every_flipped_bit() {
        let mut f = scripted(Some(pin()));
        f.pin = Some(pin());
        let b = relay_input(permit(30), &f, 16_384).unwrap();
        for i in 96..b.len() {
            for bit in 0..8 {
                let mut x = b.clone();
                x[i] ^= 1 << bit;
                assert!(read_relay_input(&x, 16_384).is_err(), "{i}:{bit}");
            }
        }
        let mut x = b.clone();
        x.push(0);
        assert_eq!(read_relay_input(&x, 16_384), Err(FrameError::Trailing));
    }

    fn scripted(pin: Option<ExecPin>) -> ExecFrame {
        let mut f = frame(Origin::Config);
        f.interpreter = Some(Interpreter {
            line: b"/bin/sh".to_vec(),
            path: b"/usr/bin/sh".to_vec(),
            pin,
        });
        f
    }

    /// `b` with the interpreter lengths and the interpreter pin replaced and
    /// the CRC recomputed.
    fn reshaped(mut b: Vec<u8>, line: u16, path: u16, pin: Option<ExecPin>) -> Vec<u8> {
        let h = &mut b[96..];
        h[LENGTHS..LENGTHS + 2].copy_from_slice(&line.to_le_bytes());
        h[LENGTHS + 2..LENGTHS + 4].copy_from_slice(&path.to_le_bytes());
        h[INTERPRETER_PIN..LENGTHS].copy_from_slice(&ExecPin::to_bytes(pin));
        let crc = exec_crc(h, [&h[EXEC_HEADER..], &[], &[], &[]]);
        h[24..28].copy_from_slice(&crc);
        b
    }

    // 이것을 실패시키는 것: encode_into나 decode가 인터프리터 줄·경로·pin 하나를 쓰지 않거나 버리는 것,
    // 본문을 줄·경로·환경 순서로 나누지 않는 것, 인터프리터 길이 뒤 예약 바이트 검사를 지우는 것.
    #[test]
    fn exec_frame_carries_interpreter() {
        for f in [scripted(None), scripted(Some(pin()))] {
            let b = relay_input(permit(30), &f, 16_384).unwrap();
            assert_eq!(read_relay_input(&b, 16_384).unwrap().1, f);
        }
        let mut b = relay_input(permit(30), &scripted(None), 16_384).unwrap();
        let h = &mut b[96..];
        h[EXEC_HEADER - 1] = 1;
        let crc = exec_crc(h, [&h[EXEC_HEADER..], &[], &[], &[]]);
        h[24..28].copy_from_slice(&crc);
        assert_eq!(read_relay_input(&b, 16_384), Err(FrameError::Flags));
    }

    // 줄과 경로는 함께 있거나 함께 없고, pin은 인터프리터가 있을 때만 있다. 이것을 실패시키는 것:
    // decode의 (줄, 경로) 짝 검사를 지우는 것(경로만 있는 프레임이 줄 없는 인터프리터가 됨), 인터프리터가
    // 없을 때의 pin 거부를 지우는 것.
    #[test]
    fn exec_frame_interpreter_parts_go_together() {
        let b = relay_input(permit(30), &frame(Origin::Config), 16_384).unwrap();
        let environment = b.len() - 96 - EXEC_HEADER - frame(Origin::Config).cwd.len();
        // Shift two environment bytes into the line or the path.
        for (line, path) in [(2, 0), (0, 2)] {
            let mut x = reshaped(b.clone(), line, path, None);
            let h = &mut x[96..];
            h[12..16].copy_from_slice(&u32::try_from(environment - 2).unwrap().to_le_bytes());
            let crc = exec_crc(h, [&h[EXEC_HEADER..], &[], &[], &[]]);
            h[24..28].copy_from_slice(&crc);
            assert_eq!(
                read_relay_input(&x, 16_384),
                Err(FrameError::Length),
                "{line} {path}"
            );
        }
        let x = reshaped(b, 0, 0, Some(pin()));
        assert_eq!(read_relay_input(&x, 16_384), Err(FrameError::Length));
    }

    // 이것을 실패시키는 것: decode의 길이 합을 checked_add 대신 그냥 더하는 것(디버그는 넘침 panic, 릴리스는
    // 감싼 작은 합으로 짧은 본문을 받아들임), 두 번째(경로 길이) checked_add만 감싸 더하는 것.
    #[test]
    fn exec_frame_length_sum_never_wraps() {
        let b = relay_input(permit(30), &frame(Origin::Config), 16_384).unwrap();
        let mut x = reshaped(b, u16::MAX, u16::MAX, None);
        let h = &mut x[96..];
        h[12..16].copy_from_slice(&u32::MAX.to_le_bytes());
        let crc = exec_crc(h, [&h[EXEC_HEADER..], &[], &[], &[]]);
        h[24..28].copy_from_slice(&crc);
        assert_eq!(read_relay_input(&x, 16_384), Err(FrameError::Length));
        // The first sum fits exactly; only adding the path length overflows.
        let b = relay_input(permit(30), &frame(Origin::Config), 16_384).unwrap();
        let mut x = reshaped(b, u16::MAX, 1, None);
        let h = &mut x[96..];
        h[12..16].copy_from_slice(&(u32::MAX - u32::from(u16::MAX)).to_le_bytes());
        let crc = exec_crc(h, [&h[EXEC_HEADER..], &[], &[], &[]]);
        h[24..28].copy_from_slice(&crc);
        assert_eq!(read_relay_input(&x, 16_384), Err(FrameError::Length));
    }
}
