//! Helper and supervisor frames. One header (magic, version, kind, length,
//! CRC32C) and three kinds: the grant (helper to supervisor, once), done
//! (helper to supervisor, after it published every result) and one result
//! per unit (supervisor to helper). A frame is at most 65,536 bytes with its
//! header, so it fits an empty default pipe in one write. Counts and
//! durations travel as data; their limits are arguments of the callers.
use super::{Error, grant::Refusal};
use crate::{
    collection::cwd_hash::sha256,
    config::compile::ExecPolicy,
    fs_trust::GroupPin,
    handoff::{Cwd, Origin, Permit},
    snapshot::crc32c,
};
use alloc::{string::String, vec::Vec};

const MAGIC: &[u8; 8] = b"BNGCMD01";
const VERSION: u16 = 1;
const DOMAIN: &[u8] = b"bingsu-command-v1\0";
/// Magic, version, kind, flags, body length, CRC32C.
pub const HEADER: usize = 20;
/// Whole frame, header included.
pub const FRAME_MAX: usize = 65_536;
pub const BODY_MAX: usize = FRAME_MAX - HEADER;
/// Spec: stdout is read up to 4 KB.
pub const STDOUT_MAX: usize = 4_096;

/// What a config unit runs. A `shell` without explicit `unsafe_shell = true`
/// has no variant, so it cannot be put in a grant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Policy {
    Argv { argv: Vec<Vec<u8>> },
    UnsafeShell { script: Vec<u8> },
}
impl Policy {
    /// The grant form of a compiled unit's policy. A `shell` without
    /// `unsafe_shell = true`, a unit that sets both `command` and `shell`, an
    /// empty argv and a language unit have none, so the helper cannot put them in a grant.
    pub fn from_config(p: &ExecPolicy) -> Option<Self> {
        match p {
            ExecPolicy::Command {
                argv, shell: None, ..
            } if !argv.is_empty() => Some(Self::Argv {
                argv: argv.iter().map(|w| w.as_bytes().to_vec()).collect(),
            }),
            ExecPolicy::Command {
                argv,
                shell: Some(script),
                unsafe_shell: true,
                ..
            } if argv.is_empty() => Some(Self::UnsafeShell {
                script: script.as_bytes().to_vec(),
            }),
            _ => None,
        }
    }
    fn tag(&self) -> u8 {
        match self {
            Self::Argv { .. } => 0,
            Self::UnsafeShell { .. } => 1,
        }
    }
}

/// One config unit of the grant. The supervisor recomputes `digest` from
/// the other fields: a consistency check between the policy and its digest
/// inside one frame. That nothing outside the grant runs rests on the fixed
/// lists of this single frame and its single writer, the helper.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Unit {
    pub id: String,
    pub digest: [u8; 32],
    pub policy: Policy,
    pub cwd: Cwd,
    /// Sanitized target environment, `NAME=VALUE\0` entries.
    pub environment: Vec<u8>,
    pub timeout: u64,
    /// The unit's `env_allow` names, so a config that changes only them
    /// gets another digest.
    pub env_allow: Vec<Vec<u8>>,
    /// The canonical executable the helper resolved from the sanitized
    /// `PATH` this round. An observation, so it is not in `digest`.
    pub executable: Vec<u8>,
    /// Its group pin when it is group-writable (`handoff::ExecFrame::pin`).
    pub pin: Option<GroupPin>,
}

/// One builtin version probe. Fixed arguments and environment come from the
/// core profile table, not from the grant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Probe {
    pub profile: u8,
    pub executable: Vec<u8>,
    /// As `Unit::pin`.
    pub pin: Option<GroupPin>,
}

/// The single grant. The supervisor can run nothing outside these lists.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Grant {
    /// Clock identity and trust deadline `verified_at + T`. A round without a
    /// valid marker still needs the helper's clock identity for builtin
    /// probes, so it carries a permit with deadline 0: `now < 0` never holds,
    /// and every config unit is refused with `Refusal::Trust`.
    pub permit: Permit,
    /// `H`.
    pub helper_deadline: u64,
    pub units: Vec<Unit>,
    pub probes: Vec<Probe>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    /// Raw wait status of the relay or target.
    Exited(i32),
    /// Stopped at its run deadline.
    Timeout,
    /// The supervisor did not spawn it; `Limit` covers a relay input above
    /// its cap.
    Refused(Refusal),
    SpawnFailed,
}

/// Supervisor to helper, one per unit or probe of the grant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outcome {
    pub origin: Origin,
    /// Position in the grant's `units` (config) or `probes` (builtin).
    pub index: u8,
    pub reason: Reason,
    pub approved_at: u64,
    pub ended_at: u64,
    pub stdout: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Message {
    Grant(Grant),
    Done,
    Result(Outcome),
}
impl Message {
    fn kind(&self) -> u8 {
        match self {
            Self::Grant(_) => 1,
            Self::Done => 2,
            Self::Result(_) => 3,
        }
    }
}

/// Digest of what a config unit runs: the policy kind byte, every argv word
/// or the script with its length, the cwd kind and the timeout.
pub fn policy_digest(policy: &Policy, cwd: Cwd, timeout: u64, env_allow: &[Vec<u8>]) -> [u8; 32] {
    let mut b = Vec::new();
    b.extend_from_slice(b"bingsu-command-policy-v1\0");
    b.push(policy.tag());
    fn word(b: &mut Vec<u8>, w: &[u8]) {
        b.extend_from_slice(&(w.len() as u64).to_le_bytes());
        b.extend_from_slice(w);
    }
    match policy {
        Policy::Argv { argv } => {
            // The word count ends the argv section; without it a longer argv
            // can collide with a shorter one and other cwd, timeout or names.
            b.extend_from_slice(&(argv.len() as u64).to_le_bytes());
            argv.iter().for_each(|w| word(&mut b, w));
        }
        Policy::UnsafeShell { script } => word(&mut b, script),
    }
    b.push(cwd.tag());
    b.extend_from_slice(&timeout.to_le_bytes());
    // Names come last, so their own length prefixes delimit them.
    env_allow.iter().for_each(|w| word(&mut b, w));
    sha256(&b)
}

/// Header check before any body byte is read or buffered.
pub fn frame_len(header: &[u8]) -> Result<usize, Error> {
    if header.len() < HEADER {
        return Err(Error::Short);
    }
    if &header[..8] != MAGIC {
        return Err(Error::Magic);
    }
    if header[8..10] != VERSION.to_le_bytes() {
        return Err(Error::Version);
    }
    if !(1..=3).contains(&header[10]) {
        return Err(Error::Kind);
    }
    if header[11] != 0 {
        return Err(Error::Flags);
    }
    let body = u32::from_le_bytes([header[12], header[13], header[14], header[15]]) as usize;
    if body > BODY_MAX {
        return Err(Error::Length);
    }
    Ok(HEADER + body)
}

pub fn encode(m: &Message) -> Result<Vec<u8>, Error> {
    let mut b = Vec::new();
    match m {
        Message::Grant(g) => {
            b.extend_from_slice(&g.permit.encode());
            b.extend_from_slice(&g.helper_deadline.to_le_bytes());
            b.push(u8::try_from(g.units.len()).map_err(|_| Error::Limit)?);
            b.push(u8::try_from(g.probes.len()).map_err(|_| Error::Limit)?);
            for u in &g.units {
                bytes16(&mut b, u.id.as_bytes());
                b.extend_from_slice(&u.digest);
                b.push(u.policy.tag());
                match &u.policy {
                    Policy::Argv { argv } => {
                        b.push(u8::try_from(argv.len()).map_err(|_| Error::Limit)?);
                        for w in argv {
                            bytes16(&mut b, w);
                        }
                    }
                    Policy::UnsafeShell { script } => bytes16(&mut b, script),
                }
                b.push(u.cwd.tag());
                b.extend_from_slice(&u.timeout.to_le_bytes());
                bytes16(&mut b, &u.environment);
                b.push(u8::try_from(u.env_allow.len()).map_err(|_| Error::Limit)?);
                for w in &u.env_allow {
                    bytes16(&mut b, w);
                }
                bytes16(&mut b, &u.executable);
                b.extend_from_slice(&GroupPin::to_bytes(u.pin));
            }
            for p in &g.probes {
                b.push(p.profile);
                bytes16(&mut b, &p.executable);
                b.extend_from_slice(&GroupPin::to_bytes(p.pin));
            }
        }
        Message::Done => {}
        Message::Result(o) => {
            if o.stdout.len() > STDOUT_MAX {
                return Err(Error::Limit);
            }
            let (tag, detail, status) = match o.reason {
                Reason::Exited(s) => (1, 0, s),
                Reason::Timeout => (2, 0, 0),
                Reason::Refused(r) => (3, refusal_tag(r), 0),
                Reason::SpawnFailed => (4, 0, 0),
            };
            b.extend([o.origin.tag(), o.index, tag, detail]);
            b.extend_from_slice(&status.to_le_bytes());
            b.extend_from_slice(&o.approved_at.to_le_bytes());
            b.extend_from_slice(&o.ended_at.to_le_bytes());
            bytes16(&mut b, &o.stdout);
        }
    }
    if b.len() > BODY_MAX {
        return Err(Error::Limit);
    }
    let mut out = Vec::with_capacity(HEADER + b.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&VERSION.to_le_bytes());
    out.extend([m.kind(), 0]);
    out.extend_from_slice(&(b.len() as u32).to_le_bytes());
    let crc = crc32c(&[DOMAIN, &out[..16], &b]);
    out.extend_from_slice(&crc);
    out.extend_from_slice(&b);
    Ok(out)
}

/// One whole frame. Refused before any allocation unless the header, the
/// exact length and the CRC agree; the body then allocates a constant
/// multiple of its own size.
pub fn decode(bytes: &[u8]) -> Result<Message, Error> {
    let total = frame_len(bytes)?;
    if bytes.len() < total {
        return Err(Error::Short);
    }
    if bytes.len() > total {
        return Err(Error::Trailing);
    }
    let body = &bytes[HEADER..];
    if crc32c(&[DOMAIN, &bytes[..16], body]) != bytes[16..20] {
        return Err(Error::Checksum);
    }
    let mut r = Reader(body);
    let m = match bytes[10] {
        1 => {
            let permit = Permit::decode(r.take(96)?).map_err(|_| Error::Checksum)?;
            let helper_deadline = r.u64()?;
            let (nu, np) = (r.u8()?, r.u8()?);
            let mut units = Vec::new();
            for _ in 0..nu {
                let id = String::from_utf8(r.bytes16()?.to_vec()).map_err(|_| Error::Utf8)?;
                let digest = r.take(32)?.try_into().map_err(|_| Error::Short)?;
                let policy = match r.u8()? {
                    0 => {
                        let n = r.u8()?;
                        let mut argv = Vec::new();
                        for _ in 0..n {
                            argv.push(no_nul(r.bytes16()?)?.to_vec());
                        }
                        Policy::Argv { argv }
                    }
                    1 => Policy::UnsafeShell {
                        script: no_nul(r.bytes16()?)?.to_vec(),
                    },
                    _ => return Err(Error::Kind),
                };
                let cwd = Cwd::from_tag(r.u8()?)?;
                let timeout = r.u64()?;
                let environment = r.bytes16()?.to_vec();
                let n = r.u8()?;
                let mut env_allow = Vec::new();
                for _ in 0..n {
                    env_allow.push(no_nul(r.bytes16()?)?.to_vec());
                }
                let executable = no_nul(r.bytes16()?)?.to_vec();
                let pin = r.pin()?;
                units.push(Unit {
                    id,
                    digest,
                    policy,
                    cwd,
                    environment,
                    timeout,
                    env_allow,
                    executable,
                    pin,
                });
            }
            let mut probes = Vec::new();
            for _ in 0..np {
                let profile = r.u8()?;
                let executable = no_nul(r.bytes16()?)?.to_vec();
                probes.push(Probe {
                    profile,
                    executable,
                    pin: r.pin()?,
                });
            }
            Message::Grant(Grant {
                permit,
                helper_deadline,
                units,
                probes,
            })
        }
        2 => Message::Done,
        _ => {
            let origin = Origin::from_tag(r.u8()?)?;
            let index = r.u8()?;
            let (tag, detail) = (r.u8()?, r.u8()?);
            let status = i32::from_le_bytes(r.take(4)?.try_into().map_err(|_| Error::Short)?);
            if tag != 1 && status != 0 || tag != 3 && detail != 0 {
                return Err(Error::Flags);
            }
            let reason = match tag {
                1 => Reason::Exited(status),
                2 => Reason::Timeout,
                3 => Reason::Refused(refusal_from(detail)?),
                4 => Reason::SpawnFailed,
                _ => return Err(Error::Kind),
            };
            let approved_at = r.u64()?;
            let ended_at = r.u64()?;
            let stdout = r.bytes16()?;
            if stdout.len() > STDOUT_MAX {
                return Err(Error::Limit);
            }
            Message::Result(Outcome {
                origin,
                index,
                reason,
                approved_at,
                ended_at,
                stdout: stdout.to_vec(),
            })
        }
    };
    if !r.0.is_empty() {
        return Err(Error::Trailing);
    }
    Ok(m)
}

/// A word with a NUL would end early in a C string and shift the words after it.
fn no_nul(w: &[u8]) -> Result<&[u8], Error> {
    if w.contains(&0) {
        return Err(Error::Utf8);
    }
    Ok(w)
}

fn refusal_tag(r: Refusal) -> u8 {
    match r {
        Refusal::Clock => 1,
        Refusal::Trust => 2,
        Refusal::Budget => 3,
        Refusal::Policy => 4,
        Refusal::Limit => 5,
    }
}
fn refusal_from(b: u8) -> Result<Refusal, Error> {
    Ok(match b {
        1 => Refusal::Clock,
        2 => Refusal::Trust,
        3 => Refusal::Budget,
        4 => Refusal::Policy,
        5 => Refusal::Limit,
        _ => return Err(Error::Kind),
    })
}

/// A field longer than `u16::MAX` makes the body longer than `BODY_MAX`,
/// which `encode` refuses after the body is built, so the cast never ships.
fn bytes16(b: &mut Vec<u8>, v: &[u8]) {
    b.extend_from_slice(&(v.len() as u16).to_le_bytes());
    b.extend_from_slice(v);
}

struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        if self.0.len() < n {
            return Err(Error::Short);
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(head)
    }
    fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }
    fn u64(&mut self) -> Result<u64, Error> {
        let mut a = [0; 8];
        a.copy_from_slice(self.take(8)?);
        Ok(u64::from_le_bytes(a))
    }
    fn bytes16(&mut self) -> Result<&'a [u8], Error> {
        let h = self.take(2)?;
        self.take(usize::from(u16::from_le_bytes([h[0], h[1]])))
    }
    fn pin(&mut self) -> Result<Option<GroupPin>, Error> {
        let b: &[u8; 24] = self.take(24)?.try_into().map_err(|_| Error::Short)?;
        Ok(GroupPin::from_bytes(b))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::grant::Refusal;
    use alloc::vec;

    fn permit() -> Permit {
        Permit {
            kind: 1,
            deadline: 100,
            boot: [1; 16],
            resume: 0,
            domain: [2; 16],
        }
    }
    fn unit(policy: Policy) -> Unit {
        Unit {
            id: "custom/kube".into(),
            digest: policy_digest(&policy, Cwd::Neutral, 7, &[b"KUBECONFIG".to_vec()]),
            policy,
            cwd: Cwd::Neutral,
            environment: b"HOME=/h\0PATH=/usr/bin\0".to_vec(),
            timeout: 7,
            env_allow: vec![b"KUBECONFIG".to_vec()],
            executable: b"/usr/local/bin/kubectl".to_vec(),
            pin: Some(GroupPin {
                dev: 7,
                ino: 8,
                gid: 1000,
                mode: 0o100_775,
            }),
        }
    }
    fn grant() -> Message {
        Message::Grant(Grant {
            permit: permit(),
            helper_deadline: 9,
            units: vec![
                unit(Policy::Argv {
                    argv: vec![b"kubectl".to_vec(), b"--".to_vec()],
                }),
                unit(Policy::UnsafeShell {
                    script: b"kubectl ctx | head -1".to_vec(),
                }),
            ],
            probes: vec![Probe {
                profile: 3,
                executable: b"/usr/bin/go".to_vec(),
                pin: Some(GroupPin {
                    dev: 1,
                    ino: 2,
                    gid: 80,
                    mode: 0o100_775,
                }),
            }],
        })
    }
    fn result() -> Message {
        Message::Result(Outcome {
            origin: Origin::Builtin,
            index: 0,
            reason: Reason::Refused(Refusal::Budget),
            approved_at: 5,
            ended_at: 6,
            stdout: b"go1.24".to_vec(),
        })
    }
    /// Recompute the CRC after editing a body byte, so only the field check
    /// can refuse it.
    fn reseal(b: &mut [u8]) {
        let crc = crc32c(&[DOMAIN, &b[..16], &b[HEADER..]]);
        b[16..20].copy_from_slice(&crc);
    }

    // 양성 대조: 세 종류와 모든 종료 이유가 그대로 돌아온다(거부 시험들이 정상 프레임까지 막지 않음).
    // 이것을 실패시키는 것: encode나 decode 한쪽에서 단위·probe의 실행 파일 경로나 pin을 빼는 것.
    #[test]
    fn frames_roundtrip() {
        for m in [grant(), Message::Done, result()] {
            assert_eq!(decode(&encode(&m).unwrap()), Ok(m));
        }
        for reason in [
            Reason::Exited(-9),
            Reason::Timeout,
            Reason::Refused(Refusal::Limit),
            Reason::SpawnFailed,
        ] {
            let Message::Result(mut o) = result() else {
                unreachable!()
            };
            o.reason = reason;
            let m = Message::Result(o);
            assert_eq!(decode(&encode(&m).unwrap()), Ok(m));
        }
    }

    // 이것을 실패시키는 것: 정책 종류 match에 셋째 팔(2 => 일반 shell)을 더하거나 `_ => Err(Kind)`를
    // 다른 변형으로 바꾸는 것.
    #[test]
    fn policy_codec_has_no_plain_shell() {
        let mut b = encode(&grant()).unwrap();
        // Body: permit 96, H 8, counts 2, then id (2 + 11) and digest 32.
        let at = HEADER + 96 + 8 + 2 + 2 + 11 + 32;
        assert_eq!(b[at], 0);
        b[at] = 2;
        reseal(&mut b);
        assert_eq!(decode(&b), Err(Error::Kind));
    }

    // 이것을 실패시키는 것: policy_digest에서 `b.push(policy.tag())`를 지우는 것. 빈 argv와 빈
    // script는 종류 바이트가 없으면 같은 바이트(길이 0의 8바이트)가 된다.
    #[test]
    fn policy_kind_in_digest() {
        let s = b"kubectl ctx".to_vec();
        let argv = Policy::Argv {
            argv: vec![s.clone()],
        };
        let shell = Policy::UnsafeShell { script: s };
        assert_ne!(
            policy_digest(&argv, Cwd::Neutral, 1, &[]),
            policy_digest(&shell, Cwd::Neutral, 1, &[])
        );
        let argv = Policy::Argv { argv: Vec::new() };
        let shell = Policy::UnsafeShell { script: Vec::new() };
        assert_ne!(
            policy_digest(&argv, Cwd::Neutral, 1, &[]),
            policy_digest(&shell, Cwd::Neutral, 1, &[])
        );
    }

    // 이것을 실패시키는 것: policy_digest의 단어 길이 접두를 지우는 것(["ab","c"]와 ["a","bc"]가 같아짐).
    #[test]
    fn policy_digest_separates_words() {
        let a = Policy::Argv {
            argv: vec![b"ab".to_vec(), b"c".to_vec()],
        };
        let b = Policy::Argv {
            argv: vec![b"a".to_vec(), b"bc".to_vec()],
        };
        assert_ne!(
            policy_digest(&a, Cwd::Neutral, 1, &[]),
            policy_digest(&b, Cwd::Neutral, 1, &[])
        );
    }

    // 이것을 실패시키는 것: policy_digest에서 env_allow 이름을 빼는 것(이름만 바꾼 설정이 같은
    // 요약값이 됨).
    #[test]
    fn policy_digest_covers_env_allow_names() {
        let p = Policy::Argv {
            argv: vec![b"kubectl".to_vec()],
        };
        let a = policy_digest(&p, Cwd::Neutral, 1, &[b"KUBECONFIG".to_vec()]);
        let b = policy_digest(&p, Cwd::Neutral, 1, &[b"SSH_AUTH_SOCK".to_vec()]);
        let none = policy_digest(&p, Cwd::Neutral, 1, &[]);
        assert_ne!(a, b);
        assert_ne!(a, none);
        // Name boundaries count too.
        let ab = policy_digest(&p, Cwd::Neutral, 1, &[b"AB".to_vec(), b"C".to_vec()]);
        let a_bc = policy_digest(&p, Cwd::Neutral, 1, &[b"A".to_vec(), b"BC".to_vec()]);
        assert_ne!(ab, a_bc);
    }

    // 이것을 실패시키는 것: policy_digest의 argv 단어 개수 접두를 지우는 것. 그러면 아래 둘이
    // 같은 바이트가 된다: argv ["x"], 이름 [""] 과 argv ["x", ""], 이름 없음(cwd neutral, timeout 0.
    // 짧은 쪽의 cwd·timeout·빈 이름 길이가 긴 쪽의 빈 단어 길이·cwd·timeout과 겹침).
    #[test]
    fn policy_digest_counts_argv_words() {
        let one = Policy::Argv {
            argv: vec![b"x".to_vec()],
        };
        let two = Policy::Argv {
            argv: vec![b"x".to_vec(), Vec::new()],
        };
        assert_ne!(
            policy_digest(&one, Cwd::Neutral, 0, &[Vec::new()]),
            policy_digest(&two, Cwd::Neutral, 0, &[])
        );
    }

    // 이것을 실패시키는 것: decode의 argv 단어·script·env_allow 이름·실행 파일 경로 no_nul 검사
    // 하나를 지우는 것(NUL 뒤 바이트가 C 문자열에서 다른 단어가 됨).
    #[test]
    fn decode_refuses_nul_in_words() {
        let Message::Grant(base) = grant() else {
            unreachable!()
        };
        let mut cases = Vec::new();
        let mut g = base.clone();
        g.units[0].policy = Policy::Argv {
            argv: vec![b"kubectl\0--".to_vec()],
        };
        cases.push(g);
        let mut g = base.clone();
        g.units[1].policy = Policy::UnsafeShell {
            script: b"true\0rm".to_vec(),
        };
        cases.push(g);
        let mut g = base.clone();
        g.units[0].env_allow = vec![b"KUBE\0LD_PRELOAD".to_vec()];
        cases.push(g);
        let mut g = base.clone();
        g.probes[0].executable = b"/usr/bin/go\0neutral".to_vec();
        cases.push(g);
        let mut g = base.clone();
        g.units[0].executable = b"/usr/bin/kubectl\0neutral".to_vec();
        cases.push(g);
        for g in cases {
            let b = encode(&Message::Grant(g)).unwrap();
            assert_eq!(decode(&b), Err(Error::Utf8));
        }
    }

    // 이것을 실패시키는 것: decode의 `bytes.len() < total` 검사를 지우는 것
    // (짧은 프레임이 Short 대신 slice panic이나 Checksum이 됨).
    #[test]
    fn frame_rejects_truncated() {
        for m in [grant(), Message::Done, result()] {
            let b = encode(&m).unwrap();
            for cut in 0..b.len() {
                assert_eq!(decode(&b[..cut]), Err(Error::Short), "{cut}");
            }
        }
    }

    // 이것을 실패시키는 것: frame_len의 magic·version·kind·flags 검사 하나를 지우거나 CRC 비교를
    // 지우는 것(그 바이트를 뒤집은 프레임이 승인됨).
    #[test]
    fn frame_rejects_every_flipped_bit() {
        for m in [grant(), Message::Done, result()] {
            let b = encode(&m).unwrap();
            for i in 0..b.len() {
                for bit in 0..8 {
                    let mut x = b.clone();
                    x[i] ^= 1 << bit;
                    assert!(decode(&x).is_err(), "{i}:{bit}");
                }
            }
        }
    }

    // 이것을 실패시키는 것: frame_len의 BODY_MAX 비교를 지우거나 `>`를 `>=`로 바꾸는 것.
    #[test]
    fn frame_length_cap_is_whole_frame() {
        let mut h = encode(&Message::Done).unwrap();
        h[12..16].copy_from_slice(&(BODY_MAX as u32).to_le_bytes());
        assert_eq!(frame_len(&h), Ok(FRAME_MAX));
        h[12..16].copy_from_slice(&(BODY_MAX as u32 + 1).to_le_bytes());
        assert_eq!(frame_len(&h), Err(Error::Length));
        // The largest grant body encodes; one byte more is refused.
        let Message::Grant(mut g) = grant() else {
            unreachable!()
        };
        g.probes.clear();
        g.units.truncate(1);
        let base = encode(&Message::Grant(g.clone())).unwrap().len();
        let grow = g.units[0].environment.len() + FRAME_MAX - base;
        g.units[0].environment.resize(grow, b'x');
        assert_eq!(encode(&Message::Grant(g.clone())).unwrap().len(), FRAME_MAX);
        g.units[0].environment.push(b'x');
        assert_eq!(encode(&Message::Grant(g)), Err(Error::Limit));
    }

    // 이것을 실패시키는 것: 결과 프레임의 STDOUT_MAX 검사(encode나 decode)를 지우는 것.
    #[test]
    fn result_stdout_is_capped() {
        let Message::Result(mut o) = result() else {
            unreachable!()
        };
        o.stdout = vec![b'y'; STDOUT_MAX];
        assert!(encode(&Message::Result(o.clone())).is_ok());
        o.stdout.push(b'y');
        assert_eq!(encode(&Message::Result(o.clone())), Err(Error::Limit));
        // A hand-made frame with 4,097 stdout bytes is refused on decode.
        o.stdout.pop();
        let mut b = encode(&Message::Result(o)).unwrap();
        b.push(b'y');
        let n = (b.len() - HEADER) as u32;
        b[12..16].copy_from_slice(&n.to_le_bytes());
        let len_at = b.len() - STDOUT_MAX - 1 - 2;
        b[len_at..len_at + 2].copy_from_slice(&((STDOUT_MAX + 1) as u16).to_le_bytes());
        reseal(&mut b);
        assert_eq!(decode(&b), Err(Error::Limit));
    }

    // 이것을 실패시키는 것: 결과 프레임에서 쓰지 않는 status·detail이 0인지 보는 검사를 지우는 것.
    #[test]
    fn result_unused_fields_are_zero() {
        let mut b = encode(&result()).unwrap();
        // Refused carries a detail; set a status anyway.
        b[HEADER + 4] = 1;
        reseal(&mut b);
        assert_eq!(decode(&b), Err(Error::Flags));
        let Message::Result(mut o) = result() else {
            unreachable!()
        };
        o.reason = Reason::Timeout;
        let mut b = encode(&Message::Result(o)).unwrap();
        b[HEADER + 3] = 1;
        reseal(&mut b);
        assert_eq!(decode(&b), Err(Error::Flags));
    }

    // 이것을 실패시키는 것: frame_len의 magic·version·kind·flags 검사 하나를 지우는 것. CRC를 다시
    // 계산해 둔 머리라 CRC 비교는 이것을 거부하지 못한다.
    #[test]
    fn header_fields_checked_under_valid_crc() {
        let cases: [(usize, u8, Error); 5] = [
            (0, b'X', Error::Magic),
            (8, 2, Error::Version),
            (10, 0, Error::Kind),
            (10, 4, Error::Kind),
            (11, 1, Error::Flags),
        ];
        for (at, v, e) in cases {
            let mut b = encode(&result()).unwrap();
            b[at] = v;
            reseal(&mut b);
            assert_eq!(decode(&b), Err(e), "{at}");
        }
    }

    // 이것을 실패시키는 것: 본문의 cwd 종류, 결과의 origin·이유·거부 사유 종류에서 `_ => Err(Kind)`
    // 하나를 정의된 변형으로 바꾸는 것.
    #[test]
    fn body_tags_checked_under_valid_crc() {
        let mut b = encode(&grant()).unwrap();
        // First unit: id 13, digest 32, kind 1, argc 1, "kubectl" 9, "--" 4, then cwd.
        let at = HEADER + 96 + 8 + 2 + 13 + 32 + 1 + 1 + 9 + 4;
        assert_eq!(b[at], 0);
        b[at] = 2;
        reseal(&mut b);
        assert_eq!(decode(&b), Err(Error::Kind));
        for (at, v) in [(0, 0), (0, 3), (2, 5), (2, 0), (3, 6), (3, 0)] {
            let mut b = encode(&result()).unwrap();
            b[HEADER + at] = v;
            if at == 2 {
                // Reason tags other than Refused carry no detail.
                b[HEADER + 3] = 0;
            }
            reseal(&mut b);
            assert_eq!(decode(&b), Err(Error::Kind), "{at}:{v}");
        }
    }

    // 이것을 실패시키는 것: encode의 argv·env_allow 개수 변환을 `as u8` 자르기로 바꾸는 것(256개째
    // 단어나 이름이 조용히 잘린 프레임이 됨), 또는 encode 끝의 BODY_MAX 검사를 지우는 것(65,536바이트 필드).
    #[test]
    fn encode_refuses_counts_that_do_not_fit() {
        let Message::Grant(mut g) = grant() else {
            unreachable!()
        };
        g.units[0].policy = Policy::Argv {
            argv: vec![b"w".to_vec(); 256],
        };
        assert_eq!(encode(&Message::Grant(g.clone())), Err(Error::Limit));
        g.units[0].policy = Policy::Argv {
            argv: vec![b"w".to_vec()],
        };
        g.units[0].env_allow = vec![b"N".to_vec(); 256];
        assert_eq!(encode(&Message::Grant(g.clone())), Err(Error::Limit));
        g.units[0].env_allow.clear();
        g.units.truncate(1);
        g.units[0].policy = Policy::UnsafeShell {
            script: vec![b's'; 65_536],
        };
        assert_eq!(encode(&Message::Grant(g)), Err(Error::Limit));
    }

    // 이것을 실패시키는 것: decode 끝의 `!r.0.is_empty()` 검사를 지우는 것(본문 안 남는 바이트가 승인됨).
    #[test]
    fn frame_rejects_trailing_bytes() {
        let mut b = encode(&Message::Done).unwrap();
        b.push(0);
        assert_eq!(decode(&b), Err(Error::Trailing));
        // Inside the body: declared length covers one extra byte.
        let mut b = encode(&result()).unwrap();
        b.push(0);
        let n = (b.len() - HEADER) as u32;
        b[12..16].copy_from_slice(&n.to_le_bytes());
        reseal(&mut b);
        assert_eq!(decode(&b), Err(Error::Trailing));
    }
}
