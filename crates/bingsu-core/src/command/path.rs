//! Sanitized `PATH` and executable lookup (spec section 4 "user command
//! execution model", rows environment and executable lookup; section 2
//! safety row for group write). Pure rules over the strings and the facts
//! the helper observed through open descriptors; the walk itself is the
//! CLI's `exec_path`.
use super::Error;
use crate::fs_trust::{Facts, GroupOracle, GroupPin, NextOwner, Verdict, entry_verdict};
use alloc::vec::Vec;

/// `PATH` entries worth resolving, in order: empty and relative entries
/// (".", "bin") are dropped, because they name folders relative to a
/// working folder the shell chose (spec: relative and empty entries excluded).
pub fn entries(path: &[u8]) -> impl Iterator<Item = &[u8]> {
    path.split(|&b| b == b':')
        .filter(|e| e.first() == Some(&b'/'))
}

/// A folder or file, as `(st_dev, st_ino)`.
pub type Id = (u64, u64);

/// Whether the walk's folder chain (from "/" to the folder holding the last
/// entry, or to the folder itself) avoids the repository root. Identity,
/// not spelling: a case-only alias on a case-insensitive volume, a firmlink
/// such as `/System/Volumes/Data` or a bind mount of the root reach the
/// same `(dev, ino)`. A bind mount of a folder below the root is not seen;
/// only root can make one (known-issues m6-B2a).
pub fn outside_repo(chain: &[Id], repo: Option<Id>) -> bool {
    !repo.is_some_and(|r| chain.contains(&r))
}

/// A canonical `PATH` folder whose name has ':' cannot be written into the
/// `PATH` value: it would split into two entries, one of them possibly empty
/// (the current folder).
pub fn path_safe(canonical: &[u8]) -> bool {
    !canonical.contains(&b':')
}

/// Whether a command or a final symlink target names a folder: it ends in
/// '/' or "/." (`/usr/bin/true/`), which the walk's name splitting would
/// otherwise drop.
pub fn names_folder(p: &[u8]) -> bool {
    p.ends_with(b"/") || p.ends_with(b"/.")
}

/// The sanitized `PATH` value: kept canonical folders, first occurrence
/// only, joined with ':'.
pub fn sanitized<'a>(folders: impl IntoIterator<Item = &'a [u8]>) -> Vec<u8> {
    let mut seen: Vec<&[u8]> = Vec::new();
    let mut out = Vec::new();
    for f in folders {
        if seen.contains(&f) {
            continue;
        }
        if !out.is_empty() {
            out.push(b':');
        }
        out.extend_from_slice(f);
        seen.push(f);
    }
    out
}

/// How a command's first word is looked up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Name<'a> {
    /// A bare name: searched in the sanitized `PATH`.
    Search(&'a [u8]),
    /// An absolute path: resolved as given.
    Absolute(&'a [u8]),
    /// Empty, ".", "..", or a relative path with a '/' (it would name a file
    /// relative to the working folder).
    Refused,
}

pub fn name(word: &[u8]) -> Name<'_> {
    match word {
        [b'/', ..] => Name::Absolute(word),
        [] | b"." | b".." => Name::Refused,
        w if w.contains(&b'/') => Name::Refused,
        w => Name::Search(w),
    }
}

/// Symlinks on the way are followed only when root or the user owns them
/// (spec section 4 native executable row: merged-/usr `/bin`, Homebrew
/// `bin/x -> ../Cellar/…`); a link someone else owns could point anywhere.
pub fn link_owner_ok(uid: u32, me: u32) -> bool {
    uid == 0 || uid == me
}

/// What the lookup does with the entry a `PATH` folder has under the name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Candidate {
    /// Run it.
    Run,
    /// Not an executable regular file: look in the next folder, as a shell
    /// does.
    Skip,
    /// An executable someone else can change, or one whose rule could not
    /// be decided: the lookup stops here and nothing runs. A later folder's
    /// file of the same name is not a substitute for the one the shell
    /// would have found.
    Refuse,
}

const S_IFMT: u32 = 0o170_000;
const S_IFREG: u32 = 0o100_000;
const EXEC_BITS: u32 = 0o111;

/// The final entry of an executable walk. `next` is the duty a root-owned
/// sticky parent left (`fs_trust::ancestor_verdict`): its entry must be the
/// user's own.
pub fn candidate(f: &Facts, me: u32, next: NextOwner, groups: &mut dyn GroupOracle) -> Candidate {
    if f.mode & S_IFMT != S_IFREG || f.mode & EXEC_BITS == 0 {
        return Candidate::Skip;
    }
    if matches!(next, NextOwner::Mine { .. }) && f.uid != me {
        return Candidate::Refuse;
    }
    match entry_verdict(f, me, false, groups) {
        Verdict::Safe => Candidate::Run,
        Verdict::Unknown | Verdict::Tamperable => Candidate::Refuse,
    }
}

/// The pin of one group-writable target the system cleared: the folder pin
/// (device, inode, group, mode) plus the status change time. Rewriting the
/// file in place, chmod, chown and ACL changes all move `st_ctime`, so a
/// group member who changes the file after the helper's check (a path the
/// group database does not show, such as a setgid binary or newgrp) makes
/// the relay refuse it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExecPin {
    pub group: GroupPin,
    pub ctime_sec: i64,
    pub ctime_nsec: u32,
}

/// Bytes of an `ExecPin` in the command frames.
pub const EXEC_PIN_LEN: usize = 40;

impl ExecPin {
    /// Whether `f`, with status change time `ctime`, is the pinned file
    /// unchanged.
    pub fn matches(&self, f: &Facts, ctime: (i64, u32)) -> bool {
        self.group == GroupPin::of(f) && (self.ctime_sec, self.ctime_nsec) == ctime
    }

    /// gid, mode, dev, ino, ctime seconds, ctime nanoseconds, 4 reserved
    /// bytes, little-endian; all zero is no pin (a pinned file's mode has
    /// its type bits set).
    pub fn to_bytes(pin: Option<Self>) -> [u8; EXEC_PIN_LEN] {
        let mut b = [0; EXEC_PIN_LEN];
        if let Some(p) = pin {
            b[..4].copy_from_slice(&p.group.gid.to_le_bytes());
            b[4..8].copy_from_slice(&p.group.mode.to_le_bytes());
            b[8..16].copy_from_slice(&p.group.dev.to_le_bytes());
            b[16..24].copy_from_slice(&p.group.ino.to_le_bytes());
            b[24..32].copy_from_slice(&p.ctime_sec.to_le_bytes());
            b[32..36].copy_from_slice(&p.ctime_nsec.to_le_bytes());
        }
        b
    }

    /// `Flags` for reserved bytes that are not zero or nanoseconds of a
    /// whole second or more.
    pub fn from_bytes(b: &[u8; EXEC_PIN_LEN]) -> Result<Option<Self>, Error> {
        if *b == [0; EXEC_PIN_LEN] {
            return Ok(None);
        }
        let word = |at: usize| u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]]);
        let wide = |at: usize| {
            let mut a = [0; 8];
            a.copy_from_slice(&b[at..at + 8]);
            a
        };
        let ctime_nsec = word(32);
        if b[36..] != [0; 4] || ctime_nsec >= 1_000_000_000 {
            return Err(Error::Flags);
        }
        Ok(Some(Self {
            group: GroupPin {
                gid: word(0),
                mode: word(4),
                dev: u64::from_le_bytes(wide(8)),
                ino: u64::from_le_bytes(wide(16)),
            },
            ctime_sec: i64::from_le_bytes(wide(24)),
            ctime_nsec,
        }))
    }
}

/// The pin the relay needs for a target `candidate` accepted: present only
/// when the file is group-writable, and then only if the group oracle
/// cleared this very file (`cleared` is what `Recording` kept). An ACL is
/// not in the pin: only the file's owner (root or the user, which
/// `entry_verdict` checked) or a holder of CAP_FOWNER can change it, and
/// both are trusted; a change also moves the ctime in the pin.
pub fn target_pin(f: &Facts, cleared: &[GroupPin], ctime: (i64, u32)) -> Option<ExecPin> {
    let group = GroupPin::of(f);
    (f.mode & 0o020 != 0 && cleared.contains(&group)).then_some(ExecPin {
        group,
        ctime_sec: ctime.0,
        ctime_nsec: ctime.1,
    })
}

/// Bytes the kernel reads for a `#!` line (`BINPRM_BUF_SIZE`).
pub const SHEBANG_MAX: usize = 256;

/// The interpreter line of a script, split as the kernel splits it: the
/// interpreter up to the first space or tab, then at most one argument (the
/// rest of the line, spaces and tabs trimmed at both ends).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Shebang<'a> {
    pub interpreter: &'a [u8],
    pub arg: Option<&'a [u8]>,
}

/// What the first bytes of an executable say about how it runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Head<'a> {
    /// No `#!`: the kernel loads it itself.
    Native,
    Script(Shebang<'a>),
    /// A `#!` line the executor does not run (spec section 4 script row):
    /// longer than `SHEBANG_MAX`, a relative interpreter, or `/usr/bin/env`,
    /// which would pick the real interpreter from `PATH`.
    Refused,
}

/// `first` is the file's first bytes, at most `SHEBANG_MAX`; fewer means the
/// file ended there, so a line without a newline is whole.
pub fn head(first: &[u8]) -> Head<'_> {
    let Some(rest) = first.strip_prefix(b"#!") else {
        return Head::Native;
    };
    let line = match rest.iter().position(|&b| b == b'\n') {
        Some(end) => &rest[..end],
        None if first.len() < SHEBANG_MAX => rest,
        None => return Head::Refused,
    };
    let blank = |b: &u8| *b == b' ' || *b == b'\t';
    let line = trim(line, blank);
    let end = line.iter().position(blank).unwrap_or(line.len());
    let (interpreter, arg) = line.split_at(end);
    let arg = trim(arg, blank);
    if interpreter.first() != Some(&b'/') || interpreter == b"/usr/bin/env" {
        return Head::Refused;
    }
    Head::Script(Shebang {
        interpreter,
        arg: (!arg.is_empty()).then_some(arg),
    })
}

fn trim(s: &[u8], blank: impl Fn(&u8) -> bool) -> &[u8] {
    let start = s.iter().position(|b| !blank(b)).unwrap_or(s.len());
    let end = s.iter().rposition(|b| !blank(b)).map_or(start, |i| i + 1);
    &s[start..end]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs_trust::{AclFacts, Group, RefuseGroupWrite};

    const ME: u32 = 501;

    fn file(uid: u32, mode: u32) -> Facts {
        Facts {
            dev: 1,
            ino: 2,
            uid,
            gid: 20,
            mode: S_IFREG | mode,
            acl: AclFacts::None,
            ownership: Some(true),
        }
    }

    struct Clear;
    impl GroupOracle for Clear {
        fn group_write(&mut self, _: &Facts) -> Group {
            Group::OnlyRootAndUser
        }
    }

    // 이것을 실패시키는 것: entries에서 첫 바이트 '/' 검사를 지우는 것(".", "bin", 빈 항목이 남음).
    #[test]
    fn entries_drop_empty_and_relative() {
        let got: Vec<&[u8]> = entries(b"/usr/bin::.:bin:/opt/x/bin:").collect();
        assert_eq!(got, [&b"/usr/bin"[..], b"/opt/x/bin"]);
    }

    // 이것을 실패시키는 것: outside_repo의 저장소 비교를 지우거나 반전하는 것, path_safe의 ':' 검사를
    // 지우는 것, names_folder의 '/'·"/." 검사 하나를 지우는 것.
    #[test]
    fn repo_identity_colons_and_folder_names() {
        let chain = [(1, 2), (1, 3), (4, 5)];
        assert!(!outside_repo(&chain, Some((1, 3))));
        assert!(outside_repo(&chain, Some((1, 6))));
        assert!(outside_repo(&chain, None));
        assert!(path_safe(b"/usr/bin"));
        assert!(!path_safe(b"/opt/a:b/bin"));
        assert!(names_folder(b"/usr/bin/true/"));
        assert!(names_folder(b"/usr/bin/true/."));
        assert!(!names_folder(b"/usr/bin/true"));
        assert!(!names_folder(b"/usr/bin/x."));
    }

    // 이것을 실패시키는 것: sanitized의 중복 검사를 지우는 것, 또는 구분자를 앞에 붙이는 것.
    #[test]
    fn sanitized_joins_first_occurrences() {
        let f: [&[u8]; 3] = [b"/usr/bin", b"/bin", b"/usr/bin"];
        assert_eq!(sanitized(f), b"/usr/bin:/bin");
        assert_eq!(sanitized([]), b"");
    }

    // 이것을 실패시키는 것: name에서 '/'가 든 상대 경로 거부를 지우는 것, 또는 "."·".."·빈 이름
    // 거부를 지우는 것.
    #[test]
    fn names() {
        assert_eq!(name(b"kubectl"), Name::Search(b"kubectl"));
        assert_eq!(name(b"/usr/bin/go"), Name::Absolute(b"/usr/bin/go"));
        for w in [&b""[..], b".", b"..", b"./x", b"bin/x"] {
            assert_eq!(name(w), Name::Refused, "{w:?}");
        }
    }

    // test_foreign_symlink_refused의 core 짝. 이것을 실패시키는 것: link_owner_ok의 소유자 비교를
    // 반전하거나 root 허용을 지우는 것.
    #[test]
    fn link_owners() {
        assert!(link_owner_ok(0, ME));
        assert!(link_owner_ok(ME, ME));
        assert!(!link_owner_ok(1000, ME));
    }

    // 이것을 실패시키는 것: candidate의 정규 파일·실행 비트 검사를 지우는 것(Skip 대신 Run), sticky
    // 상위 의무를 지우는 것, entry_verdict 확인을 지우는 것.
    #[test]
    fn candidates() {
        let g = &mut RefuseGroupWrite;
        assert_eq!(
            candidate(&file(0, 0o755), ME, NextOwner::Any, g),
            Candidate::Run
        );
        assert_eq!(
            candidate(&file(ME, 0o700), ME, NextOwner::Any, g),
            Candidate::Run
        );
        assert_eq!(
            candidate(&file(0, 0o644), ME, NextOwner::Any, g),
            Candidate::Skip
        );
        let mut dir = file(0, 0o755);
        dir.mode = 0o040_755;
        assert_eq!(candidate(&dir, ME, NextOwner::Any, g), Candidate::Skip);
        let sticky = NextOwner::Mine { parent: 1 };
        assert_eq!(candidate(&file(0, 0o755), ME, sticky, g), Candidate::Refuse);
        assert_eq!(candidate(&file(ME, 0o755), ME, sticky, g), Candidate::Run);
        assert_eq!(
            candidate(&file(1000, 0o755), ME, NextOwner::Any, g),
            Candidate::Refuse
        );
        assert_eq!(
            candidate(&file(ME, 0o757), ME, NextOwner::Any, g),
            Candidate::Refuse
        );
        assert_eq!(
            candidate(&file(ME, 0o775), ME, NextOwner::Any, g),
            Candidate::Refuse
        );
        assert_eq!(
            candidate(&file(ME, 0o775), ME, NextOwner::Any, &mut Clear),
            Candidate::Run
        );
        let mut acl = file(ME, 0o775);
        acl.acl = AclFacts::PosixExtended;
        assert_eq!(
            candidate(&acl, ME, NextOwner::Any, &mut Clear),
            Candidate::Refuse
        );
    }

    // 이것을 실패시키는 것: target_pin의 그룹 쓰기 조건을 지우는 것(그룹 쓰기 없는 파일에 pin),
    // cleared 확인을 지우는 것(오라클이 통과시키지 않은 파일에 pin), ctime을 pin에 넣지 않는 것.
    #[test]
    fn pins_only_for_cleared_group_writable_targets() {
        let f = file(ME, 0o775);
        let pin = target_pin(&f, &[GroupPin::of(&f)], (7, 9)).unwrap();
        assert_eq!(pin.group, GroupPin::of(&f));
        assert_eq!((pin.ctime_sec, pin.ctime_nsec), (7, 9));
        assert_eq!(target_pin(&f, &[], (7, 9)), None);
        let mut other = f;
        other.ino = 3;
        assert_eq!(target_pin(&f, &[GroupPin::of(&other)], (7, 9)), None);
        let plain = file(ME, 0o755);
        assert_eq!(target_pin(&plain, &[GroupPin::of(&plain)], (7, 9)), None);
    }

    // 이것을 실패시키는 것: matches에서 ctime 비교를 지우는 것(그 자리에서 고쳐 쓴 파일이 통과),
    // 또는 GroupPin 비교를 지우는 것.
    #[test]
    fn exec_pin_matches_file_and_ctime() {
        let f = file(ME, 0o775);
        let pin = target_pin(&f, &[GroupPin::of(&f)], (7, 9)).unwrap();
        assert!(pin.matches(&f, (7, 9)));
        assert!(!pin.matches(&f, (7, 10)));
        assert!(!pin.matches(&f, (8, 9)));
        let mut moved = f;
        moved.ino = 3;
        assert!(!pin.matches(&moved, (7, 9)));
    }

    // 이것을 실패시키는 것: to_bytes가 ctime을 쓰지 않거나 from_bytes가 버리는 것, 전부 0을 Some으로
    // 읽는 것, 예약 바이트·나노초 범위 검사를 지우는 것.
    #[test]
    fn exec_pin_bytes() {
        let f = file(ME, 0o775);
        let pin = target_pin(&f, &[GroupPin::of(&f)], (-5, 999_999_999)).unwrap();
        let b = ExecPin::to_bytes(Some(pin));
        assert_eq!(ExecPin::from_bytes(&b), Ok(Some(pin)));
        assert_eq!(ExecPin::from_bytes(&ExecPin::to_bytes(None)), Ok(None));
        let mut bad = b;
        bad[39] = 1;
        assert_eq!(ExecPin::from_bytes(&bad), Err(Error::Flags));
        let mut bad = b;
        bad[32..36].copy_from_slice(&1_000_000_000u32.to_le_bytes());
        assert_eq!(ExecPin::from_bytes(&bad), Err(Error::Flags));
    }

    fn script<'a>(interpreter: &'a [u8], arg: Option<&'a [u8]>) -> Head<'a> {
        Head::Script(Shebang { interpreter, arg })
    }

    // 이것을 실패시키는 것: head의 `#!` 판별을 지우는 것(네이티브가 스크립트로), 공백·탭 자르기를 한쪽이라도
    // 지우는 것(인터프리터나 인자에 공백이 남음), 인자 하나 대신 공백마다 나누는 것.
    #[test]
    fn shebang_splits_like_the_kernel() {
        assert_eq!(head(b"\x7fELF\x02\x01"), Head::Native);
        assert_eq!(head(b""), Head::Native);
        assert_eq!(head(b"#"), Head::Native);
        assert_eq!(head(b"#!/bin/sh\necho 1\n"), script(b"/bin/sh", None));
        assert_eq!(
            head(b"#! \t/bin/bash \t-e -u \t\nx"),
            script(b"/bin/bash", Some(b"-e -u"))
        );
        assert_eq!(head(b"#!/bin/sh   \n"), script(b"/bin/sh", None));
    }

    // 이것을 실패시키는 것: 줄바꿈 없이 SHEBANG_MAX를 채운 머리를 거부하는 분기를 지우는 것(잘린
    // 인터프리터로 실행), 또는 그보다 짧은 머리(파일 끝)까지 거부하는 것.
    #[test]
    fn shebang_needs_its_line_within_the_kernel_buffer() {
        let mut long = b"#!/bin/sh ".to_vec();
        long.resize(SHEBANG_MAX, b'a');
        assert_eq!(head(&long), Head::Refused);
        long.pop();
        assert!(matches!(head(&long), Head::Script(_)));
        assert_eq!(head(b"#!/bin/sh"), script(b"/bin/sh", None));
    }

    // test_env_shebang_refused의 core 짝. 이것을 실패시키는 것: 절대 경로 검사를 지우는 것(상대·빈
    // 인터프리터가 통과), `/usr/bin/env` 거부를 지우는 것.
    #[test]
    fn shebang_refuses_relative_and_env() {
        for line in [
            &b"#!sh\n"[..],
            b"#!\n",
            b"#!  \n",
            b"#!./x\n",
            b"#!/usr/bin/env sh\n",
            b"#! /usr/bin/env\n",
        ] {
            assert_eq!(head(line), Head::Refused, "{line:?}");
        }
        assert_eq!(head(b"#!/usr/bin/envx\n"), script(b"/usr/bin/envx", None));
    }
}
