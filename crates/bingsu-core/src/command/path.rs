//! Sanitized `PATH` and executable lookup (spec section 4 "user command
//! execution model", rows environment and executable lookup; section 2
//! safety row for group write). Pure rules over the strings and the facts
//! the helper observed through open descriptors; the walk itself is the
//! CLI's `exec_path`.
use crate::fs_trust::{Facts, GroupOracle, GroupPin, NextOwner, Verdict, entry_verdict};
use alloc::vec::Vec;

/// `PATH` entries worth resolving, in order: empty and relative entries
/// (".", "bin") are dropped, because they name folders relative to a
/// working folder the shell chose (spec: relative and empty entries excluded).
pub fn entries(path: &[u8]) -> impl Iterator<Item = &[u8]> {
    path.split(|&b| b == b':')
        .filter(|e| e.first() == Some(&b'/'))
}

/// Whether canonical `p` is `root` or a path below it, on a component
/// boundary (`/repo2` is not below `/repo`).
pub fn within(p: &[u8], root: &[u8]) -> bool {
    let root = match root {
        [rest @ .., b'/'] if !rest.is_empty() => rest,
        r => r,
    };
    if root == b"/" {
        return p.first() == Some(&b'/');
    }
    match p.strip_prefix(root) {
        Some(rest) => rest.is_empty() || rest.first() == Some(&b'/'),
        None => false,
    }
}

/// A resolved `PATH` folder stays when nobody else can change the way to it
/// (the walk's verdict) and it is not inside the current repository, whose
/// files whoever controls the repository chose.
pub fn keep_folder(canonical: &[u8], repo: Option<&[u8]>, walk_ok: bool) -> bool {
    walk_ok && !repo.is_some_and(|r| within(canonical, r))
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

/// The pin the relay needs for a target `candidate` accepted: present only
/// when the file is group-writable, and then only if the group oracle
/// cleared this very file (`cleared` is what `Recording` kept). An ACL is
/// not in the pin: only the file's owner (root or the user, which
/// `entry_verdict` checked) or a holder of CAP_FOWNER can change it, and
/// both are trusted.
pub fn target_pin(f: &Facts, cleared: &[GroupPin]) -> Option<GroupPin> {
    let pin = GroupPin::of(f);
    (f.mode & 0o020 != 0 && cleared.contains(&pin)).then_some(pin)
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

    // 이것을 실패시키는 것: within의 구성 요소 경계 검사를 지우는 것(`/repo2`가 `/repo` 안으로
    // 보임), 또는 keep_folder의 저장소 검사를 지우는 것.
    #[test]
    fn repo_folders_are_dropped_on_component_boundaries() {
        assert!(within(b"/w/repo", b"/w/repo"));
        assert!(within(b"/w/repo/bin", b"/w/repo"));
        assert!(within(b"/w/repo/bin", b"/w/repo/"));
        assert!(!within(b"/w/repo2/bin", b"/w/repo"));
        assert!(within(b"/usr/bin", b"/"));
        assert!(!keep_folder(b"/w/repo/bin", Some(b"/w/repo"), true));
        assert!(keep_folder(b"/w/repo2/bin", Some(b"/w/repo"), true));
        assert!(keep_folder(b"/usr/bin", None, true));
        assert!(!keep_folder(b"/usr/bin", None, false));
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
    // 또는 cleared 확인을 지우는 것(오라클이 통과시키지 않은 파일에 pin).
    #[test]
    fn pins_only_for_cleared_group_writable_targets() {
        let f = file(ME, 0o775);
        assert_eq!(target_pin(&f, &[GroupPin::of(&f)]), Some(GroupPin::of(&f)));
        assert_eq!(target_pin(&f, &[]), None);
        let mut other = f;
        other.ino = 3;
        assert_eq!(target_pin(&f, &[GroupPin::of(&other)]), None);
        let plain = file(ME, 0o755);
        assert_eq!(target_pin(&plain, &[GroupPin::of(&plain)]), None);
    }
}
