//! Who may change a file or folder: the pure rules of spec section 2
//! (`extends` safety row) and section 4 ("runtime root" 2), over facts the
//! caller observed through an open descriptor (`fstat`, the ACL, the file
//! system). The same functions serve `init` (the executable path and the
//! roots it pins), the refresh helper and the prompt front end (N4), so the
//! three cannot disagree about one folder.
//!
//! Group write is allowed only when every member of the group is root or
//! the current user. Answering that needs the system's group database,
//! which this crate cannot read: the caller passes a `GroupOracle`. What a
//! caller may ask differs by place (Task R1 ruling P-R1): `init` and the
//! helper ask the system, the prompt front end cannot.

/// Worse verdicts compare greater: Safe < Unknown < Tamperable.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Verdict {
    Safe,
    Unknown,
    Tamperable,
}

/// Members of a group, as far as the system could tell.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Group {
    OnlyRootAndUser,
    HasOthers,
    Unknown,
}

/// The extended ACL of one entry, folded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AclFacts {
    None,
    DenyOnly,
    AllowsWrite,
    Unknown,
    /// Linux: an extended POSIX access ACL exists. The mode's group bits
    /// are then its mask, the upper bound of every named user and group
    /// entry (X-28): with no group write nobody named can write, and with
    /// group write a named entry may, whatever the owning group's members.
    PosixExtended,
}

/// One extended ACL entry as read on macOS.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AclEntry {
    /// `writes`: grants write, append, delete, delete-child, attribute,
    /// extended-attribute, security or ownership change.
    Allow {
        writes: bool,
    },
    Deny,
}

/// Folds the entries of one ACL. `Err` marks an ACL call that failed or an
/// entry of a kind we do not know; the ACL then counts as unread (fail
/// closed), unless an earlier entry already allowed writing.
pub fn fold_acl(entries: impl IntoIterator<Item = Result<AclEntry, ()>>) -> AclFacts {
    let mut facts = AclFacts::None;
    for e in entries {
        match e {
            Err(()) => return AclFacts::Unknown,
            Ok(AclEntry::Allow { writes: true }) => return AclFacts::AllowsWrite,
            Ok(AclEntry::Allow { writes: false }) => {}
            Ok(AclEntry::Deny) => facts = AclFacts::DenyOnly,
        }
    }
    facts
}

/// What `fstat` (and the ACL read) gave for one entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Facts {
    /// `(st_dev, st_ino)`: which folder or file, for answers pinned to it.
    pub dev: u64,
    pub ino: u64,
    pub uid: u32,
    pub gid: u32,
    /// `st_mode` (type bits included).
    pub mode: u32,
    pub acl: AclFacts,
    /// Whether the mount enforces ownership (unknown is not safe).
    pub ownership: Option<bool>,
}

const S_ISVTX: u32 = 0o1000;
const GROUP_WRITE: u32 = 0o020;
const OTHER_WRITE: u32 = 0o002;

/// Answers "may this group's members change files" for a group-writable
/// entry. `at` is the entry, so an answer may be pinned to it (P-R1).
pub trait GroupOracle {
    fn group_write(&mut self, at: &Facts) -> Group;
}

/// A group-writable folder `init` cleared (its group's members were root
/// and the user when `init` asked), pinned to the folder and its mode
/// (ruling P-R1, spec change S-8).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GroupPin {
    pub dev: u64,
    pub ino: u64,
    pub gid: u32,
    pub mode: u32,
}

impl GroupPin {
    pub fn of(f: &Facts) -> Self {
        Self {
            dev: f.dev,
            ino: f.ino,
            gid: f.gid,
            mode: f.mode,
        }
    }
}

/// The prompt front end's oracle: it cannot ask the group database, so a
/// group-writable folder passes only when it is one `init` cleared, with
/// the same identity, group and mode. Members who join later are caught by
/// the refresh helper, which asks again on every walk.
pub struct PinnedGroupWrite<'a>(pub &'a [GroupPin]);

impl GroupOracle for PinnedGroupWrite<'_> {
    fn group_write(&mut self, at: &Facts) -> Group {
        if self.0.contains(&GroupPin::of(at)) {
            Group::OnlyRootAndUser
        } else {
            Group::HasOthers
        }
    }
}

/// An oracle that never asks: group write is refused (spec section 4
/// "runtime root" 2 as written).
pub struct RefuseGroupWrite;

impl GroupOracle for RefuseGroupWrite {
    fn group_write(&mut self, _: &Facts) -> Group {
        Group::HasOthers
    }
}

/// The rule for one entry: owned by root or `me`, nobody else can write it
/// (other write, group write unless the oracle clears the group, an ACL that
/// allows writing). `is_symlink`: a symlink's own mode bits are not used.
pub fn entry_verdict(
    f: &Facts,
    me: u32,
    is_symlink: bool,
    groups: &mut dyn GroupOracle,
) -> Verdict {
    if f.ownership != Some(true) {
        return Verdict::Unknown;
    }
    if f.uid != 0 && f.uid != me {
        return Verdict::Tamperable;
    }
    let acl = match f.acl {
        AclFacts::AllowsWrite => Verdict::Tamperable,
        AclFacts::Unknown => Verdict::Unknown,
        // The group oracle answers for the owning group only; named
        // entries under a writable mask are not covered.
        AclFacts::PosixExtended if !is_symlink && f.mode & GROUP_WRITE != 0 => Verdict::Unknown,
        AclFacts::None | AclFacts::DenyOnly | AclFacts::PosixExtended => Verdict::Safe,
    };
    if is_symlink {
        return acl;
    }
    let mode = if f.mode & OTHER_WRITE != 0 {
        Verdict::Tamperable
    } else if f.mode & GROUP_WRITE != 0 {
        match groups.group_write(f) {
            Group::OnlyRootAndUser => Verdict::Safe,
            Group::HasOthers => Verdict::Tamperable,
            Group::Unknown => Verdict::Unknown,
        }
    } else {
        Verdict::Safe
    };
    mode.max(acl)
}

/// Why a walk was refused, and where (index into the chain).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// An ancestor someone else can change (`entry_verdict` Tamperable).
    Ancestor { at: usize },
    /// An ancestor whose rule could not be decided (ACL or group unknown).
    Undecided { at: usize },
    /// A root-owned sticky folder whose next name is not owned by `me`.
    StickyNext { at: usize },
    /// The last entry fails `Last`: it is not owned by `me`, not exactly
    /// 0700 for `PrivateFolder`, or not safe under the entry rule for `Mine`.
    Last,
    /// The last entry is not on a local file system, or that is unknown.
    NotLocal,
}

/// What the last entry of a walk must be.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Last {
    /// A private folder: owned by `me`, mode exactly 0700, no ACL that
    /// allows writing (runtime root).
    PrivateFolder,
    /// A file or folder `me` owns that nobody else can write (a config
    /// file, spec section 2 safety row; the state root). Group write
    /// follows the oracle.
    Mine,
}

/// Spec section 4 "runtime root" 2, over the chain the walk opened: `/`,
/// each folder below it, and the last entry. Every ancestor follows
/// `entry_verdict`, with one exception: a root-owned sticky folder (`/tmp`)
/// that others can write passes when the next name is owned by `me`. The
/// last entry follows `last`; `local` is the file system answer for it.
pub fn walk_verdict(
    chain: &[Facts],
    me: u32,
    last: Last,
    local: Option<bool>,
    groups: &mut dyn GroupOracle,
) -> Result<(), Refusal> {
    let Some((tail, ancestors)) = chain.split_last() else {
        return Err(Refusal::Last);
    };
    let mut next = NextOwner::Any;
    for (i, f) in ancestors.iter().enumerate() {
        next = ancestor_verdict(f, me, i, next, groups)?;
    }
    final_verdict(tail, me, ancestors.len(), next, last, local, groups)
}

/// A root-owned sticky ancestor can be traversed, but its next entry must
/// belong to the user. This obligation survives the observation boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NextOwner {
    Any,
    Mine { parent: usize },
}

fn check_next(f: &Facts, me: u32, next: NextOwner) -> Result<(), Refusal> {
    if let NextOwner::Mine { parent } = next
        && f.uid != me
    {
        return Err(Refusal::StickyNext { at: parent });
    }
    Ok(())
}

/// N4: check a non-final folder before requesting the next open. `/` is
/// an ancestor, never a private runtime root. Return the next-owner duty.
pub fn ancestor_verdict(
    f: &Facts,
    me: u32,
    at: usize,
    next: NextOwner,
    groups: &mut dyn GroupOracle,
) -> Result<NextOwner, Refusal> {
    check_next(f, me, next)?;
    if f.ownership != Some(true) {
        return Err(Refusal::Undecided { at });
    }
    let sticky_ok = f.uid == 0 && f.mode & S_ISVTX != 0;
    if sticky_ok && f.mode & (OTHER_WRITE | GROUP_WRITE) != 0 {
        match f.acl {
            AclFacts::None | AclFacts::DenyOnly | AclFacts::PosixExtended => {
                return Ok(NextOwner::Mine { parent: at });
            }
            AclFacts::AllowsWrite => return Err(Refusal::Ancestor { at }),
            AclFacts::Unknown => return Err(Refusal::Undecided { at }),
        }
    }
    match entry_verdict(f, me, false, groups) {
        Verdict::Safe => Ok(NextOwner::Any),
        Verdict::Unknown => Err(Refusal::Undecided { at }),
        Verdict::Tamperable => Err(Refusal::Ancestor { at }),
    }
}

/// N4: only the final observation is checked for ownership and 0700.
pub fn final_verdict(
    tail: &Facts,
    me: u32,
    at: usize,
    next: NextOwner,
    last: Last,
    local: Option<bool>,
    groups: &mut dyn GroupOracle,
) -> Result<(), Refusal> {
    check_next(tail, me, next)?;
    if tail.ownership != Some(true) {
        return Err(Refusal::Undecided { at });
    }
    let own = tail.uid == me;
    let ok = match last {
        Last::PrivateFolder => {
            own && tail.mode & 0o7777 == 0o700
                && matches!(
                    tail.acl,
                    AclFacts::None | AclFacts::DenyOnly | AclFacts::PosixExtended
                )
        }
        Last::Mine => {
            let verdict = entry_verdict(tail, me, false, groups);
            if own && verdict == Verdict::Unknown {
                return Err(Refusal::Undecided { at });
            }
            own && verdict == Verdict::Safe
        }
    };
    if !ok {
        return Err(Refusal::Last);
    }
    match local {
        Some(true) => Ok(()),
        _ => Err(Refusal::NotLocal),
    }
}

/// macOS `statfs.f_flags` bit for a local file system (`MNT_LOCAL`,
/// <sys/mount.h>).
pub const MNT_LOCAL: u32 = 0x0000_1000;
pub const MNT_IGNORE_OWNERSHIP: u32 = 0x0020_0000;

/// Locality and permission enforcement are independent observations.
pub fn macos_ownership_enforced(flags: u32) -> bool {
    flags & MNT_IGNORE_OWNERSHIP == 0
}

/// Linux file systems that count as local (spec section 3 state file
/// location: an `f_type` allowlist, FUSE refused). Network and FUSE file
/// systems, and any type not on this list, are not local. Read-only local
/// file systems (squashfs for snaps and AppImages, erofs, iso9660) are on
/// the list: the executable path check uses the same answer, and a binary
/// there is local. The numbers are `<linux/magic.h>` (Debian 12
/// `linux-libc-dev`) and `libc` 0.2.190, except zfs (OpenZFS's
/// `ZFS_SUPER_MAGIC`, not in either).
pub const LINUX_LOCAL_TYPES: [(u64, &str); 19] = [
    (0x0102_1994, "tmpfs"),
    (0x8584_58f6, "ramfs"),
    (0x0000_ef53, "ext2/3/4"),
    (0x9123_683e, "btrfs"),
    (0x5846_5342, "xfs"),
    (0xf2f5_2010, "f2fs"),
    (0x2fc1_2fc1, "zfs"),
    (0xca45_1a4e, "bcachefs"),
    (0x794c_7630, "overlayfs"),
    (0x5265_4973, "reiserfs"),
    (0x0000_3434, "nilfs2"),
    (0x0000_f15f, "ecryptfs"),
    (0x7371_7368, "squashfs"),
    (0xe0f5_e1e2, "erofs"),
    (0x0000_9660, "iso9660"),
    (0x28cd_3d45, "cramfs"),
    (0x1501_3346, "udf"),
    (0x0000_4d44, "vfat"),
    (0x2011_bab0, "exfat"),
];

/// Linux: whether `statfs.f_type` names a local file system.
pub fn linux_fs_is_local(f_type: u64) -> bool {
    LINUX_LOCAL_TYPES.iter().any(|(t, _)| *t == f_type)
}

/// macOS: whether `statfs.f_flags` has `MNT_LOCAL`.
pub fn macos_fs_is_local(f_flags: u32) -> bool {
    f_flags & MNT_LOCAL != 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;

    const ME: u32 = 501;
    const DIR: u32 = 0o040_000;

    fn f(uid: u32, mode: u32) -> Facts {
        Facts {
            dev: 1,
            ino: 0,
            uid,
            gid: 20,
            mode: DIR | mode,
            acl: AclFacts::None,
            ownership: Some(true),
        }
    }

    struct Fixed(Group);
    impl GroupOracle for Fixed {
        fn group_write(&mut self, _: &Facts) -> Group {
            self.0
        }
    }

    // 이것을 실패시키는 것: ACL 호출 오류나 모르는 항목을 "항목 없음"으로 읽는 것(fail-open).
    #[test]
    fn acl_errors_are_unknown() {
        use AclEntry::{Allow, Deny};
        let rows: &[(&[Result<AclEntry, ()>], AclFacts)] = &[
            (&[], AclFacts::None),
            (&[Ok(Deny)], AclFacts::DenyOnly),
            (&[Ok(Allow { writes: false })], AclFacts::None),
            (
                &[Ok(Deny), Ok(Allow { writes: true })],
                AclFacts::AllowsWrite,
            ),
            (&[Err(())], AclFacts::Unknown),
            (&[Ok(Deny), Err(())], AclFacts::Unknown),
            (&[Ok(Allow { writes: false }), Err(())], AclFacts::Unknown),
            (
                &[Ok(Allow { writes: true }), Err(())],
                AclFacts::AllowsWrite,
            ),
        ];
        for (entries, want) in rows {
            assert_eq!(fold_acl(entries.iter().copied()), *want, "{entries:?}");
        }
    }

    // M1 Task A7 표 그대로(init 실행 파일 경로)와 Linux POSIX ACL 두 행. 이것을 실패시키는 것: 표의 어느 한 행이라도
    // 다르게 판정하는 것(특히 그룹 쓰기 mask 아래의 이름 붙은 ACL 항목을 그룹 구성원 판정으로 통과시키는 것).
    #[test]
    fn entry_rule_table() {
        use AclFacts as A;
        use Group as G;
        use Verdict as V;
        let e = |uid, mode, acl| Facts {
            dev: 1,
            ino: 0,
            uid,
            gid: 80,
            mode,
            acl,
            ownership: Some(true),
        };
        let rows: &[(Facts, bool, G, V, &str)] = &[
            (e(ME, 0o755, A::None), false, G::Unknown, V::Safe, "own"),
            (e(0, 0o755, A::None), false, G::Unknown, V::Safe, "root"),
            (
                e(502, 0o755, A::None),
                false,
                G::OnlyRootAndUser,
                V::Tamperable,
                "other owner",
            ),
            (
                e(ME, 0o757, A::None),
                false,
                G::OnlyRootAndUser,
                V::Tamperable,
                "o+w",
            ),
            (
                e(ME, 0o775, A::None),
                false,
                G::OnlyRootAndUser,
                V::Safe,
                "g+w, root+user",
            ),
            (
                e(ME, 0o775, A::None),
                false,
                G::HasOthers,
                V::Tamperable,
                "g+w, others",
            ),
            (
                e(ME, 0o775, A::None),
                false,
                G::Unknown,
                V::Unknown,
                "g+w, unknown",
            ),
            (
                e(ME, 0o777, A::None),
                true,
                G::HasOthers,
                V::Safe,
                "symlink mode ignored",
            ),
            (
                e(502, 0o755, A::None),
                true,
                G::OnlyRootAndUser,
                V::Tamperable,
                "symlink of other",
            ),
            (
                e(ME, 0o755, A::AllowsWrite),
                false,
                G::OnlyRootAndUser,
                V::Tamperable,
                "ACL write",
            ),
            (
                e(ME, 0o755, A::DenyOnly),
                false,
                G::OnlyRootAndUser,
                V::Safe,
                "ACL deny only",
            ),
            (
                e(ME, 0o755, A::Unknown),
                false,
                G::OnlyRootAndUser,
                V::Unknown,
                "ACL unread",
            ),
            (
                e(ME, 0o775, A::Unknown),
                false,
                G::HasOthers,
                V::Tamperable,
                "worst wins",
            ),
            (
                e(ME, 0o775, A::PosixExtended),
                false,
                G::OnlyRootAndUser,
                V::Unknown,
                "POSIX ACL under a writable mask",
            ),
            (
                e(ME, 0o755, A::PosixExtended),
                false,
                G::OnlyRootAndUser,
                V::Safe,
                "POSIX ACL, mask without write",
            ),
            (
                e(ME, 0o777, A::PosixExtended),
                true,
                G::HasOthers,
                V::Safe,
                "symlink ignores POSIX mask bits",
            ),
        ];
        for (facts, link, g, want, why) in rows {
            assert_eq!(
                entry_verdict(facts, ME, *link, &mut Fixed(*g)),
                *want,
                "{why}"
            );
        }
    }

    fn walk(chain: &[Facts], g: Group) -> Result<(), Refusal> {
        walk_verdict(chain, ME, Last::PrivateFolder, Some(true), &mut Fixed(g))
    }

    // 스펙 4절 "런타임 뿌리"의 경로 판정 예 다섯과 ACL 벡터 둘(보안 I6).
    // 이것을 실패시키는 것: sticky 예외를 빼거나 넓히는 것, 그 바로 아래 소유자를 보지 않는 것, 그룹 쓰기를 묻지 않고
    // 통과시키는 것, 마지막 폴더의 0700·소유자·로컬을 보지 않는 것, allow ACL을 통과시키거나 deny ACL을 거부하는 것.
    #[test]
    fn spec_path_vectors() {
        let root = f(0, 0o755);
        // /run/user/<uid>/bingsu
        let run_user = [root, f(0, 0o755), f(0, 0o755), f(ME, 0o700), f(ME, 0o700)];
        assert_eq!(walk(&run_user, Group::HasOthers), Ok(()));
        // /private/var/folders/xx/yyy/T/bingsu: root and me, nobody else writes.
        let folders = [
            root,
            f(0, 0o755),
            f(0, 0o755),
            f(0, 0o755),
            f(ME, 0o755),
            f(ME, 0o700),
            f(ME, 0o700),
            f(ME, 0o700),
        ];
        assert_eq!(walk(&folders, Group::HasOthers), Ok(()));
        // /tmp/<mine>/bingsu: the sticky exception.
        let tmp = [root, f(0, 0o1777), f(ME, 0o755), f(ME, 0o700)];
        assert_eq!(walk(&tmp, Group::HasOthers), Ok(()));
        assert_eq!(
            walk(&[root, f(0, 0o777), f(ME, 0o700)], Group::HasOthers),
            Err(Refusal::Ancestor { at: 1 })
        );
        assert_eq!(
            walk(&[root, f(0, 0o1770), f(ME, 0o700)], Group::HasOthers),
            Ok(())
        );
        let mut acl_tmp = tmp;
        acl_tmp[1].acl = AclFacts::AllowsWrite;
        assert_eq!(
            walk(&acl_tmp, Group::HasOthers),
            Err(Refusal::Ancestor { at: 1 })
        );
        acl_tmp[1].acl = AclFacts::Unknown;
        assert_eq!(
            walk(&acl_tmp, Group::HasOthers),
            Err(Refusal::Undecided { at: 1 })
        );
        for acl in [AclFacts::DenyOnly, AclFacts::PosixExtended] {
            acl_tmp[1].acl = acl;
            assert_eq!(walk(&acl_tmp, Group::HasOthers), Ok(()));
        }
        // The name right below the sticky folder is root's or another user's.
        for owner in [0, 502] {
            let bad = [root, f(0, 0o1777), f(owner, 0o755), f(ME, 0o700)];
            assert_eq!(
                walk(&bad, Group::HasOthers),
                Err(Refusal::StickyNext { at: 1 })
            );
        }
        // A sticky folder owned by someone else is no exception.
        let not_root = [root, f(502, 0o1777), f(ME, 0o755), f(ME, 0o700)];
        assert_eq!(
            walk(&not_root, Group::OnlyRootAndUser),
            Err(Refusal::Ancestor { at: 1 })
        );
        // ~/.cache/bingsu/run with a group-writable home: refused unless the
        // oracle clears the group.
        let gw_home = [
            root,
            f(0, 0o755),
            f(ME, 0o775),
            f(ME, 0o700),
            f(ME, 0o700),
            f(ME, 0o700),
        ];
        assert_eq!(
            walk(&gw_home, Group::HasOthers),
            Err(Refusal::Ancestor { at: 2 })
        );
        assert_eq!(
            walk(&gw_home, Group::Unknown),
            Err(Refusal::Undecided { at: 2 })
        );
        assert_eq!(walk(&gw_home, Group::OnlyRootAndUser), Ok(()));
        // ~/.cache/bingsu/run on a network home.
        let home = [
            root,
            f(0, 0o755),
            f(ME, 0o755),
            f(ME, 0o700),
            f(ME, 0o700),
            f(ME, 0o700),
        ];
        for local in [Some(false), None] {
            let got = walk_verdict(&home, ME, Last::PrivateFolder, local, &mut RefuseGroupWrite);
            assert_eq!(got, Err(Refusal::NotLocal), "{local:?}");
        }
        // The last folder: mine and exactly 0700.
        for last in [f(ME, 0o755), f(ME, 0o2700), f(502, 0o700)] {
            assert_eq!(
                walk(&[root, last], Group::OnlyRootAndUser),
                Err(Refusal::Last)
            );
        }
        for acl in [AclFacts::AllowsWrite, AclFacts::Unknown] {
            let mut last = f(ME, 0o700);
            last.acl = acl;
            assert_eq!(walk(&[root, last], Group::HasOthers), Err(Refusal::Last));
        }
        for acl in [AclFacts::DenyOnly, AclFacts::PosixExtended] {
            let mut last = f(ME, 0o700);
            last.acl = acl;
            assert_eq!(walk(&[root, last], Group::HasOthers), Ok(()));
        }
        // ACL vectors: an allow ACL that grants writing to others refuses the
        // folder; the home folder's `everyone deny delete` passes.
        let mut allow = f(ME, 0o755);
        allow.acl = AclFacts::AllowsWrite;
        assert_eq!(
            walk(&[root, allow, f(ME, 0o700)], Group::HasOthers),
            Err(Refusal::Ancestor { at: 1 })
        );
        let mut deny = f(ME, 0o750);
        deny.acl = AclFacts::DenyOnly;
        assert_eq!(walk(&[root, deny, f(ME, 0o700)], Group::HasOthers), Ok(()));
        let mut unread = f(ME, 0o755);
        unread.acl = AclFacts::Unknown;
        assert_eq!(
            walk(&[root, unread, f(ME, 0o700)], Group::HasOthers),
            Err(Refusal::Undecided { at: 1 })
        );
        assert_eq!(walk(&[], Group::HasOthers), Err(Refusal::Last));
    }

    // 판정 P-R1(S-8): 앞단은 init이 확인해 기록한 그룹 쓰기 폴더만 받는다. 같은 폴더·gid·mode일 때만.
    // 이것을 실패시키는 것: 기록과 견주지 않고 그룹 쓰기를 받는 것, 폴더 정체나 mode를 견주지 않는 것.
    #[test]
    fn the_front_end_takes_only_pinned_group_write() {
        let root = f(0, 0o755);
        let mut home = f(ME, 0o775);
        home.ino = 42;
        let chain = [root, home, f(ME, 0o700)];
        let pins = [GroupPin::of(&home)];
        let w = |c: &[Facts], p: &[GroupPin]| {
            walk_verdict(
                c,
                ME,
                Last::PrivateFolder,
                Some(true),
                &mut PinnedGroupWrite(p),
            )
        };
        assert_eq!(w(&chain, &pins), Ok(()));
        assert_eq!(w(&chain, &[]), Err(Refusal::Ancestor { at: 1 }));
        let mut moved = home;
        moved.ino = 43;
        assert_eq!(
            w(&[root, moved, f(ME, 0o700)], &pins),
            Err(Refusal::Ancestor { at: 1 })
        );
        let mut remounted = home;
        remounted.dev = 2;
        assert_eq!(
            w(&[root, remounted, f(ME, 0o700)], &pins),
            Err(Refusal::Ancestor { at: 1 })
        );
        let mut regrouped = home;
        regrouped.gid = 21;
        assert_eq!(
            w(&[root, regrouped, f(ME, 0o700)], &pins),
            Err(Refusal::Ancestor { at: 1 })
        );
        let mut opened = home;
        opened.mode = DIR | 0o770;
        assert_eq!(
            w(&[root, opened, f(ME, 0o700)], &pins),
            Err(Refusal::Ancestor { at: 1 })
        );
    }

    // 설정 파일(스펙 2절 안전 행): 내 파일이고 남이 못 쓴다. 그룹 쓰기는 구성원 판정.
    // 이것을 실패시키는 것: 파일의 그룹·다른 사용자 쓰기를 보지 않는 것, root 소유 파일을 내 파일로 보는 것.
    #[test]
    fn config_files_are_mine_and_closed() {
        let root = f(0, 0o755);
        let file = |uid: u32, mode: u32| Facts {
            dev: 1,
            ino: 0,
            uid,
            gid: 20,
            mode: 0o100_000 | mode,
            acl: AclFacts::None,
            ownership: Some(true),
        };
        let w = |c: &[Facts], g| walk_verdict(c, ME, Last::Mine, Some(true), &mut Fixed(g));
        assert_eq!(
            w(&[root, f(ME, 0o755), file(ME, 0o644)], Group::HasOthers),
            Ok(())
        );
        assert_eq!(
            w(
                &[root, f(ME, 0o755), file(ME, 0o664)],
                Group::OnlyRootAndUser
            ),
            Ok(())
        );
        assert_eq!(
            w(&[root, file(ME, 0o664)], Group::Unknown),
            Err(Refusal::Undecided { at: 1 })
        );
        let refused: Vec<Facts> = vec![
            file(ME, 0o664),
            file(ME, 0o646),
            file(0, 0o644),
            file(502, 0o600),
        ];
        for last in refused {
            assert_eq!(
                w(&[root, f(ME, 0o755), last], Group::HasOthers),
                Err(Refusal::Last),
                "{last:?}"
            );
        }
    }

    // 이것을 실패시키는 것: 목록 밖 f_type을 로컬로 보는 것(FUSE·NFS·CIFS), tmpfs·ext4나 읽기 전용 로컬(squashfs)·
    // 암호화 홈(ecryptfs)을 로컬이 아니라고 보는 것(실행 파일 경로 검사의 거짓 경고), MNT_LOCAL 비트를 보지 않는 것.
    #[test]
    fn local_file_systems() {
        for magic in [
            0x0102_1994,
            0x8584_58f6,
            0xef53,
            0x9123_683e,
            0x5846_5342,
            0xf2f5_2010,
            0x2fc1_2fc1,
            0xca45_1a4e,
            0x794c_7630,
            0x5265_4973,
            0x3434,
            0xf15f,
            0x7371_7368,
            0xe0f5_e1e2,
            0x9660,
            0x28cd_3d45,
            0x1501_3346,
            0x4d44,
            0x2011_bab0,
        ] {
            assert!(linux_fs_is_local(magic), "{magic:x}");
        }
        assert!(linux_fs_is_local(0x0102_1994));
        assert!(linux_fs_is_local(0xef53));
        assert!(!linux_fs_is_local(0x6573_5546)); // FUSE
        assert!(!linux_fs_is_local(0x6969)); // NFS
        assert!(!linux_fs_is_local(0xff53_4d42)); // CIFS
        assert!(!linux_fs_is_local(0xfe53_4d42)); // SMB2
        assert!(linux_fs_is_local(0x7371_7368)); // squashfs (snap, AppImage)
        assert!(linux_fs_is_local(0xf15f)); // ecryptfs (encrypted home)
        assert!(macos_fs_is_local(MNT_LOCAL | 1));
        assert!(!macos_fs_is_local(1));
    }
    // 이것을 실패시키는 것: 소유권 집행이 꺼졌거나 미확인인 항목·sticky 조상·마지막 항목을 안전으로 보는 것.
    #[test]
    fn ownership_ignored_is_undecidable_everywhere() {
        assert!(macos_fs_is_local(MNT_LOCAL | MNT_IGNORE_OWNERSHIP));
        assert!(!macos_ownership_enforced(MNT_LOCAL | MNT_IGNORE_OWNERSHIP));
        assert!(macos_ownership_enforced(MNT_LOCAL));
        for ownership in [None, Some(false)] {
            let mut bad = f(ME, 0o700);
            bad.ownership = ownership;
            assert_eq!(
                entry_verdict(&bad, ME, false, &mut RefuseGroupWrite),
                Verdict::Unknown
            );
            for last in [Last::Mine, Last::PrivateFolder] {
                assert_eq!(
                    walk_verdict(
                        &[f(0, 0o755), bad],
                        ME,
                        last,
                        Some(true),
                        &mut RefuseGroupWrite
                    ),
                    Err(Refusal::Undecided { at: 1 })
                );
            }
            bad.uid = 0;
            bad.mode = DIR | 0o1777;
            assert_eq!(
                walk(&[bad, f(ME, 0o700)], Group::HasOthers),
                Err(Refusal::Undecided { at: 0 })
            );
        }
    }

    // 이것을 실패시키는 것: 조상에 마지막 0700 규칙을 적용하거나 sticky 다음 소유자 의무를 버리는 것.
    #[test]
    fn staged_walk_checks_ancestors_then_final_and_carries_sticky() {
        let mut g = RefuseGroupWrite;
        assert_eq!(
            ancestor_verdict(&f(0, 0o1755), ME, 0, NextOwner::Any, &mut g),
            Ok(NextOwner::Any)
        );
        let next = ancestor_verdict(&f(0, 0o755), ME, 0, NextOwner::Any, &mut g).unwrap();
        let next = ancestor_verdict(&f(0, 0o1777), ME, 1, next, &mut g).unwrap();
        assert_eq!(next, NextOwner::Mine { parent: 1 });
        assert_eq!(
            ancestor_verdict(&f(502, 0o755), ME, 2, next, &mut g),
            Err(Refusal::StickyNext { at: 1 })
        );
        assert_eq!(
            final_verdict(
                &f(502, 0o700),
                ME,
                2,
                next,
                Last::PrivateFolder,
                Some(true),
                &mut g
            ),
            Err(Refusal::StickyNext { at: 1 })
        );
        assert_eq!(
            final_verdict(
                &f(ME, 0o700),
                ME,
                2,
                next,
                Last::PrivateFolder,
                Some(true),
                &mut g
            ),
            Ok(())
        );
        assert_eq!(
            final_verdict(
                &f(ME, 0o755),
                ME,
                2,
                next,
                Last::PrivateFolder,
                Some(true),
                &mut g
            ),
            Err(Refusal::Last)
        );
        assert_eq!(
            ancestor_verdict(&f(ME, 0o777), ME, 2, NextOwner::Any, &mut g),
            Err(Refusal::Ancestor { at: 2 })
        );
    }
}
