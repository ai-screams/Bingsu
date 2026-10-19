//! Group write (spec section 2 safety row, decision 6 review): a
//! group-writable entry is safe only when every member of the group is root
//! or the current user, and the members are asked again on every walk
//! (`SystemGroups` lives for one walk). A group whose members cannot be
//! confirmed (NSS, LDAP, a failed lookup) is `Unknown`, which the rules
//! treat as not safe, except the explicitly approved R-M1 private-primary
//! group rule (primary gid, matching user/group name, no listed members
//! confirmed by the files source in `/etc/group`).
//!
//! The policy (`membership`) is a pure function of what the system said, so
//! it is tested with made-up groups; `SystemGroups` asks the system through
//! `sys`. The executable path check of `init`, the runtime root walk (Task
//! R1) and the config file check (Task R3) all use it. Nothing here is
//! cached across walks: a verdict that decides whether configured commands
//! may run is never read from a cache.
use crate::commands::sys;
use bingsu_core::fs_trust::{Facts, Group, GroupOracle, GroupPin};
use std::cell::OnceCell;
use std::collections::HashMap;

/// One local account as the rule needs it (from `sys::local_users`).
#[derive(Clone, Debug)]
pub struct Account {
    pub name: Vec<u8>,
    pub gid: u32,
    /// macOS: the account's membership uuid, `None` if it could not be
    /// converted (any question about this account is then unanswered).
    #[cfg(target_os = "macos")]
    pub uuid: Option<[u8; 16]>,
}

/// The rule. `listed`: the group's supplementary members (`gr_mem`), `None`
/// if the group lookup failed. `accounts`: every local account, `None` if
/// the enumeration failed. `computed`: the system's answer to "is this
/// account a member" for groups whose members the system computes (macOS
/// `mbr_check_membership`; `Some(false)` where there is no such question).
pub fn membership(
    gid: u32,
    me: &[u8],
    listed: Option<&[Vec<u8>]>,
    accounts: Option<&[Account]>,
    computed: &mut dyn FnMut(&Account) -> Option<bool>,
) -> Group {
    let ok = |n: &[u8]| n == b"root" || n == me;
    let Some(listed) = listed else {
        return Group::Unknown;
    };
    if listed.iter().any(|m| !ok(m)) {
        return Group::HasOthers;
    }
    let Some(accounts) = accounts else {
        return Group::Unknown;
    };
    let mut verdict = Group::OnlyRootAndUser;
    for a in accounts {
        if ok(&a.name) {
            continue;
        }
        if a.gid == gid {
            return Group::HasOthers;
        }
        match computed(a) {
            Some(true) => return Group::HasOthers,
            Some(false) => {}
            // Keep looking: a member found later is worse than unknown.
            None => verdict = Group::Unknown,
        }
    }
    verdict
}

/// R-M1 candidate: the user's primary group, named after the user, with no
/// explicit members. NSS may omit members (SSSD's ignore_group_members),
/// so the files source must also confirm the empty list before accepting it.
/// Residual risk: a directory administrator assigns another account this
/// same primary gid. This exception was explicitly accepted by the user.
fn private_group_candidate(
    gid: u32,
    user: &[u8],
    primary: Option<u32>,
    group: Option<(&[u8], &[Vec<u8>])>,
) -> bool {
    primary == Some(gid) && group.is_some_and(|(name, members)| name == user && members.is_empty())
}

#[derive(Debug, PartialEq, Eq)]
struct FilesGroup {
    name: Vec<u8>,
    gid: u32,
    empty_members: bool,
}

/// Parse only well-formed `name:password:gid:members` records. In particular,
/// do not trim the member field: whitespace is not proof of an empty list.
fn parse_files_groups(text: &str) -> Vec<FilesGroup> {
    text.lines()
        .filter_map(|line| {
            let mut fields = line.split(':');
            let name = fields.next()?;
            let _password = fields.next()?;
            let gid = fields.next()?;
            let members = fields.next()?;
            if fields.next().is_some()
                || name.is_empty()
                || name.starts_with('#')
                || line.bytes().any(|b| b.is_ascii_whitespace() || b == 0)
                || !gid.bytes().all(|b| b.is_ascii_digit())
            {
                return None;
            }
            Some(FilesGroup {
                name: name.as_bytes().to_vec(),
                gid: gid.parse().ok()?,
                empty_members: members.is_empty(),
            })
        })
        .collect()
}

/// An absent/unreadable files source cannot confirm an NSS empty list.
/// Conflicting records for the same gid also leave it unconfirmed.
fn files_confirm_empty_group(gid: u32, name: &[u8], files: Option<&[FilesGroup]>) -> bool {
    let Some(files) = files else {
        return false;
    };
    let mut found = false;
    for group in files {
        if group.gid == gid {
            if group.name != name || !group.empty_members {
                return false;
            }
            found = true;
        }
    }
    found
}

/// Diagnostic text with a shell-encoded path; sanitize it before display.
pub fn undecided_remedy(path: &std::path::Path) -> String {
    let mut quoted = Vec::new();
    bingsu_core::shell_word::encode_word(
        bingsu_core::shell_word::Shell::Bash,
        path.as_os_str().as_encoded_bytes(),
        &mut quoted,
    );
    format!(
        "group membership could not be confirmed; chmod g-w {}",
        String::from_utf8_lossy(&quoted)
    )
}

/// Whether enumerating accounts sees every account (Linux). Accounts from
/// LDAP, SSSD, NIS and the like may not be enumerated (`getpwent` returns
/// only what the source lists, and SSSD lists nothing by default), so a
/// member whose primary group is the one in question could be missed. The
/// rule then cannot confirm the members and says `Unknown` (spec section 2:
/// members that cannot be confirmed are refused). Complete: the `passwd`
/// and `group` lines of `nsswitch.conf` name only `files` and `systemd`
/// (systemd's dynamic users get their own groups). No file, or no line,
/// means glibc's default, `files`. Action items (`[NOTFOUND=return]`) are
/// not sources.
#[cfg_attr(
    all(not(target_os = "linux"), not(test)),
    expect(dead_code, reason = "only Linux reads nsswitch.conf")
)]
pub fn accounts_complete(nsswitch: Option<&str>) -> bool {
    let Some(text) = nsswitch else {
        return true;
    };
    text.lines()
        .map(|l| l.split('#').next().unwrap_or(""))
        .filter_map(|l| l.split_once(':'))
        .filter(|(db, _)| matches!(db.trim(), "passwd" | "group"))
        .all(|(_, sources)| {
            let mut depth = 0;
            sources.split_whitespace().all(|w| {
                let ok = depth > 0 || w.starts_with('[') || matches!(w, "files" | "systemd");
                depth += w.matches('[').count();
                depth -= w.matches(']').count().min(depth);
                ok
            })
        })
}

/// Only a missing file selects the platform default. Unreadable or invalid
/// UTF-8 configuration cannot establish a complete account enumeration.
#[cfg_attr(
    all(not(target_os = "linux"), not(test)),
    expect(dead_code, reason = "only Linux reads nsswitch.conf")
)]
fn account_source_read_complete(read: Result<&str, std::io::ErrorKind>) -> bool {
    match read {
        Ok(text) => accounts_complete(Some(text)),
        Err(std::io::ErrorKind::NotFound) => accounts_complete(None),
        Err(_) => false,
    }
}

/// Asks the system, once per gid for the life of this value (one walk).
/// The account list is read at most once, and only if some entry is group
/// writable. The files group list (including a failed read) is read at most
/// once, and only for a candidate for the private-primary-group exception.
pub struct SystemGroups {
    me: Vec<u8>,
    accounts: OnceCell<Option<Vec<Account>>>,
    files_groups: OnceCell<Option<Vec<FilesGroup>>>,
    seen: HashMap<u32, Group>,
}

impl SystemGroups {
    pub fn new(me: &[u8]) -> Self {
        Self {
            me: me.to_vec(),
            accounts: OnceCell::new(),
            files_groups: OnceCell::new(),
            seen: HashMap::new(),
        }
    }

    pub fn gid(&mut self, gid: u32) -> Group {
        if let Some(g) = self.seen.get(&gid) {
            return *g;
        }
        let listed = sys::group_info(gid);
        let own = sys::passwd_entry(sys::current_uid());
        if self.private_group(
            gid,
            own.as_ref().filter(|p| p.name == self.me).map(|p| p.gid),
            listed
                .as_ref()
                .map(|(name, members)| (name.as_slice(), members.as_slice())),
            || std::fs::read_to_string("/etc/group"),
        ) {
            self.seen.insert(gid, Group::OnlyRootAndUser);
            return Group::OnlyRootAndUser;
        }
        let accounts = self.accounts.get_or_init(|| {
            #[cfg(target_os = "linux")]
            let complete = account_source_read_complete(
                std::fs::read_to_string("/etc/nsswitch.conf")
                    .as_deref()
                    .map_err(std::io::Error::kind),
            );
            #[cfg(not(target_os = "linux"))]
            let complete = true;
            complete.then(sys::local_users).flatten()
        });

        let mut computed = sys::computed_member(gid);
        let g = membership(
            gid,
            &self.me,
            listed.as_ref().map(|(_, members)| members.as_slice()),
            accounts.as_deref(),
            &mut computed,
        );
        self.seen.insert(gid, g);
        g
    }

    fn private_group(
        &self,
        gid: u32,
        primary: Option<u32>,
        group: Option<(&[u8], &[Vec<u8>])>,
        read_files: impl FnOnce() -> std::io::Result<String>,
    ) -> bool {
        if !private_group_candidate(gid, &self.me, primary, group) {
            return false;
        }
        let files = self
            .files_groups
            .get_or_init(|| read_files().ok().map(|text| parse_files_groups(&text)));
        files_confirm_empty_group(gid, &self.me, files.as_deref())
    }
}

impl GroupOracle for SystemGroups {
    fn group_write(&mut self, at: &Facts) -> Group {
        self.gid(at.gid)
    }
}

/// Passes every question on and keeps the folders it cleared (ruling P-R1,
/// spec change S-8): `init` asks the system for the runtime root's
/// group-writable ancestors and pins the cleared ones next to the root, so
/// the prompt front end, which cannot ask, compares against them
/// (`bingsu_core::fs_trust::PinnedGroupWrite`).
pub struct Recording<'a> {
    inner: &'a mut dyn GroupOracle,
    pub cleared: Vec<GroupPin>,
}

impl<'a> Recording<'a> {
    pub fn new(inner: &'a mut dyn GroupOracle) -> Self {
        Self {
            inner,
            cleared: Vec::new(),
        }
    }
}

impl GroupOracle for Recording<'_> {
    fn group_write(&mut self, at: &Facts) -> Group {
        let g = self.inner.group_write(at);
        let pin = GroupPin::of(at);
        if g == Group::OnlyRootAndUser && !self.cleared.contains(&pin) {
            self.cleared.push(pin);
        }
        g
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn acct(name: &str, gid: u32) -> Account {
        Account {
            name: name.as_bytes().to_vec(),
            gid,
            #[cfg(target_os = "macos")]
            uuid: None,
        }
    }

    fn names(n: &[&str]) -> Vec<Vec<u8>> {
        n.iter().map(|s| s.as_bytes().to_vec()).collect()
    }

    // 그룹 조회를 가짜로 바꾼 표(followups "전제조건 없으면 passed"의 판정 논리를 DI로 고정).
    // 이것을 실패시키는 것: gr_mem의 남을 보지 않는 것, 기본 그룹이 이 gid인 남을 보지 않는 것, 시스템 판정(계산 그룹)을
    // 보지 않는 것, 조회 실패를 "남 없음"으로 보는 것, 판정 불가 뒤에 나온 남을 놓치는 것.
    #[test]
    fn membership_rule_table() {
        let me = b"me".as_slice();
        let base = [acct("root", 0), acct("me", 20)];
        let no = |_: &Account| Some(false);
        assert_eq!(
            membership(20, me, Some(&[]), Some(&base), &mut |_| None),
            Group::OnlyRootAndUser
        );
        // macOS admin = root + me (the Homebrew case): allowed.
        assert_eq!(
            membership(80, me, Some(&names(&["root", "me"])), Some(&base), &mut {
                no
            }),
            Group::OnlyRootAndUser
        );
        // A listed member who is someone else.
        assert_eq!(
            membership(80, me, Some(&names(&["root", "eve"])), Some(&base), &mut {
                no
            }),
            Group::HasOthers
        );
        // Someone whose primary group is this gid.
        let with_eve = [acct("root", 0), acct("me", 20), acct("eve", 80)];
        assert_eq!(
            membership(80, me, Some(&[]), Some(&with_eve), &mut { no }),
            Group::HasOthers
        );
        // A computed member (macOS `everyone`): gr_mem empty, nobody's
        // primary group, the system says yes.
        let other = [acct("me", 20), acct("nobody", -2i32 as u32)];
        let says = |a: &Account| Some(a.name == b"nobody");
        assert_eq!(
            membership(12, me, Some(&[]), Some(&other), &mut { says }),
            Group::HasOthers
        );
        // Lookup failures.
        assert_eq!(
            membership(80, me, None, Some(&base), &mut { no }),
            Group::Unknown
        );
        assert_eq!(
            membership(80, me, Some(&[]), None, &mut { no }),
            Group::Unknown
        );
        let unsure = |_: &Account| None;
        assert_eq!(
            membership(80, me, Some(&[]), Some(&other), &mut { unsure }),
            Group::Unknown
        );
        // Unknown first, a member later: the member wins.
        let two = [acct("x", 20), acct("eve", 80)];
        let first_unsure = |a: &Account| (a.name != b"x").then_some(false);
        assert_eq!(
            membership(80, me, Some(&[]), Some(&two), &mut { first_unsure }),
            Group::HasOthers
        );
    }

    // 네트워크 계정 출처가 있으면 계정 열거가 완전하지 않으므로 구성원을 확정할 수 없다(스펙 2절: 확정 못 하면 거부).
    // 이것을 실패시키는 것: sss·ldap·nis 출처를 완전한 열거로 보는 것, files·systemd만인 기본 설정을 불완전으로 보는 것,
    // 동작 항목([NOTFOUND=return])을 출처로 읽는 것.
    #[test]
    fn network_account_sources_leave_members_unconfirmed() {
        assert!(accounts_complete(None));
        assert!(accounts_complete(Some(
            "passwd: files systemd\ngroup: files systemd\nhosts: files dns\n"
        )));
        assert!(accounts_complete(Some(
            "passwd: files [NOTFOUND=return] systemd\n# group: sss\n"
        )));
        assert!(accounts_complete(Some(
            "passwd: files [NOTFOUND=return !UNAVAIL=continue] systemd\n"
        )));
        for bad in [
            "passwd: files sss\n",
            "group: files ldap\n",
            "passwd: compat\n",
            "group:files nis\n",
        ] {
            assert!(!accounts_complete(Some(bad)), "{bad}");
        }
    }

    // 이것을 실패시키는 것: 읽기 실패를 기본 files 출처로 보거나 읽은 네트워크 출처를 무시하는 것.
    #[test]
    fn unreadable_account_sources_are_unconfirmed() {
        use std::io::ErrorKind;
        assert!(account_source_read_complete(Err(ErrorKind::NotFound)));
        assert!(account_source_read_complete(Ok(
            "passwd: files\ngroup: systemd\n"
        )));
        assert!(!account_source_read_complete(Ok("passwd: files sss\n")));
        for error in [
            ErrorKind::PermissionDenied,
            ErrorKind::InvalidData,
            ErrorKind::Interrupted,
        ] {
            assert!(!account_source_read_complete(Err(error)));
        }
    }

    // 걷기마다 다시 묻는다: 같은 걷기 안에서는 gid마다 한 번, 새 걷기는 새로. 이것을 실패시키는 것: 판정을 걷기 밖에
    // 저장하는 것(전역 캐시), 같은 gid를 매번 다시 묻는 것.
    #[test]
    fn one_question_per_gid_per_walk() {
        let me = sys::passwd_entry(sys::current_uid()).unwrap().name;
        let mut g = SystemGroups::new(&me);
        assert!(g.accounts.get().is_none());
        assert!(g.files_groups.get().is_none());
        let gid = u32::MAX - 7; // no such group
        assert_eq!(g.gid(gid), Group::Unknown);
        assert_eq!(g.seen.len(), 1);
        assert!(g.files_groups.get().is_none());
        assert_eq!(g.gid(gid), Group::Unknown);
        assert_eq!(g.seen.len(), 1);
        // A distinct cached answer proves the second call does not ask the
        // system again (an unchanged map length alone cannot prove that).
        g.seen.insert(gid, Group::HasOthers);
        assert_eq!(g.gid(gid), Group::HasOthers);
        assert!(SystemGroups::new(&me).seen.is_empty());
    }
    // 이것을 실패시키는 것: 기본 gid·이름·빈 명시 구성원 중 하나라도 생략하거나 조회 실패를 개인 그룹으로 보는 것.
    #[test]
    fn private_group_candidate_requires_all_three_conditions() {
        assert!(private_group_candidate(
            1000,
            b"alice",
            Some(1000),
            Some((b"alice", &[]))
        ));
        assert!(!private_group_candidate(
            1000,
            b"alice",
            Some(2000),
            Some((b"alice", &[]))
        ));
        assert!(!private_group_candidate(
            1000,
            b"alice",
            None,
            Some((b"alice", &[]))
        ));
        assert!(!private_group_candidate(
            1000,
            b"alice",
            Some(1000),
            Some((b"team", &[]))
        ));
        assert!(!private_group_candidate(
            1000,
            b"alice",
            Some(1000),
            Some((b"alice", &[b"alice".to_vec()]))
        ));
        assert!(!private_group_candidate(1000, b"alice", Some(1000), None));
        assert!(!accounts_complete(Some(
            "passwd: files sss\ngroup: files sss\n"
        )));
    }

    // NSS may hide eve's supplementary membership. An absent, disagreeing,
    // or nonempty files record must not bypass incomplete SSSD enumeration.
    #[test]
    fn sssd_empty_members_need_files_confirmation() {
        let accounts = accounts_complete(Some("passwd: files sss\ngroup: files sss\n"))
            .then(|| vec![acct("alice", 1000)]);
        for files in [
            "",
            "root:x:0:\n",
            "alice:x:1000:eve\n",
            "team:x:1000:\n",
            "alice:x:2000:\n",
            "alice:x:1000:\nalice:x:1000:eve\n",
            "alice:x:1000:eve\nalice:x:1000:\n",
            "alice:x:1000:\nteam:x:1000:\n",
        ] {
            let groups = SystemGroups::new(b"alice");
            let verdict = if groups.private_group(1000, Some(1000), Some((b"alice", &[])), || {
                Ok(files.to_owned())
            }) {
                Group::OnlyRootAndUser
            } else {
                membership(1000, b"alice", Some(&[]), accounts.as_deref(), &mut |_| {
                    Some(false)
                })
            };
            assert_eq!(verdict, Group::Unknown, "files: {files:?}");
        }
    }

    #[test]
    fn confirmed_local_private_group_keeps_exception() {
        let groups = SystemGroups::new(b"alice");
        assert!(
            groups.private_group(1000, Some(1000), Some((b"alice", &[])), || {
                Ok("# local groups\nroot:x:0:\nalice:x:1000:\n".to_owned())
            })
        );
        // The exception still avoids account enumeration, even with SSSD.
        assert!(groups.accounts.get().is_none());
    }

    // Reading files is unnecessary unless every original candidate condition
    // holds, and must remain unnecessary for the prompt front end.
    #[test]
    fn files_groups_are_read_only_for_private_group_candidates() {
        let groups = SystemGroups::new(b"alice");
        for (primary, group) in [
            (None, Some((b"alice".as_slice(), [].as_slice()))),
            (Some(2000), Some((b"alice".as_slice(), [].as_slice()))),
            (Some(1000), None),
            (Some(1000), Some((b"team".as_slice(), [].as_slice()))),
            (
                Some(1000),
                Some((b"alice".as_slice(), [b"eve".to_vec()].as_slice())),
            ),
        ] {
            assert!(
                !groups.private_group(1000, primary, group, || panic!("unexpected files read"))
            );
        }
        assert!(groups.files_groups.get().is_none());
    }

    #[test]
    fn files_groups_are_read_once_per_walk() {
        let groups = SystemGroups::new(b"alice");
        assert!(
            groups.private_group(1000, Some(1000), Some((b"alice", &[])), || {
                Ok("alice:x:1000:\nalice:x:1001:\n".to_owned())
            })
        );
        assert!(
            groups.private_group(1001, Some(1001), Some((b"alice", &[])), || {
                panic!("files read more than once")
            })
        );
        let fresh = SystemGroups::new(b"alice");
        assert!(fresh.files_groups.get().is_none());
        assert!(
            !fresh.private_group(1000, Some(1000), Some((b"alice", &[])), || {
                Ok("alice:x:1000:eve\n".to_owned())
            })
        );
    }

    #[test]
    fn unreadable_files_groups_never_confirm_or_retry() {
        use std::io::ErrorKind;
        for error in [
            ErrorKind::NotFound,
            ErrorKind::PermissionDenied,
            ErrorKind::InvalidData,
            ErrorKind::Interrupted,
        ] {
            let groups = SystemGroups::new(b"alice");
            assert!(
                !groups.private_group(1000, Some(1000), Some((b"alice", &[])), || {
                    Err(error.into())
                })
            );
            assert!(
                !groups.private_group(1000, Some(1000), Some((b"alice", &[])), || {
                    panic!("failed files read retried")
                })
            );
        }
    }

    #[test]
    fn files_group_parser_preserves_identity_and_member_presence() {
        assert_eq!(
            parse_files_groups(
                "# comment\n \t# comment\n\n \t\nalice:x:1000:\r\nbob::1001:eve,root\n"
            ),
            [
                FilesGroup {
                    name: b"alice".to_vec(),
                    gid: 1000,
                    empty_members: true,
                },
                FilesGroup {
                    name: b"bob".to_vec(),
                    gid: 1001,
                    empty_members: false,
                },
            ]
        );
    }

    #[test]
    fn files_group_parser_ignores_malformed_lines() {
        for malformed in [
            "alice",
            "alice:x",
            "alice:x:1000",
            "alice:x:1000::",
            ":x:1000:",
            "#alice:x:1000:",
            "  #alice:x:1000:",
            "alice:x::",
            "alice:x:bad:",
            "alice:x:-1000:",
            "alice:x:+1000:",
            "alice:x:4294967296:",
            "alice:x: 1000:",
            "alice:x:1000: ",
            "alice:x:1000:\t",
            "alice\0:x:1000:",
        ] {
            let files = parse_files_groups(&format!("{malformed}\nbob:x:1001:\n"));
            assert_eq!(files, parse_files_groups("bob:x:1001:\n"), "{malformed:?}");
        }
    }

    // 이것을 실패시키는 것: chmod g-w 안내를 빼거나 공백·따옴표·셸 메타문자를 인용하지 않는 것.
    #[test]
    fn unknown_group_diagnostic_names_chmod_and_quotes_path() {
        assert_eq!(
            undecided_remedy(std::path::Path::new("/home/a b/.config")),
            "group membership could not be confirmed; chmod g-w '/home/a b/.config'"
        );
        assert_eq!(
            undecided_remedy(std::path::Path::new("/home/a'b;$(id)/.config")),
            "group membership could not be confirmed; chmod g-w '/home/a'\\''b;$(id)/.config'"
        );
    }

    // 이것을 실패시키는 것: 미확인·남의 그룹을 기록하거나 승인된 정체를 빠뜨리거나 중복 기록하는 것.
    #[test]
    fn recording_keeps_only_unique_cleared_entries() {
        struct Answers;
        impl GroupOracle for Answers {
            fn group_write(&mut self, at: &Facts) -> Group {
                match at.gid {
                    20 => Group::OnlyRootAndUser,
                    21 => Group::Unknown,
                    _ => Group::HasOthers,
                }
            }
        }
        let mut inner = Answers;
        let mut recording = Recording::new(&mut inner);
        let mut facts = Facts {
            dev: 3,
            ino: 42,
            uid: 501,
            gid: 20,
            mode: 0o040775,
            acl: bingsu_core::fs_trust::AclFacts::None,
            ownership: Some(true),
        };
        let pin = GroupPin::of(&facts);
        for _ in 0..2 {
            assert_eq!(recording.group_write(&facts), Group::OnlyRootAndUser);
        }
        facts.gid = 21;
        assert_eq!(recording.group_write(&facts), Group::Unknown);
        facts.gid = 22;
        assert_eq!(recording.group_write(&facts), Group::HasOthers);
        assert_eq!(recording.cleared, [pin]);
    }
}
