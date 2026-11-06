//! Sanitized `PATH` and executable lookup for user commands and builtin
//! probes (spec section 4, rows environment, executable lookup and native
//! executable). The rules are `bingsu_core::command::path` and
//! `bingsu_core::fs_trust`; this file walks the file system one name at a
//! time through held descriptors and hands them the facts.
//!
//! The helper resolves; the relay, which cannot ask the group database,
//! runs only the canonical path it is given, refuses any symlink on it and
//! accepts group write only for the pin found here (B2 ruling, design A).
//! Ancestor folders get no pin: the walk below found that only root, the
//! user or a cleared group can change them, so between this check and the
//! relay's exec nobody else can swap a name on the way.
use crate::commands::group_policy::Recording;
use crate::commands::sys;
use bingsu_core::command::path::{
    self as rule, Candidate, ExecPin, Head, Name, SHEBANG_MAX, Shebang,
};
use bingsu_core::fs_trust::{GroupOracle, NextOwner, ancestor_verdict};
use bingsu_core::handoff::Interpreter;
use std::collections::VecDeque;
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::os::fd::AsFd;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Component, Path, PathBuf};

/// The same bound Linux uses for one path lookup (MAXSYMLINKS).
const LINKS_MAX: usize = 40;
/// Folders held open at once by one walk.
const DEPTH_MAX: usize = 256;

/// The executable to run: its canonical path and, when it is group-writable,
/// the pin the relay compares against; for a `#!` script, its interpreter.
#[derive(Debug, PartialEq, Eq)]
pub struct Found {
    pub executable: PathBuf,
    pub pin: Option<ExecPin>,
    pub interpreter: Option<Interpreter>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Miss {
    /// No such name on the way, or the lookup found no executable.
    Absent,
    /// A link, folder or file on the way someone else can change, or one
    /// the rules could not decide, or a name that cannot be looked up.
    Refused,
}

struct Folder {
    file: File,
    id: rule::Id,
    /// The duty this folder leaves for its next entry (sticky `/tmp`).
    next: NextOwner,
}

enum End {
    Folder {
        chain: Vec<rule::Id>,
    },
    File {
        chain: Vec<rule::Id>,
        file: File,
        next: NextOwner,
        stamp: sys::Stamp,
    },
}

/// `p`'s names in order: "/" restarts at the root, ".." steps back.
fn names(p: &Path) -> VecDeque<OsString> {
    p.components()
        .filter_map(|c| match c {
            Component::RootDir => Some(OsString::from("/")),
            Component::ParentDir => Some(OsString::from("..")),
            Component::Normal(n) => Some(n.to_os_string()),
            Component::CurDir | Component::Prefix(_) => None,
        })
        .collect()
}

/// A name that is not there, or a folder the user may not search (EACCES),
/// holds nothing to run: the lookup moves on to the next folder, as
/// `execvp` does.
fn miss(e: &std::io::Error) -> Miss {
    if matches!(
        e.kind(),
        std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied
    ) {
        Miss::Absent
    } else {
        Miss::Refused
    }
}

/// Walks absolute `path` from "/" one name at a time. Every folder entered
/// must pass the ancestor rule before any name inside it is trusted; a
/// symlink is followed only when root or `me` owns it (its folder passed
/// already); `..` steps back to the folder the walk came from. Returns the
/// canonical path and how it ended.
fn walk(
    path: &Path,
    me: u32,
    groups: &mut dyn GroupOracle,
    want_folder: bool,
) -> Result<(PathBuf, End), Miss> {
    if !path.is_absolute() || (!want_folder && rule::names_folder(path.as_os_str().as_bytes())) {
        return Err(Miss::Refused);
    }
    let root = sys::open_dir_at_search_nofollow(None, OsStr::new("/")).map_err(|e| miss(&e))?;
    let facts = sys::fd_facts(root.as_fd()).map_err(|_| Miss::Refused)?;
    let next =
        ancestor_verdict(&facts, me, 0, NextOwner::Any, groups).map_err(|_| Miss::Refused)?;
    let id = (facts.dev, facts.ino);
    let mut stack = vec![Folder {
        file: root,
        id,
        next,
    }];
    let mut canonical = PathBuf::from("/");
    let mut todo = names(path);
    let mut links = 0;
    while let Some(name) = todo.pop_front() {
        if name == "/" {
            stack.truncate(1);
            canonical = PathBuf::from("/");
            continue;
        }
        if name == ".." {
            if stack.len() > 1 {
                stack.pop();
                canonical.pop();
            }
            continue;
        }
        let top = stack.last().expect("root");
        let dir = top.file.as_fd();
        let stamp = sys::at_stamp(dir, &name).map_err(|e| miss(&e))?;
        let kind = stamp.mode & 0o170_000;
        if kind == 0o120_000 {
            links += 1;
            if links > LINKS_MAX || !rule::link_owner_ok(stamp.uid, me) {
                return Err(Miss::Refused);
            }
            let target = sys::read_link_at(dir, &name).map_err(|_| Miss::Refused)?;
            // A file's last link must not name a folder (`x -> /usr/bin/true/`).
            if !want_folder && todo.is_empty() && rule::names_folder(target.as_os_str().as_bytes())
            {
                return Err(Miss::Refused);
            }
            if sys::at_stamp(dir, &name).map_err(|_| Miss::Refused)? != stamp {
                return Err(Miss::Refused);
            }
            let mut expansion = names(&target);
            expansion.append(&mut todo);
            todo = expansion;
            continue;
        }
        let last = todo.is_empty();
        if last && !want_folder {
            if kind != 0o100_000 {
                // Not a regular file: the lookup moves on, like a shell.
                return Err(Miss::Absent);
            }
            let next = top.next;
            let file = open_target(dir, &name).map_err(|_| Miss::Refused)?;
            let now = sys::file_stamp(&file).map_err(|_| Miss::Refused)?;
            if (now.dev, now.ino) != (stamp.dev, stamp.ino) {
                return Err(Miss::Refused);
            }
            canonical.push(&name);
            let chain = stack.iter().map(|f| f.id).collect();
            return Ok((
                canonical,
                End::File {
                    chain,
                    file,
                    next,
                    stamp: now,
                },
            ));
        }
        if kind != 0o040_000 || stack.len() >= DEPTH_MAX {
            return Err(if kind == 0o040_000 {
                Miss::Refused
            } else {
                Miss::Absent
            });
        }
        let file = sys::open_dir_at_search_nofollow(Some(dir), &name).map_err(|e| miss(&e))?;
        let facts = sys::fd_facts(file.as_fd()).map_err(|_| Miss::Refused)?;
        if (facts.dev, facts.ino) != (stamp.dev, stamp.ino) {
            return Err(Miss::Refused);
        }
        let next = ancestor_verdict(&facts, me, stack.len(), top.next, groups)
            .map_err(|_| Miss::Refused)?;
        let id = (facts.dev, facts.ino);
        stack.push(Folder { file, id, next });
        canonical.push(&name);
    }
    if want_folder {
        let chain = stack.iter().map(|f| f.id).collect();
        Ok((canonical, End::Folder { chain }))
    } else {
        Err(Miss::Absent)
    }
}

/// The final file for reading (the relay reads its first bytes), or, on
/// Linux, path-only when the user may only execute it.
fn open_target(dir: std::os::fd::BorrowedFd<'_>, name: &OsStr) -> std::io::Result<File> {
    match sys::open_file_at_nofollow(dir, name) {
        #[cfg(target_os = "linux")]
        Err(e) if e.raw_os_error() == Some(libc::EACCES) => sys::open_path_at_nofollow(dir, name),
        other => other,
    }
}

/// The identity of the repository root the shell is in, for `sanitize`
/// and `lookup`. `root` is `None` only when the shell is known to be in no
/// repository; a root that cannot be read is `Refused`, never "no
/// repository", which would switch the repository rule off.
pub fn repo_id(root: Option<&Path>) -> Result<Option<rule::Id>, Miss> {
    use std::os::unix::fs::MetadataExt;
    let Some(root) = root else {
        return Ok(None);
    };
    let m = std::fs::metadata(root).map_err(|_| Miss::Refused)?;
    Ok(Some((m.dev(), m.ino())))
}

/// The folders that hold a `.git` entry (a folder, a worktree's `.git`
/// file, or anything else by that name), by identity: every one counts as a
/// repository root for `sanitize` and `lookup`, nested ones included
/// (U-24). Two sets of folders are checked:
/// - each prefix of `cwd` as the shell gave it (`/home/u/repo` for
///   `/home/u/repo/docs`), so a shell in a repository's link to a folder
///   elsewhere is still in that repository;
/// - "/" and every folder above the real folder `cwd` reaches, so an alias
///   into a repository is in it too.
///
/// The walk goes from "/" one name at a time on held descriptors; a link's
/// text is walked in its place and `..` steps back to the folder before, as
/// the kernel resolves them. It walks to the end whatever the depth (the
/// shell's folder is already bounded by the envelope's length cap). A name
/// that cannot be opened as a folder or too many links is `Refused`, never
/// "no repository". A `.git` that cannot be checked counts as present. Each
/// folder is checked once: a canonical `cwd` costs one `.git` check for "/"
/// and one per name.
pub fn repo_ancestors(cwd: &Path) -> Result<Vec<rule::Id>, Miss> {
    /// A name to walk, or the end of one of `cwd`'s own names.
    enum Step {
        Name(OsString),
        Prefix,
    }
    // Only a `.git` known to be absent leaves a folder out: one that cannot
    // be checked counts as there, so the rule fails closed.
    let holds_git = |folder: &File| {
        !matches!(sys::at_stamp(folder.as_fd(), OsStr::new(".git")),
            Err(e) if e.raw_os_error() == Some(libc::ENOENT))
    };
    if !cwd.is_absolute() {
        return Err(Miss::Refused);
    }
    let root =
        sys::open_dir_at_search_nofollow(None, OsStr::new("/")).map_err(|_| Miss::Refused)?;
    let facts = sys::fd_facts(root.as_fd()).map_err(|_| Miss::Refused)?;
    let mut stack = vec![(root, (facts.dev, facts.ino))];
    let mut todo: VecDeque<Step> = names(cwd)
        .into_iter()
        .flat_map(|n| [Step::Name(n), Step::Prefix])
        .collect();
    let mut checked: Vec<rule::Id> = Vec::new();
    let mut out: Vec<rule::Id> = Vec::new();
    let mut links = 0;
    while let Some(step) = todo.pop_front() {
        let Step::Name(name) = step else {
            let (folder, id) = stack.last().expect("root");
            if !checked.contains(id) {
                checked.push(*id);
                if holds_git(folder) {
                    out.push(*id);
                }
            }
            continue;
        };
        if name == "/" {
            stack.truncate(1);
            continue;
        }
        if name == ".." {
            if stack.len() > 1 {
                stack.pop();
            }
            continue;
        }
        let dir = stack.last().expect("root").0.as_fd();
        let stamp = sys::at_stamp(dir, &name).map_err(|_| Miss::Refused)?;
        if stamp.mode & 0o170_000 == 0o120_000 {
            links += 1;
            if links > LINKS_MAX {
                return Err(Miss::Refused);
            }
            let target = sys::read_link_at(dir, &name).map_err(|_| Miss::Refused)?;
            let mut expansion: VecDeque<Step> =
                names(&target).into_iter().map(Step::Name).collect();
            expansion.append(&mut todo);
            todo = expansion;
            continue;
        }
        let file = sys::open_dir_at_search_nofollow(Some(dir), &name).map_err(|_| Miss::Refused)?;
        let facts = sys::fd_facts(file.as_fd()).map_err(|_| Miss::Refused)?;
        stack.push((file, (facts.dev, facts.ino)));
    }
    for (folder, id) in &stack {
        if !checked.contains(id) {
            checked.push(*id);
            if holds_git(folder) {
                out.push(*id);
            }
        }
    }
    Ok(out)
}

/// Whether the folder chain avoids every repository root in `repos`.
fn outside_repos(chain: &[rule::Id], repos: &[rule::Id]) -> bool {
    repos.iter().all(|r| rule::outside_repo(chain, Some(*r)))
}

/// The canonical folders of `path_env` that commands may search, in order,
/// first occurrence only: absolute entries whose whole way passes the
/// ancestor rule, that do not pass through `repo` (the repository root the
/// shell is in, by identity) and whose name has no ':'.
pub fn sanitize(
    path_env: &[u8],
    repo: &[rule::Id],
    me: u32,
    groups: &mut dyn GroupOracle,
) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    for entry in rule::entries(path_env) {
        let walked = walk(Path::new(OsStr::from_bytes(entry)), me, groups, true);
        let Ok((canonical, End::Folder { chain })) = walked else {
            continue;
        };
        let keep = outside_repos(&chain, repo) && rule::path_safe(canonical.as_os_str().as_bytes());
        if keep && !out.contains(&canonical) {
            out.push(canonical);
        }
    }
    out
}

/// The `PATH` value for the target's environment.
pub fn path_value(folders: &[PathBuf]) -> Vec<u8> {
    rule::sanitized(folders.iter().map(|f| f.as_os_str().as_bytes()))
}

/// Looks the command's first word up: an absolute path as given, a bare
/// name in `folders` (from `sanitize`). The first folder with an
/// executable regular file of that name decides; if that file fails the
/// rules nothing runs. `repo` as in `sanitize`; the file's own folders
/// must not pass through it either.
#[cfg_attr(
    not(test),
    allow(dead_code, reason = "the command round uses lookup_open")
)]
pub fn lookup(
    word: &[u8],
    folders: &[PathBuf],
    repo: &[rule::Id],
    me: u32,
    groups: &mut dyn GroupOracle,
) -> Result<Found, Miss> {
    lookup_open(word, folders, repo, me, groups).map(|(found, _)| found)
}

/// `lookup`, also handing back the descriptor the checks ran on (macOS
/// copies a script from it).
pub fn lookup_open(
    word: &[u8],
    folders: &[PathBuf],
    repo: &[rule::Id],
    me: u32,
    groups: &mut dyn GroupOracle,
) -> Result<(Found, Checked), Miss> {
    match rule::name(word) {
        Name::Refused => Err(Miss::Refused),
        Name::Absolute(p) => resolve_open(Path::new(OsStr::from_bytes(p)), repo, me, groups),
        Name::Search(n) => {
            for folder in folders {
                match resolve_open(&folder.join(OsStr::from_bytes(n)), repo, me, groups) {
                    Err(Miss::Absent) => continue,
                    other => return other,
                }
            }
            Err(Miss::Absent)
        }
    }
}

/// One executable path: walked, then judged with the group answers kept,
/// so a group-writable target carries the pin its group was cleared for.
/// The canonical file must be outside `repo`, wherever the walk started.
pub fn resolve(
    path: &Path,
    repo: &[rule::Id],
    me: u32,
    groups: &mut dyn GroupOracle,
) -> Result<Found, Miss> {
    resolve_open(path, repo, me, groups).map(|(found, _)| found)
}

/// The descriptor `resolve_open` ran its checks on, with its canonical path
/// and the stat the walk took before the checks (device, inode, owner,
/// group, mode, status change time: what a pin binds). Only this module
/// makes one, so what reads it (a script's shebang, `ScriptCopies::copy`)
/// reads the checked file, never one opened again by name.
pub struct Checked {
    file: File,
    #[cfg_attr(
        not(target_os = "macos"),
        allow(dead_code, reason = "macOS script copies")
    )]
    path: PathBuf,
    #[cfg_attr(
        not(target_os = "macos"),
        allow(dead_code, reason = "macOS script copies")
    )]
    stamp: sys::Stamp,
}

impl Checked {
    pub fn file(&self) -> &File {
        &self.file
    }
}

/// `resolve`, also handing back the descriptor the checks ran on, so the
/// bytes read next (a script's shebang and body) are the checked file's.
/// A `#!` script's interpreter is read from that descriptor and resolved by
/// the same rules.
pub fn resolve_open(
    path: &Path,
    repo: &[rule::Id],
    me: u32,
    groups: &mut dyn GroupOracle,
) -> Result<(Found, Checked), Miss> {
    let (found, checked) = resolve_checked(path, repo, me, groups)?;
    let interpreter = match first_bytes(&checked)? {
        Some(first) => match rule::head(&first) {
            Head::Native => None,
            Head::Refused => return Err(Miss::Refused),
            Head::Script(line) => Some(interpreter(line, repo, me, groups)?),
        },
        None => None,
    };
    Ok((
        Found {
            interpreter,
            ..found
        },
        checked,
    ))
}

/// Why a script found on the way does not run, for `config check`'s W411
/// (D3a/E2 ruling Q2: one code, the reason as its argument). The decision
/// is `rule::head`'s and `interpreter`'s; this only names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScriptRefusal {
    /// `#!/usr/bin/env`, or an interpreter that is `/usr/bin/env` under
    /// another name (merged-/usr `/bin/env`).
    Env,
    /// The interpreter is not an absolute path.
    Relative,
    /// No line end within `SHEBANG_MAX` bytes.
    LongLine,
    /// A NUL in the line.
    Nul,
}

impl ScriptRefusal {
    pub fn text(self) -> &'static str {
        match self {
            Self::Env => {
                "it starts with `#!/usr/bin/env`, which would take the interpreter from PATH"
            }
            Self::Relative => "its interpreter is not an absolute path",
            Self::LongLine => "its first line is longer than 256 bytes",
            Self::Nul => "its first line holds a NUL byte",
        }
    }
}

/// What `config check --explain` shows for a unit's first word: the file
/// that would run (or why none would), found by the executor's own lookup
/// and checks, without running anything.
#[derive(Debug, PartialEq, Eq)]
pub enum Explained {
    Runs(Found),
    /// Nothing of that name on the way.
    Absent,
    /// A file was found and refused; `Some` when its first line says why.
    Refused {
        file: Option<PathBuf>,
        script: Option<ScriptRefusal>,
    },
}

/// The reason `rule::head` refused `first` (it returned `Head::Refused`):
/// checked in its own order, so each refused head gets exactly one reason.
fn head_refusal(first: &[u8]) -> ScriptRefusal {
    let rest = first.strip_prefix(b"#!").unwrap_or(first);
    let Some(end) = rest.iter().position(|&b| b == b'\n') else {
        if first.len() >= SHEBANG_MAX {
            return ScriptRefusal::LongLine;
        }
        return refusal_of_line(rest);
    };
    refusal_of_line(&rest[..end])
}

fn refusal_of_line(line: &[u8]) -> ScriptRefusal {
    if line.contains(&0) {
        return ScriptRefusal::Nul;
    }
    let word = line
        .iter()
        .position(|b| *b != b' ' && *b != b'\t')
        .map_or(&line[line.len()..], |i| &line[i..]);
    // Fails without it: explain_names_why_a_script_is_refused (relative).
    if word.first() != Some(&b'/') {
        return ScriptRefusal::Relative;
    }
    ScriptRefusal::Env
}

/// Why a refused file's first line refused it, if it did: a head
/// `rule::head` refuses, or an interpreter that is `/usr/bin/env` under
/// another name.
fn script_refusal(first: &[u8]) -> Option<ScriptRefusal> {
    match rule::head(first) {
        Head::Native => None,
        // Fails without it: explain_names_why_a_script_is_refused (the
        // reason of each refused head).
        Head::Refused => Some(head_refusal(first)),
        Head::Script(line) => {
            let word = Path::new(OsStr::from_bytes(line.interpreter));
            // Fails without it: test_env_shebang_warned (`/bin/env` on
            // merged /usr).
            let env = std::fs::canonicalize(word)
                .is_ok_and(|p| p.as_os_str().as_bytes() == b"/usr/bin/env");
            env.then_some(ScriptRefusal::Env)
        }
    }
}

/// `lookup_open` for `config check --explain` and W411: the same search
/// and checks, reporting why a found file is refused.
pub fn explain(
    word: &[u8],
    folders: &[PathBuf],
    repo: &[rule::Id],
    me: u32,
    groups: &mut dyn GroupOracle,
) -> Explained {
    let candidates: Vec<PathBuf> = match rule::name(word) {
        Name::Refused => {
            return Explained::Refused {
                file: None,
                script: None,
            };
        }
        Name::Absolute(p) => vec![PathBuf::from(OsStr::from_bytes(p))],
        Name::Search(n) => folders
            .iter()
            .map(|f| f.join(OsStr::from_bytes(n)))
            .collect(),
    };
    for path in candidates {
        // The decision is the executor's own (`resolve_open`); a refused
        // file is read again only to name why.
        match resolve_open(&path, repo, me, groups) {
            Err(Miss::Absent) => continue,
            Ok((found, _)) => return Explained::Runs(found),
            Err(Miss::Refused) => {
                let checked = resolve_checked(&path, repo, me, groups).ok();
                let script = checked
                    .as_ref()
                    .and_then(|(_, c)| first_bytes(c).ok().flatten())
                    .and_then(|first| script_refusal(&first));
                return Explained::Refused {
                    file: Some(checked.map_or(path, |(found, _)| found.executable)),
                    script,
                };
            }
        }
    }
    Explained::Absent
}

/// A script's interpreter (spec section 4 script row): an absolute path
/// resolved by the same rules, a native executable (no nested `#!`, read
/// from its checked descriptor), and not `/usr/bin/env` under another name
/// (merged-/usr `/bin/env`). A missing interpreter refuses the script; the
/// lookup does not move on.
fn interpreter(
    line: Shebang<'_>,
    repo: &[rule::Id],
    me: u32,
    groups: &mut dyn GroupOracle,
) -> Result<Interpreter, Miss> {
    let word = Path::new(OsStr::from_bytes(line.interpreter));
    let (found, checked) = resolve_checked(word, repo, me, groups).map_err(|_| Miss::Refused)?;
    let native = first_bytes(&checked)?.is_none_or(|first| rule::head(&first) == Head::Native);
    let path = found.executable.into_os_string().into_vec();
    if !native || path == b"/usr/bin/env" {
        return Err(Miss::Refused);
    }
    Ok(Interpreter {
        line: line.line.to_vec(),
        path,
        pin: found.pin,
    })
}

/// The checked file's first `SHEBANG_MAX` bytes, read at offset 0 without
/// moving its offset; `None` for a Linux path-only descriptor (an
/// execute-only file), which the relay runs as native only.
fn first_bytes(checked: &Checked) -> Result<Option<Vec<u8>>, Miss> {
    use std::os::unix::fs::FileExt;
    let mut first = vec![0u8; SHEBANG_MAX];
    match checked.file().read_at(&mut first, 0) {
        Ok(n) => {
            first.truncate(n);
            Ok(Some(first))
        }
        Err(e) if cfg!(target_os = "linux") && e.raw_os_error() == Some(libc::EBADF) => Ok(None),
        Err(_) => Err(Miss::Refused),
    }
}

/// `resolve_open` without the script step.
fn resolve_checked(
    path: &Path,
    repo: &[rule::Id],
    me: u32,
    groups: &mut dyn GroupOracle,
) -> Result<(Found, Checked), Miss> {
    let (executable, end) = walk(path, me, groups, false)?;
    let End::File {
        chain,
        file,
        next,
        stamp,
    } = end
    else {
        return Err(Miss::Absent);
    };
    if !outside_repos(&chain, repo) {
        return Err(Miss::Refused);
    }
    let ctime = (
        stamp.ctime.0,
        u32::try_from(stamp.ctime.1).map_err(|_| Miss::Refused)?,
    );
    let facts = sys::fd_facts(file.as_fd()).map_err(|_| Miss::Refused)?;
    let mut recording = Recording::new(groups);
    match rule::candidate(&facts, me, next, &mut recording) {
        Candidate::Run => {
            // macOS runs the target by path, not by descriptor: an executable
            // on a network file system (no MNT_LOCAL) is refused (spec section
            // 4, macOS executable row). Only the file itself, as that row
            // says, and only one that would run: a file the lookup skips
            // stays a skip. The test that fails this needs a network mount
            // (`test_macos_network_fs_refused`).
            #[cfg(target_os = "macos")]
            if sys::fd_is_local(std::os::fd::AsRawFd::as_raw_fd(&file)) != Some(true) {
                return Err(Miss::Refused);
            }
            Ok((
                Found {
                    executable: executable.clone(),
                    pin: rule::target_pin(&facts, &recording.cleared, ctime),
                    interpreter: None,
                },
                Checked {
                    file,
                    path: executable,
                    stamp,
                },
            ))
        }
        Candidate::Skip => Err(Miss::Absent),
        Candidate::Refuse => Err(Miss::Refused),
    }
}

/// The largest script body copied for an interpreter, as on Linux (spec
/// section 4 script row: 64 KB).
#[cfg(target_os = "macos")]
pub const SCRIPT_MAX: u64 = 65_536;

/// macOS script copies (spec section 4 script row): macOS cannot run a
/// checked descriptor, so a script's body is copied into the private folder
/// `scripts` of the runtime root and the interpreter is given the copy's
/// path. Only the user can change anything in that folder.
#[cfg(target_os = "macos")]
pub struct ScriptCopies {
    dir: File,
    /// The folder's canonical path (`F_GETPATH`): the relay refuses any
    /// symlink on the path it is given, and `$TMPDIR`-style roots sit under
    /// the `/var -> private/var` link.
    path: PathBuf,
}

/// Copies removed by one sweep, at most (C2 ruling Q1).
#[cfg(target_os = "macos")]
pub const SWEEP_MAX: usize = 64;

#[cfg(target_os = "macos")]
impl ScriptCopies {
    /// Opens (creating if needed) `scripts` in the runtime root `root` (as
    /// `open_runtime_root` checked it). The folder must be the user's,
    /// exactly 0700, with no ACL that allows writing, local.
    pub fn open(root: std::os::fd::BorrowedFd<'_>, me: u32) -> Result<Self, Miss> {
        use bingsu_core::fs_trust::{Last, RefuseGroupWrite, final_verdict};
        let name = OsStr::new("scripts");
        let made = sys::mkdir_at(root, name, 0o700).map_err(|_| Miss::Refused)?;
        let dir = sys::open_dir_at_nofollow(root, name).map_err(|_| Miss::Refused)?;
        // A umask can take bits from the folder this call made; only that
        // one is set to 0700. A folder that was already there is judged as
        // found and never repaired.
        if made {
            use std::os::unix::fs::PermissionsExt;
            dir.set_permissions(std::fs::Permissions::from_mode(0o700))
                .map_err(|_| Miss::Refused)?;
        }
        let facts = sys::fd_facts(dir.as_fd()).map_err(|_| Miss::Refused)?;
        let local = sys::fd_is_local(std::os::fd::AsRawFd::as_raw_fd(&dir));
        final_verdict(
            &facts,
            me,
            0,
            NextOwner::Any,
            Last::PrivateFolder,
            local,
            &mut RefuseGroupWrite,
        )
        .map_err(|_| Miss::Refused)?;
        let path = sys::fd_path(std::os::fd::AsRawFd::as_raw_fd(&dir)).ok_or(Miss::Refused)?;
        Ok(Self { dir, path })
    }

    /// Copies `script` (read from its start, through the checked
    /// descriptor) into a new file named `<tag>-<random>`, mode 0600, and
    /// returns its canonical path. A body over `SCRIPT_MAX` is refused. The
    /// caller removes the copy after the run (`remove`), or a later `sweep`
    /// of the same tag does.
    pub fn copy(&self, script: &Checked, tag: &str) -> Result<PathBuf, Miss> {
        use std::io::Seek;
        if !may_execute(script) {
            return Err(Miss::Refused);
        }
        let mut from = script.file();
        from.seek(std::io::SeekFrom::Start(0))
            .map_err(|_| Miss::Refused)?;
        let body = read_capped(from)?;
        #[cfg(test)]
        tests::after_read();
        // The bytes copied are those of the file the checks and the pin
        // describe: a write, chmod, chown or ACL change since moves the
        // status change time (C2 review High; fails without it:
        // test_macos_copy_refuses_a_script_changed_after_its_check).
        if !same_file(
            &sys::file_stamp(script.file()).map_err(|_| Miss::Refused)?,
            &script.stamp,
        ) {
            return Err(Miss::Refused);
        }
        let random = sys::random_bytes16().ok_or(Miss::Refused)?;
        let random: String = random.iter().map(|b| format!("{b:02x}")).collect();
        let name = format!("{tag}-{random}");
        let out = sys::create_file_at(self.dir.as_fd(), OsStr::new(&name), 0o600)
            .map_err(|_| Miss::Refused)?;
        let raw = std::os::fd::AsRawFd::as_raw_fd(&out);
        if !matches!(sys::write_fd(raw, &body), sys::WriteOutcome::Done) {
            // A short copy must not stay behind for an interpreter to read.
            let _ = sys::unlink_at(self.dir.as_fd(), OsStr::new(&name));
            return Err(Miss::Refused);
        }
        Ok(self.path.join(name))
    }

    /// Removes a copy `copy` made (by its name in this folder).
    pub fn remove(&self, copy: &Path) {
        if let Some(name) = copy.file_name() {
            let _ = sys::unlink_at(self.dir.as_fd(), name);
        }
    }

    /// Removes up to `SWEEP_MAX` copies named `<tag>-...`: what a round of
    /// the same session left when its helper did not see its supervisor
    /// end. Only the helper that holds the session lock calls it, so no
    /// live supervisor of that session uses them; other tags stay.
    pub fn sweep(&self, tag: &str) -> usize {
        let Ok(names) = sys::directory_names(self.dir.as_fd()) else {
            return 0;
        };
        let prefix = format!("{tag}-");
        let mut removed = 0;
        // Fails without the prefix test: sweep_removes_only_its_tag.
        for name in names
            .iter()
            .filter(|n| n.as_bytes().starts_with(prefix.as_bytes()))
        {
            if removed == SWEEP_MAX {
                break;
            }
            if sys::unlink_at(self.dir.as_fd(), name).is_ok() {
                removed += 1;
            }
        }
        removed
    }
}

/// Whether `now` is the checked file unchanged: device, inode, owner,
/// group, mode and status change time.
#[cfg(target_os = "macos")]
fn same_file(now: &sys::Stamp, then: &sys::Stamp) -> bool {
    let key = |s: &sys::Stamp| (s.dev, s.ino, s.uid, s.gid, s.mode, s.ctime);
    key(now) == key(then)
}

/// Whether the kernel would let this user execute the checked script, as
/// `execve` would judge it (bits, ACL, a `noexec` mount):
/// `faccessat(X_OK, AT_EACCESS)` on its canonical path, which must still
/// name the checked file afterwards (macOS has no descriptor form; C2
/// review Medium). The copy is 0600 and runs as an
/// interpreter's argument, so this is the only place the script's own
/// execute permission is decided.
#[cfg(target_os = "macos")]
fn may_execute(script: &Checked) -> bool {
    use std::os::unix::fs::MetadataExt;
    // The kernel's answer covers a `noexec` mount too: a separate fstatfs
    // check of MNT_NOEXEC was tried and no test failed without it, since
    // faccessat refuses there already. Fails without it:
    // test_macos_script_needs_its_own_execute_bit (0611) and
    // test_macos_noexec_script_refused.
    if !sys::may_execute_path(&script.path) {
        return false;
    }
    #[cfg(test)]
    tests::after_access();
    // The path faccessat judged is still the checked file (fails without
    // it: test_macos_access_check_names_the_checked_file).
    std::fs::symlink_metadata(&script.path)
        .is_ok_and(|m| (m.dev(), m.ino()) == (script.stamp.dev, script.stamp.ino))
}

/// A script body of at most `SCRIPT_MAX` bytes, reading no more than one
/// byte past it.
#[cfg(target_os = "macos")]
fn read_capped(from: impl std::io::Read) -> Result<Vec<u8>, Miss> {
    use std::io::Read;
    let mut body = Vec::new();
    from.take(SCRIPT_MAX + 1)
        .read_to_end(&mut body)
        .map_err(|_| Miss::Refused)?;
    if body.len() as u64 > SCRIPT_MAX {
        return Err(Miss::Refused);
    }
    Ok(body)
}

/// `resolve` for the current user with the system's group answers, asked
/// afresh (one `SystemGroups` per call, like every other walk).
pub fn resolve_for_user(path: &Path, repo: Option<rule::Id>) -> Result<Found, Miss> {
    let me = sys::current_uid();
    let user = sys::passwd_entry(me).ok_or(Miss::Refused)?;
    let mut groups = crate::commands::group_policy::SystemGroups::new(&user.name);
    resolve(path, repo.as_slice(), me, &mut groups)
}

/// A test that needs a user other than root: true (skip) when running as
/// root, unless `BINGSU_REQUIRE_NONROOT_TESTS=1` (a CI cell that runs as
/// another user), which makes a root run fail instead of passing silently.
#[cfg(test)]
pub(crate) fn test_skip_as_root() -> bool {
    if sys::current_uid() != 0 {
        return false;
    }
    #[allow(
        clippy::disallowed_methods,
        reason = "test-only switch from CI; sys and the relay forbid environment reads"
    )]
    let required = std::env::var_os("BINGSU_REQUIRE_NONROOT_TESTS");
    assert!(
        required.as_deref() != Some(std::ffi::OsStr::new("1")),
        "this cell must not run as root"
    );
    eprintln!("skipped as root: the case needs another user");
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Runs inside `ScriptCopies::copy` after the body is read (tests only).
    #[cfg(target_os = "macos")]
    type Hook = Option<Box<dyn FnMut()>>;
    #[cfg(target_os = "macos")]
    thread_local! {
        static AFTER_READ: std::cell::RefCell<Hook> = const { std::cell::RefCell::new(None) };
        /// Runs in `may_execute` right after faccessat.
        static AFTER_ACCESS: std::cell::RefCell<Hook> = const { std::cell::RefCell::new(None) };
    }
    #[cfg(target_os = "macos")]
    pub(super) fn after_read() {
        AFTER_READ.with(|h| {
            if let Some(f) = h.borrow_mut().as_mut() {
                f();
            }
        });
    }
    #[cfg(target_os = "macos")]
    pub(super) fn after_access() {
        AFTER_ACCESS.with(|h| {
            if let Some(f) = h.borrow_mut().as_mut() {
                f();
            }
        });
    }

    // 사용자 칸에서는 비 root 전용 시험이 실제로 돈다. 이것을 실패시키는 것: test_skip_as_root가 늘 참을 돌려주는 것
    // (실행 전용 relay 시험이 아무것도 단언하지 않고 통과).
    #[test]
    fn nonroot_cases_run_for_a_user() {
        if sys::current_uid() != 0 {
            assert!(!test_skip_as_root());
        }
    }
    use bingsu_core::fs_trust::{Facts, Group, RefuseGroupWrite};
    use std::os::unix::fs::{PermissionsExt, symlink};

    struct Clear;
    impl GroupOracle for Clear {
        fn group_write(&mut self, _: &Facts) -> Group {
            Group::OnlyRootAndUser
        }
    }

    fn me() -> u32 {
        sys::current_uid()
    }

    /// A fresh folder under the temporary folder, canonical (macOS `/var`
    /// is a root-owned link to `/private/var`).
    fn scratch(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("bingsu-exec-path-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::canonicalize(&dir).unwrap()
    }

    /// Folders up to `p`, each 0755 whatever the umask (a 0002 umask makes
    /// them group-writable, which `RefuseGroupWrite` refuses).
    fn folders(p: &Path) {
        if p.is_dir() {
            return;
        }
        folders(p.parent().unwrap());
        std::fs::create_dir(p).unwrap();
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    fn exe(path: &Path, mode: u32) {
        folders(path.parent().unwrap());
        std::fs::copy(std::fs::canonicalize("/usr/bin/true").unwrap(), path).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    fn bytes(p: &Path) -> &[u8] {
        p.as_os_str().as_bytes()
    }

    fn id_of(p: &Path) -> rule::Id {
        use std::os::unix::fs::MetadataExt;
        let m = std::fs::metadata(p).unwrap();
        (m.dev(), m.ino())
    }

    // U-24: 셸 폴더와 그 위에서 `.git`(폴더, worktree의 파일)을 가진 조상을 모두 저장소로 본다. 이것을 실패시키는
    // 것: `.git` 부재 판정을 뒤집는 것(저장소 없는 경로가 모든 조상을 냄), 판정을 지워 아무것도 내지 않는 것, 가장
    // 가까운 하나에서 멈추는 것(바깥 저장소가 빠짐).
    #[test]
    fn repo_ancestors_are_every_folder_holding_git() {
        let t = scratch("scan");
        let outer = t.join("outer");
        let inner = outer.join("a/inner");
        let cwd = inner.join("sub/deep");
        folders(&cwd);
        assert_eq!(repo_ancestors(&cwd), Ok(vec![]));
        std::fs::create_dir(outer.join(".git")).unwrap();
        std::fs::write(inner.join(".git"), "gitdir: /elsewhere\n").unwrap();
        assert_eq!(repo_ancestors(&cwd), Ok(vec![id_of(&outer), id_of(&inner)]));
        std::fs::create_dir(cwd.join(".git")).unwrap();
        assert_eq!(
            repo_ancestors(&cwd),
            Ok(vec![id_of(&outer), id_of(&inner), id_of(&cwd)])
        );
    }

    // 별칭 경로: 링크로 들어간 셸 폴더는 실제 폴더의 조상으로 판정한다(절대·상대 링크, 링크 안의 `..`). 이것을
    // 실패시키는 것: 링크를 따르지 않는 것(실제 폴더의 조상인 저장소가 빠짐).
    #[test]
    fn repo_ancestors_follow_the_real_folder_of_an_alias() {
        use std::os::unix::fs::symlink;
        let t = scratch("scan-alias");
        let repo = t.join("repo");
        folders(&repo.join("sub"));
        std::fs::create_dir(repo.join(".git")).unwrap();
        folders(&t.join("x"));
        symlink(repo.join("sub"), t.join("x/abs")).unwrap();
        symlink("../repo/sub", t.join("x/rel")).unwrap();
        for alias in ["x/abs", "x/rel"] {
            assert_eq!(
                repo_ancestors(&t.join(alias)),
                Ok(vec![id_of(&repo)]),
                "{alias}"
            );
        }
    }

    // `.git`이 가리키는 곳이 없는 링크나 고리 링크여도 그 이름이 있으면 저장소다: 링크를 따르지 않고 이름만 본다.
    // 이것을 실패시키는 것: 폴더·파일일 때만 있음으로 세는 것, `.git`을 링크를 따라 확인하는 것(끊긴 링크가 없음이
    // 됨).
    #[test]
    fn repo_ancestors_count_a_git_link_whatever_it_names() {
        use std::os::unix::fs::symlink;
        let t = scratch("scan-git-link");
        let (dangling, looped) = (t.join("dangling"), t.join("looped"));
        folders(&dangling);
        folders(&looped);
        symlink("nowhere", dangling.join(".git")).unwrap();
        symlink(".git", looped.join(".git")).unwrap();
        assert_eq!(repo_ancestors(&dangling), Ok(vec![id_of(&dangling)]));
        assert_eq!(repo_ancestors(&looped), Ok(vec![id_of(&looped)]));
    }

    // `.git`을 확인하지 못하는 폴더(검색 권한 없는 셸 폴더)는 저장소로 센다(U-24 L3). 이것을 실패시키는 것: 확인
    // 오류를 "없음"으로 보는 것(열린 쪽 실패).
    #[test]
    fn repo_ancestors_count_a_folder_they_cannot_check() {
        let t = scratch("scan-unchecked");
        let cwd = t.join("shut");
        folders(&cwd);
        assert_eq!(repo_ancestors(&cwd), Ok(vec![]));
        if me() == 0 {
            return; // root searches any folder: the check never fails
        }
        std::fs::set_permissions(&cwd, std::fs::Permissions::from_mode(0o600)).unwrap();
        let got = repo_ancestors(&cwd);
        std::fs::set_permissions(&cwd, std::fs::Permissions::from_mode(0o755)).unwrap();
        // Linux opens the folder path-only (O_PATH) and then fails to check
        // inside it; macOS's O_SEARCH open already refuses the walk.
        if cfg!(target_os = "linux") {
            assert_eq!(got, Ok(vec![id_of(&cwd)]));
        } else {
            assert_eq!(got, Err(Miss::Refused));
        }
    }

    // 셸이 준 논리 경로의 접두사도 본다(U-24 L1): 저장소 안의 `docs -> 바깥 폴더`로 들어간 셸은 그 저장소 안이다.
    // 이것을 실패시키는 것: 논리 경로의 접두사 검사를 지우는 것(실제 폴더의 조상만 남아 저장소가 빠짐).
    #[test]
    fn repo_ancestors_count_the_shells_own_path() {
        use std::os::unix::fs::symlink;
        let t = scratch("scan-logical");
        let repo = t.join("repo");
        let elsewhere = t.join("elsewhere");
        folders(&repo);
        folders(&elsewhere);
        std::fs::create_dir(repo.join(".git")).unwrap();
        symlink(&elsewhere, repo.join("docs")).unwrap();
        assert_eq!(repo_ancestors(&repo.join("docs")), Ok(vec![id_of(&repo)]));
        assert_eq!(repo_ancestors(&elsewhere), Ok(vec![]));
    }

    // 링크 안의 `..`는 앞 폴더로 돌아간다(U-24 M1). 셸 경로에도 실제 폴더의 조상에도 없는 폴더(링크가 놓인
    // 저장소 b)는 저장소가 아니고, `../a/../a…`로 길게 쓴 링크도 폴더를 쌓지 않는다. 이것을 실패시키는 것: `..`를
    // 부모를 새로 여는 이름으로 걷는 것(b가 들어감), 절대 링크의 "/"에서 걸은 폴더를 버리지 않는 것.
    #[test]
    fn repo_ancestors_step_back_on_parent_names_in_links() {
        use std::os::unix::fs::symlink;
        let t = scratch("scan-parent");
        let repo = t.join("repo");
        folders(&repo.join("sub"));
        folders(&t.join("a"));
        folders(&t.join("b"));
        std::fs::create_dir(t.join("b/.git")).unwrap();
        symlink(t.join("b/l2"), t.join("a/l1")).unwrap();
        symlink("../repo/sub", t.join("b/l2")).unwrap();
        assert_eq!(repo_ancestors(&t.join("a/l1")), Ok(vec![]));
        // A link's own walk before an absolute link is dropped there: c is
        // neither on the shell's path nor above the real folder.
        folders(&t.join("a/c"));
        std::fs::create_dir(t.join("a/c/.git")).unwrap();
        symlink("c/l3", t.join("a/l4")).unwrap();
        symlink(repo.join("sub"), t.join("a/c/l3")).unwrap();
        assert_eq!(repo_ancestors(&t.join("a/l4")), Ok(vec![]));
        let long = "../b/".repeat(200) + "../repo/sub";
        symlink(&long, t.join("b/long")).unwrap();
        assert_eq!(
            repo_ancestors(&t.join("b/long")),
            Ok(vec![id_of(&t.join("b"))])
        );
    }

    // 걸을 수 없는 경로와 링크 고리는 "저장소 없음"이 아니라 거부다. 깊이에는 상한이 없다(U-24 판정). 이것을
    // 실패시키는 것: 이름 조회 실패를 건너뛰는 것, 링크 수 상한을 지우거나 옮기는 것, 깊이 상한을 두는 것(깊이 40의
    // 셸 폴더가 거부됨), 들어갈 수 없는 폴더를 "저장소 없음"으로 보는 것.
    #[test]
    fn repo_ancestors_refuse_what_they_cannot_walk() {
        use std::os::unix::fs::symlink;
        let t = scratch("scan-refuse");
        assert_eq!(repo_ancestors(&t.join("gone")), Err(Miss::Refused));
        assert_eq!(repo_ancestors(Path::new("relative")), Err(Miss::Refused));
        std::fs::write(t.join("file"), "").unwrap();
        assert_eq!(repo_ancestors(&t.join("file")), Err(Miss::Refused));
        symlink("loop", t.join("loop")).unwrap();
        assert_eq!(repo_ancestors(&t.join("loop")), Err(Miss::Refused));
        // A chain of LINKS_MAX links still ends on its folder; one more is refused.
        folders(&t.join("end"));
        let mut previous = "end".to_owned();
        for i in 0..=LINKS_MAX {
            symlink(&previous, t.join(format!("l{i}"))).unwrap();
            previous = format!("l{i}");
        }
        assert_eq!(
            repo_ancestors(&t.join(format!("l{}", LINKS_MAX - 1))),
            Ok(vec![])
        );
        assert_eq!(
            repo_ancestors(&t.join(format!("l{LINKS_MAX}"))),
            Err(Miss::Refused)
        );
        // No depth cap: a `.git` far above a deep folder is still found.
        let mut deep = t.join("deep");
        folders(&deep);
        std::fs::create_dir(deep.join(".git")).unwrap();
        let top = id_of(&deep);
        while deep.components().count() - 1 < 40 {
            deep = deep.join("d");
        }
        folders(&deep);
        assert_eq!(repo_ancestors(&deep), Ok(vec![top]));
        // A folder on the way the user may not search (root searches anyway).
        if me() != 0 {
            folders(&t.join("locked/sub"));
            std::fs::set_permissions(t.join("locked"), std::fs::Permissions::from_mode(0o000))
                .unwrap();
            let got = repo_ancestors(&t.join("locked/sub"));
            std::fs::set_permissions(t.join("locked"), std::fs::Permissions::from_mode(0o755))
                .unwrap();
            assert_eq!(got, Err(Miss::Refused));
        }
    }

    // 이것을 실패시키는 것: sanitize에서 저장소 검사(keep_folder의 repo)를 지우는 것(저장소의 bin/env가
    // 뽑힘), 또는 entries의 상대·빈 항목 제외를 지우는 것.
    #[test]
    fn test_path_skips_repo_and_relative_entries() {
        let t = scratch("repo");
        let repo = t.join("repo");
        exe(&repo.join("bin/env"), 0o755);
        let mut path = bytes(&repo.join("bin")).to_vec();
        path.extend_from_slice(b":.::bin:/usr/bin");
        let folders = sanitize(
            &path,
            repo_id(Some(&repo)).unwrap().as_slice(),
            me(),
            &mut RefuseGroupWrite,
        );
        let found = lookup(
            b"env",
            &folders,
            repo_id(Some(&repo)).unwrap().as_slice(),
            me(),
            &mut RefuseGroupWrite,
        )
        .unwrap();
        assert_eq!(
            found.executable,
            std::fs::canonicalize("/usr/bin/env").unwrap()
        );
        assert!(
            folders
                .iter()
                .all(|f| f.is_absolute() && !f.starts_with(&repo)),
            "{folders:?}"
        );
        let usr_bin = std::fs::canonicalize("/usr/bin").unwrap();
        assert_eq!(path_value(&folders), bytes(&usr_bin));
        // Positive control: outside a repository the same folder stays and wins.
        let folders = sanitize(&path, &[], me(), &mut RefuseGroupWrite);
        let found = lookup(b"env", &folders, &[], me(), &mut RefuseGroupWrite).unwrap();
        assert_eq!(found.executable, repo.join("bin/env"));
        std::fs::remove_dir_all(&t).unwrap();
    }

    // 양성 대조(Homebrew 모양). 이것을 실패시키는 것: walk가 본인 소유 symlink까지 거부하는 것, 상대
    // 대상의 ".."를 링크가 있던 폴더 기준으로 풀지 않는 것.
    #[test]
    fn test_brew_cellar_symlink_resolved() {
        let t = scratch("brew");
        let real = t.join("Cellar/x/1/bin/x");
        exe(&real, 0o755);
        folders(&t.join("bin"));
        symlink("../Cellar/x/1/bin/x", t.join("bin/x")).unwrap();
        let folders = sanitize(bytes(&t.join("bin")), &[], me(), &mut RefuseGroupWrite);
        let found = lookup(b"x", &folders, &[], me(), &mut RefuseGroupWrite).unwrap();
        assert_eq!(
            found,
            Found {
                executable: real,
                pin: None,
                interpreter: None,
            }
        );
        std::fs::remove_dir_all(&t).unwrap();
    }

    // 다른 uid 소유 symlink는 root만 만들 수 있다(lchown). Linux 컨테이너에서 root로 --ignored로 돌린다.
    // 이것을 실패시키는 것: walk의 link_owner_ok 비교를 반전하거나 지우는 것.
    #[test]
    #[ignore = "needs root (lchown to another uid); run in the Linux container"]
    fn test_foreign_symlink_refused() {
        assert_eq!(me(), 0, "run as root");
        let t = scratch("foreign");
        let real = t.join("real/x");
        exe(&real, 0o755);
        let link = t.join("x");
        symlink(&real, &link).unwrap();
        // Positive control: a root-owned link resolves.
        assert_eq!(
            resolve(&link, &[], 0, &mut RefuseGroupWrite)
                .unwrap()
                .executable,
            real
        );
        std::os::unix::fs::lchown(&link, Some(12345), Some(12345)).unwrap();
        assert_eq!(
            resolve(&link, &[], 0, &mut RefuseGroupWrite),
            Err(Miss::Refused)
        );
        std::fs::remove_dir_all(&t).unwrap();
    }

    // 이것을 실패시키는 것: walk의 폴더 ancestor_verdict를 지우는 것(남이 쓸 수 있는 폴더가 남음).
    #[test]
    fn folders_others_can_write_are_dropped() {
        let t = scratch("loose");
        let loose = t.join("loose");
        exe(&loose.join("x"), 0o755);
        std::fs::set_permissions(&loose, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(sanitize(bytes(&loose), &[], me(), &mut RefuseGroupWrite).is_empty());
        assert_eq!(
            resolve(&loose.join("x"), &[], me(), &mut RefuseGroupWrite),
            Err(Miss::Refused)
        );
        std::fs::set_permissions(&loose, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            sanitize(bytes(&loose), &[], me(), &mut RefuseGroupWrite),
            [loose]
        );
        std::fs::remove_dir_all(&t).unwrap();
    }

    // 이것을 실패시키는 것: lookup이 Refused에서 다음 폴더로 넘어가는 것(앞 폴더의 남이 쓸 수 있는 x 대신
    // 뒤 폴더의 x가 실행됨), 또는 실행 비트 없는 파일에서 멈추는 것.
    #[test]
    fn first_executable_decides() {
        let t = scratch("first");
        let (a, b) = (t.join("a"), t.join("b"));
        exe(&a.join("x"), 0o757);
        exe(&a.join("y"), 0o644);
        exe(&b.join("x"), 0o755);
        exe(&b.join("y"), 0o755);
        let folders = [a.clone(), b.clone()];
        assert_eq!(
            lookup(b"x", &folders, &[], me(), &mut RefuseGroupWrite),
            Err(Miss::Refused)
        );
        assert_eq!(
            lookup(b"y", &folders, &[], me(), &mut RefuseGroupWrite)
                .unwrap()
                .executable,
            b.join("y")
        );
        assert_eq!(
            lookup(b"z", &folders, &[], me(), &mut RefuseGroupWrite),
            Err(Miss::Absent)
        );
        assert_eq!(
            lookup(b"a/x", &folders, &[], me(), &mut RefuseGroupWrite),
            Err(Miss::Refused)
        );
        std::fs::remove_dir_all(&t).unwrap();
    }

    // 이것을 실패시키는 것: resolve의 outside_repo 검사를 지우는 것(저장소 밖 폴더의 본인 소유 symlink가
    // 저장소 안 실행 파일로 이어지거나, 저장소 안 절대 경로 명령이 실행됨).
    #[test]
    fn executables_inside_the_repo_are_refused_through_links() {
        let t = scratch("repo-link");
        let repo = t.join("repo");
        exe(&repo.join("bin/tool"), 0o755);
        folders(&t.join("bin"));
        symlink(repo.join("bin/tool"), t.join("bin/tool")).unwrap();
        let folders = sanitize(
            bytes(&t.join("bin")),
            repo_id(Some(&repo)).unwrap().as_slice(),
            me(),
            &mut RefuseGroupWrite,
        );
        assert_eq!(folders, [t.join("bin")]);
        let g = &mut RefuseGroupWrite;
        assert_eq!(
            lookup(
                b"tool",
                &folders,
                repo_id(Some(&repo)).unwrap().as_slice(),
                me(),
                g
            ),
            Err(Miss::Refused)
        );
        let absolute = repo.join("bin/tool");
        assert_eq!(
            lookup(
                bytes(&absolute),
                &[],
                repo_id(Some(&repo)).unwrap().as_slice(),
                me(),
                g
            ),
            Err(Miss::Refused)
        );
        // Positive control: outside any repository the link resolves.
        assert_eq!(
            lookup(b"tool", &folders, &[], me(), g).unwrap().executable,
            absolute
        );
        std::fs::remove_dir_all(&t).unwrap();
    }

    // 대소문자를 가리지 않는 볼륨(macOS 기본)에서 대소문자만 다른 철자로 저장소에 들어가도 저장소 안이다.
    // 대소문자를 가리는 볼륨이면 그 철자는 다른 폴더라 단언하지 않는다. 이것을 실패시키는 것: 저장소 판정을
    // 경로 바이트 접두사 비교로 되돌리는 것, 또는 sanitize·resolve의 outside_repo 검사 하나를 지우는 것.
    #[test]
    fn repo_case_alias_is_inside() {
        let t = scratch("case");
        let repo = t.join("repo");
        exe(&repo.join("bin/tool"), 0o755);
        let alias = t.join("REPO");
        // A case-sensitive volume has no `REPO`: nothing to assert there.
        if repo_id(Some(&alias)).ok() != Some(repo_id(Some(&repo)).unwrap()) {
            std::fs::remove_dir_all(&t).unwrap();
            return;
        }
        let g = &mut RefuseGroupWrite;
        let id = repo_id(Some(&repo)).unwrap();
        assert!(sanitize(bytes(&alias.join("bin")), id.as_slice(), me(), g).is_empty());
        let absolute = alias.join("bin/tool");
        assert_eq!(
            lookup(bytes(&absolute), &[], id.as_slice(), me(), g),
            Err(Miss::Refused)
        );
        assert_eq!(
            lookup(bytes(&absolute), &[], &[], me(), g)
                .unwrap()
                .executable,
            absolute
        );
        std::fs::remove_dir_all(&t).unwrap();
    }

    // 저장소 루트를 bind mount한 다른 경로도 저장소 안이다. mount가 필요해 Linux 컨테이너에서 root와
    // CAP_SYS_ADMIN으로 --ignored로 돌린다. 이것을 실패시키는 것: 저장소 판정을 경로 바이트 접두사 비교로
    // 되돌리는 것.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "needs root and CAP_SYS_ADMIN (bind mount); run in the Linux container"]
    fn repo_bind_mount_is_inside() {
        // It spawns mount and umount (see sys::test_inherited_fd_lock).
        let _serial = sys::test_inherited_fd_lock();
        let t = scratch("bind");
        let repo = t.join("repo");
        exe(&repo.join("bin/tool"), 0o755);
        let alias = t.join("alias");
        folders(&alias);
        let mount = |args: &[&std::ffi::OsStr]| {
            let st = std::process::Command::new("mount")
                .args(args)
                .status()
                .unwrap();
            assert!(st.success(), "mount {args:?}");
        };
        mount(&[OsStr::new("--bind"), repo.as_os_str(), alias.as_os_str()]);
        let g = &mut RefuseGroupWrite;
        let id = repo_id(Some(&repo)).unwrap();
        let folders_got = sanitize(bytes(&alias.join("bin")), id.as_slice(), me(), g);
        let refused = lookup(bytes(&alias.join("bin/tool")), &[], id.as_slice(), me(), g);
        let outside = lookup(bytes(&alias.join("bin/tool")), &[], &[], me(), g);
        let st = std::process::Command::new("umount")
            .arg(&alias)
            .status()
            .unwrap();
        assert!(st.success());
        assert!(folders_got.is_empty(), "{folders_got:?}");
        assert_eq!(refused, Err(Miss::Refused));
        assert_eq!(outside.unwrap().executable, alias.join("bin/tool"));
        std::fs::remove_dir_all(&t).unwrap();
    }

    // 이것을 실패시키는 것: repo_id가 읽지 못한 저장소 루트를 저장소 없음(Ok(None))으로 바꾸는 것(저장소
    // 규칙이 꺼진 채 실행됨).
    #[test]
    fn unreadable_repo_root_refuses() {
        let t = scratch("repo-gone");
        assert_eq!(repo_id(Some(&t.join("gone"))), Err(Miss::Refused));
        assert_eq!(repo_id(None), Ok(None));
        assert!(repo_id(Some(&t)).unwrap().is_some());
        std::fs::remove_dir_all(&t).unwrap();
    }

    // 이것을 실패시키는 것: sanitize의 path_safe(':') 검사를 지우는 것(정규화한 이름에 ':'가 든 폴더가
    // 남아 PATH 값에서 두 항목으로 갈라짐).
    #[test]
    fn folders_with_a_colon_are_dropped() {
        let t = scratch("colon");
        exe(&t.join("a:b/x"), 0o755);
        symlink(t.join("a:b"), t.join("link")).unwrap();
        let g = &mut RefuseGroupWrite;
        assert!(sanitize(bytes(&t.join("link")), &[], me(), g).is_empty());
        // Positive control: the same folder through a name without ':' stays.
        folders(&t.join("plain"));
        assert_eq!(
            sanitize(bytes(&t.join("plain")), &[], me(), g),
            [t.join("plain")]
        );
        std::fs::remove_dir_all(&t).unwrap();
    }

    // 이것을 실패시키는 것: walk의 names_folder 검사 둘(명령, 마지막 symlink 대상) 중 하나를 지우는 것
    // (`/…/x/`가 파일 x로 풀림).
    #[test]
    fn commands_and_links_naming_a_folder_are_refused() {
        let t = scratch("slash");
        let x = t.join("x");
        exe(&x, 0o755);
        let g = &mut RefuseGroupWrite;
        assert_eq!(resolve(&x, &[], me(), g).unwrap().executable, x);
        for tail in ["/", "/."] {
            let mut p = x.clone().into_os_string();
            p.push(tail);
            assert_eq!(
                lookup(p.as_bytes(), &[], &[], me(), g),
                Err(Miss::Refused),
                "{p:?}"
            );
        }
        for (name, tail) in [("l", "/"), ("ld", "/.")] {
            let mut target = x.clone().into_os_string();
            target.push(tail);
            symlink(&target, t.join(name)).unwrap();
            assert_eq!(
                resolve(&t.join(name), &[], me(), g),
                Err(Miss::Refused),
                "{tail}"
            );
        }
        std::fs::remove_dir_all(&t).unwrap();
    }

    // 양성 대조: 폴더를 가리키는 끝 '/'는 폴더 자리에서는 정상이다. 이것을 실패시키는 것: walk의 명령
    // 검사나 링크 검사에서 `!want_folder`를 지우는 것(PATH 항목 `…/safe/bin/`이나 `link -> …/safe/bin/`이
    // 빠짐), 링크 검사에서 `todo.is_empty()`를 지우는 것(중간 링크 `link -> …/safe/bin/`을 지난
    // `link/tool`이 거부됨).
    #[test]
    fn folder_slashes_pass_where_a_folder_is_meant() {
        let t = scratch("folder-slash");
        let bin = t.join("safe/bin");
        exe(&bin.join("tool"), 0o755);
        let mut with_slash = bin.clone().into_os_string();
        with_slash.push("/");
        symlink(&with_slash, t.join("link")).unwrap();
        let g = &mut RefuseGroupWrite;
        assert_eq!(
            sanitize(with_slash.as_bytes(), &[], me(), g),
            std::slice::from_ref(&bin)
        );
        assert_eq!(
            sanitize(bytes(&t.join("link")), &[], me(), g),
            std::slice::from_ref(&bin)
        );
        let found = resolve(&t.join("link/tool"), &[], me(), g).unwrap();
        assert_eq!(found.executable, bin.join("tool"));
        std::fs::remove_dir_all(&t).unwrap();
    }

    // 이것을 실패시키는 것: miss가 EACCES(PermissionDenied)를 Refused로 두는 것(들어갈 수 없는 앞 폴더에서
    // 찾기가 멈춤). root는 검색 권한을 무시하므로 root가 아닌 사용자로 돌려야 뜻이 있다.
    #[test]
    fn unsearchable_folders_are_skipped() {
        let t = scratch("nosearch");
        let (a, b) = (t.join("a"), t.join("b"));
        exe(&a.join("x"), 0o755);
        exe(&b.join("x"), 0o755);
        std::fs::set_permissions(&a, std::fs::Permissions::from_mode(0o600)).unwrap();
        let found = lookup(
            b"x",
            &[a.clone(), b.clone()],
            &[],
            me(),
            &mut RefuseGroupWrite,
        );
        std::fs::set_permissions(&a, std::fs::Permissions::from_mode(0o755)).unwrap();
        if me() != 0 {
            assert_eq!(found.unwrap().executable, b.join("x"));
        }
        std::fs::remove_dir_all(&t).unwrap();
    }

    // 이것을 실패시키는 것: walk의 LINKS_MAX 상한을 지우는 것(고리를 끝없이 돎).
    #[test]
    fn symlink_loops_are_refused() {
        let t = scratch("loop");
        symlink(t.join("b"), t.join("a")).unwrap();
        symlink(t.join("a"), t.join("b")).unwrap();
        assert_eq!(
            resolve(&t.join("a/x"), &[], me(), &mut RefuseGroupWrite),
            Err(Miss::Refused)
        );
        std::fs::remove_dir_all(&t).unwrap();
    }

    // root 소유 1777 폴더 아래 실행 파일은 본인 소유만 실행된다. chown과 root 소유 파일이 필요해 Linux
    // 컨테이너에서 root로 --ignored로 돌린다. 폴더는 sticky가 아닌 "/" 바로 아래에 둔다(/tmp 아래면 사용자
    // 12345 쪽에서 /tmp의 의무가 먼저 걸린다). 이것을 실패시키는 것: candidate의 sticky 상위 의무를 지우는
    // 것(사용자 12345에게 root 소유 파일이 실행됨).
    #[test]
    #[ignore = "needs root (chown to another uid); run in the Linux container"]
    fn sticky_folder_files_must_be_mine() {
        assert_eq!(me(), 0, "run as root");
        let t = PathBuf::from(format!("/bingsu-exec-path-sticky-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&t);
        folders(&t);
        let sticky = t.join("sticky");
        folders(&sticky);
        std::fs::set_permissions(&sticky, std::fs::Permissions::from_mode(0o1777)).unwrap();
        let (root_file, theirs) = (sticky.join("root"), sticky.join("theirs"));
        exe(&root_file, 0o755);
        exe(&theirs, 0o755);
        std::os::unix::fs::chown(&theirs, Some(12345), Some(12345)).unwrap();
        let g = &mut RefuseGroupWrite;
        // For root: its own file runs, the other uid's file is refused.
        assert_eq!(
            resolve(&root_file, &[], 0, g).unwrap().executable,
            root_file
        );
        assert_eq!(resolve(&theirs, &[], 0, g), Err(Miss::Refused));
        // For uid 12345: its own file runs; root's file, fine by owner alone, is
        // refused by the sticky folder's duty.
        assert_eq!(resolve(&theirs, &[], 12345, g).unwrap().executable, theirs);
        assert_eq!(resolve(&root_file, &[], 12345, g), Err(Miss::Refused));
        std::fs::remove_dir_all(&t).unwrap();
    }

    // 이것을 실패시키는 것: resolve가 Recording 없이 판정해 pin을 비우는 것, target_pin을 빼는 것,
    // 또는 그룹 쓰기 파일을 오라클 답 없이 받는 것.
    #[test]
    fn group_writable_target_gets_its_pin() {
        let t = scratch("pin");
        let x = t.join("x");
        exe(&x, 0o775);
        assert_eq!(
            resolve(&x, &[], me(), &mut RefuseGroupWrite),
            Err(Miss::Refused)
        );
        let found = resolve(&x, &[], me(), &mut Clear).unwrap();
        let file = File::open(&x).unwrap();
        let facts = sys::fd_facts(file.as_fd()).unwrap();
        let stamp = sys::file_stamp(&file).unwrap();
        let pin = found.pin.unwrap();
        assert_eq!(pin.group, bingsu_core::fs_trust::GroupPin::of(&facts));
        assert_eq!((pin.ctime_sec, i64::from(pin.ctime_nsec)), stamp.ctime);
        std::fs::remove_dir_all(&t).unwrap();
    }

    /// `chmod +a <entry> <path>` (macOS extended ACL).
    #[cfg(target_os = "macos")]
    fn add_acl(entry: &str, path: &Path) {
        // It spawns /bin/chmod (see sys::test_inherited_fd_lock).
        let _serial = sys::test_inherited_fd_lock();
        let st = std::process::Command::new("/bin/chmod")
            .args(["+a", entry])
            .arg(path)
            .status()
            .unwrap();
        assert!(st.success(), "chmod +a {entry} {path:?}");
    }

    // 다른 사용자(nobody)에게 확장 속성 쓰기만 허용한 ACL은 실행 파일에 있어도, 상위 폴더에 있어도 거부.
    // 이것을 실패시키는 것: sys::macos_acl::WRITE_CLASS에서 ACL_WRITE_EXTATTRIBUTES(1 << 10)를 빼는 것.
    #[cfg(target_os = "macos")]
    #[test]
    fn test_macos_acl_write_extattr_refused() {
        let t = scratch("acl-xattr");
        let (x, y) = (t.join("x"), t.join("d/y"));
        exe(&x, 0o755);
        exe(&y, 0o755);
        let g = &mut RefuseGroupWrite;
        // Positive control: without the ACL both run.
        assert_eq!(resolve(&x, &[], me(), g).unwrap().executable, x);
        assert_eq!(resolve(&y, &[], me(), g).unwrap().executable, y);
        add_acl("nobody allow writeextattr", &x);
        add_acl("nobody allow writeextattr", &t.join("d"));
        assert_eq!(resolve(&x, &[], me(), g), Err(Miss::Refused));
        assert_eq!(resolve(&y, &[], me(), g), Err(Miss::Refused));
        std::fs::remove_dir_all(&t).unwrap();
    }

    // 실행 파일 두 단계 위 폴더만 그룹 쓰기이고 그 그룹에 다른 구성원이 있으면(RefuseGroupWrite가 그렇게
    // 답한다) 거부. 양성 대조: 같은 폴더를 오라클이 통과시키면 실행. 이것을 실패시키는 것: walk가 마지막
    // 이름을 담은 폴더에서만 ancestor_verdict를 부르는 것(걷기를 한 단계에서 멈춤).
    #[cfg(target_os = "macos")]
    #[test]
    fn test_macos_parent_walk() {
        let t = scratch("parent-walk");
        let top = t.join("top");
        let x = top.join("mid/x");
        exe(&x, 0o755);
        std::fs::set_permissions(&top, std::fs::Permissions::from_mode(0o775)).unwrap();
        assert_eq!(
            resolve(&x, &[], me(), &mut RefuseGroupWrite),
            Err(Miss::Refused)
        );
        assert_eq!(resolve(&x, &[], me(), &mut Clear).unwrap().executable, x);
        std::fs::remove_dir_all(&t).unwrap();
    }

    // 네트워크 파일 시스템(MNT_LOCAL 없음)의 실행 파일은 거부하고, 같은 폴더의 실행할 수 없는 파일은 거부
    // 없이 건너뛴다. 이 Mac에는 그런 마운트가 없어(`mount`에 local이 아닌 것은 autofs
    // /System/Volumes/Data/home뿐, 실행 파일을 둘 수 없음) 무시한다. SMB·NFS 마운트가 있는 칸에서
    // BINGSU_NETWORK_FS_EXE=<그 안의 실행 파일, 본인 소유 0755, 그 폴더에 쓸 수 있음>로 --ignored로 돌린다.
    // 소유권을 무시하는 마운트(SMB 등에서 흔함)면 소유권 판정이 먼저 거부해 locality 검사가 시험되지 않으므로,
    // 같은 fixture에서 walk 성공과 candidate == Run을 먼저 단언해 거부 원인이 locality 하나뿐임을 보인다.
    // 이것을 실패시키는 것: resolve의 fd_is_local 검사 제거(실행 파일이 통과), 그 검사를 Candidate::Run
    // 분기 앞으로 되돌리는 것(0644 파일에서 찾기가 Refused로 멈춤). 네트워크 FS 칸에서만 확인할 수 있고,
    // 이 Mac은 BLOCKED다(검사를 지워도 이 Mac의 시험은 모두 통과, 2026-11-04 확인).
    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "needs an executable on a network file system (BINGSU_NETWORK_FS_EXE)"]
    #[allow(
        clippy::disallowed_methods,
        reason = "a manual test reads where the mount is from its runner"
    )]
    fn test_macos_network_fs_refused() {
        let x = PathBuf::from(std::env::var_os("BINGSU_NETWORK_FS_EXE").expect("set it"));
        assert_eq!(sys::fs_is_local(&x), Some(false), "not a network mount");
        let g = &mut RefuseGroupWrite;
        let Ok((_, End::File { file, next, .. })) = walk(&x, me(), g, false) else {
            panic!("the walk to {x:?} fails before the file");
        };
        let f = sys::fd_facts(file.as_fd()).unwrap();
        assert_eq!(f.ownership, Some(true), "the mount ignores ownership");
        assert_eq!(rule::candidate(&f, me(), next, g), Candidate::Run);
        assert_eq!(resolve(&x, &[], me(), g), Err(Miss::Refused));
        // A file there that would not run is skipped, not refused.
        let net = x.parent().unwrap().to_path_buf();
        let name = format!("bingsu-skip-{}", std::process::id());
        exe(&net.join(&name), 0o644);
        let local = scratch("net-skip");
        exe(&local.join(&name), 0o755);
        let found = lookup(name.as_bytes(), &[net.clone(), local.clone()], &[], me(), g);
        std::fs::remove_file(net.join(&name)).unwrap();
        assert_eq!(found.unwrap().executable, local.join(&name));
        std::fs::remove_dir_all(&local).unwrap();
    }

    /// A runtime root stand-in: a fresh 0700 folder and its search descriptor.
    #[cfg(target_os = "macos")]
    fn root_at(t: &Path) -> File {
        std::fs::set_permissions(t, std::fs::Permissions::from_mode(0o700)).unwrap();
        sys::open_dir_at_search_nofollow(None, t.as_os_str()).unwrap()
    }

    #[cfg(target_os = "macos")]
    fn runtime_root(tag: &str) -> (PathBuf, File) {
        let t = scratch(tag);
        let fd = root_at(&t);
        (t, fd)
    }

    #[cfg(target_os = "macos")]
    fn mode_of(p: &Path) -> u32 {
        std::fs::symlink_metadata(p).unwrap().permissions().mode() & 0o7777
    }

    /// `body` as an executable script at `p`, checked by `resolve_open`.
    #[cfg(target_os = "macos")]
    fn script_at(p: &Path, body: &[u8]) -> Checked {
        std::fs::write(p, body).unwrap();
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o755)).unwrap();
        resolve_open(p, &[], me(), &mut RefuseGroupWrite).unwrap().1
    }

    /// Runs one `#[ignore]` child test of this module in a fresh process
    /// (it changes process-wide state: umask, file size limit).
    #[cfg(target_os = "macos")]
    /// `hard_fsize`: a finite soft and hard file size limit (512-byte blocks) the
    /// child inherits, set by `/bin/sh` before it execs the child.
    fn run_child(name: &str, hard_fsize: Option<u32>) {
        let _serial = sys::test_inherited_fd_lock();
        let exe = std::env::current_exe().unwrap();
        let mut cmd = match hard_fsize {
            None => std::process::Command::new(&exe),
            Some(blocks) => {
                let mut sh = std::process::Command::new("/bin/sh");
                sh.args(["-c", &format!("ulimit -f {blocks} && exec \"$0\" \"$@\"")])
                    .arg(&exe);
                sh
            }
        };
        let out = cmd
            .args([
                "--ignored",
                "--exact",
                &format!("commands::exec_path::tests::{name}"),
                "--test-threads=1",
                "--nocapture",
            ])
            .output()
            .unwrap();
        assert!(out.status.success(), "{out:?}");
    }

    /// The parent's scratch folder `tag`, seen from a child.
    #[cfg(target_os = "macos")]
    fn parent_scratch(tag: &str) -> PathBuf {
        let ppid = std::os::unix::process::parent_id();
        let dir = std::env::temp_dir().join(format!("bingsu-exec-path-{ppid}-{tag}"));
        std::fs::canonicalize(dir).unwrap()
    }

    // 이것을 실패시키는 것: ScriptCopies::open의 fchmod 모드를 0o755로 바꾸는 것(final_verdict가 거부해
    // open이 실패), copy의 파일 모드를 0o644로 바꾸는 것, copy의 처음으로 되감기를 지우는 것(shebang을 먼저
    // 읽은 fd에서 앞 두 바이트가 빠짐).
    #[cfg(target_os = "macos")]
    #[test]
    fn test_macos_script_copy_is_private() {
        use std::io::Read;
        let (t, root) = runtime_root("script-copy");
        let script = t.join("tool.sh");
        let checked = script_at(&script, b"#!/bin/sh\necho hi\n");
        let copies = ScriptCopies::open(root.as_fd(), me()).unwrap();
        assert_eq!(mode_of(&t.join("scripts")), 0o700);
        checked.file().read_exact(&mut [0; 2]).unwrap();
        let copy = copies.copy(&checked, "t").unwrap();
        let folder = std::fs::canonicalize(t.join("scripts")).unwrap();
        assert_eq!(copy.parent(), Some(folder.as_path()));
        assert!(copy.file_name().unwrap().as_bytes().starts_with(b"t-"));
        assert_eq!(mode_of(&copy), 0o600);
        assert_eq!(
            std::fs::read(&copy).unwrap(),
            std::fs::read(&script).unwrap()
        );
        // A second open finds the folder it made and accepts it.
        assert!(ScriptCopies::open(root.as_fd(), me()).is_ok());
        std::fs::remove_dir_all(&t).unwrap();
    }

    // C2 리뷰 High: 검사한 뒤 바뀐 원본(본문을 읽은 직후의 다시 쓰기)은 복사하지 않는다. 양성 대조: 그대로 두면
    // 복사된다. 이것을 실패시키는 것: copy의 복사 뒤 stat 비교를 지우는 것, 그 비교를 본문 읽기 앞으로 옮기는 것.
    #[cfg(target_os = "macos")]
    #[test]
    fn test_macos_copy_refuses_a_script_changed_after_its_check() {
        let (t, root) = runtime_root("changed");
        let copies = ScriptCopies::open(root.as_fd(), me()).unwrap();
        let script = t.join("tool.sh");
        assert!(
            copies
                .copy(&script_at(&script, b"#!/bin/sh\necho a\n"), "t")
                .is_ok()
        );
        let checked = script_at(&script, b"#!/bin/sh\necho a\n");
        let path = script.clone();
        AFTER_READ.with(|h| {
            *h.borrow_mut() = Some(Box::new(move || {
                std::thread::sleep(std::time::Duration::from_millis(5));
                std::fs::write(&path, b"#!/bin/sh\necho b\n").unwrap();
            }));
        });
        let got = copies.copy(&checked, "t");
        AFTER_READ.with(|h| *h.borrow_mut() = None);
        assert_eq!(got, Err(Miss::Refused));
        std::fs::remove_dir_all(&t).unwrap();
    }

    // C2 리뷰 Medium: faccessat이 판정한 경로가 아직 검사한 파일이어야 한다. 판정 직후 상위 폴더를 옮기고 같은
    // 경로에 다른 스크립트를 두면(검사한 inode의 ctime은 그대로라 복사 뒤 비교로는 못 잡는다) 복사하지 않는다.
    // 이것을 실패시키는 것: may_execute의 판정 뒤 (dev, ino) 비교를 지우는 것.
    #[cfg(target_os = "macos")]
    #[test]
    fn test_macos_access_check_names_the_checked_file() {
        let (t, root) = runtime_root("access-swap");
        let copies = ScriptCopies::open(root.as_fd(), me()).unwrap();
        let folder = t.join("a");
        std::fs::create_dir(&folder).unwrap();
        let script = folder.join("tool.sh");
        let checked = script_at(&script, b"#!/bin/sh\necho a\n");
        let (folder2, moved) = (folder.clone(), t.join("b"));
        AFTER_ACCESS.with(|h| {
            *h.borrow_mut() = Some(Box::new(move || {
                std::fs::rename(&folder2, &moved).unwrap();
                std::fs::create_dir(&folder2).unwrap();
                let other = folder2.join("tool.sh");
                std::fs::write(&other, b"#!/bin/sh\necho b\n").unwrap();
                std::fs::set_permissions(&other, std::fs::Permissions::from_mode(0o700)).unwrap();
            }));
        });
        let got = copies.copy(&checked, "t");
        AFTER_ACCESS.with(|h| *h.borrow_mut() = None);
        assert_eq!(got, Err(Miss::Refused));
        std::fs::remove_dir_all(&t).unwrap();
    }

    // C2 재리뷰 Low: 검사가 끝난 뒤 copy() 전에 바뀐 원본도 복사하지 않는다. 비교 기준은 걷기 때의 Stamp다. 이것을
    // 실패시키는 것: copy가 Checked의 Stamp 대신 copy 시작 때 새로 읽은 stat과 비교하는 것.
    #[cfg(target_os = "macos")]
    #[test]
    fn test_macos_copy_refuses_a_script_changed_before_the_copy() {
        let (t, root) = runtime_root("changed-early");
        let copies = ScriptCopies::open(root.as_fd(), me()).unwrap();
        let script = t.join("tool.sh");
        let checked = script_at(&script, b"#!/bin/sh\necho a\n");
        std::thread::sleep(std::time::Duration::from_millis(5));
        std::fs::write(&script, b"#!/bin/sh\necho b\n").unwrap();
        assert_eq!(copies.copy(&checked, "t"), Err(Miss::Refused));
        std::fs::remove_dir_all(&t).unwrap();
    }

    // C2 리뷰 Medium: 원본 스크립트의 실행 권한은 커널에 묻는다. 소유자 실행 비트가 없는 0611(남에게만 실행)과
    // 0011은 복사하지 않는다. 양성 대조: 0711. 이것을 실패시키는 것: may_execute의 faccessat 검사를 지우는 것.
    #[cfg(target_os = "macos")]
    #[test]
    fn test_macos_script_needs_its_own_execute_bit() {
        let (t, root) = runtime_root("xbit");
        let copies = ScriptCopies::open(root.as_fd(), me()).unwrap();
        for (mode, ok) in [(0o711, true), (0o611, false), (0o011, false)] {
            let script = t.join(format!("tool-{mode:o}"));
            std::fs::write(&script, b"#!/bin/sh\necho a\n").unwrap();
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(mode)).unwrap();
            let copied = resolve_open(&script, &[], me(), &mut Clear)
                .ok()
                .and_then(|(_, checked)| copies.copy(&checked, "t").ok());
            assert_eq!(copied.is_some(), ok, "{mode:o}");
        }
        std::fs::remove_dir_all(&t).unwrap();
    }

    // C2 리뷰 Medium: noexec 마운트 위의 원본 스크립트는 복사하지 않는다(사용자가 붙인 dmg를 noexec로 다시
    // 마운트). 양성 대조: noexec가 아닌 같은 dmg. 이것을 실패시키는 것: may_execute의 faccessat 검사를 지우는 것
    // (따로 둔 MNT_NOEXEC 검사를 지운 변이는 살아남아 그 검사는 넣지 않았다).
    #[cfg(target_os = "macos")]
    #[test]
    fn test_macos_noexec_script_refused() {
        for noexec in [false, true] {
            let (t, root) = runtime_root(if noexec { "noexec" } else { "exec" });
            let copies = ScriptCopies::open(root.as_fd(), me()).unwrap();
            let volume = sys::TestVolume::new(&t, true, noexec);
            let script = volume.mount.join("tool");
            std::fs::write(&script, b"#!/bin/sh\necho a\n").unwrap();
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
            let (_, checked) = resolve_open(&script, &[], me(), &mut Clear).unwrap();
            assert_eq!(
                copies.copy(&checked, "t").is_ok(),
                !noexec,
                "noexec {noexec}"
            );
            drop(checked);
            drop(volume);
            std::fs::remove_dir_all(&t).unwrap();
        }
    }

    // C2 판정 Q1: sweep은 자기 태그의 사본만, 한 번에 SWEEP_MAX개까지 지운다. 이것을 실패시키는 것: 접두사
    // 비교를 지우는 것(다른 세션의 사본이 지워짐), 상한 검사를 지우는 것(70개가 한 번에 지워짐).
    #[cfg(target_os = "macos")]
    #[test]
    fn sweep_removes_only_its_tag() {
        let (t, root) = runtime_root("sweep");
        let copies = ScriptCopies::open(root.as_fd(), me()).unwrap();
        let folder = t.join("scripts");
        for i in 0..70 {
            std::fs::write(folder.join(format!("mine-{i:032x}")), b"x").unwrap();
        }
        std::fs::write(folder.join("other-0"), b"x").unwrap();
        std::fs::write(folder.join("minex-0"), b"x").unwrap();
        assert_eq!(copies.sweep("mine"), SWEEP_MAX);
        assert_eq!(copies.sweep("mine"), 70 - SWEEP_MAX);
        let mut left: Vec<_> = std::fs::read_dir(&folder)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        left.sort();
        assert_eq!(left, ["minex-0", "other-0"]);
        std::fs::remove_dir_all(&t).unwrap();
    }

    // umask 0o177이면 mkdir 0o700이 0600 폴더를 만든다. 이번 호출이 만든 폴더만 0700으로 맞춘다. 이것을
    // 실패시키는 것: ScriptCopies::open의 fchmod를 지우는 것(0600 폴더를 final_verdict가 거부).
    #[cfg(target_os = "macos")]
    #[test]
    fn script_folder_made_under_a_tight_umask_is_0700() {
        let t = scratch("umask");
        run_child("umask_child", None);
        assert_eq!(mode_of(&t.join("scripts")), 0o700);
        std::fs::remove_dir_all(&t).unwrap();
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "child: opens the script folder under umask 0o177"]
    fn umask_child() {
        let t = parent_scratch("umask");
        let root = root_at(&t);
        sys::test_umask(0o177);
        assert!(ScriptCopies::open(root.as_fd(), me()).is_ok());
        sys::exit_now(0);
    }

    // 이미 있는 scripts 폴더가 0755이거나, 남에게 파일 추가를 허용하는 ACL(상속 전용 줄 포함)이 있거나,
    // 다른 0700 폴더를 가리키는 symlink면 고치지 않고 거부. 이것을 실패시키는 것: ScriptCopies::open의
    // final_verdict 확인을 지우는 것, fchmod를 이번 호출이 만든 폴더 조건 없이 하는 것(0755가 고쳐짐),
    // 폴더를 이름으로 따라가며 여는 것(symlink가 통과).
    #[cfg(target_os = "macos")]
    #[test]
    fn script_folder_others_can_change_is_refused() {
        let (t, root) = runtime_root("script-loose");
        let scripts = t.join("scripts");
        let refused = || matches!(ScriptCopies::open(root.as_fd(), me()), Err(Miss::Refused));
        let fresh = || {
            let _ = std::fs::remove_dir_all(&scripts);
            std::fs::create_dir(&scripts).unwrap();
            std::fs::set_permissions(&scripts, std::fs::Permissions::from_mode(0o700)).unwrap();
        };
        fresh();
        std::fs::set_permissions(&scripts, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(refused());
        assert_eq!(mode_of(&scripts), 0o755);
        fresh();
        assert!(ScriptCopies::open(root.as_fd(), me()).is_ok());
        add_acl("nobody allow add_file", &scripts);
        assert!(refused());
        fresh();
        add_acl("nobody allow write,file_inherit,only_inherit", &scripts);
        assert!(refused());
        std::fs::remove_dir_all(&scripts).unwrap();
        let other = t.join("other");
        std::fs::create_dir(&other).unwrap();
        std::fs::set_permissions(&other, std::fs::Permissions::from_mode(0o700)).unwrap();
        symlink(&other, &scripts).unwrap();
        assert!(refused());
        std::fs::remove_dir_all(&t).unwrap();
    }

    // 이것을 실패시키는 것: read_capped의 SCRIPT_MAX 검사를 지우는 것(65,537바이트가 복사됨), 또는 `>`를
    // `>=`로 바꾸는 것(정확히 65,536바이트가 거부됨).
    #[cfg(target_os = "macos")]
    #[test]
    fn script_copy_over_64k_refused() {
        let (t, root) = runtime_root("script-big");
        let copies = ScriptCopies::open(root.as_fd(), me()).unwrap();
        let script = t.join("big.sh");
        let max = usize::try_from(SCRIPT_MAX).unwrap();
        let copy = copies
            .copy(&script_at(&script, &vec![b'#'; max]), "t")
            .unwrap();
        assert_eq!(std::fs::metadata(&copy).unwrap().len(), SCRIPT_MAX);
        assert_eq!(
            copies.copy(&script_at(&script, &vec![b'#'; max + 1]), "t"),
            Err(Miss::Refused)
        );
        std::fs::remove_dir_all(&t).unwrap();
    }

    /// Serves `#` without end, but panics when asked for more than
    /// `SCRIPT_MAX + 1` bytes in all.
    #[cfg(target_os = "macos")]
    struct Endless(u64);

    #[cfg(target_os = "macos")]
    impl std::io::Read for Endless {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            assert!(self.0 <= SCRIPT_MAX, "read past SCRIPT_MAX + 1");
            buf.fill(b'#');
            self.0 += buf.len() as u64;
            Ok(buf.len())
        }
    }

    // 이것을 실패시키는 것: read_capped의 `.take(SCRIPT_MAX + 1)`을 지우는 것(끝없는 입력을 끝까지 읽음).
    #[cfg(target_os = "macos")]
    #[test]
    fn script_reads_stop_one_byte_past_the_limit() {
        assert_eq!(read_capped(Endless(0)), Err(Miss::Refused));
    }

    // 쓰기가 중간에 실패하면 짧은 복사본을 남기지 않는다. 자식에서 파일 크기 상한(RLIMIT_FSIZE)을 16바이트로
    // 두어 쓰기를 EFBIG로 실패시킨다. 이것을 실패시키는 것: copy의 쓰기 실패 분기에서 unlink_at을 지우는 것,
    // sys::test_limit_file_size가 물려받은 유한한 hard limit을 RLIM_INFINITY로 올리는 것(EPERM).
    #[cfg(target_os = "macos")]
    #[test]
    fn failed_copy_leaves_nothing() {
        let t = scratch("short-copy");
        // A finite inherited hard limit: the helper must lower only the soft one.
        run_child("short_copy_child", Some(4096));
        assert_eq!(std::fs::read_dir(t.join("scripts")).unwrap().count(), 0);
        std::fs::remove_dir_all(&t).unwrap();
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "child: copies a script under a 16-byte file size limit"]
    fn short_copy_child() {
        let t = parent_scratch("short-copy");
        let root = root_at(&t);
        let checked = script_at(&t.join("tool.sh"), &[b'#'; 1000]);
        let copies = ScriptCopies::open(root.as_fd(), me()).unwrap();
        sys::test_limit_file_size(16);
        assert_eq!(copies.copy(&checked, "t"), Err(Miss::Refused));
        sys::exit_now(0);
    }

    // 이것을 실패시키는 것: open_target의 O_PATH 재시도를 지우는 것, first_bytes가 O_PATH fd의 EBADF를
    // 거부로 보는 것(실행 전용 파일은 #! 줄을 읽지 않고 네이티브로만). root는 읽기 권한을 무시하므로
    // root가 아닌 사용자로 돌려야 뜻이 있다.
    #[cfg(target_os = "linux")]
    #[test]
    fn execute_only_target_resolves() {
        let t = scratch("xonly");
        let x = t.join("x");
        exe(&x, 0o111);
        assert_eq!(
            resolve(&x, &[], me(), &mut RefuseGroupWrite)
                .unwrap()
                .executable,
            x
        );
        std::fs::remove_dir_all(&t).unwrap();
    }

    fn script(path: &Path, body: &str) {
        folders(path.parent().unwrap());
        std::fs::write(path, body).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    fn interpreter_of(path: &Path) -> Result<Option<Interpreter>, Miss> {
        resolve(path, &[], me(), &mut RefuseGroupWrite).map(|f| f.interpreter)
    }

    // 도우미가 #! 줄의 인터프리터를 같은 규칙으로 해석해 줄 원문과 정규 경로를 함께 싣는다. 이것을 실패시키는
    // 것: resolve가 interpreter를 비우는 것, line에 정규 경로를 넣는 것(본인 소유 링크의 이름이 사라짐),
    // path에 원문을 넣는 것(중계가 링크를 거부).
    #[test]
    fn test_script_interpreter_resolved() {
        let t = scratch("script");
        let cat = std::fs::canonicalize("/bin/cat").unwrap();
        symlink(&cat, t.join("link")).unwrap();
        let s = t.join("s");
        script(&s, &format!("#!{} -\n", t.join("link").display()));
        let mut line = bytes(&t.join("link")).to_vec();
        line.extend_from_slice(b" -");
        let want = Interpreter {
            line,
            path: bytes(&cat).to_vec(),
            pin: None,
        };
        assert_eq!(interpreter_of(&s), Ok(Some(want)));
        script(&s, "#!/bin/sh\necho 1\n");
        let sh = std::fs::canonicalize("/bin/sh").unwrap();
        let got = interpreter_of(&s).unwrap().unwrap();
        assert_eq!(
            (got.line.as_slice(), got.path.as_slice()),
            (&b"/bin/sh"[..], bytes(&sh))
        );
        assert_eq!(interpreter_of(&cat), Ok(None));
        std::fs::remove_dir_all(&t).unwrap();
    }

    // 이것을 실패시키는 것: interpreter의 네이티브 검사(중첩 #!)를 지우는 것, 정규 경로 `/usr/bin/env` 거부를
    // 지우는 것(본인 소유 링크 이름의 env가 통과), 해석 실패를 Refused 대신 그대로 넘기는 것(없는 인터프리터가
    // Absent가 되어 다음 PATH 폴더로 넘어감), head의 Refused를 네이티브로 보는 것. 남이 쓸 수 있는
    // 인터프리터(`open`)는 resolve_file의 같은 규칙이 거부한다.
    #[test]
    fn test_script_interpreter_refused() {
        let t = scratch("script-refused");
        let s = t.join("s");
        script(&t.join("nested"), "#!/bin/sh\n");
        symlink(
            std::fs::canonicalize("/usr/bin/env").unwrap(),
            t.join("env"),
        )
        .unwrap();
        exe(&t.join("open"), 0o777);
        for line in [
            format!("#!{}\n", t.join("nested").display()),
            format!("#!{} sh\n", t.join("env").display()),
            format!("#!{}\n", t.join("missing").display()),
            format!("#!{}\n", t.join("open").display()),
            "#!/usr/bin/env sh\n".to_owned(),
            // merged-/usr: `/bin/env` is `/usr/bin/env` (elsewhere it is missing).
            "#!/bin/env sh\n".to_owned(),
        ] {
            script(&s, &line);
            assert_eq!(interpreter_of(&s), Err(Miss::Refused), "{line}");
        }
        std::fs::remove_dir_all(&t).unwrap();
    }
}
