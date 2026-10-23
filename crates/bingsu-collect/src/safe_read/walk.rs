//! Downward held-fd walk. Identity checks detect replacement, not ancestry or
//! ABA. Full reads require a separate kernel guarantee; ctime is not evidence.
use super::*;
use std::collections::VecDeque;

const DIR_FLAGS: i32 =
    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC;
const FILE_FLAGS: i32 = libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC;

fn components(
    path: &[u8],
    scratch: &mut PathAllocation,
    meter: &mut Meter,
) -> Result<VecDeque<Vec<u8>>, ReadError> {
    if path.len() > 65_536 || path.contains(&0) {
        return Err(ReadError::Escape);
    }
    let count = path
        .split(|&b| b == b'/')
        .filter(|part| !part.is_empty())
        .count();
    if count > 4096 {
        return Err(ReadError::Limit);
    }
    scratch.reserve(
        path.len() + 1 + (count + 1) * std::mem::size_of::<Vec<u8>>(),
        meter,
    )?;
    let mut result: VecDeque<_> = path
        .split(|&b| b == b'/')
        .filter(|part| !part.is_empty())
        .map(<[u8]>::to_vec)
        .collect();
    if path.ends_with(b"/") {
        result.push_back(b".".to_vec());
    }
    Ok(result)
}

pub(super) fn lstat(
    parent: RawFd,
    name: &std::ffi::CStr,
    meter: &mut Meter,
) -> Result<libc::stat, ReadError> {
    // SAFETY: stat is a plain C output record.
    let mut out = unsafe { std::mem::zeroed() };
    retry(meter, Op::Stat, || {
        // SAFETY: live dirfd, terminated one-component name, writable record.
        unsafe {
            libc::fstatat(parent, name.as_ptr(), &mut out, libc::AT_SYMLINK_NOFOLLOW) as isize
        }
    })?;
    Ok(out)
}

fn unchanged(before: &libc::stat, after: &libc::stat) -> bool {
    before.st_dev == after.st_dev && before.st_ino == after.st_ino
}

/// Reduced stage A: exactly one fixed name, never readlink or a path walk.
pub(super) fn one_component(
    root: &Root,
    name: &[u8],
    is_dir: bool,
    meter: &mut Meter,
) -> Result<Opened, ReadError> {
    if name.is_empty() || name.contains(&b'/') || name == b"." || name == b".." {
        return Err(ReadError::Escape);
    }
    let name = cstring(name, meter)?;
    let before = lstat(root.fd.as_raw_fd(), &name, meter)?;
    if before.st_mode & libc::S_IFMT == libc::S_IFLNK {
        return Err(ReadError::Symlink);
    }
    meter.event("before_open_component");
    let flags = if is_dir { DIR_FLAGS } else { FILE_FLAGS };
    let opened = inspect(openat(root.fd.as_raw_fd(), &name, flags, meter)?, meter)?;
    if !unchanged(&before, &opened.metadata) {
        return Err(ReadError::Changed);
    }
    same_mount(opened.identity, root.identity)?;
    meter.event("after_open_component");
    Ok(opened)
}

/// Worktree cache edge: exactly one component from a verified parent. The
/// same lstat/open/fstat/device/mount checks as the full component walk apply.
/// This is a metadata capability; it does not prove atomic root ancestry.
pub(super) fn worktree_component(
    parent: &Root,
    name: &std::ffi::CStr,
    is_dir: bool,
    access: &Access,
    meter: &mut Meter,
) -> Result<Opened, ReadError> {
    meter.charge(Op::Component)?;
    let before = lstat(parent.fd.as_raw_fd(), name, meter)?;
    match before.st_mode & libc::S_IFMT {
        libc::S_IFLNK => return Err(ReadError::Missing),
        libc::S_IFDIR if is_dir => {}
        libc::S_IFREG if !is_dir => {}
        _ => {
            return Err(if is_dir {
                ReadError::Missing
            } else {
                ReadError::Special
            });
        }
    }
    meter.event("before_open_component");
    let fd = match access.backend {
        #[cfg(target_os = "linux")]
        Resolver::Openat2 => linux::open_nofollow(parent, name.to_bytes(), is_dir, meter)?,
        _ => {
            let flags = if is_dir { DIR_FLAGS } else { FILE_FLAGS };
            #[cfg(target_os = "macos")]
            let flags = if access.darwin.nofollow_any {
                (flags & !libc::O_NOFOLLOW) | macos::NOFOLLOW_ANY
            } else {
                flags
            };
            openat(parent.fd.as_raw_fd(), name, flags, meter)?
        }
    };
    let opened = inspect(fd, meter)?;
    if !unchanged(&before, &opened.metadata) {
        return Err(ReadError::Changed);
    }
    same_mount(opened.identity, parent.identity)?;
    meter.event("after_open_component");
    Ok(opened)
}

fn target(
    parent: RawFd,
    name: &std::ffi::CStr,
    before: &libc::stat,
    scratch: &mut PathAllocation,
    meter: &mut Meter,
) -> Result<Vec<u8>, ReadError> {
    let mut buffer = [0; 4097];
    let size = retry(meter, Op::Readlink, || {
        // SAFETY: live directory, terminated name, writable bounded buffer.
        unsafe {
            libc::readlinkat(
                parent,
                name.as_ptr(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
            )
        }
    })? as usize;
    if size == buffer.len() {
        return Err(ReadError::Limit);
    }
    if !unchanged(before, &lstat(parent, name, meter)?) {
        return Err(ReadError::Changed);
    }
    scratch.reserve(size, meter)?;
    Ok(buffer[..size].to_vec())
}

fn visit(visits: &mut usize, meter: &mut Meter) -> Result<(), ReadError> {
    if *visits == 4096 {
        return Err(ReadError::Limit);
    }
    *visits += 1;
    meter.charge(Op::Component)
}

pub(super) fn acquire(
    cwd: &[u8],
    query: DiscoveryQuery,
    meter: &mut Meter,
) -> Result<Discovery, ReadError> {
    if !cwd.starts_with(b"/") || cwd.contains(&0) {
        return Err(ReadError::Escape);
    }
    let mut scratch = meter.path_allocation();
    let mut pending = components(cwd, &mut scratch, meter)?;
    let fd = openat(libc::AT_FDCWD, c"/", DIR_FLAGS, meter)?;
    meter.allocation(34 * std::mem::size_of::<Root>())?;
    let mut stack = VecDeque::with_capacity(34);
    stack.push_back(Root {
        identity: identity(fd.as_raw_fd(), meter)?,
        fd,
    });
    let slash = stack[0].identity;
    let mut dropped = 0;
    let mut visits = 0;
    let mut links = 0;
    let mut logical = !cwd
        .split(|&byte| byte == b'/')
        .any(|part| part == b"." || part == b"..");
    while let Some(part) = pending.pop_front() {
        visit(&mut visits, meter)?;
        if part == b"." {
            continue;
        }
        if part == b".." {
            logical = false;
            if stack.len() > 1 {
                stack.pop_back();
            } else if dropped != 0 {
                return Err(ReadError::Limit);
            }
            continue;
        }
        let name = cstring(&part, meter)?;
        let parent = stack.back().ok_or(ReadError::Changed)?.fd.as_raw_fd();
        let before = lstat(parent, &name, meter)?;
        if before.st_mode & libc::S_IFMT == libc::S_IFLNK {
            logical = false;
            links += 1;
            if links > 40 {
                return Err(ReadError::Symlink);
            }
            let path = target(parent, &name, &before, &mut scratch, meter)?;
            if path.starts_with(b"/") {
                // Absolute links are permitted only during acquisition, reset
                // to the fixed / capability rather than an ambient cwd.
                stack.clear();
                let fd = openat(libc::AT_FDCWD, c"/", DIR_FLAGS, meter)?;
                stack.push_back(Root {
                    identity: identity(fd.as_raw_fd(), meter)?,
                    fd,
                });
                dropped = 0;
            }
            let mut expanded = components(&path, &mut scratch, meter)?;
            expanded.append(&mut pending);
            pending = expanded;
            continue;
        }
        let Opened {
            fd,
            metadata: after,
            identity,
        } = inspect(openat(parent, &name, DIR_FLAGS, meter)?, meter)?;
        // Acquisition has no content root yet. Changes to unrelated entries
        // in a shared ancestor (e.g. /tmp) do not change this opened inode.
        if before.st_dev != after.st_dev || before.st_ino != after.st_ino {
            return Err(ReadError::Changed);
        }
        let node = Root { identity, fd };
        // No cross-mount comparison in acquisition. Every fd must nevertheless
        // have an identity and must not be procfs.
        stack.push_back(node);
        if stack.len() > 33 {
            stack.pop_front();
            dropped += 1;
        }
    }
    let cwd = stack.pop_back().ok_or(ReadError::Changed)?;
    meter.allocation(stack.len() * std::mem::size_of::<Root>())?;
    Ok(Discovery {
        cwd,
        ancestors: stack.into_iter().map(|root| AncestorDir { root }).collect(),
        logical,
        query,
        slash,
    })
}

struct Step {
    fd: Fd,
    name: PathCString,
}

pub(super) fn resolve(
    root: &Root,
    path: &[u8],
    is_dir: bool,
    access: &Access,
    single_link: bool,
    meter: &mut Meter,
) -> Result<Opened, ReadError> {
    resolve_inner(root, path, is_dir, access, single_link, false, meter)
}

pub(super) fn resolve_nofollow(
    root: &Root,
    path: &[u8],
    is_dir: bool,
    access: &Access,
    meter: &mut Meter,
) -> Result<Opened, ReadError> {
    resolve_inner(root, path, is_dir, access, false, true, meter)
}

#[allow(clippy::too_many_arguments)]
fn resolve_inner(
    root: &Root,
    path: &[u8],
    is_dir: bool,
    access: &Access,
    single_link: bool,
    nofollow: bool,
    meter: &mut Meter,
) -> Result<Opened, ReadError> {
    let mut scratch = meter.path_allocation();
    let mut pending = components(path, &mut scratch, meter)?;
    let mut stack: Vec<Step> = Vec::new();
    let mut links = 0;
    let mut visits = 0;
    loop {
        let Some(part) = pending.pop_front() else {
            if !is_dir {
                return Err(ReadError::Special);
            }
            let parent = stack
                .last()
                .map_or(root.fd.as_raw_fd(), |step| step.fd.as_raw_fd());
            let opened = inspect(openat(parent, c".", DIR_FLAGS, meter)?, meter)?;
            return finish(root, &stack, c".", opened, true, access, false, meter);
        };
        visit(&mut visits, meter)?;
        if part == b"." {
            continue;
        }
        if part == b".." {
            if stack.pop().is_none() {
                return Err(ReadError::Escape);
            }
            continue;
        }
        let parent = stack
            .last()
            .map_or(root.fd.as_raw_fd(), |step| step.fd.as_raw_fd());
        let name = cstring(&part, meter)?;
        let before = lstat(parent, &name, meter)?;
        let kind = before.st_mode & libc::S_IFMT;
        if kind == libc::S_IFLNK {
            if nofollow {
                return Err(ReadError::Symlink);
            }
            links += 1;
            if links > 40 {
                return Err(ReadError::Symlink);
            }
            let path = target(parent, &name, &before, &mut scratch, meter)?;
            if path.starts_with(b"/") {
                return Err(ReadError::Escape);
            }
            let mut expanded = components(&path, &mut scratch, meter)?;
            expanded.append(&mut pending);
            pending = expanded;
            continue;
        }
        let last = pending.is_empty();
        let need_directory = !last || is_dir;
        if need_directory && kind != libc::S_IFDIR {
            return Err(ReadError::Missing);
        }
        if !need_directory && kind != libc::S_IFREG {
            return Err(ReadError::Special);
        }
        meter.event("before_open_component");
        let flags = if need_directory {
            DIR_FLAGS
        } else {
            FILE_FLAGS
        };
        #[cfg(target_os = "macos")]
        let flags = if access.darwin.nofollow_any {
            (flags & !libc::O_NOFOLLOW) | macos::NOFOLLOW_ANY
        } else {
            flags
        };
        let fd = openat(parent, &name, flags, meter)?;
        let opened = inspect(fd, meter)?;
        let metadata = opened.metadata;
        if !unchanged(&before, &metadata) {
            return Err(ReadError::Changed);
        }
        let found = opened.identity;
        if found.device != root.identity.device || found.mount != root.identity.mount {
            return Err(ReadError::Escape);
        }
        meter.event("after_open_component");
        if last {
            if single_link && metadata.st_nlink != 1 {
                return Err(ReadError::Special);
            }
            return finish(
                root,
                &stack,
                &name,
                opened,
                is_dir,
                access,
                single_link,
                meter,
            );
        }
        scratch.reserve(std::mem::size_of::<Step>(), meter)?;
        stack.try_reserve_exact(1).map_err(|_| ReadError::Limit)?;
        stack.push(Step {
            fd: opened.fd,
            name,
        });
    }
}

#[allow(clippy::too_many_arguments)]
fn finish(
    root: &Root,
    stack: &[Step],
    name: &std::ffi::CStr,
    opened: Opened,
    is_dir: bool,
    access: &Access,
    single_link: bool,
    meter: &mut Meter,
) -> Result<Opened, ReadError> {
    #[cfg(target_os = "macos")]
    if access.guarantee() == Some(Guarantee::DarwinBeneath) {
        // Read ONLY the fd opened atomically from root. Per-component BENEATH
        // relative to a moved intermediate fd would not confine to this root.
        let size = stack
            .iter()
            .map(|s| s.name.to_bytes().len() + 1)
            .sum::<usize>()
            + name.to_bytes().len();
        let mut scratch = meter.path_allocation();
        scratch.reserve(size, meter)?;
        let mut canonical = Vec::with_capacity(size);
        for step in stack {
            canonical.extend_from_slice(step.name.to_bytes());
            canonical.push(b'/');
        }
        canonical.extend_from_slice(name.to_bytes());
        meter.event("before_beneath_open");
        let atomic = macos::open(root, &canonical, is_dir, single_link, access.darwin, meter)?;
        if atomic.identity != opened.identity {
            return Err(ReadError::Changed);
        }
        return Ok(atomic);
    }
    let _ = (root, stack, name, is_dir, access, single_link, meter);
    Ok(opened)
}

#[cfg(test)]
mod tests {
    use super::*;
    // 이것을 실패시키는 것: 단계 A primitive에 '/', '.', '..', 빈 이름을 허용하는 것.
    #[test]
    fn stage_a_component_rejects_paths_before_io() {
        let mut meter = Meter::new(std::time::Instant::now() + std::time::Duration::from_secs(30));
        let root = super::super::acquire(b"/dev", DiscoveryQuery::default(), &mut meter)
            .unwrap()
            .select_cwd()
            .unwrap();
        let before = meter.counts;
        for name in [b"".as_slice(), b".", b"..", b"./null", b"/null"] {
            assert!(matches!(
                one_component(&root, name, false, &mut meter),
                Err(ReadError::Escape)
            ));
        }
        assert_eq!(meter.counts, before);
    }
}
