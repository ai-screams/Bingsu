//! Runtime semantics, not SDK/OS version, grant Darwin authority. B2 supplies
//! its validated helper fixture fd; no fixture means stage A only.
use super::*;
use std::os::fd::BorrowedFd;

// Darwin UAPI values, including flags absent from older libc/SDK releases.
pub const BENEATH: i32 = 0x0000_1000;
pub const UNIQUE: i32 = 0x0000_2000;
pub const NOFOLLOW_ANY: i32 = 0x2000_0000;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DarwinCaps {
    pub beneath: bool,
    pub nofollow_any: bool,
    pub unique: bool,
}

/// Expected fixture: value (single link), dir/file, dir/inner -> ../value,
/// linkdir -> dir, absolute -> /, escape -> ../outside, hard (two links).
/// The helper prepares this fixed namespace; the worker revalidates it here.
pub fn probe(fixture: Option<BorrowedFd<'_>>, meter: &mut Meter) -> Result<Access, ReadError> {
    let previous = meter.phase;
    meter.phase = Phase::Probe;
    let result = (|| {
        let Some(fd) = fixture else {
            return Ok(Access::stage_a_only());
        };
        match validate_fixture(fd, meter) {
            Ok(()) => probe_flags(Some(fd), [BENEATH, NOFOLLOW_ANY, UNIQUE], meter),
            Err(e @ (ReadError::Deadline | ReadError::Limit)) => Err(e),
            Err(_) => Ok(Access::stage_a_only()),
        }
    })();
    meter.phase = previous;
    result
}

fn probe_flags(
    fixture: Option<BorrowedFd<'_>>,
    flags: [i32; 3],
    meter: &mut Meter,
) -> Result<Access, ReadError> {
    let mut access = Access::stage_a_only();
    let Some(fixture) = fixture else {
        return Ok(access);
    };
    let previous = meter.phase;
    meter.phase = Phase::Probe;
    let result = (|| {
        let fd = fixture.as_raw_fd();
        access.darwin = evaluate_flags(flags, |path, flag| attempt(fd, path, flag, meter))?;
        meter.check()?;
        if access.darwin.beneath {
            access.backend = Resolver::DarwinBeneath;
            access.guarantee = Some(Guarantee::DarwinBeneath);
        }
        Ok(access)
    })();
    meter.phase = previous;
    result
}

impl Access {
    pub fn darwin_caps(&self) -> DarwinCaps {
        self.darwin
    }
}

pub(super) fn open(
    root: &Root,
    canonical: &[u8],
    is_dir: bool,
    single_link: bool,
    caps: DarwinCaps,
    meter: &mut Meter,
) -> Result<Opened, ReadError> {
    let path = cstring(canonical, meter)?;
    let flags = libc::O_RDONLY
        | libc::O_NONBLOCK
        | libc::O_CLOEXEC
        | BENEATH
        | if caps.nofollow_any {
            NOFOLLOW_ANY
        } else {
            libc::O_NOFOLLOW
        }
        | if is_dir { libc::O_DIRECTORY } else { 0 }
        | if single_link && caps.unique {
            UNIQUE
        } else {
            0
        };
    // NOFOLLOW_ANY|NOFOLLOW is EINVAL on Darwin: select exactly one.
    let fd = openat(root.fd.as_raw_fd(), &path, flags, meter)?;
    inspect(fd, meter)
}

#[cfg(test)]
pub fn probe_flags_for_test(
    fixture: BorrowedFd<'_>,
    flags: [i32; 3],
    meter: &mut Meter,
) -> Result<Access, ReadError> {
    probe_flags(Some(fixture), flags, meter)
}

/// Raw semantic fixtures from B1 deliberately have no helper namespace.
#[cfg(test)]
pub fn probe_unvalidated_for_test(
    fixture: Option<BorrowedFd<'_>>,
    meter: &mut Meter,
) -> Result<Access, ReadError> {
    probe_flags(fixture, [BENEATH, NOFOLLOW_ANY, UNIQUE], meter)
}

fn evaluate_flags(
    flags: [i32; 3],
    mut observed: impl FnMut(&std::ffi::CStr, i32) -> Result<i32, ReadError>,
) -> Result<DarwinCaps, ReadError> {
    // Exact errno is evidence: EXDEV is not proof of ENOTCAPABLE.
    let mut beneath = true;
    for (path, expected) in [
        (c"value", 0),
        (c"dir/../value", 0),
        (c"dir/inner", 0),
        (c"../outside", libc::ENOTCAPABLE),
        (c"/", libc::ENOTCAPABLE),
        (c"absolute", libc::ENOTCAPABLE),
        (c"escape", libc::ENOTCAPABLE),
        (c"dir/up", libc::ENOTCAPABLE),
        (c"/dev/fd/0", libc::ENOTCAPABLE),
    ] {
        beneath &= observed(path, flags[0])? == expected;
    }
    let nofollow_any = observed(c"dir/file", flags[1])? == 0
        && observed(c"linkdir/file", flags[1])? == libc::ELOOP
        && observed(c"dir/file", flags[1] | libc::O_NOFOLLOW)? == libc::EINVAL;
    let unique =
        observed(c"value", flags[2])? == 0 && observed(c"hard", flags[2])? == libc::ENOTCAPABLE;
    Ok(DarwinCaps {
        beneath,
        nofollow_any,
        unique,
    })
}

#[cfg(test)]
pub fn caps_for_test(
    observed: impl FnMut(&std::ffi::CStr, i32) -> Result<i32, ReadError>,
) -> Result<DarwinCaps, ReadError> {
    evaluate_flags([BENEATH, NOFOLLOW_ANY, UNIQUE], observed)
}

fn attempt(
    fd: RawFd,
    path: &std::ffi::CStr,
    flag: i32,
    meter: &mut Meter,
) -> Result<i32, ReadError> {
    let _lease = meter.lease()?;
    retry(meter, Op::Open, || {
        // SAFETY: live fixture, bounded terminated path, read-only/nonblocking.
        let opened = unsafe {
            libc::openat(
                fd,
                path.as_ptr(),
                libc::O_RDONLY | libc::O_NONBLOCK | libc::O_CLOEXEC | flag,
            )
        };
        if opened >= 0 {
            // SAFETY: fresh fd, no other owner; no content is read by a flag test.
            drop(unsafe { OwnedFd::from_raw_fd(opened) });
            0
        } else {
            let error = errno();
            // Reuse the shared bounded EINTR policy. Preserve every other exact
            // errno as an observation, rather than normalizing it to ReadError.
            if error == libc::EINTR {
                -1
            } else {
                error as isize
            }
        }
    })
    .map(|value| value as i32)
}

fn private_directory(fd: RawFd, meter: &mut Meter) -> Result<Identity, ReadError> {
    let st = stat(fd, meter)?;
    // SAFETY: read-only process identity.
    let me = unsafe { libc::geteuid() };
    if st.st_mode & libc::S_IFMT != libc::S_IFDIR || st.st_mode & 0o7777 != 0o700 || st.st_uid != me
    {
        return Err(ReadError::Denied);
    }
    let found = identity_from(fd, &st, meter)?;
    // SAFETY: initialized output for a live descriptor.
    let mut fs: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: live fd and a writable statfs record.
    retry(meter, Op::Filesystem, || unsafe {
        libc::fstatfs(fd, &mut fs) as isize
    })?;
    if fs.f_flags & libc::MNT_LOCAL as u32 == 0 {
        return Err(ReadError::Denied);
    }
    Ok(found)
}

fn validate_fixture(fixture: BorrowedFd<'_>, meter: &mut Meter) -> Result<(), ReadError> {
    let root = fixture.as_raw_fd();
    let mut path = [0u8; libc::PATH_MAX as usize];
    retry(meter, Op::Stat, || {
        // SAFETY: descriptor-only query with a PATH_MAX writable buffer.
        unsafe { libc::fcntl(root, libc::F_GETPATH, path.as_mut_ptr()) as isize }
    })?;
    let end = path.iter().position(|b| *b == 0).ok_or(ReadError::Denied)?;
    if !path[..end].ends_with(b"/collector-probes-v1/open-flags/root") {
        return Err(ReadError::Denied);
    }
    let root_id = private_directory(root, meter)?;
    let dirs = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    // Startup-only fixed parent validation, never the repository resolver.
    // The only inherited fd is root, so these bounded parent opens verify the
    // helper namespace; content '..' continues to pop the held stack in bingsu.
    let parent = openat(root, c"..", dirs, meter)?;
    let namespace = openat(parent.as_raw_fd(), c"..", dirs, meter)?;
    let runtime = openat(namespace.as_raw_fd(), c"..", dirs, meter)?;
    for (child, base, name) in [
        (root, parent.as_raw_fd(), c"root"),
        (parent.as_raw_fd(), namespace.as_raw_fd(), c"open-flags"),
        (
            namespace.as_raw_fd(),
            runtime.as_raw_fd(),
            c"collector-probes-v1",
        ),
    ] {
        let expected = private_directory(child, meter)?;
        private_directory(base, meter)?;
        let named = openat(base, name, dirs, meter)?;
        if identity(named.as_raw_fd(), meter)? != expected {
            return Err(ReadError::Changed);
        }
        same_mount(root_id, expected)?;
    }
    let outside = openat(parent.as_raw_fd(), c"outside", dirs, meter)?;
    same_mount(root_id, private_directory(outside.as_raw_fd(), meter)?)?;
    let dir = openat(root, c"dir", dirs, meter)?;
    same_mount(root_id, private_directory(dir.as_raw_fd(), meter)?)?;
    let mut hard_id = None;
    for (base, name, expected, links) in [
        (root, c"value", b"inside".as_slice(), 1),
        (dir.as_raw_fd(), c"file", b"inside".as_slice(), 1),
        (root, c"hard", b"linked".as_slice(), 2),
        (root, c"hard2", b"linked".as_slice(), 2),
    ] {
        let fd = openat(
            base,
            name,
            libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            meter,
        )?;
        let st = stat(fd.as_raw_fd(), meter)?;
        // SAFETY: read-only effective identity.
        let me = unsafe { libc::geteuid() };
        if st.st_mode & libc::S_IFMT != libc::S_IFREG
            || st.st_mode & 0o7777 != 0o600
            || st.st_uid != me
            || st.st_nlink != links
            || st.st_size != 6
        {
            return Err(ReadError::Denied);
        }
        let found = identity_from(fd.as_raw_fd(), &st, meter)?;
        same_mount(root_id, found)?;
        if links == 2 {
            if hard_id.is_some_and(|id| id != found) {
                return Err(ReadError::Changed);
            }
            hard_id = Some(found);
        }
        // Exact known sentinel bytes are the preimage of the helper's fixed
        // SHA-256 check; bounded same-fd comparison also rejects a trailing byte.
        let mut bytes = [0; 7];
        meter.read_capacity(bytes.len())?;
        // SAFETY: live readable fd and exactly sized writable buffer.
        let n = retry(meter, Op::Read, || unsafe {
            libc::read(fd.as_raw_fd(), bytes.as_mut_ptr().cast(), bytes.len())
        })? as usize;
        meter.returned_bytes(n);
        if &bytes[..n] != expected {
            return Err(ReadError::Denied);
        }
    }
    for (base, name, expected) in [
        (dir.as_raw_fd(), c"inner", b"../value".as_slice()),
        (dir.as_raw_fd(), c"up", b"../../outside".as_slice()),
        (root, c"linkdir", b"dir".as_slice()),
        (root, c"absolute", b"/".as_slice()),
        (root, c"escape", b"../outside".as_slice()),
    ] {
        let mut bytes = [0; 32];
        // SAFETY: live parent, terminated fixed name, bounded output buffer.
        let n = retry(meter, Op::Readlink, || unsafe {
            libc::readlinkat(base, name.as_ptr(), bytes.as_mut_ptr().cast(), bytes.len())
        })? as usize;
        if &bytes[..n] != expected {
            return Err(ReadError::Denied);
        }
    }
    Ok(())
}
