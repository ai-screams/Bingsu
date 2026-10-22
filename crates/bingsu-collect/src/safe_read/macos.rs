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
/// B2 validates ownership and sentinel contents before supplying this fd.
pub fn probe(fixture: Option<BorrowedFd<'_>>, meter: &mut Meter) -> Result<Access, ReadError> {
    probe_flags(fixture, [BENEATH, NOFOLLOW_ANY, UNIQUE], meter)
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
        let attempt = |path: &std::ffi::CStr, flag, meter: &mut Meter| {
            openat(
                fd,
                path,
                libc::O_RDONLY | libc::O_NONBLOCK | libc::O_CLOEXEC | flag,
                meter,
            )
        };
        // Both positive and exact negative semantics are mandatory. Ignored
        // unknown bits cannot pass the escape/symlink/hardlink tests.
        let beneath = attempt(c"value", flags[0], meter).is_ok()
            && attempt(c"dir/../value", flags[0], meter).is_ok()
            && attempt(c"dir/inner", flags[0], meter).is_ok()
            && [c"../outside", c"/", c"absolute", c"escape", c"/dev/fd/0"]
                .iter()
                .all(|p| matches!(attempt(p, flags[0], meter), Err(ReadError::Escape)));
        let nofollow_any = attempt(c"dir/file", flags[1], meter).is_ok()
            && matches!(
                attempt(c"linkdir/file", flags[1], meter),
                Err(ReadError::Symlink)
            );
        let unique = attempt(c"value", flags[2], meter).is_ok()
            && matches!(attempt(c"hard", flags[2], meter), Err(ReadError::Escape));
        meter.check()?;
        access.darwin = DarwinCaps {
            beneath,
            nofollow_any,
            unique,
        };
        if beneath {
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
