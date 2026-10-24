//! Darwin getattrlistbulk records, packed at four-byte field alignment.
//! ABI: Apple XNU bsd/man/man2/{getattrlist,getattrlistbulk}.2 and sys/attr.h.
//! No FSOPT_PACK_INVAL_ATTRS: only returned fields occupy the packed record.
use super::*;

// ATTR_CMN_ERROR is missing in libc 0.2.190 (Darwin sys/attr.h).
const ERROR: u32 = 0x2000_0000;
const COMMON: u32 = libc::ATTR_CMN_RETURNED_ATTRS
    | libc::ATTR_CMN_NAME
    | libc::ATTR_CMN_OBJTYPE
    | libc::ATTR_CMN_DEVID
    | libc::ATTR_CMN_FILEID
    | libc::ATTR_CMN_MODTIME
    | libc::ATTR_CMN_CHGTIME
    | libc::ATTR_CMN_OWNERID
    | libc::ATTR_CMN_GRPID
    | libc::ATTR_CMN_ACCESSMASK
    | ERROR;
const INVALID: ReadError = ReadError::Io(libc::EIO);
const UNSUPPORTED: ReadError = ReadError::Io(libc::ENOTSUP);

#[repr(align(8))]
struct Buffer([u8; crate::meter::DIRENT_CHUNK]);

pub(super) fn visit_batch(
    root: &Root,
    meter: &mut Meter,
    mut visitor: impl FnMut(&[u8], Result<&libc::stat, ReadError>, &mut Meter) -> Result<(), ReadError>,
) -> Result<bool, ReadError> {
    let mut attrs = libc::attrlist {
        bitmapcount: libc::ATTR_BIT_MAP_COUNT,
        reserved: 0,
        commonattr: COMMON,
        volattr: 0,
        dirattr: libc::ATTR_DIR_DATALENGTH,
        fileattr: libc::ATTR_FILE_DATALENGTH,
        forkattr: 0,
    };
    let mut buffer = Buffer([0; crate::meter::DIRENT_CHUNK]);
    meter.event("before_worktree_bulk");
    let count = retry(meter, Op::List, || {
        // SAFETY: verified, readable directory with a fresh OFD; fully
        // initialized attrlist, aligned bounded writable output. The API
        // returns symlink metadata itself, regardless of NOFOLLOW.
        unsafe {
            libc::getattrlistbulk(
                root.fd.as_raw_fd(),
                (&mut attrs as *mut libc::attrlist).cast(),
                buffer.0.as_mut_ptr().cast(),
                buffer.0.len(),
                libc::FSOPT_NOFOLLOW as u64,
            ) as isize
        }
    })? as usize;
    meter.event("after_worktree_bulk");
    if count == 0 {
        return Ok(false);
    }
    if count > buffer.0.len() / 24 {
        return Err(INVALID);
    }
    // Charge the entire returned batch BEFORE decoding/matching any entry,
    // including names absent from the index. Never fall back on exhaustion.
    meter.raw_entries(count as u64)?;
    meter.charge_axis(bingsu_core::collection::budget::Axis::Stats, count as u64)?;
    let mut remaining = buffer.0.as_slice();
    for _ in 0..count {
        let record = Record::parse(remaining)?;
        #[cfg(test)]
        let record = {
            let mut r = record;
            if let Some(device) = meter.worktree_device {
                r.metadata.st_dev = device as _;
            }
            r
        };
        visitor(record.name, record.result(), meter)?;
        remaining = &remaining[record.length..];
    }
    Ok(true)
}

struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
}
impl Cursor<'_> {
    fn bytes<const N: usize>(&mut self) -> Result<[u8; N], ReadError> {
        let end = self.at.checked_add(N).ok_or(INVALID)?;
        let value = self
            .bytes
            .get(self.at..end)
            .ok_or(INVALID)?
            .try_into()
            .map_err(|_| INVALID)?;
        self.at = end;
        Ok(value)
    }
    fn u32(&mut self) -> Result<u32, ReadError> {
        Ok(u32::from_ne_bytes(self.bytes()?))
    }
    fn u64(&mut self) -> Result<u64, ReadError> {
        Ok(u64::from_ne_bytes(self.bytes()?))
    }
    fn time(&mut self) -> Result<(i64, i64), ReadError> {
        let sec = self.u64()? as i64;
        let nsec = self.u64()? as i64;
        if !(0..1_000_000_000).contains(&nsec) {
            return Err(INVALID);
        }
        Ok((sec, nsec))
    }
}

struct Record<'a> {
    length: usize,
    name: &'a [u8],
    metadata: libc::stat,
    error: Option<ReadError>,
}
impl<'a> Record<'a> {
    fn result(&self) -> Result<&libc::stat, ReadError> {
        self.error.map_or(Ok(&self.metadata), Err)
    }
    fn parse(block: &'a [u8]) -> Result<Self, ReadError> {
        let mut c = Cursor {
            bytes: block,
            at: 0,
        };
        let length = c.u32()? as usize;
        if length < 24 || length % 8 != 0 {
            return Err(INVALID);
        }
        c.bytes = block.get(..length).ok_or(INVALID)?;
        let common = c.u32()?;
        let vol = c.u32()?;
        let dir = c.u32()?;
        let file = c.u32()?;
        let fork = c.u32()?;
        if common & !COMMON != 0
            || vol != 0
            || fork != 0
            || dir & !libc::ATTR_DIR_DATALENGTH != 0
            || file & !libc::ATTR_FILE_DATALENGTH != 0
            || common & libc::ATTR_CMN_RETURNED_ATTRS == 0
        {
            return Err(INVALID);
        }
        // ERROR is the exceptional first field after RETURNED_ATTRS, not bit order.
        let errno = if common & ERROR != 0 { c.u32()? } else { 0 };
        if common & libc::ATTR_CMN_NAME == 0 {
            return Err(INVALID);
        }
        let reference = c.at;
        let offset = c.u32()? as i32;
        let namesize = c.u32()? as usize;
        // SAFETY: plain C output record, filled only for fields actually present.
        let mut metadata: libc::stat = unsafe { std::mem::zeroed() };
        if common & libc::ATTR_CMN_DEVID != 0 {
            metadata.st_dev = c.u32()? as _;
        }
        let kind = if common & libc::ATTR_CMN_OBJTYPE != 0 {
            c.u32()?
        } else {
            0
        };
        if common & libc::ATTR_CMN_MODTIME != 0 {
            (metadata.st_mtime, metadata.st_mtime_nsec) = c.time()?;
        }
        if common & libc::ATTR_CMN_CHGTIME != 0 {
            (metadata.st_ctime, metadata.st_ctime_nsec) = c.time()?;
        }
        if common & libc::ATTR_CMN_OWNERID != 0 {
            metadata.st_uid = c.u32()?;
        }
        if common & libc::ATTR_CMN_GRPID != 0 {
            metadata.st_gid = c.u32()?;
        }
        let permissions = if common & libc::ATTR_CMN_ACCESSMASK != 0 {
            c.u32()?
        } else {
            0
        };
        if common & libc::ATTR_CMN_FILEID != 0 {
            metadata.st_ino = c.u64()?;
        }
        // Darwin vtype enum (sys/vnode.h), not dirent DT_* or st_mode bits.
        let mode = match kind {
            1 => libc::S_IFREG,
            2 => libc::S_IFDIR,
            3 => libc::S_IFBLK,
            4 => libc::S_IFCHR,
            5 => libc::S_IFLNK,
            6 => libc::S_IFSOCK,
            7 => libc::S_IFIFO,
            _ => 0,
        };
        metadata.st_mode = (permissions as libc::mode_t & 0o7777) | mode;
        if dir != 0 {
            metadata.st_size = c.u64()? as i64;
        }
        if file != 0 {
            metadata.st_size = c.u64()? as i64;
        }
        if metadata.st_size < 0 || (dir != 0 && kind != 2) || (file != 0 && kind == 2) {
            return Err(INVALID);
        }
        let name_start = reference
            .checked_add_signed(offset as isize)
            .ok_or(INVALID)?;
        let end = name_start.checked_add(namesize).ok_or(INVALID)?;
        if name_start < c.at || !(2..=4097).contains(&namesize) {
            return Err(INVALID);
        }
        let terminated = c.bytes.get(name_start..end).ok_or(INVALID)?;
        let name = &terminated[..namesize - 1];
        if terminated[namesize - 1] != 0
            || name.contains(&0)
            || name.contains(&b'/')
            || name == b"."
            || name == b".."
        {
            return Err(INVALID);
        }
        let required = COMMON & !ERROR;
        let error = if errno != 0 {
            Some(ReadError::errno(errno as i32))
        } else if common & required != required
            || mode == 0
            || (kind == 2 && dir == 0)
            || (kind != 2 && file == 0)
        {
            Some(UNSUPPORTED)
        } else {
            None
        };
        Ok(Self {
            length,
            name,
            metadata,
            error,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(common: u32, dir: bool) -> Vec<u8> {
        let mut bytes = vec![0; 4];
        for value in [
            common,
            0,
            if dir { libc::ATTR_DIR_DATALENGTH } else { 0 },
            if dir { 0 } else { libc::ATTR_FILE_DATALENGTH },
            0,
        ] {
            bytes.extend(value.to_ne_bytes());
        }
        if common & ERROR != 0 {
            bytes.extend(0u32.to_ne_bytes());
        }
        let reference = bytes.len();
        bytes.extend([0; 8]);
        if common & libc::ATTR_CMN_DEVID != 0 {
            bytes.extend(123u32.to_ne_bytes());
        }
        if common & libc::ATTR_CMN_OBJTYPE != 0 {
            bytes.extend(if dir { 2u32 } else { 1u32 }.to_ne_bytes());
        }
        for bit in [libc::ATTR_CMN_MODTIME, libc::ATTR_CMN_CHGTIME] {
            if common & bit != 0 {
                bytes.extend(123456u64.to_ne_bytes());
                bytes.extend(789u64.to_ne_bytes());
            }
        }
        for (bit, value) in [
            (libc::ATTR_CMN_OWNERID, 501u32),
            (libc::ATTR_CMN_GRPID, 20),
            (libc::ATTR_CMN_ACCESSMASK, 0o6754),
        ] {
            if common & bit != 0 {
                bytes.extend(value.to_ne_bytes());
            }
        }
        if common & libc::ATTR_CMN_FILEID != 0 {
            bytes.extend(0x1234_5678_9abc_def0u64.to_ne_bytes());
        }
        bytes.extend(42u64.to_ne_bytes());
        let offset = (bytes.len() - reference) as i32;
        bytes[reference..reference + 4].copy_from_slice(&offset.to_ne_bytes());
        bytes[reference + 4..reference + 8].copy_from_slice(&5u32.to_ne_bytes());
        bytes.extend(b"name\0");
        bytes.resize(bytes.len().next_multiple_of(8), 0);
        let length = bytes.len() as u32;
        bytes[..4].copy_from_slice(&length.to_ne_bytes());
        bytes
    }

    // 이것을 실패시키는 것: packed offset·partial attr·폭/순서·permission/type 구분을 무시하는 것.
    #[test]
    fn bulk_packed_fields_and_partial_returns() {
        for directory in [false, true] {
            let bytes = frame(COMMON, directory);
            let record = Record::parse(&bytes).unwrap();
            let m = record.result().unwrap();
            assert_eq!(record.name, b"name");
            assert_eq!(
                (m.st_dev, m.st_ino, m.st_uid, m.st_gid, m.st_size),
                (123, 0x1234_5678_9abc_def0, 501, 20, 42)
            );
            assert_eq!(
                (m.st_mtime, m.st_mtime_nsec, m.st_ctime, m.st_ctime_nsec),
                (123456, 789, 123456, 789)
            );
            assert_eq!(
                m.st_mode,
                (if directory {
                    libc::S_IFDIR
                } else {
                    libc::S_IFREG
                }) | 0o6754
            );
        }
        for bit in [
            libc::ATTR_CMN_DEVID,
            libc::ATTR_CMN_MODTIME,
            libc::ATTR_CMN_CHGTIME,
            libc::ATTR_CMN_OWNERID,
            libc::ATTR_CMN_GRPID,
            libc::ATTR_CMN_ACCESSMASK,
            libc::ATTR_CMN_FILEID,
            libc::ATTR_CMN_OBJTYPE,
        ] {
            let bytes = frame(COMMON & !bit, false);
            let record = Record::parse(&bytes).unwrap();
            assert_eq!(record.name, b"name");
            assert_eq!(record.result().err(), Some(UNSUPPORTED));
        }
        for (directory, field) in [(false, 16), (true, 12)] {
            let mut bytes = frame(COMMON, directory);
            bytes[field..field + 4].fill(0);
            assert_eq!(
                Record::parse(&bytes).unwrap().result().err(),
                Some(UNSUPPORTED)
            );
        }
        let mut bytes = frame(COMMON, false);
        bytes[24..28].copy_from_slice(&(libc::EACCES as u32).to_ne_bytes());
        assert_eq!(
            Record::parse(&bytes).unwrap().result().err(),
            Some(ReadError::Denied)
        );
        let bytes = frame(COMMON & !ERROR, false);
        assert!(Record::parse(&bytes).unwrap().result().is_ok());
    }

    // 이것을 실패시키는 것: record/name 길이·offset·종료 NUL·지원 bit·나노초 경계 검사 제거.
    #[test]
    fn bulk_truncated_oversized_and_malformed_buffers() {
        let valid = frame(COMMON, false);
        for n in 0..valid.len() {
            assert_eq!(
                Record::parse(&valid[..n]).err(),
                Some(INVALID),
                "prefix {n}"
            );
        }
        for (at, value) in [
            (0, 0u32),
            (0, u32::MAX),
            (0, 24),
            (0, 113),
            (4, COMMON | libc::ATTR_CMN_FSID),
            (4, COMMON & !libc::ATTR_CMN_NAME),
            (4, COMMON & !libc::ATTR_CMN_RETURNED_ATTRS),
            (8, 1),
            (12, 1),
            (16, 1),
            (20, 1),
            (28, u32::MAX),
            (28, 0),
            (28, i32::MIN as u32),
            (32, 0),
            (32, 1),
            (32, 4098),
            (32, u32::MAX),
            (52, 1_000_000_000),
        ] {
            let mut bad = valid.clone();
            bad[at..at + 4].copy_from_slice(&value.to_ne_bytes());
            assert_eq!(Record::parse(&bad).err(), Some(INVALID), "{at}={value}");
        }
        let name = 28 + i32::from_ne_bytes(valid[28..32].try_into().unwrap()) as usize;
        for (offset, value) in [(name, 0), (name, b'/'), (name + 4, b'x')] {
            let mut bad = valid.clone();
            bad[offset] = value;
            assert_eq!(Record::parse(&bad).err(), Some(INVALID));
        }
        let mut bad = valid.clone();
        bad[name..name + 4].copy_from_slice(b".\0\0\0");
        bad[32..36].copy_from_slice(&2u32.to_ne_bytes());
        assert_eq!(Record::parse(&bad).err(), Some(INVALID));
        // Extra backing capacity is permitted; the record's own bound wins.
        let mut extra = valid.clone();
        extra.extend([0xaa; 8192]);
        assert_eq!(Record::parse(&extra).unwrap().name, b"name");
        let unaligned = valid.len() as u32 + 1;
        extra[..4].copy_from_slice(&unaligned.to_ne_bytes());
        assert_eq!(Record::parse(&extra).err(), Some(INVALID));
        let mut overlap = valid.clone();
        overlap[28..32].copy_from_slice(&48i32.to_ne_bytes());
        overlap[76..80].copy_from_slice(b"name");
        overlap[80] = 0;
        assert_eq!(Record::parse(&overlap).err(), Some(INVALID));
        // Raw name framing does not require UTF-8, even on a host filesystem
        // that refuses creating such a filename.
        let mut raw = valid.clone();
        raw[name] = 0xff;
        assert_eq!(Record::parse(&raw).unwrap().name, b"\xffame");
    }
}

#[cfg(test)]
mod native_buffer_tests {
    use super::*;
    // 이것을 실패시키는 것: syscall buffer 크기를 실제 writable 범위보다 크게 넘기는 것.
    #[test]
    fn native_bulk_rejects_tiny_buffer() {
        let path = std::env::temp_dir().join(format!("bingsu-bulk-buffer-{}", std::process::id()));
        std::fs::create_dir(&path).unwrap();
        std::fs::write(path.join("file"), b"x").unwrap();
        let dir = std::fs::File::open(&path).unwrap();
        let mut attrs = libc::attrlist {
            bitmapcount: libc::ATTR_BIT_MAP_COUNT,
            reserved: 0,
            commonattr: COMMON,
            volattr: 0,
            dirattr: libc::ATTR_DIR_DATALENGTH,
            fileattr: libc::ATTR_FILE_DATALENGTH,
            forkattr: 0,
        };
        let mut buffer = [0x5au8; 16];
        // SAFETY: live fixture fd and initialized records; only the middle
        // four bytes are advertised to the kernel, with canaries on both sides.
        let result = unsafe {
            libc::getattrlistbulk(
                dir.as_raw_fd(),
                (&mut attrs as *mut libc::attrlist).cast(),
                buffer[4..].as_mut_ptr().cast(),
                4,
                libc::FSOPT_NOFOLLOW as u64,
            )
        };
        assert_eq!(result, -1);
        assert_eq!(errno(), libc::ERANGE);
        assert_eq!(&buffer[..4], &[0x5a; 4]);
        assert_eq!(&buffer[8..], &[0x5a; 8]);
        std::fs::remove_dir_all(path).unwrap();
    }
}
