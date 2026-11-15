//! The catalog's byte form: pure encode and decode, no I/O. A small checked
//! binary catalog, independent of the worker wire. The bytes are checked
//! (magic, size cap, CRC) before any name in them is trusted, and no input
//! string is a filesystem path until the grammar and exact root bytes
//! validate; the grammar and counter checks reuse the parent's rules
//! (`component`, `descend`, `entry_valid`, `location`). The types it reads
//! and builds stay private to the parent module.
use super::{
    CATALOG_MAX, Catalog, Cursor, Entry, MAX_DEPTH, MAX_SCAN_DEPTH, MAX_STORES, RESERVATION,
    component, descend, entry_valid, location,
};
use crate::commands::snapshot_store::StoreError;
use bingsu_core::snapshot::{self, Clock};

fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), StoreError> {
    if out.len().saturating_add(4).saturating_add(bytes.len()) > CATALOG_MAX {
        return Err(StoreError::Unsafe);
    }
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}
fn put_clock(out: &mut Vec<u8>, clock: Clock) {
    out.extend_from_slice(&clock.boot);
    out.push(clock.kind);
    out.extend_from_slice(&clock.domain);
    out.extend_from_slice(&clock.resume.to_le_bytes());
    out.extend_from_slice(&clock.now.to_le_bytes());
}
pub(super) fn encode(c: &Catalog) -> Result<Vec<u8>, StoreError> {
    let mut out = b"BNGCGC04\0\0\0\0".to_vec();
    for n in [c.dev, c.ino, c.stores, c.nodes, c.bytes] {
        out.extend_from_slice(&n.to_le_bytes());
    }
    out.extend_from_slice(&c.next.to_le_bytes());
    out.extend_from_slice(&[u8::from(c.ready), u8::from(c.unsafe_seen)]);
    out.extend_from_slice(&(c.entries.len() as u32).to_le_bytes());
    for e in &c.entries {
        out.extend_from_slice(&(e.path.len() as u32).to_le_bytes());
        for part in &e.path {
            put_bytes(&mut out, part.as_bytes())?;
        }
        put_bytes(&mut out, &e.cwd)?;
        for n in [e.dev, e.ino, e.bytes] {
            out.extend_from_slice(&n.to_le_bytes());
        }
        out.push(u8::from(e.reserved));
        put_clock(&mut out, e.used);
    }
    out.extend_from_slice(&(c.prune.len() as u32).to_le_bytes());
    for part in &c.prune {
        put_bytes(&mut out, part.as_bytes())?;
    }
    out.extend_from_slice(&(c.cursor.len() as u32).to_le_bytes());
    for cursor in &c.cursor {
        put_bytes(&mut out, cursor.name.as_bytes())?;
        for n in [
            cursor.dev,
            cursor.ino,
            cursor.mtime.0 as u64,
            cursor.mtime.1 as u64,
            cursor.position,
            cursor.stores,
            cursor.nodes,
            cursor.bytes,
            cursor.entries as u64,
            cursor.unknown as u64,
        ] {
            out.extend_from_slice(&n.to_le_bytes());
        }
        out.extend_from_slice(&[u8::from(cursor.finished), u8::from(cursor.unsafe_seen)]);
        out.extend_from_slice(&(cursor.pending.len() as u32).to_le_bytes());
        for name in &cursor.pending {
            put_bytes(&mut out, name.as_bytes())?;
        }
        out.extend_from_slice(&(cursor.prune.len() as u32).to_le_bytes());
        for name in &cursor.prune {
            put_bytes(&mut out, name.as_bytes())?;
        }
    }
    out.extend_from_slice(&(c.unknown.len() as u32).to_le_bytes());
    for path in &c.unknown {
        out.extend_from_slice(&(path.len() as u32).to_le_bytes());
        for part in path {
            put_bytes(&mut out, part.as_bytes())?;
        }
    }
    if out.len() > CATALOG_MAX {
        return Err(StoreError::Unsafe);
    }
    let crc = snapshot::crc32c(&[&out[12..]]);
    out[8..12].copy_from_slice(&crc);
    Ok(out)
}
struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], StoreError> {
        let out = self.0.get(..n).ok_or(StoreError::Unsafe)?;
        self.0 = &self.0[n..];
        Ok(out)
    }
    fn u64(&mut self) -> Result<u64, StoreError> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn count(&mut self, max: usize) -> Result<usize, StoreError> {
        let n = u32::from_le_bytes(self.take(4)?.try_into().unwrap()) as usize;
        if n > max {
            return Err(StoreError::Unsafe);
        }
        Ok(n)
    }
    fn flag(&mut self) -> Result<bool, StoreError> {
        match self.take(1)?[0] {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(StoreError::Unsafe),
        }
    }
    fn bytes(&mut self, cap: usize) -> Result<Vec<u8>, StoreError> {
        let n = self.count(cap)?;
        Ok(self.take(n)?.to_vec())
    }
    fn string(&mut self) -> Result<String, StoreError> {
        String::from_utf8(self.bytes(120)?).map_err(|_| StoreError::Unsafe)
    }
    fn clock(&mut self) -> Result<Clock, StoreError> {
        let boot = self.take(16)?.try_into().unwrap();
        let kind = self.take(1)?[0];
        let domain = self.take(16)?.try_into().unwrap();
        if !matches!(kind, 1 | 2) {
            return Err(StoreError::Unsafe);
        }
        Ok(Clock {
            boot,
            kind,
            domain,
            resume: self.u64()?,
            now: self.u64()?,
        })
    }
}
pub(super) fn decode(bytes: &[u8]) -> Result<Catalog, StoreError> {
    if bytes.len() < 12
        || bytes.len() > CATALOG_MAX
        || !matches!(&bytes[..8], b"BNGCGC03" | b"BNGCGC04")
        || snapshot::crc32c(&[&bytes[12..]]) != bytes[8..12]
    {
        return Err(StoreError::Unsafe);
    }
    let mut r = Reader(&bytes[12..]);
    let mut c = Catalog {
        dev: r.u64()?,
        ino: r.u64()?,
        stores: r.u64()?,
        nodes: r.u64()?,
        bytes: r.u64()?,
        next: r.count(MAX_STORES as usize)? as u32,
        ready: r.flag()?,
        unsafe_seen: r.flag()?,
        entries: vec![],
        prune: vec![],
        cursor: vec![],
        unknown: vec![],
    };
    let count = r.count(MAX_STORES as usize)?;
    for _ in 0..count {
        let count = r.count(MAX_DEPTH)?;
        let mut path = Vec::new();
        for _ in 0..count {
            let part = r.string()?;
            if !component(&part) {
                return Err(StoreError::Unsafe);
            }
            path.push(part);
        }
        let e = Entry {
            path,
            cwd: r.bytes(65_536)?,
            dev: r.u64()?,
            ino: r.u64()?,
            bytes: r.u64()?,
            reserved: r.flag()?,
            used: r.clock()?,
        };
        if !entry_valid(&e)
            || e.bytes > RESERVATION
            || c.entries.iter().any(|other| other.path == e.path)
        {
            return Err(StoreError::Unsafe);
        }
        c.entries.push(e);
    }
    let count = r.count(MAX_DEPTH)?;
    for _ in 0..count {
        c.prune.push(r.string()?);
    }
    if !c.prune.is_empty() {
        let mut path = c.prune.clone();
        if path.last().is_some_and(|n| n == "collections-v1") {
            path.push("0".repeat(64));
        }
        path.push("store".into());
        location(&path)?;
    }
    let count = r.count(MAX_DEPTH)?;
    let mut path = Vec::new();
    for i in 0..count {
        let mut cursor = Cursor {
            name: r.string()?,
            dev: r.u64()?,
            ino: r.u64()?,
            mtime: (r.u64()? as i64, r.u64()? as i64),
            position: r.u64()?,
            stores: r.u64()?,
            nodes: r.u64()?,
            bytes: r.u64()?,
            entries: usize::try_from(r.u64()?).map_err(|_| StoreError::Unsafe)?,
            unknown: usize::try_from(r.u64()?).map_err(|_| StoreError::Unsafe)?,
            finished: r.flag()?,
            unsafe_seen: r.flag()?,
            pending: vec![],
            prune: vec![],
        };
        let count = r.count(512)?;
        let mut total = 0;
        for _ in 0..count {
            let bytes = r.bytes(255)?;
            total += bytes.len();
            let name = String::from_utf8(bytes).map_err(|_| StoreError::Unsafe)?;
            if name.is_empty()
                || name == "."
                || name == ".."
                || name.contains(['/', '\0'])
                || total > 8192
            {
                return Err(StoreError::Unsafe);
            }
            cursor.pending.push(name);
        }
        if (i == 0 && !cursor.name.is_empty())
            || (i > 0 && !descend(&path, &cursor.name))
            || cursor.position > i64::MAX as u64
            || cursor.entries > c.entries.len()
            || cursor.unknown > MAX_STORES as usize
            || cursor.stores > c.stores
            || cursor.nodes > c.nodes
            || cursor.bytes > c.bytes
        {
            return Err(StoreError::Unsafe);
        }
        if i > 0 {
            path.push(cursor.name.clone());
        }
        if &bytes[..8] == b"BNGCGC04" {
            let count = r.count(CATALOG_MAX / 4)?;
            for _ in 0..count {
                let name = r.string()?;
                if !descend(&path, &name) {
                    return Err(StoreError::Unsafe);
                }
                cursor.prune.push(name);
            }
        }
        c.cursor.push(cursor);
    }
    let count = r.count(MAX_STORES as usize)?;
    for _ in 0..count {
        let count = r.count(MAX_SCAN_DEPTH)?;
        if count < 2 {
            return Err(StoreError::Unsafe);
        }
        let mut path = Vec::new();
        for _ in 0..count {
            let name = r.string()?;
            if !descend(&path, &name) {
                return Err(StoreError::Unsafe);
            }
            path.push(name);
        }
        c.unknown.push(path);
    }
    if c.next > c.entries.len() as u32
        || !r.0.is_empty()
        || c.ready != c.cursor.is_empty()
        || c.stores < c.entries.len() as u64
        || c.bytes < c.entries.iter().map(|e| e.bytes).sum::<u64>()
    {
        return Err(StoreError::Unsafe);
    }
    Ok(c)
}
