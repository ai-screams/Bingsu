//! BNGCFG10: bounded CompiledConfig codec with an explicit fact schema version.
//!
//! HEAD, COMMON, INDEX (one entry per variant), the variants, the band names.
//! The snapshot header checksum covers HEAD, COMMON and INDEX; each variant and
//! the name block have their own CRC, kept in INDEX and COMMON. So the front
//! decodes COMMON and one variant and proves both without touching the rest,
//! and the helper's whole decode checks every section.
use crate::{
    bands::Band,
    color::{
        math::{OklchQ, Srgb8},
        palette::{AnsiSlot, PaletteWarning, ResolvedPalette, ResolvedToken},
    },
    config::{
        compile::{
            CompiledConfig, CustomKind, CustomSegment, ExecPolicy, ExecUnit, LayoutRef, NotRun,
            Setup, Side,
        },
        merge::Origin,
        schema::FACT_SCHEMA_VERSION,
        source::Trust,
    },
    diag::SourceId,
    diag_widths::WidthRun,
    icons::IconSet,
    ident::{Namespace, parse_segment_id},
    layout::When,
    layout_view::FrontConfig,
    shorten::{Keep, Method},
    template::{
        compile::{CompiledLine, FillKind, MAX_LINES, Node, Shape, StyleSpec},
        syntax::{Mode, Span},
    },
    width::WidthProfile,
};
use alloc::{collections::BTreeSet, string::String, vec::Vec};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Short,
    Tag,
    Limit,
    Utf8,
    Shape,
    Trailing,
}
pub const MAX_BYTES: usize = 16 * 1024 * 1024;
const MAX_ALLOC: usize = 64 * 1024 * 1024;
/// Magic, version, fact schema, COMMON length, variant count.
pub const HEAD: usize = 20;
/// Offset, length and CRC of one variant, then four reserved zero bytes.
const ENTRY: usize = 16;
const MAGIC: &[u8; 8] = b"BNGCFG10";
const VERSION: u16 = 10;
/// CRC of one variant or of the name block.
pub fn section_sum(section: &[u8]) -> [u8; 4] {
    crate::snapshot::crc32c(&[b"bingsu-compiled-v10\0", section])
}
struct Reader<'a> {
    rest: &'a [u8],
    budget: usize,
    /// Segment numbers below this exist (built-ins, then user text segments).
    segs: usize,
}
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        if n > self.rest.len() {
            return Err(Error::Short);
        }
        let (v, r) = self.rest.split_at(n);
        self.rest = r;
        Ok(v)
    }
    fn charge(&mut self, n: usize) -> Result<(), Error> {
        self.budget = self.budget.checked_sub(n).ok_or(Error::Limit)?;
        Ok(())
    }
}
// `size_of` below accounts for native heap usage only; it never defines wire bytes.
struct Writer {
    bytes: Option<Vec<u8>>,
    len: usize,
    error: Option<Error>,
    /// Segment numbers below this exist where nodes are written now: the
    /// built-ins in COMMON, then the config's text segments in the variants.
    /// Checked while writing, not while sizing; the decode checks the same
    /// per line (`LineCheck`). `usize::MAX` checks nothing (tests that forge
    /// bytes).
    segs: usize,
}
impl Writer {
    fn extend_from_slice(&mut self, b: &[u8]) {
        if self.error.is_some() {
            return;
        }
        let Some(n) = self.len.checked_add(b.len()).filter(|n| *n <= MAX_BYTES) else {
            self.error = Some(Error::Limit);
            return;
        };
        if let Some(out) = &mut self.bytes {
            out.extend_from_slice(b);
        }
        self.len = n;
    }
    /// Fills bytes reserved earlier; the sizing pass has none to fill.
    fn patch(&mut self, at: usize, b: &[u8]) {
        if let Some(slot) = self
            .bytes
            .as_mut()
            .and_then(|out| out.get_mut(at..at + b.len()))
        {
            slot.copy_from_slice(b);
        }
    }
    fn sum_since(&self, at: usize) -> [u8; 4] {
        match self.bytes.as_ref().and_then(|out| out.get(at..)) {
            Some(written) => section_sum(written),
            None => [0; 4],
        }
    }
}
fn put_slice<T: Wire>(items: &[T], o: &mut Writer) {
    items.len().put(o);
    for x in items {
        if o.error.is_some() {
            break;
        }
        x.put(o);
    }
}
trait Wire: Sized {
    fn put(&self, o: &mut Writer);
    fn get(r: &mut Reader<'_>) -> Result<Self, Error>;
}

impl Wire for u8 {
    fn put(&self, o: &mut Writer) {
        o.extend_from_slice(&self.to_le_bytes())
    }
    fn get(r: &mut Reader<'_>) -> Result<Self, Error> {
        Ok(Self::from_le_bytes(
            r.take(1)?.try_into().map_err(|_| Error::Short)?,
        ))
    }
}
impl Wire for u16 {
    fn put(&self, o: &mut Writer) {
        o.extend_from_slice(&self.to_le_bytes())
    }
    fn get(r: &mut Reader<'_>) -> Result<Self, Error> {
        Ok(Self::from_le_bytes(
            r.take(2)?.try_into().map_err(|_| Error::Short)?,
        ))
    }
}
impl Wire for u32 {
    fn put(&self, o: &mut Writer) {
        o.extend_from_slice(&self.to_le_bytes())
    }
    fn get(r: &mut Reader<'_>) -> Result<Self, Error> {
        Ok(Self::from_le_bytes(
            r.take(4)?.try_into().map_err(|_| Error::Short)?,
        ))
    }
}
impl Wire for u64 {
    fn put(&self, o: &mut Writer) {
        o.extend_from_slice(&self.to_le_bytes())
    }
    fn get(r: &mut Reader<'_>) -> Result<Self, Error> {
        Ok(Self::from_le_bytes(
            r.take(8)?.try_into().map_err(|_| Error::Short)?,
        ))
    }
}
impl Wire for i32 {
    fn put(&self, o: &mut Writer) {
        o.extend_from_slice(&self.to_le_bytes())
    }
    fn get(r: &mut Reader<'_>) -> Result<Self, Error> {
        Ok(Self::from_le_bytes(
            r.take(4)?.try_into().map_err(|_| Error::Short)?,
        ))
    }
}
impl Wire for i64 {
    fn put(&self, o: &mut Writer) {
        o.extend_from_slice(&self.to_le_bytes())
    }
    fn get(r: &mut Reader<'_>) -> Result<Self, Error> {
        Ok(Self::from_le_bytes(
            r.take(8)?.try_into().map_err(|_| Error::Short)?,
        ))
    }
}
impl Wire for usize {
    fn put(&self, o: &mut Writer) {
        match u32::try_from(*self) {
            Ok(n) => n.put(o),
            Err(_) => o.error = Some(Error::Limit),
        }
    }
    fn get(r: &mut Reader<'_>) -> Result<Self, Error> {
        usize::try_from(u32::get(r)?).map_err(|_| Error::Limit)
    }
}
impl Wire for bool {
    fn put(&self, o: &mut Writer) {
        u8::from(*self).put(o)
    }
    fn get(r: &mut Reader<'_>) -> Result<Self, Error> {
        match u8::get(r)? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(Error::Tag),
        }
    }
}
impl<T: Wire> Wire for Option<T> {
    fn put(&self, o: &mut Writer) {
        self.is_some().put(o);
        if let Some(v) = self {
            v.put(o)
        }
    }
    fn get(r: &mut Reader<'_>) -> Result<Self, Error> {
        Ok(if bool::get(r)? {
            Some(T::get(r)?)
        } else {
            None
        })
    }
}
impl<T: Wire> Wire for Vec<T> {
    fn put(&self, o: &mut Writer) {
        put_slice(self, o)
    }
    fn get(r: &mut Reader<'_>) -> Result<Self, Error> {
        let n = usize::get(r)?;
        if n > r.rest.len() {
            return Err(Error::Limit);
        }
        r.charge(
            n.checked_mul(core::mem::size_of::<T>())
                .ok_or(Error::Limit)?,
        )?;
        let mut v = Vec::new();
        v.try_reserve_exact(n).map_err(|_| Error::Limit)?;
        for _ in 0..n {
            v.push(T::get(r)?)
        }
        Ok(v)
    }
}
impl Wire for String {
    fn put(&self, o: &mut Writer) {
        self.len().put(o);
        o.extend_from_slice(self.as_bytes())
    }
    fn get(r: &mut Reader<'_>) -> Result<Self, Error> {
        let n = usize::get(r)?;
        r.charge(n)?;
        let s = core::str::from_utf8(r.take(n)?).map_err(|_| Error::Utf8)?;
        let mut out = String::new();
        out.try_reserve_exact(s.len()).map_err(|_| Error::Limit)?;
        out.push_str(s);
        Ok(out)
    }
}
impl<A: Wire, B: Wire> Wire for (A, B) {
    fn put(&self, o: &mut Writer) {
        self.0.put(o);
        self.1.put(o)
    }
    fn get(r: &mut Reader<'_>) -> Result<Self, Error> {
        Ok((A::get(r)?, B::get(r)?))
    }
}

impl Wire for Band {
    fn put(&self, o: &mut Writer) {
        self.min_cols.put(o);
        self.max_cols.put(o);
        self.order.put(o);
    }
    fn get(r: &mut Reader<'_>) -> Result<Self, Error> {
        Ok(Self {
            min_cols: Wire::get(r)?,
            max_cols: Wire::get(r)?,
            order: Wire::get(r)?,
        })
    }
}
impl Wire for Srgb8 {
    fn put(&self, o: &mut Writer) {
        self.r.put(o);
        self.g.put(o);
        self.b.put(o);
    }
    fn get(r: &mut Reader<'_>) -> Result<Self, Error> {
        Ok(Self {
            r: Wire::get(r)?,
            g: Wire::get(r)?,
            b: Wire::get(r)?,
        })
    }
}
impl Wire for OklchQ {
    fn put(&self, o: &mut Writer) {
        self.l.put(o);
        self.c.put(o);
        self.h.put(o);
    }
    fn get(r: &mut Reader<'_>) -> Result<Self, Error> {
        Ok(Self {
            l: Wire::get(r)?,
            c: Wire::get(r)?,
            h: Wire::get(r)?,
        })
    }
}
impl Wire for Span {
    fn put(&self, o: &mut Writer) {
        self.start.put(o);
        self.end.put(o);
    }
    fn get(r: &mut Reader<'_>) -> Result<Self, Error> {
        Ok(Self {
            start: Wire::get(r)?,
            end: Wire::get(r)?,
        })
    }
}
impl Wire for StyleSpec {
    fn put(&self, o: &mut Writer) {
        self.fg.put(o);
        self.bg.put(o);
        self.attrs.put(o);
    }
    fn get(r: &mut Reader<'_>) -> Result<Self, Error> {
        Ok(Self {
            fg: Wire::get(r)?,
            bg: Wire::get(r)?,
            attrs: Wire::get(r)?,
        })
    }
}
impl Wire for crate::config::tree::Span {
    fn put(&self, o: &mut Writer) {
        self.start.put(o);
        self.end.put(o);
    }
    fn get(r: &mut Reader<'_>) -> Result<Self, Error> {
        Ok(Self {
            start: Wire::get(r)?,
            end: Wire::get(r)?,
        })
    }
}
impl Wire for WidthProfile {
    fn put(&self, o: &mut Writer) {
        self.ambiguous().put(o);
        self.emoji().put(o)
    }
    fn get(r: &mut Reader<'_>) -> Result<Self, Error> {
        Self::new(u8::get(r)?, u8::get(r)?).ok_or(Error::Shape)
    }
}
impl Wire for WidthRun {
    fn put(&self, o: &mut Writer) {
        self.from.put(o);
        self.to.put(o);
        self.band.put(o);
    }
    fn get(r: &mut Reader<'_>) -> Result<Self, Error> {
        Ok(Self {
            from: Wire::get(r)?,
            to: Wire::get(r)?,
            band: Wire::get(r)?,
        })
    }
}
impl Wire for Origin {
    fn put(&self, o: &mut Writer) {
        self.source.put(o);
        self.key_span.put(o);
        self.span.put(o);
        self.trust.put(o);
    }
    fn get(r: &mut Reader<'_>) -> Result<Self, Error> {
        Ok(Self {
            source: Wire::get(r)?,
            key_span: Wire::get(r)?,
            span: Wire::get(r)?,
            trust: Wire::get(r)?,
        })
    }
}
impl Wire for LayoutRef {
    fn put(&self, o: &mut Writer) {
        self.band.put(o);
        self.line.put(o);
        self.side.put(o);
        self.origin.put(o);
    }
    fn get(r: &mut Reader<'_>) -> Result<Self, Error> {
        Ok(Self {
            band: Wire::get(r)?,
            line: Wire::get(r)?,
            side: Wire::get(r)?,
            origin: Wire::get(r)?,
        })
    }
}
impl Wire for Setup {
    fn put(&self, o: &mut Writer) {
        self.priority.put(o);
        self.required.put(o);
        self.methods.put(o);
        self.when.put(o);
    }
    fn get(r: &mut Reader<'_>) -> Result<Self, Error> {
        Ok(Self {
            priority: Wire::get(r)?,
            required: Wire::get(r)?,
            methods: Wire::get(r)?,
            when: Wire::get(r)?,
        })
    }
}
/// What compile gives a built-in segment no config setting touches.
fn plain_setup() -> Setup {
    Setup {
        priority: 0,
        required: false,
        methods: Vec::new(),
        when: When::Needed,
    }
}
/// The per-built-in setup table, sparse: the count, then each entry that
/// differs from `plain_setup` as (`field::BUILTIN` index, setup), indexes
/// strictly ascending. The table grows with the catalog while a config
/// changes a few entries, and the prompt decodes and checksums COMMON.
fn put_setup(table: &[Setup], o: &mut Writer) {
    let plain = plain_setup();
    let changed = || table.iter().enumerate().filter(|(_, s)| **s != plain);
    changed().count().put(o);
    for (i, s) in changed() {
        if o.error.is_some() {
            break;
        }
        match u16::try_from(i) {
            Ok(i) => i.put(o),
            Err(_) => o.error = Some(Error::Limit),
        }
        s.put(o);
    }
}
/// Always `field::BUILTIN.len()` entries; a missing index is `plain_setup`.
fn get_setup(r: &mut Reader<'_>) -> Result<Vec<Setup>, Error> {
    let len = crate::field::BUILTIN.len();
    let n = usize::get(r)?;
    // Fails without it: sparse_setup_bounds (count past the catalog).
    if n > len {
        return Err(Error::Limit);
    }
    // The dense table, as `Vec::get` charged it. Fails without it:
    // sparse_setup_bounds (budget).
    r.charge(
        len.checked_mul(core::mem::size_of::<Setup>())
            .ok_or(Error::Limit)?,
    )?;
    let mut table = Vec::new();
    table.try_reserve_exact(len).map_err(|_| Error::Limit)?;
    table.resize(len, plain_setup());
    let mut next = 0;
    for _ in 0..n {
        let i = usize::from(u16::get(r)?);
        // Ascending also refuses a repeated index. Fails without it:
        // sparse_setup_bounds (repeated and descending indexes).
        if i < next {
            return Err(Error::Shape);
        }
        // Fails without it: sparse_setup_bounds (index past the catalog).
        let slot = table.get_mut(i).ok_or(Error::Shape)?;
        *slot = Setup::get(r)?;
        next = i + 1;
    }
    Ok(table)
}
impl Wire for CustomSegment {
    fn put(&self, o: &mut Writer) {
        self.id.put(o);
        match &self.kind {
            CustomKind::Text(text) => {
                0u8.put(o);
                text.put(o);
            }
            CustomKind::Command => 1u8.put(o),
            CustomKind::Env(name) => {
                2u8.put(o);
                name.put(o);
            }
        }
    }
    fn get(r: &mut Reader<'_>) -> Result<Self, Error> {
        Ok(Self {
            id: Wire::get(r)?,
            kind: match u8::get(r)? {
                0 => CustomKind::Text(Wire::get(r)?),
                1 => CustomKind::Command,
                2 => CustomKind::Env(Wire::get(r)?),
                _ => return Err(Error::Shape),
            },
        })
    }
}
impl Wire for ExecUnit {
    fn put(&self, o: &mut Writer) {
        self.id.put(o);
        self.policy.put(o);
        self.timeout_ms.put(o);
        self.cache_ms.put(o);
        self.origins.put(o);
        self.approved_by.put(o);
        self.shown_at.put(o);
        self.not_run.put(o);
        self.pattern.put(o);
    }
    fn get(r: &mut Reader<'_>) -> Result<Self, Error> {
        Ok(Self {
            id: Wire::get(r)?,
            policy: Wire::get(r)?,
            timeout_ms: Wire::get(r)?,
            cache_ms: Wire::get(r)?,
            origins: Wire::get(r)?,
            approved_by: Wire::get(r)?,
            shown_at: Wire::get(r)?,
            not_run: Wire::get(r)?,
            pattern: Wire::get(r)?,
        })
    }
}
impl Wire for ResolvedToken {
    fn put(&self, o: &mut Writer) {
        self.fg.put(o);
        self.bg.put(o);
        self.fg_oklch.put(o);
        self.bg_oklch.put(o);
        self.fg256.put(o);
        self.bg256.put(o);
        self.ansi.put(o);
        self.on_block.put(o);
        self.on_block256.put(o);
        self.on_block_ansi.put(o);
        self.clipped.put(o);
    }
    fn get(r: &mut Reader<'_>) -> Result<Self, Error> {
        Ok(Self {
            fg: Wire::get(r)?,
            bg: Wire::get(r)?,
            fg_oklch: Wire::get(r)?,
            bg_oklch: Wire::get(r)?,
            fg256: Wire::get(r)?,
            bg256: Wire::get(r)?,
            ansi: Wire::get(r)?,
            on_block: Wire::get(r)?,
            on_block256: Wire::get(r)?,
            on_block_ansi: Wire::get(r)?,
            clipped: Wire::get(r)?,
        })
    }
}
impl Wire for ResolvedPalette {
    fn put(&self, o: &mut Writer) {
        self.tokens.put(o);
        self.background.put(o);
        self.warnings.put(o);
    }
    fn get(r: &mut Reader<'_>) -> Result<Self, Error> {
        Ok(Self {
            tokens: Wire::get(r)?,
            background: Wire::get(r)?,
            warnings: Wire::get(r)?,
        })
    }
}
impl Wire for Trust {
    fn put(&self, o: &mut Writer) {
        let tag: u8 = match self {
            Self::Executable => 0,
            Self::ShapeOnly => 1,
            Self::Unsafe => 2,
        };
        tag.put(o)
    }
    fn get(r: &mut Reader<'_>) -> Result<Self, Error> {
        match u8::get(r)? {
            0 => Ok(Self::Executable),
            1 => Ok(Self::ShapeOnly),
            2 => Ok(Self::Unsafe),
            _ => Err(Error::Tag),
        }
    }
}
impl Wire for Side {
    fn put(&self, o: &mut Writer) {
        let tag: u8 = match self {
            Self::Left => 0,
            Self::Right => 1,
        };
        tag.put(o)
    }
    fn get(r: &mut Reader<'_>) -> Result<Self, Error> {
        match u8::get(r)? {
            0 => Ok(Self::Left),
            1 => Ok(Self::Right),
            _ => Err(Error::Tag),
        }
    }
}
impl Wire for IconSet {
    fn put(&self, o: &mut Writer) {
        let tag: u8 = match self {
            Self::Nerd => 0,
            Self::Light => 1,
            Self::Unicode => 2,
            Self::Ascii => 3,
        };
        tag.put(o)
    }
    fn get(r: &mut Reader<'_>) -> Result<Self, Error> {
        match u8::get(r)? {
            0 => Ok(Self::Nerd),
            1 => Ok(Self::Light),
            2 => Ok(Self::Unicode),
            3 => Ok(Self::Ascii),
            _ => Err(Error::Tag),
        }
    }
}
impl Wire for When {
    fn put(&self, o: &mut Writer) {
        let tag: u8 = match self {
            Self::Needed => 0,
            Self::Always => 1,
        };
        tag.put(o)
    }
    fn get(r: &mut Reader<'_>) -> Result<Self, Error> {
        match u8::get(r)? {
            0 => Ok(Self::Needed),
            1 => Ok(Self::Always),
            _ => Err(Error::Tag),
        }
    }
}
impl Wire for Keep {
    fn put(&self, o: &mut Writer) {
        let tag: u8 = match self {
            Self::Start => 0,
            Self::End => 1,
        };
        tag.put(o)
    }
    fn get(r: &mut Reader<'_>) -> Result<Self, Error> {
        match u8::get(r)? {
            0 => Ok(Self::Start),
            1 => Ok(Self::End),
            _ => Err(Error::Tag),
        }
    }
}
impl Wire for Shape {
    fn put(&self, o: &mut Writer) {
        let tag: u8 = match self {
            Self::Triangle => 0,
            Self::Round => 1,
            Self::Slant => 2,
            Self::Flat => 3,
        };
        tag.put(o)
    }
    fn get(r: &mut Reader<'_>) -> Result<Self, Error> {
        match u8::get(r)? {
            0 => Ok(Self::Triangle),
            1 => Ok(Self::Round),
            2 => Ok(Self::Slant),
            3 => Ok(Self::Flat),
            _ => Err(Error::Tag),
        }
    }
}
impl Wire for FillKind {
    fn put(&self, o: &mut Writer) {
        let tag: u8 = match self {
            Self::Space => 0,
            Self::Dot => 1,
            Self::Line => 2,
        };
        tag.put(o)
    }
    fn get(r: &mut Reader<'_>) -> Result<Self, Error> {
        match u8::get(r)? {
            0 => Ok(Self::Space),
            1 => Ok(Self::Dot),
            2 => Ok(Self::Line),
            _ => Err(Error::Tag),
        }
    }
}
impl Wire for Mode {
    fn put(&self, o: &mut Writer) {
        let tag: u8 = match self {
            Self::Plain => 0,
            Self::Block => 1,
        };
        tag.put(o)
    }
    fn get(r: &mut Reader<'_>) -> Result<Self, Error> {
        match u8::get(r)? {
            0 => Ok(Self::Plain),
            1 => Ok(Self::Block),
            _ => Err(Error::Tag),
        }
    }
}
impl Wire for SourceId {
    fn put(&self, o: &mut Writer) {
        self.0.put(o)
    }
    fn get(r: &mut Reader<'_>) -> Result<Self, Error> {
        Ok(Self(u32::get(r)?))
    }
}
impl Wire for AnsiSlot {
    fn put(&self, o: &mut Writer) {
        match self {
            Self::Default => 0u8.put(o),
            Self::Slot(x) => {
                1u8.put(o);
                x.put(o)
            }
        }
    }
    fn get(r: &mut Reader<'_>) -> Result<Self, Error> {
        match u8::get(r)? {
            0 => Ok(Self::Default),
            1 => {
                let n = u8::get(r)?;
                if n > 15 {
                    return Err(Error::Shape);
                }
                Ok(Self::Slot(n))
            }
            _ => Err(Error::Tag),
        }
    }
}
impl Wire for Method {
    fn put(&self, o: &mut Writer) {
        match self {
            Self::None => 0u8.put(o),
            Self::Depth(v) => {
                1u8.put(o);
                v.put(o)
            }
            Self::Abbrev(v) => {
                2u8.put(o);
                v.put(o)
            }
            Self::Unique => 3u8.put(o),
            Self::Repo => 4u8.put(o),
            Self::Truncate { max, keep } => {
                5u8.put(o);
                max.put(o);
                keep.put(o)
            }
        }
    }
    fn get(r: &mut Reader<'_>) -> Result<Self, Error> {
        Ok(match u8::get(r)? {
            0 => Self::None,
            1 => Self::Depth(Wire::get(r)?),
            2 => Self::Abbrev(Wire::get(r)?),
            3 => Self::Unique,
            4 => Self::Repo,
            5 => Self::Truncate {
                max: Wire::get(r)?,
                keep: Wire::get(r)?,
            },
            _ => return Err(Error::Tag),
        })
    }
}
impl Wire for NotRun {
    fn put(&self, o: &mut Writer) {
        match self {
            Self::Disabled => 0u8.put(o),
            Self::NotInTrustedLayout => 1u8.put(o),
            Self::UnsafeFile { key } => {
                2u8.put(o);
                key.put(o)
            }
            Self::UnknownBand => 3u8.put(o),
            Self::ShellNotAllowed => 4u8.put(o),
            Self::MatchInvalid => 5u8.put(o),
        }
    }
    fn get(r: &mut Reader<'_>) -> Result<Self, Error> {
        Ok(match u8::get(r)? {
            0 => Self::Disabled,
            1 => Self::NotInTrustedLayout,
            2 => Self::UnsafeFile { key: Wire::get(r)? },
            3 => Self::UnknownBand,
            4 => Self::ShellNotAllowed,
            5 => Self::MatchInvalid,
            _ => return Err(Error::Tag),
        })
    }
}
impl Wire for ExecPolicy {
    fn put(&self, o: &mut Writer) {
        match self {
            Self::Command {
                argv,
                cwd,
                env_allow,
                shell,
                unsafe_shell,
            } => {
                0u8.put(o);
                argv.put(o);
                cwd.put(o);
                env_allow.put(o);
                shell.put(o);
                unsafe_shell.put(o)
            }
            Self::Language {
                interpreter,
                version_argv,
                detect_files,
            } => {
                1u8.put(o);
                interpreter.put(o);
                version_argv.put(o);
                detect_files.put(o)
            }
        }
    }
    fn get(r: &mut Reader<'_>) -> Result<Self, Error> {
        Ok(match u8::get(r)? {
            0 => Self::Command {
                argv: Wire::get(r)?,
                cwd: Wire::get(r)?,
                env_allow: Wire::get(r)?,
                shell: Wire::get(r)?,
                unsafe_shell: Wire::get(r)?,
            },
            1 => Self::Language {
                interpreter: Wire::get(r)?,
                version_argv: Wire::get(r)?,
                detect_files: Wire::get(r)?,
            },
            _ => return Err(Error::Tag),
        })
    }
}
impl Wire for PaletteWarning {
    fn put(&self, o: &mut Writer) {
        match self {
            Self::TextContrast { token, milli } => {
                0u8.put(o);
                token.put(o);
                milli.put(o)
            }
            Self::BlockContrast { token, milli } => {
                1u8.put(o);
                token.put(o);
                milli.put(o)
            }
            Self::Clipped { token } => {
                2u8.put(o);
                token.put(o)
            }
            Self::MarkContrast { token, milli } => {
                3u8.put(o);
                token.put(o);
                milli.put(o)
            }
            Self::BackgroundClipped => 4u8.put(o),
        }
    }
    fn get(r: &mut Reader<'_>) -> Result<Self, Error> {
        Ok(match u8::get(r)? {
            0 => Self::TextContrast {
                token: Wire::get(r)?,
                milli: Wire::get(r)?,
            },
            1 => Self::BlockContrast {
                token: Wire::get(r)?,
                milli: Wire::get(r)?,
            },
            2 => Self::Clipped {
                token: Wire::get(r)?,
            },
            3 => Self::MarkContrast {
                token: Wire::get(r)?,
                milli: Wire::get(r)?,
            },
            4 => Self::BackgroundClipped,
            _ => return Err(Error::Tag),
        })
    }
}
impl Wire for Node {
    fn put(&self, o: &mut Writer) {
        match self {
            Self::Text(v) => {
                0u8.put(o);
                v.put(o)
            }
            Self::Segment { seg, mode } => {
                if o.bytes.is_some() && usize::from(*seg) >= o.segs {
                    o.error.get_or_insert(Error::Shape);
                }
                1u8.put(o);
                seg.put(o);
                mode.put(o)
            }
            Self::Field { seg, field } => {
                if o.bytes.is_some() && usize::from(*seg) >= o.segs {
                    o.error.get_or_insert(Error::Shape);
                }
                2u8.put(o);
                seg.put(o);
                field.put(o)
            }
            Self::Sep(v) => {
                3u8.put(o);
                v.put(o)
            }
            Self::Head(v) => {
                4u8.put(o);
                v.put(o)
            }
            Self::Tail(v) => {
                5u8.put(o);
                v.put(o)
            }
            Self::Fill(v) => {
                6u8.put(o);
                v.put(o)
            }
            Self::Icon(v) => {
                7u8.put(o);
                v.put(o)
            }
            Self::Style(v) => {
                8u8.put(o);
                v.put(o)
            }
            Self::StyleEnd => 9u8.put(o),
            Self::Group { len } => {
                10u8.put(o);
                len.put(o)
            }
            Self::GroupEnd => 11u8.put(o),
        }
    }
    #[inline(always)]
    fn get(r: &mut Reader<'_>) -> Result<Self, Error> {
        Ok(match u8::get(r)? {
            0 => Self::Text(Wire::get(r)?),
            1 => Self::Segment {
                seg: Wire::get(r)?,
                mode: Wire::get(r)?,
            },
            2 => Self::Field {
                seg: Wire::get(r)?,
                field: Wire::get(r)?,
            },
            3 => Self::Sep(Wire::get(r)?),
            4 => Self::Head(Wire::get(r)?),
            5 => Self::Tail(Wire::get(r)?),
            6 => Self::Fill(Wire::get(r)?),
            7 => Self::Icon(Wire::get(r)?),
            8 => Self::Style(Wire::get(r)?),
            9 => Self::StyleEnd,
            10 => Self::Group { len: Wire::get(r)? },
            11 => Self::GroupEnd,
            _ => return Err(Error::Tag),
        })
    }
}
impl Wire for CompiledLine {
    fn put(&self, o: &mut Writer) {
        put_slice(self.nodes(), o);
        put_slice(self.origin(), o);
        self.fill().put(o)
    }
    fn get(r: &mut Reader<'_>) -> Result<Self, Error> {
        let segs = r.segs;
        CompiledLine::from_snapshot(Wire::get(r)?, Wire::get(r)?, Wire::get(r)?, segs)
            .ok_or(Error::Shape)
    }
}
/// Writes the sections in order. Offsets and CRCs need the written bytes, so
/// they go into space reserved for them; the sizing pass leaves it zero.
fn put_compiled(c: &CompiledConfig, o: &mut Writer) {
    o.extend_from_slice(MAGIC);
    VERSION.put(o);
    FACT_SCHEMA_VERSION.put(o);
    let common_len_at = o.len;
    0usize.put(o);
    c.variants.len().put(o);
    let common = o.len;
    c.bands.put(o);
    c.band_order.put(o);
    c.transient.put(o);
    c.vi.put(o);
    c.palette.put(o);
    c.light_palette.put(o);
    put_setup(&c.setup, o);
    c.collect_mask.put(o);
    c.icons.put(o);
    c.profile.put(o);
    c.use_last_column.put(o);
    c.duration_min_ms.put(o);
    c.exec_units.put(o);
    c.custom.put(o);
    c.widths.put(o);
    c.band_names.len().put(o);
    let names_seal = o.len;
    o.extend_from_slice(&[0; 8]);
    o.patch(common_len_at, &((o.len - common) as u32).to_le_bytes());
    let index = o.len;
    for _ in &c.variants {
        o.extend_from_slice(&[0; ENTRY]);
    }
    o.segs = crate::field::BUILTIN.len() + c.custom.len();
    for (i, v) in c.variants.iter().enumerate() {
        let at = o.len;
        v.put(o);
        let seal = index + i * ENTRY;
        o.patch(seal, &(at as u32).to_le_bytes());
        o.patch(seal + 4, &((o.len - at) as u32).to_le_bytes());
        o.patch(seal + 8, &o.sum_since(at));
    }
    let at = o.len;
    c.band_names.put(o);
    o.patch(names_seal, &((o.len - at) as u32).to_le_bytes());
    o.patch(names_seal + 4, &o.sum_since(at));
}
/// Size first, then one fallible allocation. No cloned nodes or partial oversized buffer.
pub fn encode_compiled(c: &CompiledConfig) -> Result<Vec<u8>, Error> {
    let size = compiled_size(c)?;
    validate(c)?;
    write_compiled(c, size)
}
fn compiled_size(c: &CompiledConfig) -> Result<usize, Error> {
    let mut size = Writer {
        bytes: None,
        len: 0,
        error: None,
        segs: crate::field::BUILTIN.len(),
    };
    put_compiled(c, &mut size);
    match size.error {
        Some(e) => Err(e),
        None => Ok(size.len),
    }
}
fn write_compiled(c: &CompiledConfig, size: usize) -> Result<Vec<u8>, Error> {
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(size).map_err(|_| Error::Limit)?;
    let mut out = Writer {
        bytes: Some(bytes),
        len: 0,
        error: None,
        segs: crate::field::BUILTIN.len(),
    };
    put_compiled(c, &mut out);
    if let Some(e) = out.error {
        return Err(e);
    }
    out.bytes.ok_or(Error::Limit)
}
struct Head {
    common: usize,
    variants: usize,
    /// HEAD + COMMON + INDEX; at most `c_len`.
    front: usize,
}
fn le32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}
fn parse_head(c: &[u8], c_len: usize) -> Result<Head, Error> {
    let h = c.get(..HEAD).ok_or(Error::Short)?;
    if h[..8] != *MAGIC || h[8..10] != VERSION.to_le_bytes() {
        return Err(Error::Tag);
    }
    // Field nodes store indices. Reject before decoding any nodes so an older
    // schema takes the caller's existing snapshot miss/recompile path.
    if h[10..12] != FACT_SCHEMA_VERSION.to_le_bytes() {
        return Err(Error::Tag);
    }
    let common = usize::try_from(le32(h, 12)).map_err(|_| Error::Limit)?;
    let variants = usize::try_from(le32(h, 16)).map_err(|_| Error::Limit)?;
    if !(1..=crate::bands::MAX_BANDS + 1).contains(&variants) {
        return Err(Error::Limit);
    }
    let front = (HEAD + variants * ENTRY)
        .checked_add(common)
        .ok_or(Error::Limit)?;
    if front > c_len {
        return Err(Error::Shape);
    }
    Ok(Head {
        common,
        variants,
        front,
    })
}
/// Length of HEAD + COMMON + INDEX, read from HEAD. `c_len` is the whole section.
pub fn front_len(head: &[u8], c_len: usize) -> Result<usize, Error> {
    Ok(parse_head(head, c_len)?.front)
}
/// Every field of COMMON, in wire order.
struct Common {
    bands: Vec<Band>,
    band_order: Vec<usize>,
    transient: CompiledLine,
    vi: CompiledLine,
    palette: ResolvedPalette,
    light_palette: ResolvedPalette,
    setup: Vec<Setup>,
    collect_mask: u32,
    icons: IconSet,
    profile: WidthProfile,
    use_last_column: bool,
    duration_min_ms: u64,
    exec_units: Vec<ExecUnit>,
    custom: Vec<CustomSegment>,
    widths: Vec<WidthRun>,
    name_count: usize,
    names_len: usize,
    names_crc: [u8; 4],
}
fn get_common(r: &mut Reader<'_>) -> Result<Common, Error> {
    Ok(Common {
        bands: Wire::get(r)?,
        band_order: Wire::get(r)?,
        transient: Wire::get(r)?,
        vi: Wire::get(r)?,
        palette: Wire::get(r)?,
        light_palette: Wire::get(r)?,
        setup: get_setup(r)?,
        collect_mask: Wire::get(r)?,
        icons: Wire::get(r)?,
        profile: Wire::get(r)?,
        use_last_column: Wire::get(r)?,
        duration_min_ms: Wire::get(r)?,
        exec_units: Wire::get(r)?,
        custom: Wire::get(r)?,
        widths: Wire::get(r)?,
        name_count: Wire::get(r)?,
        names_len: Wire::get(r)?,
        names_crc: r.take(4)?.try_into().map_err(|_| Error::Short)?,
    })
}
struct Entry {
    offset: usize,
    len: usize,
    crc: [u8; 4],
    pad: u32,
}
/// COMMON decoded and INDEX proved; nothing past INDEX has been looked at.
struct Sections<'a> {
    common: Common,
    index: &'a [u8],
    /// Where the name block starts: right after the last variant.
    names: usize,
    budget: usize,
}
impl Sections<'_> {
    fn entry(&self, i: usize) -> Entry {
        let e = &self.index[i * ENTRY..(i + 1) * ENTRY];
        Entry {
            offset: le32(e, 0) as usize,
            len: le32(e, 4) as usize,
            crc: [e[8], e[9], e[10], e[11]],
            pad: le32(e, 12),
        }
    }
    fn variants(&self) -> usize {
        self.index.len() / ENTRY
    }
}
/// `front` is exactly HEAD + COMMON + INDEX, already proved by the header
/// checksum on the front. Every later section slice relies on the tiling
/// checked here, so this is the memory-safety condition, not only a shape
/// check: variants start at the end of INDEX, each where the one before ended,
/// and the name block ends exactly at `c_len`.
fn parse_sections(front: &[u8], c_len: usize) -> Result<Sections<'_>, Error> {
    let head = parse_head(front, c_len)?;
    if front.len() != head.front {
        return Err(Error::Shape);
    }
    let mut r = Reader {
        rest: &front[HEAD..HEAD + head.common],
        budget: MAX_ALLOC,
        // COMMON's own lines (`transient`, `vi`) draw only built-ins.
        segs: crate::field::BUILTIN.len(),
    };
    let common = get_common(&mut r)?;
    if !r.rest.is_empty() {
        return Err(Error::Trailing);
    }
    let budget = r.budget;
    let mut sections = Sections {
        common,
        index: &front[HEAD + head.common..],
        names: 0,
        budget,
    };
    let mut end = head.front;
    for i in 0..head.variants {
        let e = sections.entry(i);
        if e.offset != end || e.len == 0 || e.pad != 0 {
            return Err(Error::Shape);
        }
        end = end.checked_add(e.len).ok_or(Error::Limit)?;
    }
    if end.checked_add(sections.common.names_len) != Some(c_len) {
        return Err(Error::Shape);
    }
    sections.names = end;
    Ok(sections)
}
/// What the front holds between INDEX and the selected variant.
#[derive(Debug)]
pub struct FrontPlan {
    pub config: FrontConfig,
    /// Where the selected variant starts in the compiled section.
    pub offset: usize,
    pub len: usize,
    crc: [u8; 4],
    budget: usize,
}
/// The front's checks over `front` (see `parse_sections`): everything
/// `validate` checks but what needs the names or unselected variants.
pub fn plan_front(front: &[u8], c_len: usize, width: u16) -> Result<FrontPlan, Error> {
    let s = parse_sections(front, c_len)?;
    let c = &s.common;
    check(&Parts {
        variants: s.variants(),
        // `finish_front` checks the selected variant's line count.
        variant_lines: true,
        bands: &c.bands,
        band_names: None,
        name_count: c.name_count,
        band_order: &c.band_order,
        setup: c.setup.len(),
        palette: &c.palette,
        light_palette: &c.light_palette,
        collect_mask: c.collect_mask,
        exec_units: &c.exec_units,
        custom: &c.custom,
        widths: &c.widths,
    })?;
    let band = crate::bands::select(&c.band_order, &c.bands, width);
    // `check` made the count `bands.len() + 1`; `select` returns a band index.
    let e = s.entry(band.map_or(0, |b| b + 1));
    let budget = s.budget;
    let c = s.common;
    Ok(FrontPlan {
        config: FrontConfig {
            lines: Vec::new(),
            band,
            bands: c.bands,
            band_order: c.band_order,
            transient: c.transient,
            vi: c.vi,
            palette: c.palette,
            light_palette: c.light_palette,
            setup: c.setup,
            collect_mask: c.collect_mask,
            icons: c.icons,
            profile: c.profile,
            use_last_column: c.use_last_column,
            duration_min_ms: c.duration_min_ms,
            exec_units: c.exec_units,
            custom: c.custom,
            widths: c.widths,
        },
        offset: e.offset,
        len: e.len,
        crc: e.crc,
        budget,
    })
}
/// The selected variant's CRC, then its lines (each checked by `from_snapshot`).
/// It spends what COMMON left of the budget: the section has one `MAX_ALLOC`.
pub fn finish_front(mut plan: FrontPlan, variant: &[u8]) -> Result<FrontConfig, Error> {
    if section_sum(variant) != plan.crc {
        return Err(Error::Shape);
    }
    let mut r = Reader {
        rest: variant,
        budget: plan.budget,
        segs: crate::field::BUILTIN.len() + plan.config.custom.len(),
    };
    let lines: Vec<CompiledLine> = Wire::get(&mut r)?;
    if !r.rest.is_empty() {
        return Err(Error::Trailing);
    }
    if !(1..=MAX_LINES).contains(&lines.len()) {
        return Err(Error::Shape);
    }
    plan.config.lines = lines;
    Ok(plan.config)
}
/// The helper's whole decode: every CRC and section the front skips, under the
/// one budget COMMON started, then all of `validate`. Whatever passes here
/// passes the front at every width, with the same result.
pub fn decode_compiled(c: &[u8]) -> Result<CompiledConfig, Error> {
    if c.len() > MAX_BYTES {
        return Err(Error::Limit);
    }
    let s = parse_sections(&c[..parse_head(c, c.len())?.front], c.len())?;
    let n = s.variants();
    let mut budget = n
        .checked_mul(size_of::<Vec<CompiledLine>>())
        .and_then(|table| s.budget.checked_sub(table))
        .ok_or(Error::Limit)?;
    let segs = crate::field::BUILTIN.len() + s.common.custom.len();
    let mut variants = Vec::new();
    variants.try_reserve_exact(n).map_err(|_| Error::Limit)?;
    for i in 0..n {
        let e = s.entry(i);
        let (lines, left) = section(&c[e.offset..e.offset + e.len], e.crc, budget, segs)?;
        variants.push(lines);
        budget = left;
    }
    let (band_names, _): (Vec<String>, _) =
        section(&c[s.names..], s.common.names_crc, budget, segs)?;
    let m = s.common;
    // The front's `check` used this count; the file must agree with itself.
    if m.name_count != band_names.len() {
        return Err(Error::Shape);
    }
    let out = CompiledConfig {
        variants,
        bands: m.bands,
        band_names,
        band_order: m.band_order,
        transient: m.transient,
        vi: m.vi,
        palette: m.palette,
        light_palette: m.light_palette,
        setup: m.setup,
        collect_mask: m.collect_mask,
        icons: m.icons,
        profile: m.profile,
        use_last_column: m.use_last_column,
        duration_min_ms: m.duration_min_ms,
        exec_units: m.exec_units,
        custom: m.custom,
        widths: m.widths,
    };
    validate(&out)?;
    Ok(out)
}
/// One CRC-covered section, spending from `budget`; returns what is left.
fn section<T: Wire>(
    body: &[u8],
    crc: [u8; 4],
    budget: usize,
    segs: usize,
) -> Result<(T, usize), Error> {
    if section_sum(body) != crc {
        return Err(Error::Shape);
    }
    let mut r = Reader {
        rest: body,
        budget,
        segs,
    };
    let value = T::get(&mut r)?;
    if !r.rest.is_empty() {
        return Err(Error::Trailing);
    }
    Ok((value, r.budget))
}
pub(crate) fn validate(c: &CompiledConfig) -> Result<(), Error> {
    check(&Parts {
        variants: c.variants.len(),
        variant_lines: c
            .variants
            .iter()
            .all(|v| (1..=MAX_LINES).contains(&v.len())),
        bands: &c.bands,
        band_names: Some(&c.band_names),
        name_count: c.band_names.len(),
        band_order: &c.band_order,
        setup: c.setup.len(),
        palette: &c.palette,
        light_palette: &c.light_palette,
        collect_mask: c.collect_mask,
        exec_units: &c.exec_units,
        custom: &c.custom,
        widths: &c.widths,
    })
}
/// What `validate` reads. The front fills it from COMMON without the variants
/// or the band names, so both paths run one set of checks.
struct Parts<'c> {
    variants: usize,
    /// Every variant has 1..=MAX_LINES lines.
    variant_lines: bool,
    bands: &'c [Band],
    /// None on the front: the helper's decode and publishing check the names,
    /// their uniqueness and every band-name reference.
    band_names: Option<&'c [String]>,
    name_count: usize,
    band_order: &'c [usize],
    setup: usize,
    palette: &'c ResolvedPalette,
    light_palette: &'c ResolvedPalette,
    collect_mask: u32,
    exec_units: &'c [ExecUnit],
    custom: &'c [CustomSegment],
    widths: &'c [WidthRun],
}
fn check(c: &Parts<'_>) -> Result<(), Error> {
    let named = |n: &String| c.band_names.is_none_or(|names| names.contains(n));
    if c.bands.len() > crate::bands::MAX_BANDS
        || c.variants != c.bands.len() + 1
        || c.name_count != c.bands.len()
        || c.setup != crate::field::BUILTIN.len()
        || c.palette.tokens.len() != crate::color::palette::TOKENS.len()
        || c.light_palette.tokens.len() != crate::color::palette::TOKENS.len()
    {
        return Err(Error::Shape);
    }
    // Band names are arbitrary TOML keys, not segment ids. The source
    // table and merge guarantee uniqueness, including for quoted keys.
    let mut names = BTreeSet::new();
    if c.band_names
        .into_iter()
        .flatten()
        .any(|name| !names.insert(name.as_str()))
    {
        return Err(Error::Shape);
    }
    // Validate the supplied order without allocating a graph or recompiling it.
    if c.band_order.len() != c.bands.len() {
        return Err(Error::Shape);
    }
    let mut ranks = [u16::MAX; crate::bands::MAX_BANDS];
    for (rank, &i) in c.band_order.iter().enumerate() {
        if i >= c.bands.len() || ranks[i] != u16::MAX {
            return Err(Error::Shape);
        }
        ranks[i] = rank as u16;
    }
    for b in c.bands {
        if b.min_cols.unwrap_or(0) > b.max_cols.unwrap_or(u16::MAX) {
            return Err(Error::Shape);
        }
    }
    if c.bands.iter().all(|b| b.order.is_none()) {
        // The same containment forest as bands::order_bands. Check only parent
        // edges (transitivity checks every ancestor), with bounded stack storage.
        // Ordinary unordered bands stay O(n log n), including the 4096-band cap.
        let mut sorted = [0u16; crate::bands::MAX_BANDS];
        let mut stack = [0u16; crate::bands::MAX_BANDS];
        for (i, slot) in sorted[..c.bands.len()].iter_mut().enumerate() {
            *slot = i as u16;
        }
        sorted[..c.bands.len()].sort_unstable_by_key(|&i| {
            let b = c.bands[usize::from(i)];
            (
                b.min_cols.unwrap_or(0),
                core::cmp::Reverse(b.max_cols.unwrap_or(u16::MAX)),
                i,
            )
        });
        let mut depth = 0;
        for &i in &sorted[..c.bands.len()] {
            let child = usize::from(i);
            while depth > 0 {
                let parent = usize::from(stack[depth - 1]);
                if c.bands[parent].max_cols.unwrap_or(u16::MAX)
                    < c.bands[child].min_cols.unwrap_or(0)
                {
                    depth -= 1;
                } else {
                    break;
                }
            }
            if depth > 0 {
                let parent = usize::from(stack[depth - 1]);
                let _ = crate::bands::before(c.bands, child, parent, &mut || {})
                    .map_err(|_| Error::Shape)?;
                if ranks[child] >= ranks[parent] {
                    return Err(Error::Shape);
                }
            }
            stack[depth] = i;
            depth += 1;
        }
    } else {
        // Mixed explicit precedence can cycle; the existing 4096-band bound
        // also bounds this O(n²) check, without allocating an edge graph.
        for i in 0..c.bands.len() {
            for j in i + 1..c.bands.len() {
                if let Some(before) =
                    crate::bands::before(c.bands, i, j, &mut || {}).map_err(|_| Error::Shape)?
                {
                    if (ranks[i] < ranks[j]) != before {
                        return Err(Error::Shape);
                    }
                }
            }
        }
    }
    // Text segments take numbers after the built-ins and never a mask bit.
    if c.custom.len() > crate::config::compile::MAX_CUSTOM_TEXT
        || !c.custom.windows(2).all(|w| w[0].id < w[1].id)
        || c.custom.iter().any(|t| {
            parse_segment_id(&t.id).map(|id| id.namespace()) != Ok(Namespace::Custom)
                || match &t.kind {
                    CustomKind::Text(text) => {
                        !text.chars().all(|c| !crate::sanitize::is_removed(c))
                            || text.len() > usize::from(crate::field::CUSTOM_TEXT_CELLS) * 4
                    }
                    CustomKind::Command => false,
                    CustomKind::Env(name) => !crate::config::check::env_name(name),
                }
        })
    {
        return Err(Error::Shape);
    }
    const _: () = assert!(crate::field::BUILTIN.len() < 32);
    if c.collect_mask >> crate::field::BUILTIN.len() != 0 {
        return Err(Error::Shape);
    }
    if !c.variant_lines {
        return Err(Error::Shape);
    }
    for p in [c.palette, c.light_palette] {
        for w in &p.warnings {
            let token = match w {
                PaletteWarning::TextContrast { token, .. }
                | PaletteWarning::BlockContrast { token, .. }
                | PaletteWarning::Clipped { token }
                | PaletteWarning::MarkContrast { token, .. } => Some(*token),
                PaletteWarning::BackgroundClipped => None,
            };
            if token.is_some_and(|n| n >= p.tokens.len()) {
                return Err(Error::Shape);
            }
        }
        for t in &p.tokens {
            for a in [t.ansi, t.on_block_ansi] {
                if matches!(a, AnsiSlot::Slot(n) if n > 15) {
                    return Err(Error::Shape);
                }
            }
        }
    }
    let mut ids = BTreeSet::new();
    for u in c.exec_units {
        // A unit is looked up by id, and the compiler always writes at least
        // the `kind` key of a custom segment.
        if !parse_segment_id(&u.id).is_ok_and(|id| id.namespace() == Namespace::Custom)
            || !ids.insert(u.id.as_str())
            || u.origins.is_empty()
        {
            return Err(Error::Shape);
        }
        // Recheck the source compiler's permission boundary for either
        // wire direction; a syntactically valid unit is not enough to run.
        if u.not_run.is_none()
            && (u.origins.iter().any(|(_, o)| o.trust == Trust::Unsafe)
                || u.approved_by.is_empty()
                || u.shown_at.is_empty())
        {
            return Err(Error::Shape);
        }
        if matches!(&u.not_run, Some(NotRun::UnsafeFile { key })
            if !u.origins.iter().any(|(k, _)| k == key))
        {
            return Err(Error::Shape);
        }
        for (_, o) in &u.origins {
            valid_origin(o)?;
        }
        for r in u.approved_by.iter().chain(&u.shown_at) {
            // An unknown band index is kept only on a unit that never runs for it.
            let unknown = r.band.is_some_and(|b| usize::from(b) >= c.bands.len());
            if r.line > 2 || (unknown && u.not_run != Some(NotRun::UnknownBand)) {
                return Err(Error::Shape);
            }
            if let Some(o) = &r.origin {
                valid_origin(o)?;
            }
        }
    }
    for w in c.widths {
        if w.from > w.to || w.band.as_ref().is_some_and(|n| !named(n)) {
            return Err(Error::Shape);
        }
    }
    Ok(())
}
fn valid_origin(o: &Origin) -> Result<(), Error> {
    if o.key_span.start > o.key_span.end || o.span.start > o.span.end {
        return Err(Error::Shape);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
