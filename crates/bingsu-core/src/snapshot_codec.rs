//! BNGCFG03: bounded CompiledConfig codec with an explicit fact schema version.
use crate::{
    bands::Band,
    color::{
        math::{OklchQ, Srgb8},
        palette::{AnsiSlot, PaletteWarning, ResolvedPalette, ResolvedToken},
    },
    config::{
        compile::{CompiledConfig, ExecPolicy, ExecUnit, LayoutRef, NotRun, Setup, Side},
        merge::Origin,
        schema::FACT_SCHEMA_VERSION,
        source::Trust,
    },
    diag::SourceId,
    diag_widths::WidthRun,
    icons::IconSet,
    ident::parse_segment_id,
    layout::When,
    layout_view::FrontConfig,
    shorten::{Keep, Method},
    template::{
        compile::{CompiledLine, FillKind, LineCheck, MAX_LINES, Node, Shape, StyleSpec},
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
struct Reader<'a> {
    rest: &'a [u8],
    budget: usize,
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
        let n = get_len::<T>(r)?;
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
        let s = get_str(r)?;
        let mut out = String::new();
        out.try_reserve_exact(s.len()).map_err(|_| Error::Limit)?;
        out.push_str(s);
        Ok(out)
    }
}
/// `String::get` without the copy: the same charge and checks, borrowed.
#[inline(always)]
fn get_str<'a>(r: &mut Reader<'a>) -> Result<&'a str, Error> {
    let n = usize::get(r)?;
    r.charge(n)?;
    core::str::from_utf8(r.take(n)?).map_err(|_| Error::Utf8)
}
/// `Vec::<T>::get`'s length checks and charge, before any element is read.
fn get_len<T>(r: &mut Reader<'_>) -> Result<usize, Error> {
    let n = usize::get(r)?;
    if n > r.rest.len() {
        return Err(Error::Limit);
    }
    r.charge(
        n.checked_mul(core::mem::size_of::<T>())
            .ok_or(Error::Limit)?,
    )?;
    Ok(n)
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
impl Wire for CompiledConfig {
    fn put(&self, o: &mut Writer) {
        self.variants.put(o);
        self.bands.put(o);
        self.band_names.put(o);
        self.band_order.put(o);
        self.transient.put(o);
        self.vi.put(o);
        self.palette.put(o);
        self.light_palette.put(o);
        self.setup.put(o);
        self.collect_mask.put(o);
        self.icons.put(o);
        self.profile.put(o);
        self.use_last_column.put(o);
        self.duration_min_ms.put(o);
        self.exec_units.put(o);
        self.widths.put(o);
    }
    fn get(r: &mut Reader<'_>) -> Result<Self, Error> {
        Ok(Self {
            variants: Wire::get(r)?,
            bands: Wire::get(r)?,
            band_names: Wire::get(r)?,
            band_order: Wire::get(r)?,
            transient: Wire::get(r)?,
            vi: Wire::get(r)?,
            palette: Wire::get(r)?,
            light_palette: Wire::get(r)?,
            setup: Wire::get(r)?,
            collect_mask: Wire::get(r)?,
            icons: Wire::get(r)?,
            profile: Wire::get(r)?,
            use_last_column: Wire::get(r)?,
            duration_min_ms: Wire::get(r)?,
            exec_units: Wire::get(r)?,
            widths: Wire::get(r)?,
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
        }
    }
    fn get(r: &mut Reader<'_>) -> Result<Self, Error> {
        Ok(match u8::get(r)? {
            0 => Self::Disabled,
            1 => Self::NotInTrustedLayout,
            2 => Self::UnsafeFile { key: Wire::get(r)? },
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
                1u8.put(o);
                seg.put(o);
                mode.put(o)
            }
            Self::Field { seg, field } => {
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
    // Two callers (the line decode and the scan); keep each one's loop flat.
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
        CompiledLine::from_snapshot(Wire::get(r)?, Wire::get(r)?, Wire::get(r)?).ok_or(Error::Shape)
    }
}
/// Size first, then one fallible allocation. No cloned nodes or partial oversized buffer.
pub fn encode_compiled(c: &CompiledConfig) -> Result<Vec<u8>, Error> {
    let mut size = Writer {
        bytes: None,
        len: 0,
        error: None,
    };
    size.extend_from_slice(b"BNGCFG03");
    3u16.put(&mut size);
    FACT_SCHEMA_VERSION.put(&mut size);
    c.put(&mut size);
    if let Some(e) = size.error {
        return Err(e);
    }
    validate(c)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(size.len)
        .map_err(|_| Error::Limit)?;
    let mut out = Writer {
        bytes: Some(bytes),
        len: 0,
        error: None,
    };
    out.extend_from_slice(b"BNGCFG03");
    3u16.put(&mut out);
    FACT_SCHEMA_VERSION.put(&mut out);
    c.put(&mut out);
    if let Some(e) = out.error {
        return Err(e);
    }
    out.bytes.ok_or(Error::Limit)
}
pub fn decode_compiled(bytes: &[u8]) -> Result<CompiledConfig, Error> {
    if bytes.len() > MAX_BYTES {
        return Err(Error::Limit);
    }
    let mut r = Reader {
        rest: bytes,
        budget: MAX_ALLOC,
    };
    if r.take(8)? != b"BNGCFG03" || u16::get(&mut r)? != 3 {
        return Err(Error::Tag);
    }
    // Field nodes store indices. Reject before decoding any nodes so an older
    // schema takes the caller's existing snapshot miss/recompile path.
    if u16::get(&mut r)? != FACT_SCHEMA_VERSION {
        return Err(Error::Tag);
    }
    let c = CompiledConfig::get(&mut r)?;
    if !r.rest.is_empty() {
        return Err(Error::Trailing);
    }
    validate(&c)?;
    Ok(c)
}
/// `decode_compiled` without materializing variants or band names: the same
/// reads in the same order, the same allocation charges and every check,
/// so it rejects exactly what `decode_compiled` rejects, with the same error
/// (barring an allocation failure, which only the whole decode can meet).
/// Each variant is checked line by line and only its offset kept; `select`
/// then decodes the one variant the width picks (K63).
pub fn scan_compiled(bytes: &[u8]) -> Result<CompiledLayout<'_>, Error> {
    if bytes.len() > MAX_BYTES {
        return Err(Error::Limit);
    }
    let mut r = Reader {
        rest: bytes,
        budget: MAX_ALLOC,
    };
    if r.take(8)? != b"BNGCFG03" || u16::get(&mut r)? != 3 {
        return Err(Error::Tag);
    }
    if u16::get(&mut r)? != FACT_SCHEMA_VERSION {
        return Err(Error::Tag);
    }
    let n = get_len::<Vec<CompiledLine>>(&mut r)?;
    // More than MAX_BANDS + 1 variants fails `check`; keep reading for the
    // decoder's error order, but record no more offsets than can be used.
    let kept = n.min(crate::bands::MAX_BANDS + 1);
    let mut offsets = Vec::new();
    offsets.try_reserve_exact(kept).map_err(|_| Error::Limit)?;
    let mut variant_lines = true;
    for _ in 0..n {
        if offsets.len() < kept {
            // MAX_BYTES bounds the offset.
            offsets.push((bytes.len() - r.rest.len()) as u32);
        }
        let lines = get_len::<CompiledLine>(&mut r)?;
        variant_lines &= (1..=MAX_LINES).contains(&lines);
        for _ in 0..lines {
            scan_line(&mut r)?;
        }
    }
    let bands: Vec<Band> = Wire::get(&mut r)?;
    // Names are borrowed for `check`; past MAX_BANDS + 1 the count fails it.
    let names = get_len::<String>(&mut r)?;
    let kept = names.min(crate::bands::MAX_BANDS + 1);
    let mut band_names = Vec::new();
    band_names
        .try_reserve_exact(kept)
        .map_err(|_| Error::Limit)?;
    for _ in 0..names {
        let name = get_str(&mut r)?;
        if band_names.len() < kept {
            band_names.push(name);
        }
    }
    let layout = CompiledLayout {
        bytes,
        offsets,
        band_order: Wire::get(&mut r)?,
        transient: Wire::get(&mut r)?,
        vi: Wire::get(&mut r)?,
        palette: Wire::get(&mut r)?,
        light_palette: Wire::get(&mut r)?,
        setup: Wire::get(&mut r)?,
        collect_mask: Wire::get(&mut r)?,
        icons: Wire::get(&mut r)?,
        profile: Wire::get(&mut r)?,
        use_last_column: Wire::get(&mut r)?,
        duration_min_ms: Wire::get(&mut r)?,
        exec_units: Wire::get(&mut r)?,
        widths: Wire::get(&mut r)?,
        bands,
    };
    if !r.rest.is_empty() {
        return Err(Error::Trailing);
    }
    check(&Parts {
        variants: n,
        variant_lines,
        bands: &layout.bands,
        band_names: &band_names,
        band_order: &layout.band_order,
        setup: layout.setup.len(),
        palette: &layout.palette,
        light_palette: &layout.light_palette,
        collect_mask: layout.collect_mask,
        exec_units: &layout.exec_units,
        widths: &layout.widths,
    })?;
    Ok(layout)
}
/// `CompiledLine::get` without building it: the reads, charges and the N1
/// line checks of `from_snapshot`, in the same order.
fn scan_line(r: &mut Reader<'_>) -> Result<(), Error> {
    let n = get_len::<Node>(r)?;
    let mut line = LineCheck::new(n);
    for _ in 0..n {
        // Only `Text` (tag 0) owns heap memory; every other node is read as
        // `Node::get` reads it.
        if r.rest.first() == Some(&0) {
            r.take(1)?;
            line.text(get_str(r)?);
        } else {
            line.node(&Node::get(r)?);
        }
    }
    let spans = get_len::<Span>(r)?;
    line.spans(spans);
    for _ in 0..spans {
        line.span(Span::get(r)?);
    }
    let fill = Option::<usize>::get(r)?;
    if line.finish(fill) {
        Ok(())
    } else {
        Err(Error::Shape)
    }
}
/// A checked compiled config with every field but the variants and band
/// names decoded. Only `scan_compiled` makes one, from the bytes it holds.
#[derive(Debug)]
pub struct CompiledLayout<'a> {
    bytes: &'a [u8],
    /// Where variant i starts in `bytes`; `check` made it `bands.len() + 1` long.
    offsets: Vec<u32>,
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
    widths: Vec<WidthRun>,
}
impl CompiledLayout<'_> {
    pub fn collect_mask(&self) -> u32 {
        self.collect_mask
    }
    pub fn exec_units(&self) -> &[ExecUnit] {
        &self.exec_units
    }
    /// Materialize the variant `bands::select` picks at `width` (else the
    /// default), as `CompiledConfig`'s selection would. The scan already
    /// checked and charged it; this decode only fails if allocation does.
    pub fn select(self, width: u16) -> Result<FrontConfig, Error> {
        let band = crate::bands::select(&self.band_order, &self.bands, width);
        let at = band
            .and_then(|b| self.offsets.get(b + 1))
            .or(self.offsets.first())
            .ok_or(Error::Shape)?;
        let mut r = Reader {
            rest: self.bytes.get(*at as usize..).ok_or(Error::Shape)?,
            budget: MAX_ALLOC,
        };
        Ok(FrontConfig {
            lines: Wire::get(&mut r)?,
            band,
            bands: self.bands,
            band_order: self.band_order,
            transient: self.transient,
            vi: self.vi,
            palette: self.palette,
            light_palette: self.light_palette,
            setup: self.setup,
            collect_mask: self.collect_mask,
            icons: self.icons,
            profile: self.profile,
            use_last_column: self.use_last_column,
            duration_min_ms: self.duration_min_ms,
            exec_units: self.exec_units,
            widths: self.widths,
        })
    }
}
pub(crate) fn validate(c: &CompiledConfig) -> Result<(), Error> {
    check(&Parts {
        variants: c.variants.len(),
        variant_lines: c
            .variants
            .iter()
            .all(|v| (1..=MAX_LINES).contains(&v.len())),
        bands: &c.bands,
        band_names: &c.band_names,
        band_order: &c.band_order,
        setup: c.setup.len(),
        palette: &c.palette,
        light_palette: &c.light_palette,
        collect_mask: c.collect_mask,
        exec_units: &c.exec_units,
        widths: &c.widths,
    })
}
/// What `validate` reads. The scan fills it without materializing variants
/// or band names, so both paths run one set of checks.
struct Parts<'c, N> {
    variants: usize,
    /// Every variant has 1..=MAX_LINES lines.
    variant_lines: bool,
    bands: &'c [Band],
    band_names: &'c [N],
    band_order: &'c [usize],
    setup: usize,
    palette: &'c ResolvedPalette,
    light_palette: &'c ResolvedPalette,
    collect_mask: u32,
    exec_units: &'c [ExecUnit],
    widths: &'c [WidthRun],
}
fn check<N: AsRef<str>>(c: &Parts<'_, N>) -> Result<(), Error> {
    let named = |n: &String| c.band_names.iter().any(|b| b.as_ref() == n.as_str());
    if c.bands.len() > crate::bands::MAX_BANDS
        || c.variants != c.bands.len() + 1
        || c.band_names.len() != c.bands.len()
        || c.setup != crate::field::BUILTIN.len()
        || c.palette.tokens.len() != crate::color::palette::TOKENS.len()
        || c.light_palette.tokens.len() != crate::color::palette::TOKENS.len()
    {
        return Err(Error::Shape);
    }
    // Band names are arbitrary TOML keys, not segment ids. The source
    // table and merge guarantee uniqueness, including for quoted keys.
    let mut names = BTreeSet::new();
    if c.band_names.iter().any(|name| !names.insert(name.as_ref())) {
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
    for u in c.exec_units {
        if parse_segment_id(&u.id).is_err() {
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
            if r.line > 2 || r.band.as_ref().is_some_and(|n| !named(n)) {
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
