//! Collection follows the renderer's selected layout, before value-dependent
//! overflow or conditional groups. A catalog grants worker capability separately.
use super::path_facts::PathQuery;
use crate::{
    config::compile::CustomKind,
    field::{self, SegmentDecl},
    layout_view::LayoutView,
    template::compile::{CompiledLine, Node},
};

/// Fixed adapter policy, never populated from configuration or shell input.
pub struct Catalog<'a> {
    pub segments: &'a [SegmentDecl],
    pub workers: u32,
}

/// The bits of the builtin language segments in `field::BUILTIN`.
pub const LANGUAGE_SEGMENTS: u32 = language_segments();

const fn same(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

const fn language_segments() -> u32 {
    let mut mask = 0;
    let mut i = 0;
    while i < field::BUILTIN.len() && i < 32 {
        let mut j = 0;
        while j < super::language::BUILTIN.len() {
            if same(
                field::BUILTIN[i].id.as_bytes(),
                super::language::BUILTIN[j].id,
            ) {
                mask |= 1 << i;
            }
            j += 1;
        }
        i += 1;
    }
    mask
}

/// Only directory facts and Git have shipped worker capability.
pub const PRODUCT: Catalog<'static> = Catalog {
    segments: field::BUILTIN,
    workers: (1 << 1) | (1 << 3),
};

pub(crate) fn references(lines: &[CompiledLine]) -> u32 {
    lines
        .iter()
        .flat_map(|line| line.nodes())
        .fold(0, |mask, node| match node {
            // A user text segment's number is past the built-ins: its bit
            // (or none, from 32) is dropped by `collect_mask`, which has
            // only built-in bits (`snapshot_codec::check`).
            Node::Segment { seg, .. } | Node::Field { seg, .. } => {
                mask | 1u32.checked_shl(u32::from(*seg)).unwrap_or(0)
            }
            _ => mask,
        })
}

// Keep selection specialized for the caller's width even when the front and
// collector share this entry point (notably the 4,096-band maximum-width scan).
#[inline]
pub fn builtin_mask<L: LayoutView>(config: &L, width: u16) -> u32 {
    config.lines_at(width).map_or(0, |lines| references(lines)) & config.shared().collect_mask
}

impl Catalog<'_> {
    pub(crate) fn declared_mask(&self) -> u32 {
        if self.segments.len() > 32 {
            return 0;
        }
        u32::MAX
            .checked_shr(32 - self.segments.len() as u32)
            .unwrap_or(0)
    }

    /// The workers a round asks: those of the drawn segments, and the
    /// folder facts (the `dir` worker) whenever a language is drawn: a
    /// builtin one, since the repository root bounds the builtin probes'
    /// PATH and executable rules (D3a review H1), or a user language that
    /// may run, whose detect files are searched up to that root. A layout
    /// that draws only a user language still collects, so its files are
    /// found. One rule for the helper's request and the front's expected
    /// binding (D3a review M2).
    ///
    /// Inlined, with the facts asked only when the catalog grants the dir
    /// worker: a caller whose catalog grants none (the historical M3b
    /// policy bench, `product_mask_zero`) then drops the whole mask at
    /// compile time, as it did before user languages. With either part
    /// missing, that bench on x86_64 costs one more instruction per band
    /// (53,262 to about 57,640 over 4,096 bands). Neither changes a result
    /// (the mask is cut to `allowed` at the end), so no test sees them; the
    /// instruction count does.
    #[inline(always)]
    pub fn worker_mask<L: LayoutView>(&self, config: &L, width: u16, redraw: bool) -> u32 {
        if redraw {
            return 0;
        }
        let drawn = builtin_mask(config, width);
        let allowed = self.workers & self.declared_mask();
        let dir = 1 << super::DIR_SEGMENT;
        // Fails without it: language_segments_ask_for_the_folder_facts, and
        // test_builtin_probe_never_runs_from_the_repository; without the
        // user language half, a_drawn_user_language_asks_for_the_folder_facts.
        let facts = if allowed & dir != 0
            && (drawn & LANGUAGE_SEGMENTS != 0 || draws_user_language(config, width))
        {
            dir
        } else {
            0
        };
        (drawn | facts) & allowed
    }
}

/// Whether the lines drawn at `width` show a user language segment whose
/// unit may run: drawn by a trusted layout and turned on (`not_run` is
/// none), the units the helper asks the collection about. Most configs
/// declare no language, and they stop at the first check.
fn draws_user_language<L: LayoutView>(config: &L, width: u16) -> bool {
    let shared = config.shared();
    let language = |seg: u16| {
        usize::from(seg)
            .checked_sub(field::BUILTIN.len())
            .and_then(|i| shared.custom.get(i))
            .is_some_and(|c| {
                matches!(c.kind, CustomKind::Language)
                    && shared
                        .exec_units
                        .iter()
                        .any(|u| u.id == c.id && u.not_run.is_none())
            })
    };
    if !shared
        .custom
        .iter()
        .any(|c| matches!(c.kind, CustomKind::Language))
    {
        return false;
    }
    config.lines_at(width).is_some_and(|lines| {
        lines.iter().flat_map(|l| l.nodes()).any(|node| match node {
            Node::Segment { seg, .. } | Node::Field { seg, .. } => language(*seg),
            _ => false,
        })
    })
}

pub fn worker_mask<L: LayoutView>(config: &L, width: u16, redraw: bool) -> u32 {
    PRODUCT.worker_mask(config, width, redraw)
}

/// Bind the home boundary on both sides of the handoff. Only a selected dir
/// using unique shortening requests names; readonly and repo facts need no names.
pub fn path_query<L: LayoutView>(
    config: &L,
    width: u16,
    pwd: &[u8],
    home: Option<&[u8]>,
) -> PathQuery {
    PathQuery::for_path(
        pwd,
        home,
        config
            .shared()
            .setup
            .get(1)
            .is_some_and(|setup| setup.methods.contains(&crate::shorten::Method::Unique))
            && builtin_mask(config, width) & (1 << 1) != 0,
    )
}
