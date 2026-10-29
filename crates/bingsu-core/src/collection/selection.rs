//! Collection follows the renderer's selected layout, before value-dependent
//! overflow or conditional groups. A catalog grants worker capability separately.
use super::path_facts::PathQuery;
use crate::{
    field::{self, SegmentDecl},
    layout_view::LayoutView,
    template::compile::{CompiledLine, Node},
};

/// Fixed adapter policy, never populated from configuration or shell input.
pub struct Catalog<'a> {
    pub segments: &'a [SegmentDecl],
    pub workers: u32,
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

    pub fn worker_mask<L: LayoutView>(&self, config: &L, width: u16, redraw: bool) -> u32 {
        if redraw {
            return 0;
        }
        builtin_mask(config, width) & self.workers & self.declared_mask()
    }
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
