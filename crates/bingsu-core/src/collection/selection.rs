//! Collection follows the renderer's selected layout, before value-dependent
//! overflow or conditional groups. A catalog grants worker capability separately.
use crate::{
    bands,
    config::compile::CompiledConfig,
    field::{self, SegmentDecl},
    template::compile::{CompiledLine, Node},
};

/// Fixed adapter policy, never populated from configuration or shell input.
pub struct Catalog<'a> {
    pub segments: &'a [SegmentDecl],
    pub workers: u32,
}

/// No product builtin collects in this milestone.
pub const PRODUCT: Catalog<'static> = Catalog {
    segments: field::BUILTIN,
    workers: 0,
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

pub fn builtin_mask(config: &CompiledConfig, width: u16) -> u32 {
    let lines = bands::select(&config.band_order, &config.bands, width)
        .and_then(|band| config.variants.get(band + 1))
        .or(config.variants.first());
    lines.map_or(0, |lines| references(lines)) & config.collect_mask
}

impl Catalog<'_> {
    pub fn worker_mask(&self, config: &CompiledConfig, width: u16, redraw: bool) -> u32 {
        if redraw || self.segments.len() > 32 {
            return 0;
        }
        let declared = u32::MAX
            .checked_shr(32 - self.segments.len() as u32)
            .unwrap_or(0);
        builtin_mask(config, width) & self.workers & declared
    }
}

pub fn worker_mask(config: &CompiledConfig, width: u16, redraw: bool) -> u32 {
    PRODUCT.worker_mask(config, width, redraw)
}
