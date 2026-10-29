//! The helper keeps the whole `CompiledConfig`; the prompt front decodes a
//! `FrontConfig`, which holds only the variant its width selects (K63). Both
//! answer the front's questions through `LayoutView`, so the renderer and the
//! worker mask cannot tell them apart at the width they were selected for.
//! Data types only: no config parsing, merging, checking or compiling.
use crate::bands::{self, Band};
use crate::color::palette::{Mode, ResolvedPalette};
use crate::config::compile::{CompiledConfig, ExecUnit, Setup};
use crate::diag_widths::WidthRun;
use crate::icons::IconSet;
use crate::layout::SegmentSetup;
use crate::render::Theme;
use crate::template::compile::CompiledLine;
use crate::width::WidthProfile;
use alloc::vec::Vec;

/// Everything the front reads besides the variant.
#[derive(Clone, Copy, Debug)]
pub struct Shared<'a> {
    pub transient: &'a CompiledLine,
    pub vi: &'a CompiledLine,
    pub palette: &'a ResolvedPalette,
    pub light_palette: &'a ResolvedPalette,
    pub setup: &'a [Setup],
    pub collect_mask: u32,
    pub icons: IconSet,
    pub profile: WidthProfile,
    pub use_last_column: bool,
    pub duration_min_ms: u64,
    pub exec_units: &'a [ExecUnit],
}

impl<'a> Shared<'a> {
    /// A theme drawing only `lines`: with no bands, layout takes `variants[0]`.
    pub fn theme(&self, lines: Option<&'a Vec<CompiledLine>>, display_mode: Mode) -> Theme<'a> {
        Theme {
            variants: match lines {
                Some(lines) => core::slice::from_ref(lines),
                None => &[],
            },
            bands: &[],
            band_order: &[],
            transient: self.transient,
            vi: self.vi,
            palette: match display_mode {
                Mode::Dark => self.palette,
                Mode::Light => self.light_palette,
            },
        }
    }
    pub fn segment_setup(&self) -> Vec<SegmentSetup<'a>> {
        self.setup
            .iter()
            .map(|s| SegmentSetup {
                priority: s.priority,
                required: s.required,
                methods: &s.methods,
                when: s.when,
            })
            .collect()
    }
}

pub trait LayoutView {
    /// The lines drawn at `width`: the variant of the band `bands::select`
    /// picks, else the default (`variants[0]`). None: nothing to draw.
    fn lines_at(&self, width: u16) -> Option<&Vec<CompiledLine>>;
    fn shared(&self) -> Shared<'_>;
}

impl LayoutView for CompiledConfig {
    #[inline]
    fn lines_at(&self, width: u16) -> Option<&Vec<CompiledLine>> {
        bands::select(&self.band_order, &self.bands, width)
            .and_then(|band| self.variants.get(band + 1))
            .or(self.variants.first())
    }
    fn shared(&self) -> Shared<'_> {
        Shared {
            transient: &self.transient,
            vi: &self.vi,
            palette: &self.palette,
            light_palette: &self.light_palette,
            setup: &self.setup,
            collect_mask: self.collect_mask,
            icons: self.icons,
            profile: self.profile,
            use_last_column: self.use_last_column,
            duration_min_ms: self.duration_min_ms,
            exec_units: &self.exec_units,
        }
    }
}

/// A compiled config with only the variant selected at one width. It drops
/// the other variants and the band names; `bands` and `band_order` stay, so a
/// different width is recognized instead of drawn with the wrong variant.
#[derive(Clone, Debug, PartialEq)]
pub struct FrontConfig {
    pub(crate) lines: Vec<CompiledLine>,
    /// `bands::select` at the selected width.
    pub(crate) band: Option<usize>,
    pub(crate) bands: Vec<Band>,
    pub(crate) band_order: Vec<usize>,
    pub(crate) transient: CompiledLine,
    pub(crate) vi: CompiledLine,
    pub(crate) palette: ResolvedPalette,
    pub(crate) light_palette: ResolvedPalette,
    pub(crate) setup: Vec<Setup>,
    pub(crate) collect_mask: u32,
    pub(crate) icons: IconSet,
    pub(crate) profile: WidthProfile,
    pub(crate) use_last_column: bool,
    pub(crate) duration_min_ms: u64,
    pub(crate) exec_units: Vec<ExecUnit>,
    pub(crate) widths: Vec<WidthRun>,
}

impl FrontConfig {
    /// The same selection the snapshot front decode makes, from a whole config.
    pub fn from_compiled(mut c: CompiledConfig, width: u16) -> Self {
        let band = bands::select(&c.band_order, &c.bands, width);
        let at = band
            .map(|b| b + 1)
            .filter(|&i| i < c.variants.len())
            .unwrap_or(0);
        let lines = if at < c.variants.len() {
            c.variants.swap_remove(at)
        } else {
            Vec::new()
        };
        Self {
            lines,
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
            widths: c.widths,
        }
    }
    pub fn lines(&self) -> &[CompiledLine] {
        &self.lines
    }
    pub fn band(&self) -> Option<usize> {
        self.band
    }
    pub fn bands(&self) -> &[Band] {
        &self.bands
    }
    pub fn band_order(&self) -> &[usize] {
        &self.band_order
    }
    pub fn exec_units(&self) -> &[ExecUnit] {
        &self.exec_units
    }
    pub fn widths(&self) -> &[WidthRun] {
        &self.widths
    }
}

impl LayoutView for FrontConfig {
    /// Only the selected width's band has lines here. Another width gets
    /// None (draw nothing, collect nothing); re-select from the snapshot bytes.
    #[inline]
    fn lines_at(&self, width: u16) -> Option<&Vec<CompiledLine>> {
        (bands::select(&self.band_order, &self.bands, width) == self.band).then_some(&self.lines)
    }
    fn shared(&self) -> Shared<'_> {
        Shared {
            transient: &self.transient,
            vi: &self.vi,
            palette: &self.palette,
            light_palette: &self.light_palette,
            setup: &self.setup,
            collect_mask: self.collect_mask,
            icons: self.icons,
            profile: self.profile,
            use_last_column: self.use_last_column,
            duration_min_ms: self.duration_min_ms,
            exec_units: &self.exec_units,
        }
    }
}
