//! Decision log (spec section 3 "템플릿 문법" 결정 기록, F-24): the chosen
//! band, the overflow steps applied, hidden segments with a reason code and
//! shortened segments with the method used. Off by default at zero cost:
//! layout is generic over `R: Recorder` and every call site is
//! `if R::ENABLED { … }` with `Copy` arguments the layout has anyway, so
//! with the zero-sized `NoopRecorder` the calls compile away
//! (monomorphization). `explain` (M7) prints `DecisionLog`.
use alloc::vec::Vec;

/// Overflow steps of spec section 3 "한 줄 조립과 넘칠 때", 1–7.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Step {
    ShortenNames = 1,
    HideRightByPriority = 2,
    HideRight = 3,
    TruncateLeft = 4,
    HideLeftOptional = 5,
    DropDecoration = 6,
    Minimal = 7,
}

/// Why a segment is not drawn. A segment referenced on both sides of the
/// fill can be hidden on one side only (steps 2 and 3 hide the right side).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HideReason {
    /// The segment sent no value.
    NoValue,
    /// Step 2.
    Priority,
    /// Step 3.
    RightHidden,
    /// Step 5.
    LeftOptional,
    /// Step 7 dropped everything but the prompt character.
    Minimal,
    /// A conditional group vanished because the segment's fields in it are
    /// all empty (Absent, an empty text, a zero count, `false`). A group
    /// that vanished because its segments are hidden or have no value is
    /// recorded under those reasons instead.
    EmptyGroup,
}

/// Records of one `layout` call. Per line there are at most 7 steps, two
/// `shortened` per segment of the catalog (`when = always`, then step 1),
/// and at most 5 `hidden` per segment (no value, step 2 or 3, step 5, step
/// 7: a segment is hidden once per side) plus one `EmptyGroup` per field
/// node of the line. `layout` calls `begin` first, so a reused log holds one
/// call's records.
pub trait Recorder {
    const ENABLED: bool;
    /// Starts a new call: forget earlier records (keeping their memory).
    fn begin(&mut self);
    fn band(&mut self, band: Option<usize>);
    fn step(&mut self, line: usize, step: Step);
    fn hidden(&mut self, line: usize, segment: usize, reason: HideReason);
    /// `method` is the index in the segment's method list.
    fn shortened(&mut self, line: usize, segment: usize, method: usize);
}

/// Records nothing; zero-sized.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoopRecorder;

impl Recorder for NoopRecorder {
    const ENABLED: bool = false;
    #[inline(always)]
    fn begin(&mut self) {}
    #[inline(always)]
    fn band(&mut self, _: Option<usize>) {}
    #[inline(always)]
    fn step(&mut self, _: usize, _: Step) {}
    #[inline(always)]
    fn hidden(&mut self, _: usize, _: usize, _: HideReason) {}
    #[inline(always)]
    fn shortened(&mut self, _: usize, _: usize, _: usize) {}
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DecisionLog {
    pub band: Option<usize>,
    pub steps: Vec<(usize, Step)>,
    pub hidden: Vec<(usize, usize, HideReason)>,
    pub shortened: Vec<(usize, usize, usize)>,
}

impl Recorder for DecisionLog {
    const ENABLED: bool = true;
    fn begin(&mut self) {
        self.band = None;
        self.steps.clear();
        self.hidden.clear();
        self.shortened.clear();
    }
    fn band(&mut self, band: Option<usize>) {
        self.band = band;
    }
    fn step(&mut self, line: usize, step: Step) {
        self.steps.push((line, step));
    }
    fn hidden(&mut self, line: usize, segment: usize, reason: HideReason) {
        self.hidden.push((line, segment, reason));
    }
    fn shortened(&mut self, line: usize, segment: usize, method: usize) {
        self.shortened.push((line, segment, method));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // 이것을 실패시키는 것: NoopRecorder에 필드를 더해 크기가 0이 아니게 되거나 ENABLED가 참이 되는 것,
    // DecisionLog의 ENABLED가 거짓이 되는 것.
    #[test]
    fn noop_is_zero_sized_and_disabled() {
        assert_eq!(core::mem::size_of::<NoopRecorder>(), 0);
        const { assert!(!NoopRecorder::ENABLED) };
        const { assert!(DecisionLog::ENABLED) };
    }

    // 이것을 실패시키는 것: `begin`이 폭 구간이나 기록 하나라도 남기는 것.
    #[test]
    fn begin_forgets_everything() {
        let mut log = DecisionLog::default();
        log.band(Some(3));
        log.step(0, Step::Minimal);
        log.hidden(0, 1, HideReason::Minimal);
        log.shortened(0, 1, 0);
        log.begin();
        assert_eq!(log, DecisionLog::default());
    }
}
