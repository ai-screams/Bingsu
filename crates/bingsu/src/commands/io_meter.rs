//! The refresh helper's config-source I/O meter (spec 9 "갱신 도우미의 축
//! 아홉", 1435: one fixed cap per axis, no axis covers another, exceeding any
//! one ends the check incomplete and leaves the marker as it was). One
//! `Loader` owns one meter, and refresh makes one `Loader` per round, so a
//! meter covers the whole round: root discovery, path walks, every reference
//! attempt (refused, duplicate, missing and cyclic ones included), conf.d
//! listings and every revalidation before publication. Charges are counted
//! work, not accepted work: unlike core's semantic budget (32 files, 1 MiB,
//! `config::source`), nothing is given back when a shape-only subgraph is
//! dropped, so the caps (user decision U2, 2026-10-30) are not those numbers.
//!
//! | Axis | Unit, charged where | Cap |
//! | -- | -- | -- |
//! | F | distinct canonical paths of source files opened, before the `openat` | 256 |
//! | P | names descended with `openat(O_NOFOLLOW)` (walks and the conf.d chain), before each | 8,192 |
//! | L | `readlinkat` calls (walks and retained-evidence revalidation), before each | 1,024 |
//! | R | candidates tried: each root candidate (absent ones too) and each `extends` entry before it is resolved | 256 |
//! | D | distinct source folders listed (conf.d by canonical path), before the listing | 2 |
//! | E_n | raw directory entries read, `.` and `..` included, before filtering, per entry | 1,024 |
//! | E_b | the `d_reclen` of those entries, per entry | 131,072 |
//! | M | distinct mounts (`st_dev`) whose `fstatfs` a walk reads, before it; Linux reads none | 16 |
//! | B | bytes read from source files, after the read, which never asks for more than the room left plus one | 2,097,152 |
//!
//! The meter latches: after the first refusal every later charge on every
//! axis fails, so the session does no further metered work. Callers check
//! the latch before any unmetered call that would follow it.
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HelperAxis {
    F,
    P,
    L,
    R,
    D,
    En,
    Eb,
    M,
    B,
}

impl HelperAxis {
    pub(crate) const ALL: [Self; 9] = [
        Self::F,
        Self::P,
        Self::L,
        Self::R,
        Self::D,
        Self::En,
        Self::Eb,
        Self::M,
        Self::B,
    ];

    fn index(self) -> usize {
        self as usize
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AxisCaps {
    pub f: u64,
    pub p: u64,
    pub l: u64,
    pub r: u64,
    pub d: u64,
    pub e_n: u64,
    pub e_b: u64,
    pub m: u64,
    pub b: u64,
}

impl AxisCaps {
    pub(crate) fn cap(&self, axis: HelperAxis) -> u64 {
        match axis {
            HelperAxis::F => self.f,
            HelperAxis::P => self.p,
            HelperAxis::L => self.l,
            HelperAxis::R => self.r,
            HelperAxis::D => self.d,
            HelperAxis::En => self.e_n,
            HelperAxis::Eb => self.e_b,
            HelperAxis::M => self.m,
            HelperAxis::B => self.b,
        }
    }
}

/// User decision U2 (2026-10-30), option (나).
pub(crate) const AXIS_CAPS: AxisCaps = AxisCaps {
    f: 256,
    p: 8_192,
    l: 1_024,
    r: 256,
    d: 2,
    e_n: 1_024,
    e_b: 131_072,
    m: 16,
    b: 2_097_152,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AxisExceeded {
    pub axis: HelperAxis,
    /// What the axis would have reached with the refused charge.
    pub used: u64,
    pub cap: u64,
}

impl From<AxisExceeded> for std::io::Error {
    fn from(e: AxisExceeded) -> Self {
        // `Other`, never `NotFound`: callers read NotFound as a checked absence.
        std::io::Error::other(format!(
            "helper I/O budget: axis {:?} would reach {} of {}",
            e.axis, e.used, e.cap
        ))
    }
}

/// Per-axis amounts, indexed like `HelperAxis::ALL`.
pub(crate) type AxisUse = [u64; 9];

pub(crate) struct IoMeter {
    caps: AxisCaps,
    used: AxisUse,
    exceeded: Option<AxisExceeded>,
    files: BTreeSet<PathBuf>,
    folders: BTreeSet<PathBuf>,
    mounts: BTreeSet<u64>,
}

#[cfg(test)]
thread_local! {
    static TEST_CAPS: std::cell::Cell<Option<AxisCaps>> = const { std::cell::Cell::new(None) };
}

/// Test builds only: refresh sessions on this thread use `caps` until the
/// guard drops.
#[cfg(test)]
pub(crate) struct TestCaps;

#[cfg(test)]
impl TestCaps {
    pub(crate) fn set(caps: AxisCaps) -> Self {
        TEST_CAPS.with(|c| c.set(Some(caps)));
        Self
    }
}

#[cfg(test)]
impl Drop for TestCaps {
    fn drop(&mut self) {
        TEST_CAPS.with(|c| c.set(None));
    }
}

#[cfg(test)]
thread_local! {
    static LAST: std::cell::Cell<Option<(AxisUse, Option<AxisExceeded>)>> =
        const { std::cell::Cell::new(None) };
}

/// Test builds only: what the last meter dropped on this thread had charged.
#[cfg(test)]
pub(crate) fn last_session() -> Option<(AxisUse, Option<AxisExceeded>)> {
    LAST.with(std::cell::Cell::take)
}

#[cfg(test)]
impl Drop for IoMeter {
    fn drop(&mut self) {
        LAST.with(|l| l.set(Some((self.used, self.exceeded))));
    }
}

impl IoMeter {
    pub(crate) fn new(caps: AxisCaps) -> Self {
        Self {
            caps,
            used: [0; 9],
            exceeded: None,
            files: BTreeSet::new(),
            folders: BTreeSet::new(),
            mounts: BTreeSet::new(),
        }
    }

    /// The meter of one refresh round: `AXIS_CAPS`, or a test override.
    pub(crate) fn session() -> Self {
        #[cfg(test)]
        if let Some(caps) = TEST_CAPS.with(std::cell::Cell::get) {
            return Self::new(caps);
        }
        Self::new(AXIS_CAPS)
    }

    /// The latch: `Err` once any axis refused a charge.
    pub(crate) fn check(&self) -> Result<(), AxisExceeded> {
        self.exceeded.map_or(Ok(()), Err)
    }

    #[cfg(test)]
    pub(crate) fn exceeded(&self) -> Option<AxisExceeded> {
        self.exceeded
    }

    pub(crate) fn charge(&mut self, axis: HelperAxis, amount: u64) -> Result<(), AxisExceeded> {
        self.check()?;
        let i = axis.index();
        let used = self.used[i].saturating_add(amount);
        let cap = self.caps.cap(axis);
        if used > cap {
            let e = AxisExceeded { axis, used, cap };
            self.exceeded = Some(e);
            return Err(e);
        }
        self.used[i] = used;
        Ok(())
    }

    /// F: one per distinct canonical file path.
    pub(crate) fn charge_file(&mut self, canonical: &Path) -> Result<(), AxisExceeded> {
        self.check()?;
        if self.files.contains(canonical) {
            return Ok(());
        }
        self.charge(HelperAxis::F, 1)?;
        self.files.insert(canonical.to_path_buf());
        Ok(())
    }

    /// D: one per distinct canonical folder listed.
    pub(crate) fn charge_folder(&mut self, canonical: &Path) -> Result<(), AxisExceeded> {
        self.check()?;
        if self.folders.contains(canonical) {
            return Ok(());
        }
        self.charge(HelperAxis::D, 1)?;
        self.folders.insert(canonical.to_path_buf());
        Ok(())
    }

    /// M: one per distinct `st_dev`.
    pub(crate) fn charge_mount(&mut self, dev: u64) -> Result<(), AxisExceeded> {
        self.check()?;
        if self.mounts.contains(&dev) {
            return Ok(());
        }
        self.charge(HelperAxis::M, 1)?;
        self.mounts.insert(dev);
        Ok(())
    }

    pub(crate) fn used(&self, axis: HelperAxis) -> u64 {
        self.used[axis.index()]
    }

    pub(crate) fn all_used(&self) -> AxisUse {
        self.used
    }

    /// What `axis` can still take.
    pub(crate) fn room(&self, axis: HelperAxis) -> u64 {
        self.caps.cap(axis).saturating_sub(self.used(axis))
    }

    /// Whether `more` (per axis) still fits, without charging it; a refusal
    /// latches like a refused charge. Used before refresh moves the sequence:
    /// the final revalidation repeats work whose cost is already known, and
    /// it must not cross a cap after that point.
    pub(crate) fn fits(&mut self, more: &AxisUse) -> Result<(), AxisExceeded> {
        self.check()?;
        for axis in HelperAxis::ALL {
            let used = self.used(axis).saturating_add(more[axis.index()]);
            let cap = self.caps.cap(axis);
            if used > cap {
                let e = AxisExceeded { axis, used, cap };
                self.exceeded = Some(e);
                return Err(e);
            }
        }
        Ok(())
    }
}

/// An optional meter on a shared walk: init, `config use` and the build
/// identity walk the same paths unmetered.
pub(crate) type Meter<'a> = Option<&'a mut IoMeter>;

pub(crate) fn charge(meter: &mut Meter<'_>, axis: HelperAxis, amount: u64) -> std::io::Result<()> {
    match meter {
        Some(m) => m.charge(axis, amount).map_err(Into::into),
        None => Ok(()),
    }
}

pub(crate) fn latch(meter: &Meter<'_>) -> std::io::Result<()> {
    match meter {
        Some(m) => m.check().map_err(Into::into),
        None => Ok(()),
    }
}

pub(crate) fn charge_file(meter: &mut Meter<'_>, canonical: &Path) -> std::io::Result<()> {
    match meter {
        Some(m) => m.charge_file(canonical).map_err(Into::into),
        None => Ok(()),
    }
}

pub(crate) fn charge_mount(meter: &mut Meter<'_>, dev: u64) -> std::io::Result<()> {
    match meter {
        Some(m) => m.charge_mount(dev).map_err(Into::into),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests;
