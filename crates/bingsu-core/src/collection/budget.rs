//! Pure pre-operation counters. Git limits are measurement hypotheses; callers
//! enforce deadlines and stop the affected stage on the first failed charge.
pub const A_MS: u64 = 5;
pub const PATH_MS: u64 = 3;
pub const B_MS: u64 = 28;
pub const C_MS: u64 = 8;
pub const D_MS: u64 = 4;
pub const RESERVE_MS: u64 = 2;
pub const INDEX_BYTES: u64 = 4_194_304;
pub const INDEX_ENTRIES: u64 = 50_000;
pub const WORKTREE_ENTRIES: u64 = 65_536;
pub const DIRECTORIES: u64 = 4_096;
pub const STATS: u64 = 100_000;
pub const IGNORE_FILES: u64 = 128;
pub const IGNORE_BYTES: u64 = 262_144;
pub const IGNORE_PATTERNS: u64 = 8_192;
pub const ATTRIBUTE_FILES: u64 = 128;
pub const ATTRIBUTE_BYTES: u64 = 262_144;
pub const ATTRIBUTE_PATTERNS: u64 = 8_192;
pub const CONFIG_BYTES: u64 = 65_536;
pub const SMALL_FILE_BYTES: u64 = 65_536;
pub const PACKS: u64 = 8;
pub const PACK_BYTES: u64 = 8_388_608;
pub const MAPPED_BYTES: u64 = 8_388_608;
pub const OBJECT_ALLOC: u64 = 2_097_152;
pub const DECOMPRESSED_BYTES: u64 = 8_388_608;
pub const WORKTREE_READ_BYTES: u64 = 8_388_608;
pub const COMMITS: u64 = 10_000;
pub const REF_BYTES: u64 = 262_144;
pub const REF_ENTRIES: u64 = 4_096;
pub const REFLOG_BYTES: u64 = 262_144;
pub const STASH_ENTRIES: u64 = 1_024;
pub const LIVE_FDS: u64 = 56;
pub const READ_CHUNK: u64 = 16_384;
pub const DIRENT_CHUNK: u64 = 8_192;

/// Cumulative axes shared across stages. Per-file/object caps and simultaneous
/// fd/chunk limits above are enforced by the I/O adapter, not summed here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Axis {
    IndexBytes,
    IndexEntries,
    WorktreeEntries,
    Directories,
    Stats,
    IgnoreFiles,
    IgnoreBytes,
    IgnorePatterns,
    AttributeFiles,
    AttributeBytes,
    AttributePatterns,
    Packs,
    PackBytes,
    MappedBytes,
    DecompressedBytes,
    WorktreeReadBytes,
    Commits,
    RefBytes,
    RefEntries,
    ReflogBytes,
    StashEntries,
}
impl Axis {
    pub const ALL: [Self; 21] = [
        Self::IndexBytes,
        Self::IndexEntries,
        Self::WorktreeEntries,
        Self::Directories,
        Self::Stats,
        Self::IgnoreFiles,
        Self::IgnoreBytes,
        Self::IgnorePatterns,
        Self::AttributeFiles,
        Self::AttributeBytes,
        Self::AttributePatterns,
        Self::Packs,
        Self::PackBytes,
        Self::MappedBytes,
        Self::DecompressedBytes,
        Self::WorktreeReadBytes,
        Self::Commits,
        Self::RefBytes,
        Self::RefEntries,
        Self::ReflogBytes,
        Self::StashEntries,
    ];
    pub const fn limit(self) -> u64 {
        match self {
            Self::IndexBytes => INDEX_BYTES,
            Self::IndexEntries => INDEX_ENTRIES,
            Self::WorktreeEntries => WORKTREE_ENTRIES,
            Self::Directories => DIRECTORIES,
            Self::Stats => STATS,
            Self::IgnoreFiles => IGNORE_FILES,
            Self::IgnoreBytes => IGNORE_BYTES,
            Self::IgnorePatterns => IGNORE_PATTERNS,
            Self::AttributeFiles => ATTRIBUTE_FILES,
            Self::AttributeBytes => ATTRIBUTE_BYTES,
            Self::AttributePatterns => ATTRIBUTE_PATTERNS,
            Self::Packs => PACKS,
            Self::PackBytes => PACK_BYTES,
            Self::MappedBytes => MAPPED_BYTES,
            Self::DecompressedBytes => DECOMPRESSED_BYTES,
            Self::WorktreeReadBytes => WORKTREE_READ_BYTES,
            Self::Commits => COMMITS,
            Self::RefBytes => REF_BYTES,
            Self::RefEntries => REF_ENTRIES,
            Self::ReflogBytes => REFLOG_BYTES,
            Self::StashEntries => STASH_ENTRIES,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BudgetExceeded {
    pub axis: Axis,
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BudgetCounters {
    used: [u64; Axis::ALL.len()],
}
impl BudgetCounters {
    pub fn used(&self, axis: Axis) -> u64 {
        self.used[axis as usize]
    }
    pub fn charge(&mut self, axis: Axis, amount: u64) -> Result<(), BudgetExceeded> {
        let next = self
            .used(axis)
            .checked_add(amount)
            .filter(|n| *n <= axis.limit())
            .ok_or(BudgetExceeded { axis })?;
        self.used[axis as usize] = next;
        Ok(())
    }
}
