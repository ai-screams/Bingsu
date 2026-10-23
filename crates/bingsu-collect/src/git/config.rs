//! Isolated config: repository bytes only; include directives remain inert data.
use super::io::{RepoIo, RepoPath, RootId};
use crate::safe_read::{ReadCap, ReadError};
use bingsu_core::collection::budget::CONFIG_BYTES;

#[derive(Default)]
pub struct Config {
    common: Option<gix_config::File>,
    worktree: Option<gix_config::File>,
}

impl Config {
    pub fn load(io: &RepoIo<'_>) -> Result<Self, ReadError> {
        // Inspect both fixed candidates, including core.worktree in an inactive
        // config.worktree. Interpretation/activation belongs to preflight.
        Ok(Self {
            common: read(io, RootId::CommonDir, b"config")?,
            worktree: read(io, RootId::GitDir, b"config.worktree")?,
        })
    }

    pub fn common(&self) -> Option<&gix_config::File> {
        self.common.as_ref()
    }
    pub fn worktree(&self) -> Option<&gix_config::File> {
        self.worktree.as_ref()
    }

    pub fn has_core_worktree(&self) -> bool {
        [&self.common, &self.worktree]
            .into_iter()
            .flatten()
            .any(|file| file.raw_value("core.worktree").is_ok())
    }
}

fn read(io: &RepoIo<'_>, root: RootId, name: &[u8]) -> Result<Option<gix_config::File>, ReadError> {
    let bytes = match io.read(
        RepoPath::new(root, name),
        ReadCap {
            bytes: CONFIG_BYTES,
            single_link: true,
        },
    ) {
        Ok(bytes) => bytes,
        Err(ReadError::Missing) => return Ok(None),
        Err(error) => return Err(error),
    };
    io.metered(|meter| {
        // Input is capped before the parser can allocate. Charge its input copy;
        // gix's internal event allocations remain under the worker memory limit.
        meter.allocation(bytes.len())?;
        let file = gix_config::File::from_bytes_no_includes(
            &bytes,
            gix_config::file::Metadata::from(gix_config::Source::Local),
            gix_config::file::init::Options {
                lossy: true,
                ..Default::default()
            },
        )
        .map_err(|_| ReadError::Io(libc::EINVAL))?;
        meter.check()?;
        Ok(Some(file))
    })
}
