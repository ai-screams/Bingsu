//! Bytes-only Git readers. No repository discovery or product activation here.
pub mod config;
pub mod io;
pub mod refs;

use crate::safe_read::ReadError;
use bingsu_core::collection::budget::Axis;

#[derive(Debug)]
pub enum CollectError {
    Read(ReadError),
    Budget(Axis),
    Deadline,
    Sink(std::io::Error),
    Panic,
}

/// Bingsu state, not a gix repository. C5 supplies validated capabilities after
/// ownership/preflight policy. No lazy ambient-path constructor is stored here.
pub struct GuardedRepository<'a> {
    pub io: io::RepoIo<'a>,
    pub config: config::Config,
    pub refs: refs::Refs,
}

impl<'a> GuardedRepository<'a> {
    pub fn new(io: io::RepoIo<'a>) -> Self {
        Self {
            io,
            config: config::Config::default(),
            refs: refs::Refs::default(),
        }
    }

    /// C3 supplies the object adapter. Never fall back to a path-based store.
    pub fn object(&self, _id: &[u8]) -> Result<Vec<u8>, ReadError> {
        Err(io::UNSUPPORTED)
    }
}
