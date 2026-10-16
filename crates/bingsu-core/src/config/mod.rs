//! The config model (spec section 2): pure functions over file bytes. The
//! CLI opens files, resolves paths and decides trust; this module parses,
//! orders the `extends` graph, merges, records where every value came
//! from, checks and compiles. Nothing here reads a file or a clock.
pub mod tree;
