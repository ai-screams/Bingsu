# Collector X-14

This independent experiment pins gix 0.83.0 and uses the product collector's
classic BPF and Landlock implementation as a path dependency. It is not part of
the product dependency graph. The parallel gix feature is disabled; the probe
creates and joins one Rust thread, then runs status synchronously.

The release lead must generate and fetch the independent lock on a networked
host before submitting the change:

```sh
cargo generate-lockfile --manifest-path bench/probes/collector-x14/Cargo.toml
cargo fetch --locked --manifest-path bench/probes/collector-x14/Cargo.toml
```

The lock is deliberately not synthesized or copied from another gix version.
CI requires it and audits it; a missing lock is a failure, never a skipped probe.

```sh
cargo run --locked --manifest-path bench/probes/collector-x14/Cargo.toml --release -- --case all
```

The parent creates a new trusted temporary repository with a tracked change and
an untracked file, no hooks, submodules, attributes, or external filters. The
filtered child uses the same 32 MiB AS allowance and base limits as the worker.
Acceptance requires a joined Rust thread, fork EPERM, clone3 ENOSYS, completed
gix status with both changes, unchanged index bytes in child and parent, and
exactly one `X-14 status PASS` record. `Outcome::write_changes` is never called.
Failure must lead to reviewing read-only syscall needs or the memory budget,
without loosening the protection policy automatically.

The independent `collector-x14` CI matrix runs native x86_64 and aarch64 with
glibc 2.35+ and musl, preserving both PASS assertions and logs. Its separate
build graph no longer consumes the Dedicated collector's 30-minute budget.
The workspace filter tests independently require a pre-filter
clone3 EINVAL control, real per-row syscall probes, inherited thread protection,
and X-16's six denial cells. Those tests do not depend on fetching gix.
