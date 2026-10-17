N1 version 2 byte fixture

fixture.bin contains one complete frame, followed by a 208-byte marker,
96-byte sequence and 96-byte relay permit. The frame's CompiledConfig carries
both palettes, executable and language policies, provenance and palette warnings.
The shared fixture is crates/bingsu-core-tests/src/snapshot_fixture.rs.

Regenerate and review every changed byte:
  cargo run -j 2 -q -p bingsu-core-tests --example snapshot_fixture > tests/golden/snapshot/fixture.bin

Native check:
  cargo test -j 2 -p bingsu-core-tests --test snapshot_wire -- --test-threads=2

Execute the same fixture with a wasm32-unknown-unknown target and Node:
  RUSTFLAGS='--cfg getrandom_backend="unsupported"' cargo build -j 2 -p bingsu-core-tests --example snapshot_fixture --target wasm32-unknown-unknown
  node scripts/check_snapshot_wasm.mjs target/wasm32-unknown-unknown/debug/examples/snapshot_fixture.wasm tests/golden/snapshot/fixture.bin

The unsupported entropy backend is for the test crate's proptest dependency.
This fixture requests no randomness. Product features and the core purity gate
remain unchanged. The example also writes stdout natively or under WASI.

These bounded byte corpora and mutation checks are not a completed fuzz campaign.
Changing Node/field/token/icon index meanings requires a compiled ABI/codec bump;
keep the header and prefix versions, all explicit tags, reserved zero bytes and
checksum domains synchronized with the version being written.
