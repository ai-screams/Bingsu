//! Instruction counts of field formatting (spec section 8 "측정과 게이트",
//! section 9 M2 row). Each bench group is its own bench target: in one
//! shared binary this count moved by 3.5% and 4.57% when unrelated benches
//! joined, because the inlining of shared generic code changed.
use bingsu_core::field::{Field, FieldValue};
use bingsu_core::width::WidthProfile;
use gungraun::prelude::*;
use std::hint::black_box;

// Only the code inside the benchmark function is counted (the runner
// collects within `__gungraun_wrapper_mod::*`). An owned input would be
// dropped, and freed, at the end of that function, so each bench returns
// its input: the caller drops the returned value outside the counted code.
//
// The output buffer is reserved here, so the counted code formats without
// growing a String: the growth path (`RawVec::finish_grow`) is shared
// generic code whose inlining depends on what else is in the binary.
fn fields(_: u32) -> (Vec<Field>, String) {
    let fields = vec![
        Field::known(FieldValue::Count {
            n: 1234,
            saturated: true,
        }),
        Field::known(FieldValue::Duration { ms: 3_723_000 }),
        Field::known(FieldValue::Int(-130)),
        Field::text(b"feature/very-long-branch-name", 24, WidthProfile::DEFAULT),
    ];
    (fields, String::with_capacity(256))
}

#[library_benchmark]
#[bench::four(args = [4], setup = fields)]
fn field_format((input, mut s): (Vec<Field>, String)) -> (Vec<Field>, String) {
    for f in black_box(&input) {
        f.write_to(&mut s);
    }
    (input, black_box(s))
}

library_benchmark_group!(name = core_m2, benchmarks = [field_format]);

// main! defines `fn main` itself: wrapped in a fn of ours the bench would
// build, exit 0 and measure nothing.
main!(library_benchmark_groups = core_m2);
