//! Pure collected git merge, formatting and readonly layout costs. New cases
//! record their first positive Ir in CI; existing renderer limits stay at 1%.
use bingsu_core::{
    collection::{self, response::Completed, wire::ProtocolError},
    field::{BUILTIN, Value},
    icons::IconSet,
    layout::{self, Inputs, LaidLine, Options, SegmentSetup, When},
    recorder::NoopRecorder,
    shell_values::{self, Collected},
    shorten::Method,
    template::compile::{CompiledLine, compile},
    width::WidthProfile,
};
use gungraun::{library_benchmark, library_benchmark_group, main};
use std::hint::black_box;

#[allow(dead_code, unused_imports, reason = "shared core and golden fixtures")]
#[path = "../../bingsu-core/tests/git_render.rs"]
mod fixture;

#[inline(never)]
fn format_call(value: &Value, icons: IconSet, profile: WidthProfile) -> Value {
    shell_values::format_git(value, icons, profile)
}

#[library_benchmark]
#[bench::clean(args = ["clean"], setup = fixture::git_value)]
#[bench::counts(args = ["counts"], setup = fixture::git_value)]
#[bench::pending(args = ["pending"], setup = fixture::git_value)]
#[bench::saturated(args = ["saturated"], setup = fixture::git_value)]
#[bench::filtered(args = ["filtered"], setup = fixture::git_value)]
#[bench::no_repo(args = ["no-repo"], setup = fixture::git_value)]
fn format_git(value: Value) -> (Value, Value) {
    let output = black_box(format_call(
        black_box(&value),
        black_box(IconSet::Nerd),
        black_box(WidthProfile::DEFAULT),
    ));
    (value, output)
}

struct MergeCase {
    values: Collected,
    response: Option<Completed>,
    expected: collection::wire::Binding,
}

fn merge_case(kind: u8) -> MergeCase {
    let mut response = fixture::response(fixture::git_value("counts"));
    if kind == 2 {
        response.binding.snapshot.generation += 1;
    }
    MergeCase {
        values: shell_values::collect(&fixture::envelope()),
        response: (kind != 1).then_some(response),
        expected: fixture::binding(),
    }
}

#[inline(never)]
fn merge_call(case: &mut MergeCase) -> Result<(), ProtocolError> {
    collection::merge(
        &mut case.values,
        case.response.as_ref(),
        &case.expected,
        &case.expected.cwd,
        Some(b"/home/u"),
    )
}

#[library_benchmark]
#[bench::complete(args = [0], setup = merge_case)]
#[bench::missing(args = [1], setup = merge_case)]
#[bench::mismatch(args = [2], setup = merge_case)]
fn merge_git(mut case: MergeCase) -> (MergeCase, Result<(), ProtocolError>) {
    let result = black_box(merge_call(black_box(&mut case)));
    (case, result)
}

struct LayoutCase {
    values: Collected,
    line: CompiledLine,
    setup: Vec<SegmentSetup<'static>>,
    options: Options,
}

fn layout_case(width: u16) -> LayoutCase {
    let mut setup = vec![
        SegmentSetup {
            priority: 10,
            required: false,
            methods: &[],
            when: When::Needed,
        };
        BUILTIN.len()
    ];
    setup[1] = SegmentSetup {
        priority: 900,
        required: true,
        methods: &[Method::Repo, Method::Unique, Method::Depth(1)],
        when: When::Needed,
    };
    LayoutCase {
        values: fixture::merged(
            fixture::git_value("counts"),
            IconSet::Ascii,
            WidthProfile::DEFAULT,
        ),
        line: compile("{dir} {git}", BUILTIN).unwrap().remove(0),
        setup,
        options: Options {
            width,
            profile: WidthProfile::DEFAULT,
            icons: IconSet::Ascii,
            use_last_column: false,
        },
    }
}

#[inline(never)]
fn layout_call(case: &LayoutCase) -> LaidLine {
    layout::layout_line(
        0,
        &case.line,
        false,
        &Inputs {
            catalog: BUILTIN,
            values: &case.values.values,
            facts: &case.values.facts,
            setup: &case.setup,
        },
        &case.options,
        &mut NoopRecorder,
    )
}

#[library_benchmark]
#[bench::wide(args = [80], setup = layout_case)]
#[bench::shorten(args = [20], setup = layout_case)]
#[bench::truncate(args = [9], setup = layout_case)]
#[bench::minimal(args = [3], setup = layout_case)]
fn readonly_layout(case: LayoutCase) -> (LayoutCase, LaidLine) {
    let output = black_box(layout_call(black_box(&case)));
    (case, output)
}

#[inline(never)]
fn budget_call() -> collection::budget::BudgetCounters {
    use collection::budget::{Axis, BudgetCounters};
    let mut budget = BudgetCounters::default();
    for axis in Axis::ALL {
        black_box(budget.charge(axis, axis.limit())).unwrap();
        black_box(budget.charge(axis, 1)).unwrap_err();
    }
    budget
}

#[library_benchmark]
fn git_budget() -> collection::budget::BudgetCounters {
    black_box(budget_call())
}

#[inline(never)]
fn facts_call() -> collection::path_facts::PathFactInput {
    use collection::path_facts::{PathFactInput, SiblingSet};
    let value = PathFactInput {
        repo_component: Some(2),
        in_repo: Some(true),
        readonly: Some(false),
        siblings: vec![SiblingSet {
            component: 2,
            complete: true,
            names: vec![b"project".to_vec(), b"project-other".to_vec()],
        }],
        partial: false,
    };
    let cwd = b"/home/u/project";
    let bytes = value.encode(black_box(cwd)).unwrap();
    PathFactInput::decode(black_box(&bytes), black_box(cwd)).unwrap()
}

#[library_benchmark]
fn path_facts_codec() -> collection::path_facts::PathFactInput {
    black_box(facts_call())
}

// 이것을 실패시키는 것: 새 budget/PathFacts 작업을 bench 그룹에서 빼거나 측정 helper를 inline하는 것.
library_benchmark_group!(name = git; benchmarks = format_git, merge_git, readonly_layout, git_budget, path_facts_codec);
main!(library_benchmark_groups = git);
