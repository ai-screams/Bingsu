//! F2 fixed-seed regression corpus on the stable toolchain. The entries and
//! seeds are the same files fuzz/collector's libFuzzer targets include; here
//! each seed's verdict is pinned and the shared oracles must hold.
#![cfg(unix)]
#![allow(dead_code)]
#[path = "../src/git/mod.rs"]
mod git;
#[cfg(target_os = "linux")]
#[path = "../src/landlock.rs"]
mod landlock;
#[path = "../src/meter.rs"]
mod meter;
#[path = "../src/safe_read/mod.rs"]
mod safe_read;
#[path = "../src/update_sink.rs"]
mod update_sink;

#[path = "support/allocation.rs"]
mod allocation;
#[path = "../../../fuzz/collector/src/entries.rs"]
mod entries;
#[path = "../../../fuzz/collector/src/formats.rs"]
mod formats;
#[path = "../../../fuzz/collector/src/seeds.rs"]
mod seeds;

use entries::Target;
use seeds::Class;
use std::{collections::BTreeSet, time::Duration};

// 이것을 실패시키는 것: 상한 검사(예: index의 INDEX_ENTRIES charge, pack의
// DELTA_DEPTH, config의 SECTION_LIMIT) 하나를 지우거나 `>`를 `>=`로 바꾸는
// 것. cap±1 seed의 고정 판정이 바뀐다. 예약 해제·deadline·heap 상한을 어기는
// parser 변경도 assert_bounded에서 실패한다.
#[test]
fn fixed_seed_corpus_replays_with_pinned_verdicts() {
    let mut failures = Vec::new();
    for seed in seeds::all() {
        let mut prepared = entries::prepare(seed.target, &seed.data);
        let (outcome, counts) = allocation::measure(|| entries::execute(&mut prepared));
        // Debug builds are slower; the release fuzz job uses DEADLINE + 1 s.
        entries::assert_bounded(
            &outcome,
            counts.peak,
            seed.data.len(),
            Duration::from_secs(8),
        );
        if outcome.verdict != seed.expect {
            failures.push(format!(
                "{}/{} ({:?}): expected {:?}, got {:?}",
                seed.target.name(),
                seed.name,
                seed.class,
                seed.expect,
                outcome.verdict
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

// 이것을 실패시키는 것: 한 target에서 damaged·truncated·cyclic·oversize·
// cap-1·cap·cap+1 중 한 class의 seed를 지우는 것, 또는 이름 중복.
#[test]
fn every_target_has_every_seed_class() {
    let all = seeds::all();
    for target in Target::ALL {
        let classes: BTreeSet<Class> = all
            .iter()
            .filter(|s| s.target == target)
            .map(|s| s.class)
            .collect();
        assert_eq!(
            classes,
            Class::REQUIRED.into_iter().collect(),
            "{}",
            target.name()
        );
    }
    let names: BTreeSet<_> = all.iter().map(|s| (s.target, s.name)).collect();
    assert_eq!(names.len(), all.len(), "duplicate seed name");
}

// 이것을 실패시키는 것: fuzz_targets/<name>.rs가 다른 entry를 부르거나
// target 파일이 빠지는 것. 열 target 모두 같은 entries::run을 공유한다.
#[test]
fn every_fuzz_target_calls_its_shared_entry() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fuzz/collector");
    let manifest = std::fs::read_to_string(root.join("Cargo.toml"))
        .unwrap()
        .replace("\r\n", "\n");
    let mut files: Vec<_> = std::fs::read_dir(root.join("fuzz_targets"))
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    files.sort();
    let mut expected: Vec<_> = Target::ALL
        .iter()
        .map(|t| format!("{}.rs", t.name()))
        .collect();
    expected.sort();
    assert_eq!(files, expected);
    for target in Target::ALL {
        let name = target.name();
        let source = std::fs::read_to_string(root.join(format!("fuzz_targets/{name}.rs")))
            .unwrap()
            .replace("\r\n", "\n");
        let variant = format!("{target:?}");
        assert!(
            source.contains(&format!("fuzz_one(Target::{variant}, data)")),
            "{name}"
        );
        assert_eq!(source.matches("Target::").count(), 1, "{name}");
        assert!(
            manifest.contains(&format!(
                "[[bin]]\nname = \"{name}\"\npath = \"fuzz_targets/{name}.rs\"\n"
            )),
            "{name}"
        );
    }
}
