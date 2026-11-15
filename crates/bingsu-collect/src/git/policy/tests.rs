use super::*;
use gix_attributes::search::MetadataCollection;
use std::time::{Duration, Instant};

fn add(p: &mut Patterns, bytes: &[u8], source: &str, m: &mut Meter) {
    p.add_buffer(
        bytes,
        source.into(),
        PatternKind::Ignore,
        Axis::IgnorePatterns,
        m,
    )
    .unwrap();
}

// gix turned this panic into an error; a refused source must leave no list.
// 이것을 실패시키는 것: add_buffer의 add_patterns_buffer 오류 두 곳 중 하나를
// 버리는 것.
#[test]
fn source_without_a_parent_is_refused() {
    for (kind, axis) in [
        (PatternKind::Ignore, Axis::IgnorePatterns),
        (PatternKind::Attributes, Axis::AttributePatterns),
    ] {
        let mut meter = Meter::new(Instant::now() + Duration::from_secs(30));
        let mut patterns = Patterns::default();
        let added = patterns.add_buffer(b"*.log text\n", "".into(), kind, axis, &mut meter);
        assert_eq!(added, Err(INVALID));
        assert!(patterns.ignore.patterns.is_empty());
        assert!(patterns.attributes.is_empty());
        assert!(patterns.ignore_weights.is_empty());
    }
}

// 이것을 실패시키는 것: class_bytes에서 escape 건너뛰기, 앞 `!`·`^`·`]` 처리,
// `[:name:]` 처리, 닫히지 않은 클래스를 줄 끝까지 세기 중 하나를 빼는 것.
#[test]
fn class_bytes_follow_the_glob_grammar() {
    for (line, bytes) in [
        (&b"*.py[cod]"[..], 5),
        (b"[Bb]in/", 4),
        (b"report.[0-9]*.[0-9]*.[0-9]*.[0-9]*.json", 20),
        (b"[]a]", 4),
        (b"[!]a]x", 5),
        (b"[^a]", 4),
        (b"[[:alpha:]]x", 11),
        (b"[a[:x:]]", 8),
        (b"\\[a]", 0),
        (b"[a\\]]", 5),
        (b"x[ab", 3),
        (b"[", 1),
    ] {
        assert_eq!(class_bytes(line), bytes, "{:?}", line.as_bstr());
    }
}

// 이것을 실패시키는 것: gix-ignore가 패턴 텍스트를 원시 줄보다 무겁게 만드는
// 것(예: 따옴표 해제를 하는 버전으로 올리는 것). 무작위 줄과 앞 `\!`,
// 뒤 공백, `\ ` 같은 변형 줄에서 텍스트의 런·클래스 수가 줄의 것 이하인지 본다.
#[test]
fn ignore_text_never_outweighs_its_line() {
    const PARTS: [&str; 16] = [
        "*", "**", "/", "[a]", "[", "]", "\\", "\\ ", " ", "!", "#", "$", "\"", "\\052", "a",
        "[!a]",
    ];
    let mut rng = Rng(0x2545_f491_4f6c_dd1d);
    for _ in 0..20_000 {
        let mut line = String::new();
        for _ in 0..(rng.0 % 12 + 1) {
            line.push_str(rng.pick(&PARTS));
        }
        for (pattern, _, _) in gix_ignore::parse(line.as_bytes(), false) {
            let text = &pattern.text;
            let (runs, globstars) = star_runs(text);
            let (line_runs, line_globstars) = star_runs(line.as_bytes());
            assert!(runs <= line_runs && globstars <= line_globstars, "{line:?}");
            assert!(
                class_bytes(text) <= class_bytes(line.as_bytes()),
                "{line:?}"
            );
            assert!(weight(text) <= weight(line.as_bytes()), "{line:?}");
        }
    }
}

// 이것을 실패시키는 것: gix-attributes가 따옴표 없는 패턴도 무겁게 만드는
// 것(예: escape를 푸는 버전으로 올리는 것). 따옴표로 시작하지 않는 무작위
// 줄(앞 공백, `\!`, 클래스, escape, 속성 포함)에서 텍스트가 줄 이하인지 본다.
#[test]
fn attribute_unquoted_text_never_outweighs_its_line() {
    const PARTS: [&str; 18] = [
        "*", "**", "/", "[a]", "[", "]", "\\", "\\ ", " ", "\t", "\\!", "#", "a", "[!a]", "\\052",
        " text", " -diff", "\"",
    ];
    let mut rng = Rng(0x5851_f42d_4c95_7f2d);
    let mut seen = 0;
    for _ in 0..20_000 {
        let mut line = String::new();
        for _ in 0..(rng.0 % 12 + 1) {
            line.push_str(rng.pick(&PARTS));
        }
        if quoted(line.as_bytes(), 1) {
            continue;
        }
        // A leading line keeps it off the first line, as gix numbers them.
        let text = format!("x\n{line}\n");
        for item in gix_attributes::parse(text.as_bytes()).flatten() {
            let (gix_attributes::parse::Kind::Pattern(pattern), _, 2) = item else {
                continue;
            };
            let raw = line.as_bytes();
            let (runs, globstars) = star_runs(&pattern.text);
            let (line_runs, line_globstars) = star_runs(raw);
            assert!(runs <= line_runs && globstars <= line_globstars, "{line:?}");
            assert!(class_bytes(&pattern.text) <= class_bytes(raw), "{line:?}");
            assert!(weight(&pattern.text) <= weight(raw), "{line:?}");
            seen += 1;
        }
    }
    assert!(seen > 10_000, "{seen}");
}

// The shape of a real 1,205-line .gitignore (names replaced): 430 comment
// lines (3,440 words here, 2,060 in the real file), 460 one-word patterns
// and 315 blank lines.
// 이것을 실패시키는 것: 주석 줄의 단어를 단어 상한에 세는 것.
#[test]
fn long_commented_ignore_file_is_accepted() {
    // Kinds spread over the file by a stride coprime with 1,205.
    let mut text = String::new();
    for i in 0..1205 {
        let k = i * 7 % 1205;
        match k {
            0..430 => text.push_str(&format!("# section {k} keeps generated files of tool\n")),
            430..890 if k % 3 == 0 => text.push_str(&format!("/out-{k}/\n")),
            430..890 if k % 3 == 1 => text.push_str(&format!("**/cache-{k}\n")),
            430..890 => text.push_str(&format!("*.ext{k}\n")),
            _ => text.push('\n'),
        }
    }
    let lines = |f: fn(&str) -> bool| text.lines().filter(|l| f(l)).count();
    assert_eq!(lines(|l| l.starts_with('#')), 430);
    assert_eq!(lines(|l| !l.is_empty() && !l.starts_with('#')), 460);
    let all: usize = text.split_ascii_whitespace().count();
    assert!(all > 2048, "{all}");
    let mut m = Meter::new(Instant::now() + Duration::from_secs(30));
    let mut patterns = Patterns::default();
    add(&mut patterns, text.as_bytes(), ".gitignore", &mut m);
    assert_eq!(
        patterns.ignored_in(&mut m, b"src/a.ext431", false, NamePolicy::default()),
        Ok(true)
    );
}

// 이것을 실패시키는 것: ignored_in에서 list나 pattern 순회의 `.rev()`를 지우는
// 것, base를 떼지 않은 경로로 맞추는 것, 부정 판정을 뒤집는 것, case를
// Sensitive로 고정하는 것. 모두 gix_ignore::Search와 판정이 갈린다.
#[test]
fn ignore_loop_matches_gix_search() {
    let files: [(&str, &[u8]); 3] = [
        ("info/exclude", b"*.log\n!keep.log\nbuild/\n"),
        (".gitignore", b"!*.log\n/root.txt\nDocs/**/*.md\n"),
        (
            "sub/.gitignore",
            b"*.tmp\n!important.tmp\n/anchored\nnested/\n",
        ),
    ];
    let mut m = Meter::new(Instant::now() + Duration::from_secs(30));
    let mut ours = Patterns::default();
    let mut gix = gix_ignore::Search::default();
    for (source, bytes) in files {
        add(&mut ours, bytes, source, &mut m);
        let root = (source != "info/exclude").then_some(Path::new(""));
        let parse = gix_ignore::search::Ignore {
            support_precious: false,
        };
        gix.add_patterns_buffer(bytes, source, root, parse).unwrap();
    }
    for path in [
        "a.log",
        "keep.log",
        "sub/a.log",
        "x.tmp",
        "sub/x.tmp",
        "sub/important.tmp",
        "SUB/X.TMP",
        "anchored",
        "sub/anchored",
        "sub/deep/anchored",
        "build",
        "sub/build",
        "sub/nested",
        "root.txt",
        "sub/root.txt",
        "Docs/a/b.md",
        "docs/a/b.md",
    ] {
        for is_dir in [false, true] {
            for ignore_case in [false, true] {
                let names = NamePolicy {
                    ignore_case,
                    precompose_unicode: false,
                };
                let want = gix
                    .pattern_matching_relative_path(path.into(), Some(is_dir), names.case())
                    .is_some_and(|found| !found.pattern.is_negative());
                assert_eq!(
                    ours.ignored_in(&mut m, path.as_bytes(), is_dir, names),
                    Ok(want),
                    "{path} dir={is_dir} ignore_case={ignore_case}"
                );
            }
        }
    }
}

// 이것을 실패시키는 것: 가중치를 (`*` 런 + 1) << `**` 런이 아닌 값(예: 1)으로
// 두거나, 클래스 바이트 계수를 빼거나, 작업량에서 패턴 바이트를 빼거나,
// MATCH_CHECK_UNITS를 바꾸는 것.
// 검사 횟수가 고정값에서 벗어난다.
#[test]
fn ignore_check_interval_follows_the_pattern_weight() {
    let checks = |line: &str, path: &str| {
        let mut m = Meter::new(Instant::now() + Duration::from_secs(30));
        let mut patterns = Patterns::default();
        add(
            &mut patterns,
            line.repeat(512).as_bytes(),
            ".gitignore",
            &mut m,
        );
        let count = std::rc::Rc::new(std::cell::Cell::new(0));
        let seen = count.clone();
        m.hook = Some(Box::new(move |event| {
            if event == "ignore_match_check" {
                seen.set(seen.get() + 1);
            }
        }));
        assert_eq!(
            patterns.ignored_in(&mut m, path.as_bytes(), false, NamePolicy::default()),
            Ok(false)
        );
        count.get()
    };
    let long = "a/".repeat(500) + "z";
    // (1001 + 20) * 72 units per pattern: one check before each.
    assert_eq!(checks("**/*a*/**/*a*/**/*ax\n", &long), 512);
    // (1001 + 5) * 2 units: one check per 33 patterns.
    assert_eq!(checks("*.log\n", &long), 15);
    // (7 + 5) * 2 units: the 512 patterns fit in one interval.
    assert_eq!(checks("*.log\n", "src/a.c"), 0);
    // (7 + 205) * 2 units: the pattern's own bytes count too.
    let named = "a".repeat(200) + "*.log\n";
    assert_eq!(checks(&named, "src/a.c"), 3);
    // (1001 + 9) * 2 * (1 + 5 / 4) units: class bytes raise the weight.
    assert_eq!(checks("*.py[cod]\n", &long), 30);
}

// 이것을 실패시키는 것: ignored_in 루프의 MATCH_CHECK_UNITS 검사를 지우는 것.
// 첫 m.check()는 마감 전이라 통과하고, 그 뒤에는 cap 모양 패턴 512개를 다
// 맞춰 수 초 뒤에 Ok(false)를 낸다.
#[test]
fn ignore_matching_checks_the_deadline_between_patterns() {
    let line = "**/*a*/**/*a*/**/*ax\n";
    assert_eq!(
        star_runs(line.trim_end().as_bytes()),
        (STAR_RUNS, GLOBSTAR_RUNS)
    );
    let mut m = Meter::new(Instant::now() + Duration::from_secs(30));
    let mut patterns = Patterns::default();
    add(
        &mut patterns,
        line.repeat(512).as_bytes(),
        ".gitignore",
        &mut m,
    );
    let path = vec!["aa"; 16_384].join("/");
    let mut m = Meter::new(Instant::now() + Duration::from_millis(20));
    let start = Instant::now();
    assert_eq!(
        patterns.ignored_in(&mut m, path.as_bytes(), false, NamePolicy::default()),
        Err(ReadError::Deadline)
    );
    assert!(
        start.elapsed() < Duration::from_secs(2),
        "{:?}",
        start.elapsed()
    );
}

fn add_attributes(p: &mut Patterns, bytes: &[u8], source: &str, m: &mut Meter) {
    p.add_buffer(
        bytes,
        source.into(),
        PatternKind::Attributes,
        Axis::AttributePatterns,
        m,
    )
    .unwrap();
}

/// Matches of one outcome, without line numbers (each part counts its own).
fn matches(out: &gix_attributes::search::Outcome, selected: bool) -> Vec<String> {
    let show = |a: gix_attributes::search::Match<'_>| {
        format!(
            "{:?} {:?} {:?} {:?}",
            a.assignment, a.pattern.text, a.kind, a.location.source
        )
    };
    if selected {
        out.iter_selected().map(show).collect()
    } else {
        out.iter().map(show).collect()
    }
}

struct Rng(u64);
impl Rng {
    fn pick<'a>(&mut self, items: &[&'a str]) -> &'a str {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        items[(self.0 % items.len() as u64) as usize]
    }
}

// 이것을 실패시키는 것: match_attributes에서 part 순회의 `.rev()`를 지우는 것,
// info와 일반 part 순서를 바꾸는 것, part를 `start - 1`이 아닌 `start`부터
// 자르는 것, part 경계에서 줄을 빠뜨리거나 겹치는 것. 모두 gix 원 Search와
// 선택 결과 또는 전체 결과(우선순위, 값, 매치한 패턴)가 갈린다.
#[test]
fn attribute_parts_match_gix_search() {
    const PATTERNS: [&str; 15] = [
        "\"\\052.c\"",
        "\"q\\040p\"",
        "*.c",
        "a/**/b",
        "**/x",
        "/root",
        "sub/*",
        "\"q p\"",
        "sub/neg",
        "x",
        "*",
        "docs/**",
        "+/v8",
        "\u{feff}bom",
        "A*.C",
    ];
    const ATTRS: [&str; 13] = [
        "text",
        "-text",
        "!text",
        "text=auto",
        "eol=lf",
        "eol=crlf",
        "filter=lfs",
        "binary",
        "diff",
        "ident",
        "working-tree-encoding=UTF-16",
        "linguist-vendored",
        "-diff",
    ];
    const PATHS: [&str; 15] = [
        "a.c",
        "sub/a.c",
        "sub/x",
        "root",
        "sub/root",
        "a/b",
        "a/x/b",
        "docs/q p",
        "q p",
        "+/v8",
        "bom",
        "x",
        "sub/neg",
        "A.C",
        "docs/deep/x",
    ];
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    // A fixed boundary case: PART_WEIGHT / 2 lines of weight 2 fill a part, so the
    // `+/v8` line starts the next one.
    let mut fixed = "*.c eol=lf\n".repeat(PART_WEIGHT / 2);
    fixed.push_str("+/v8 text\n");
    let mut refused = 0;
    'round: for round in 0..400 {
        let mut files = Vec::new();
        for source in ["info/attributes", ".gitattributes", "sub/.gitattributes"] {
            let mut text = if round == 0 && source == ".gitattributes" {
                fixed.clone()
            } else {
                String::new()
            };
            for _ in 0..(round % 90) {
                let mut line = rng.pick(&["", "", "", "# c *", " "]).to_owned();
                if line.is_empty() {
                    line.push_str(rng.pick(&PATTERNS));
                    for _ in 0..(rng.0 % 3 + 1) {
                        line.push(' ');
                        line.push_str(rng.pick(&ATTRS));
                    }
                }
                line.push_str(rng.pick(&["\n", "\n", "\r\n"]));
                text.push_str(&line);
            }
            files.push((source, text));
        }
        let mut m = Meter::new(Instant::now() + Duration::from_secs(30));
        let mut ours = Patterns::default();
        let (mut info, mut rest) = (
            gix_attributes::Search::default(),
            gix_attributes::Search::default(),
        );
        let mut metadata = MetadataCollection::default();
        for (source, text) in &files {
            let added = ours.add_buffer(
                text.as_bytes(),
                (*source).into(),
                PatternKind::Attributes,
                Axis::AttributePatterns,
                &mut m,
            );
            // Only gix parse errors are refused, e.g. a file-start `+/v8`
            // mark leaving a negated pattern.
            if added.is_err() {
                assert!(
                    gix_attributes::parse(text.as_bytes()).any(|line| line.is_err()),
                    "{text:?}"
                );
                refused += 1;
                continue 'round;
            }
            let root = (*source != "info/attributes").then_some(Path::new(""));
            let search = if root.is_none() { &mut info } else { &mut rest };
            search
                .add_patterns_buffer(text.as_bytes(), source.into(), root, &mut metadata, false)
                .unwrap();
        }
        for path in PATHS {
            for case in [
                gix_ignore::glob::pattern::Case::Sensitive,
                gix_ignore::glob::pattern::Case::Fold,
            ] {
                for selected in [true, false] {
                    let init = |out: &mut gix_attributes::search::Outcome,
                                metadata: &MetadataCollection| {
                        if selected {
                            out.initialize_with_selection(
                                metadata,
                                ["filter", "text", "eol", "ident", "working-tree-encoding"],
                            );
                        } else {
                            out.initialize(metadata);
                        }
                    };
                    let mut want = gix_attributes::search::Outcome::default();
                    init(&mut want, &metadata);
                    let path = path.into();
                    info.pattern_matching_relative_path(path, case, Some(false), &mut want);
                    if !want.is_done() {
                        rest.pattern_matching_relative_path(path, case, Some(false), &mut want);
                    }
                    let mut got = gix_attributes::search::Outcome::default();
                    init(&mut got, &ours.metadata);
                    ours.match_attributes(&mut m, path, case, &mut got).unwrap();
                    assert_eq!(
                        matches(&got, selected),
                        matches(&want, selected),
                        "round {round} {path} {case:?} selected={selected}\n{files:?}"
                    );
                }
            }
        }
    }
    assert!(refused < 100, "{refused} of 400 rounds refused");
}

// 이것을 실패시키는 것: match_attributes의 MATCH_CHECK_UNITS 검사를 지우는 것.
#[test]
fn attribute_matching_checks_the_deadline_between_parts() {
    let line = "**/*a*/**/*a*/**/*ax text\n";
    assert_eq!(
        star_runs(line.trim_end().as_bytes()),
        (STAR_RUNS, GLOBSTAR_RUNS)
    );
    let mut m = Meter::new(Instant::now() + Duration::from_secs(30));
    let mut patterns = Patterns::default();
    add_attributes(
        &mut patterns,
        line.repeat(1024).as_bytes(),
        ".gitattributes",
        &mut m,
    );
    let path = vec!["aa"; 16_384].join("/");
    let policies = Policies::from_config(&Config::default()).unwrap();
    let mut m = Meter::new(Instant::now() + Duration::from_millis(20));
    let start = Instant::now();
    assert_eq!(
        patterns.conversion_in(&mut m, path.as_bytes(), policies),
        Err(ReadError::Deadline)
    );
    assert!(
        start.elapsed() < Duration::from_secs(2),
        "{:?}",
        start.elapsed()
    );
}

// 이것을 실패시키는 것: part 가중치를 줄 가중치의 합이 아닌 값으로 두거나
// 줄 바이트 항을 빼는 것, PART_WEIGHT·MATCH_CHECK_UNITS를 바꾸는 것, 또는
// 선택이 다 찬 뒤에도 남은
// part를 도는 것(마지막 시험의 검사 횟수가 0에서 벗어난다).
#[test]
fn attribute_check_interval_follows_the_part_weight() {
    let checks = |text: &str, path: &str| {
        let mut m = Meter::new(Instant::now() + Duration::from_secs(30));
        let mut patterns = Patterns::default();
        add_attributes(&mut patterns, text.as_bytes(), ".gitattributes", &mut m);
        let count = std::rc::Rc::new(std::cell::Cell::new(0));
        let seen = count.clone();
        m.hook = Some(Box::new(move |event| {
            if event == "attribute_match_check" {
                seen.set(seen.get() + 1);
            }
        }));
        let policies = Policies::from_config(&Config::default()).unwrap();
        patterns
            .conversion_in(&mut m, path.as_bytes(), policies)
            .unwrap();
        count.get()
    };
    let long = "a/".repeat(500) + "z";
    // Weight 72 per line, a part each: (1001 * 72 + 26 * 72) units.
    assert_eq!(
        checks(&"**/*a*/**/*a*/**/*ax text\n".repeat(512), &long),
        512
    );
    // Weight 2, 32 lines a part: 1001 * 64 + 32 * 22 units per part.
    assert_eq!(checks(&"*.log text\n".repeat(512), &long), 8);
    assert_eq!(checks(&"*.log text\n".repeat(512), "src/a.c"), 0);
    // 7 * 64 + 32 * 422 units per part: the lines' own bytes count too.
    let named = "a".repeat(200) + "*.log text\n";
    assert_eq!(checks(&named.repeat(512), "src/a.c"), 3);
    // A quoted line weighs as gix's unquoted `**/*a/c`: (2 + 1) << 1 = 6,
    // 10 lines a part, 1001 * 60 + 10 * 23 * 6 units per part.
    let quoted = "\"\\052\\052/\\052a/c\" text\n";
    assert_eq!(checks(&quoted.repeat(512), &long), 26);
    // The last line fills every selected attribute; nothing else is visited.
    let mut filled = "**/*a*/**/*a*/**/*ax text\n".repeat(512);
    filled.push_str("* text eol=lf filter=x ident working-tree-encoding=x\n");
    assert_eq!(checks(&filled, &long), 0);
}

// The match loops copy gix-ignore 0.24 and gix-attributes 0.37 search order
// over gix-glob 0.29 wildmatch; the cap costs were measured on the previous
// releases, whose match and wildmatch code is unchanged in these.
// 이것을 실패시키는 것: Cargo.lock의 셋 중 하나를 GIX_MATCH_VERSIONS와 다른
// 버전으로 올리는 것.
#[test]
fn match_loops_are_pinned_to_gix_versions() {
    let lock = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../Cargo.lock"))
        .replace("\r\n", "\n");
    for (name, version) in GIX_MATCH_VERSIONS {
        let found: Vec<_> = lock
            .split("\n[[package]]\n")
            .filter(|block| block.starts_with(&format!("name = \"{name}\"\n")))
            .map(|block| block.lines().nth(1).unwrap_or_default())
            .collect();
        assert_eq!(found, [format!("version = \"{version}\"")], "{name}");
    }
}
