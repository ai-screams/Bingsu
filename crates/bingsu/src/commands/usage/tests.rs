use super::*;
use std::collections::BTreeSet;

/// Every command line that has a help, top level first.
fn helped() -> Vec<Vec<&'static str>> {
    let mut out = vec![vec![]];
    for c in COMMANDS.iter().filter(|c| c.help) {
        out.push(vec![c.name]);
        if c.name == "config" {
            for s in c.subs {
                out.push(vec![c.name, s.name]);
            }
        }
    }
    out
}

fn os(words: &[&str]) -> Vec<OsString> {
    words.iter().map(OsString::from).collect()
}

// 이것을 실패시키는 것: 오늘의 사용법 줄을 한 바이트라도 바꾸는 것(오류 경로의 문구와 그것을 고정한 시험이 갈라짐),
// 표에 없는 경로에 최상위 줄이 아닌 다른 줄을 주는 것.
#[test]
fn usage_lines_are_the_ones_from_before() {
    let want: [(&[&str], &str); 10] = [
        (
            &[],
            "usage: bingsu <config|doctor|explain|help|init|list|prompt|reload|setup|--version> ...",
        ),
        (
            &["config"],
            "usage: bingsu config <check [--explain] [--format json|text]|edit|path|schema [--theme]|use PATH>",
        ),
        (&["config", "use"], "usage: bingsu config use PATH"),
        (
            &["doctor"],
            "usage: bingsu doctor [--format json|text] [--terminal] [--evidence-stdin]",
        ),
        (
            &["explain"],
            "usage: bingsu explain [SEGMENT] [--width N] [--config FILE] [--format json|text]",
        ),
        (
            &["help"],
            "usage: bingsu help <code>   (a code such as E201, W404 or N501)",
        ),
        (
            &["list"],
            "usage: bingsu list <presets [--preview [--icons nerd|light|unicode|ascii]]|segments|flavors|roles|shorteners|icons>",
        ),
        (&["reload"], "usage: bingsu reload"),
        (
            &["setup"],
            "usage: bingsu setup [--yes] [--plain] [--icons nerd|light|unicode|ascii] [--mode auto|dark|light]",
        ),
        (&["--version"], "usage: bingsu --version"),
    ];
    for (path, line) in want {
        assert_eq!(super::line(path), line, "{path:?}");
    }
    // A wrong use of `init` prints a message, not a usage line: this line is
    // new, and only its help shows it.
    assert_eq!(super::line(&["init"]), "usage: bingsu init zsh|bash|fish");
    // A path the table does not know gets the top-level line.
    assert_eq!(super::line(&["nope"]), super::line(&[]));
    assert_eq!(super::line(&["config", "nope"]), super::line(&[]));
}

// 이것을 실패시키는 것: 도움말 줄이 80칸을 넘거나 ASCII 밖 글자를 쓰거나 빈칸으로 끝나는 것, 도움말에 그 명령의
// 사용법·한 줄 목적·옵션·-h 안내가 빠지는 것, 들어가는 사용법 줄이 오류 때의 줄과 다른 것, 하위 명령 안내를 config 밖에
// 붙이거나 config에서 빼는 것.
#[test]
fn every_help_is_ascii_within_80_columns() {
    for path in helped() {
        let t = text(&path);
        for l in t.lines() {
            assert!(!l.ends_with(' '), "{path:?}: {l:?}");
            assert!(l.is_ascii(), "{path:?}: {l:?}");
            assert!(l.len() <= WIDTH, "{path:?}: {} columns: {l}", l.len());
        }
        assert!(t.contains("-h, --help"), "{path:?}");
        let footer = t.contains("<command> --help shows the arguments");
        assert_eq!(footer, path.is_empty() || path == ["config"], "{path:?}");
        if find(&path).is_some_and(|c| c.subs.is_empty()) {
            // A usage line that fits is the one a wrong use prints.
            let usage = line(&path);
            if usage.len() <= WIDTH {
                assert!(t.contains(&format!("\n{usage}\n")), "{path:?}");
            }
        }
        if let Some(c) = find(&path) {
            assert!(
                t.starts_with(&format!("bingsu {}: {}\n", path.join(" "), c.what)),
                "{path:?}"
            );
            assert!(t.contains(&format!("usage: bingsu {}", path.join(" "))));
            for o in c.opts {
                // Two spaces or a new line between an option and what it does.
                let apart = [
                    format!("  {}  ", o.words),
                    format!("  {}\n{:COLUMN$}{}\n", o.words, "", o.what),
                ];
                assert!(
                    apart.iter().any(|a| t.contains(a.as_str())),
                    "{path:?} {}",
                    o.words
                );
                assert!(t.contains(o.what), "{path:?} {}", o.words);
            }
        }
    }
}

// 이것을 실패시키는 것: -h·--help를 그 명령의 유일한 단어가 아닐 때도 도움말로 보는 것, config 밖의 하위 명령이나
// 도움말이 없는 명령(prompt, --version)에 도움말을 주는 것.
#[test]
fn help_is_asked_only_by_the_sole_word() {
    for path in helped() {
        for h in HELP_WORDS {
            let mut words = path.clone();
            words.push(h);
            assert_eq!(asked(&os(&words)), Some(text(&path)), "{words:?}");
        }
    }
    for words in [
        &["setup", "--yes", "--help"][..],
        &["--help", "setup"],
        &["setup", "--help", "--yes"],
        &["config", "use", "./--help"],
        &["config", "use", "x", "--help"],
        &["list", "presets", "--help"],
        &["--version", "--help"],
        &["prompt", "--help"],
        &["nope", "--help"],
        &["explain", "--config", "--help"],
        &["setup", "--HELP"],
        &["setup", "help"],
        &[],
    ] {
        assert_eq!(asked(&os(words)), None, "{words:?}");
    }
}

/// The words a parser takes for an option or operand of the table: its
/// value words split at `|`, a sample for a placeholder.
#[cfg(unix)]
fn samples(words: &str) -> Vec<Vec<String>> {
    let parts: Vec<&str> = words.split(' ').collect();
    let sample = |w: &str| match w {
        "N" => vec![String::from("40")],
        "FILE" | "PATH" => vec![String::from("f.toml")],
        "SEGMENT" => vec![String::from("git")],
        "<code>" => vec![String::from("E201")],
        w => w.split('|').map(String::from).collect(),
    };
    match parts.as_slice() {
        [flag, value] => sample(value)
            .into_iter()
            .map(|v| vec![(*flag).to_owned(), v])
            .collect(),
        [one] if one.starts_with("--") => vec![vec![(*one).to_owned()]],
        [one] => sample(one).into_iter().map(|v| vec![v]).collect(),
        _ => panic!("an option of more than two words: {words}"),
    }
}

// 이것을 실패시키는 것: 도움말이 이름하는 옵션·값·하위 명령을 실제 파서가 받지 않는 것(도움말이 없는 인자를 안내함).
// The parsers of the commands are built on Unix only.
#[cfg(unix)]
#[test]
fn every_option_the_help_names_is_accepted() {
    let accepts = |path: &[&str], args: &[String]| -> bool {
        let a: Vec<OsString> = args.iter().map(OsString::from).collect();
        match path {
            ["config", sub] => {
                let mut all = vec![OsString::from(*sub)];
                all.extend(a);
                super::super::config::parse(&all).is_some()
            }
            ["doctor"] => super::super::doctor::parse(&a).is_some(),
            ["explain"] => super::super::explain::parse(&a).is_some(),
            ["help"] => args
                .first()
                .and_then(|w| bingsu_core::diag_help::parse_code(w))
                .is_some(),
            ["init"] => {
                args.len() == 1
                    && bingsu_core::shell_word::Shell::parse(args[0].as_bytes()).is_some()
            }
            ["list"] => {
                // Options of `presets`, after the word.
                let mut all = vec![OsString::from("presets"), OsString::from("--preview")];
                if args.first().is_some_and(|w| w == "--icons") {
                    all.extend(a);
                }
                super::super::list::parse(&all).is_some()
            }
            ["setup"] => super::super::setup::parse(&a).is_ok(),
            _ => panic!("no parser for {path:?}"),
        }
    };
    let mut checked = 0;
    for path in helped().into_iter().filter(|p| !p.is_empty()) {
        let c = find(&path).unwrap();
        for o in c.opts {
            for args in samples(o.words) {
                assert!(accepts(&path, &args), "{path:?} {args:?}");
                checked += 1;
            }
        }
    }
    // The subcommands themselves, bare.
    for sub in ["check", "edit", "path", "schema"] {
        assert!(accepts(&["config", sub], &[]), "config {sub}");
    }
    for s in find(&["list"]).unwrap().subs {
        let a = [OsString::from(s.name)];
        assert!(super::super::list::parse(&a).is_some(), "list {}", s.name);
    }
    assert!(checked > 20, "{checked}");
}

/// The body of the first `fn NAME` in `src`, from its `{` to the matching
/// `}`, skipping braces inside string and char literals.
fn body<'a>(src: &'a str, name: &str) -> &'a str {
    let (from, f) = match name.split_once("::") {
        Some((ty, f)) => (
            src.find(&format!("impl {ty} "))
                .unwrap_or_else(|| panic!("no impl {ty}")),
            f,
        ),
        None => (0, name),
    };
    let at = from
        + src[from..]
            .find(&format!("fn {f}("))
            .unwrap_or_else(|| panic!("no fn {name}"));
    let open = at + src[at..].find('{').unwrap();
    let b = src.as_bytes();
    let (mut depth, mut i) = (0usize, open);
    while i < b.len() {
        match b[i] {
            b'"' => {
                i += 1;
                while b[i] != b'"' {
                    i += if b[i] == b'\\' { 2 } else { 1 };
                }
            }
            b'\'' if b.get(i + 2) == Some(&b'\'') => i += 2,
            b'\'' if b.get(i + 1) == Some(&b'\\') => {
                i += 2;
                while b[i] != b'\'' {
                    i += 1;
                }
            }
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return &src[open..=i];
                }
            }
            _ => {}
        }
        i += 1;
    }
    panic!("fn {name} does not end");
}

/// The string literals of `code` (`"…"` and `b"…"`) that are one word:
/// option words (`--x`, `-x`) always, plain words only when `words`.
fn literals(code: &str, words: bool) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    // Attributes (`#[cfg(feature = "...")]`) and the paths of this table
    // (`usage::line(&["setup"])`) hold no argument words.
    let mut code: String = code
        .lines()
        .filter(|l| !l.trim_start().starts_with("#["))
        .collect::<Vec<_>>()
        .join("\n");
    while let Some(at) = code.find("usage::line(&[") {
        let end = at + code[at..].find("])").expect("a closed path");
        code.replace_range(at..end + 2, "");
    }
    let mut rest = code.as_str();
    while let Some(at) = rest.find('"') {
        let after = &rest[at + 1..];
        let Some(end) = after.find('"') else { break };
        let lit = &after[..end];
        let flag = lit.starts_with('-')
            && lit.len() > 1
            && lit
                .trim_start_matches('-')
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-');
        let word = !lit.is_empty()
            && lit.chars().next().is_some_and(|c| c.is_ascii_lowercase())
            && lit
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
        if flag || (words && word) {
            out.insert(lit.to_owned());
        }
        rest = &after[end + 1..];
    }
    out
}

/// The words the option list of the help at `path` names: the options and
/// operands, the subcommands and their options; the commands at the top.
fn documented(path: &[&str]) -> BTreeSet<String> {
    let mut words = String::new();
    let mut add = |w: &str| {
        words.push_str(w);
        words.push(' ');
    };
    match find(path) {
        None => COMMANDS.iter().for_each(|c| add(c.name)),
        Some(c) => {
            c.opts.iter().for_each(|o| add(o.words));
            for s in c.subs {
                add(s.name);
                s.opts.iter().for_each(|o| add(o.words));
            }
        }
    }
    tokens(&words)
}

fn tokens(text: &str) -> BTreeSet<String> {
    text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '-' || c == '_'))
        .filter(|w| !w.is_empty())
        .map(String::from)
        .collect()
}

fn source(text: &str) -> String {
    text.replace("\r\n", "\n")
}

// 이것을 실패시키는 것: 파서가 받는 플래그·값·하위 명령을 도움말에 적지 않는 것(파서에 플래그를 더하고 도움말을
// 빼먹으면 실패한다).
#[test]
fn every_word_a_parser_takes_is_in_its_help() {
    let file = |name: &str| -> String {
        source(match name {
            "mod" => include_str!("../mod.rs"),
            "config" => include_str!("../config.rs"),
            "config_use" => include_str!("../config_use.rs"),
            "config_edit" => include_str!("../config_edit.rs"),
            "doctor" => include_str!("../doctor.rs"),
            "explain" => include_str!("../explain.rs"),
            "help" => include_str!("../help.rs"),
            "init" => include_str!("../init/mod.rs"),
            "list" => include_str!("../list.rs"),
            "reload" => include_str!("../reload.rs"),
            "setup" => include_str!("../setup.rs"),
            "version" => include_str!("../version.rs"),
            "shell_word" => include_str!("../../../../bingsu-core/src/shell_word.rs"),
            "listing" => include_str!("../../../../bingsu-core/src/listing.rs"),
            "icons" => include_str!("../../../../bingsu-core/src/icons.rs"),
            "starter" => include_str!("../../../../bingsu-core/src/config/starter.rs"),
            _ => panic!("{name}"),
        })
    };
    // (help path, source file, function, plain words too): a parser's
    // words, and a command's `run` for flags it might read itself.
    let regions: [(&[&str], &str, &str, bool); 21] = [
        (&[], "mod", "run", true),
        (&["config"], "config", "parse", true),
        (&["config"], "config", "check_flags", true),
        (&["config"], "config", "run", false),
        (&["config", "use"], "config_use", "run", false),
        (&["config", "edit"], "config_edit", "run", false),
        (&["doctor"], "doctor", "parse", true),
        (&["doctor"], "doctor", "run", false),
        (&["explain"], "explain", "parse", true),
        (&["explain"], "explain", "run", false),
        (&["help"], "help", "run", false),
        (&["init"], "shell_word", "parse", true),
        (&["init"], "init", "run", false),
        (&["list"], "list", "parse", true),
        (&["list"], "listing", "word", true),
        (&["list"], "icons", "parse", true),
        (&["reload"], "reload", "run", false),
        // `--version` has no help of its own: the top level names it.
        (&[], "version", "run", false),
        (&["setup"], "setup", "parse", true),
        (&["setup"], "starter", "Icons::parse", true),
        (&["setup"], "starter", "Mode::parse", true),
    ];
    let mut seen = 0;
    for (path, name, func, words) in regions {
        let known = documented(path);
        for lit in literals(body(&file(name), func), words) {
            // Internal entry points of the top level.
            if lit.starts_with("__") {
                continue;
            }
            assert!(
                known.contains(&lit),
                "{name}::{func} takes {lit:?}, which the options of {path:?} do not name"
            );
            seen += 1;
        }
    }
    assert!(seen > 30, "{seen}");
}

// 이것을 실패시키는 것: 최상위 도움말이 분기하는 사용자 명령 하나를 빼먹는 것.
#[test]
fn the_top_help_lists_every_command_the_dispatch_takes() {
    let top = text(&[]);
    let names: BTreeSet<&str> = COMMANDS.iter().map(|c| c.name).collect();
    for lit in literals(body(&source(include_str!("../mod.rs")), "run"), true) {
        if lit.starts_with("__") {
            continue;
        }
        assert!(names.contains(lit.as_str()), "{lit} is not in COMMANDS");
        assert!(top.contains(&format!("\n  {lit} ")), "{lit} is not listed");
    }
}

// 이것을 실패시키는 것: 도움말 검사를 내부 진입점(중계 `__exec-v2`, 갱신 도우미, 명령 감독, 벤치 대역)의 분기 앞으로
// 옮기는 것(신뢰하는 중계가 시작하기 전에 다른 코드가 돈다).
#[test]
fn the_internal_entry_points_come_before_the_help() {
    let src = source(include_str!("../mod.rs"));
    let run = body(&src, "run");
    let help = run.find("usage::asked").expect("the help check");
    for arm in [
        "Some(bingsu_core::handoff::ENTRY)",
        "Some(\"__refresh-v1\")",
        "Some(command_supervisor::ENTRY)",
        "Some(\"__collect-stub\")",
    ] {
        let at = run.find(arm).unwrap_or_else(|| panic!("no arm {arm}"));
        assert!(at < help, "{arm} comes after the help check");
    }
}

// 이것을 실패시키는 것: 80칸을 꼭 채우는 줄을 접는 것, 80칸을 넘는 줄을 그대로 두는 것, 이어지는 줄을 첫 묶음 아래에서
// 시작하지 않는 것, 괄호 안의 빈칸에서 접는 것.
#[test]
fn a_usage_line_breaks_only_past_80_columns_between_groups() {
    // `usage: bingsu n` is 15 columns; ` [` + 62 + `]` fills a row to 80.
    let long = format!("[{}]", "a".repeat(62));
    let mut out = String::new();
    wrapped("n", &format!("{long} [x y]"), &mut out);
    let indent = " ".repeat(15);
    assert_eq!(out, format!("usage: bingsu n {long}\n{indent} [x y]\n"));
    let setup = text(&["setup"]);
    assert!(
        setup.contains(&format!("\n{} [--mode auto|dark|light]\n", " ".repeat(19))),
        "{setup}"
    );
}

// 이것을 실패시키는 것: 설명을 옵션 바로 뒤 한 칸에 붙이는 것(21칸 옵션), 22칸을 넘지 않는 옵션을 다음 줄로 내리는 것.
#[test]
fn an_option_keeps_two_spaces_before_what_it_does() {
    let row = |words: &str| {
        let mut out = String::new();
        item(words, "what", &mut out);
        out
    };
    let w18 = "w".repeat(18);
    assert_eq!(row(&w18), format!("  {w18}  what\n"));
    let w19 = "w".repeat(19);
    assert_eq!(row(&w19), format!("  {w19}\n{:COLUMN$}what\n", ""));
}
