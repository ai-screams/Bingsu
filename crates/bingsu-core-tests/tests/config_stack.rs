//! Parse the worst combined nesting on a small helper-sized stack.
//! An overflow aborts the process and cannot be caught as a parse error.
use bingsu_core::config::tree::{NESTING_MAX, SyntaxErrorKind, parse};

/// Inputs that reach `NESTING_MAX` in each way and mixed, and one past it.
fn worst() -> Vec<String> {
    let n = NESTING_MAX as usize;
    let arrays = format!("a = {}{}\n", "[".repeat(n), "]".repeat(n));
    let inline = format!("a = {}1{}\n", "{ b = ".repeat(n), " }".repeat(n));
    let dotted = format!("{} = 1\n", vec!["a"; n].join("."));
    let header = format!("[{}]\nk = 1\n", vec!["a"; n].join("."));
    let mixed = format!(
        "[{}]\n{} = {{ {} = {{ x = [1] }} }}\n",
        ["a"; 10].join("."),
        ["b"; 10].join("."),
        ["c"; 11].join(".")
    );
    let past = format!("a = {}{}\n", "[".repeat(n + 1), "]".repeat(n + 1));
    // Each of the parser's own caps (80) alone, multiplied: a header of 79
    // parts, then 40 inline tables, each under a key of 79 parts (about
    // 3,300 levels in 7 KB; without our cap this overflowed a 2 MiB stack).
    let k79 = vec!["a"; 79].join(".");
    let attack = format!(
        "[{k79}]\n{k79} = {}x = 1{}\n",
        format!("{{ {k79} = ").repeat(40),
        " }".repeat(40)
    );
    // The same inside an array after a multi-line string that ends with
    // extra quotes (`"""q""""` holds `q"`): a scan that closes at the first
    // `"""` counted none of this line.
    let quoted = |q: &str| {
        let inner = format!("{{ {k79} = ").repeat(40) + "1" + &" }".repeat(40);
        format!("x = [ {q}, {inner} ]\n")
    };
    let (dq, sq) = (quoted(r#""""q"""""#), quoted("'''q''''"));
    vec![arrays, inline, dotted, header, mixed, past, attack, dq, sq]
}

fn read_all() -> usize {
    let inputs = worst();
    for (i, src) in inputs.iter().enumerate() {
        let result = parse(src.as_bytes());
        if i < 5 {
            assert!(result.is_ok(), "case {i}: {result:?}");
        } else {
            assert_eq!(
                result.unwrap_err()[0].kind,
                SyntaxErrorKind::TooDeep,
                "case {i}"
            );
        }
    }
    inputs.len()
}

// 이것을 실패시키는 것: 합친 깊이 상한을 지우거나 크게 올리는 것(작은 스택에서 abort), 파서가 정상 입력을 거부하거나 과도한 깊이를 받아들이는 것.
#[test]
fn the_worst_nesting_reads_in_a_small_stack() {
    for stack in [256 * 1024, 1024 * 1024] {
        let n = std::thread::Builder::new()
            .name(String::from("the_worst_nesting_reads_in_a_small_stack"))
            .stack_size(stack)
            .spawn(read_all)
            .unwrap()
            .join()
            .unwrap();
        assert_eq!(n, 9, "stack {stack}");
    }
}

/// The exact 12,810-byte review input: recovery supplies the missing `=`s.
fn recovered_nesting() -> String {
    let key = ["a"; 79].join(".");
    let src = "x = { ".to_owned() + &(key + " { ").repeat(79) + "z 1," + &" }".repeat(80);
    assert_eq!(src.len(), 12_810);
    src
}

// 이것을 실패시키는 것: 복구 가능한 문법에서 키 깊이나 여는 괄호를 빠뜨리는 것.
#[test]
fn recovered_nesting_is_rejected_before_building_a_tree_on_small_stacks() {
    for stack in [256 * 1024, 1024 * 1024] {
        std::thread::Builder::new()
            .stack_size(stack)
            .spawn(|| {
                let src = recovered_nesting();
                let errors = parse(src.as_bytes()).unwrap_err();
                assert_eq!(
                    errors.len(),
                    1,
                    "preflight must reject before TOML recovery"
                );
                assert_eq!(errors[0].kind, SyntaxErrorKind::TooDeep);
                // Missing separators, mismatched closers and unpaired close events
                // must take the same bounded event path as the actual parser.
                for src in [
                    "x = { ".repeat(80) + "z 1," + &" }".repeat(80),
                    "x = [".to_owned() + &"[".repeat(80) + &"}".repeat(80),
                    "x = { a = 1 ".to_owned() + &"b.c { ".repeat(80) + "z 1,",
                    "x = { {}, ".to_owned() + &"a = { {}, ".repeat(2_000) + "z=1",
                ] {
                    assert!(parse(src.as_bytes()).is_err());
                }
            })
            .unwrap()
            .join()
            .unwrap();
    }
}

// 이것을 실패시키는 것: 표 배열에서 배열과 원소 표를 각각 한 단으로 세지 않는 것.
#[test]
fn arrays_of_tables_have_an_exact_combined_depth_boundary() {
    for stack in [256 * 1024, 1024 * 1024] {
        std::thread::Builder::new()
            .stack_size(stack)
            .spawn(|| {
                let mut src = String::new();
                for n in 1..=16 {
                    src.push_str(&format!("[[{}]]\n", vec!["a"; n].join(".")));
                }
                // Sixteen arrays and their element tables: exactly 32.
                assert!(parse((src.clone() + "x=1\n").as_bytes()).is_ok());
                for suffix in [
                    "x=[]\n".to_owned(),
                    format!("[[{}]]\n", ["a"; 17].join(".")),
                ] {
                    let errors = parse((src.clone() + &suffix).as_bytes()).unwrap_err();
                    assert_eq!(
                        errors
                            .iter()
                            .filter(|e| e.kind == SyntaxErrorKind::TooDeep)
                            .count(),
                        1
                    );
                }
            })
            .unwrap()
            .join()
            .unwrap();
    }
}
