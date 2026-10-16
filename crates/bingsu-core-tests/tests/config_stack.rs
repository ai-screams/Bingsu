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
