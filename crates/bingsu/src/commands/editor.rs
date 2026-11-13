//! The editor `bingsu config edit` starts: how `$VISUAL` or `$EDITOR` is read
//! and which program it names. No shell is involved at any point. The value
//! is split into words and unquoted here; a character a shell would give a
//! meaning to (a command, a variable, a redirect, a list) is refused instead
//! of being run or silently kept, and the program is looked up only in
//! absolute places, so a program in the current folder is never picked up.
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

#[derive(Debug, PartialEq, Eq)]
pub enum EditorError {
    /// Neither `$VISUAL` nor `$EDITOR` has a value.
    NotSet,
    /// A shell character outside single quotes; the character is named.
    ShellSyntax(char),
    /// A quote that never closes, or a backslash at the end.
    Unfinished,
    /// The value has no word.
    Empty,
    /// The program is a relative path (it has a `/` but does not start with one).
    RelativeProgram,
    /// Not found in any absolute folder of `PATH`.
    NotFound,
    /// The value is not UTF-8.
    NotText,
}

/// `$VISUAL`, or `$EDITOR` when that is unset or empty.
pub fn pick(
    visual: Option<&std::ffi::OsStr>,
    editor: Option<&std::ffi::OsStr>,
) -> Result<String, EditorError> {
    for v in [visual, editor].into_iter().flatten() {
        if v.is_empty() {
            continue;
        }
        return v.to_str().map(str::to_owned).ok_or(EditorError::NotText);
    }
    Err(EditorError::NotSet)
}

/// Splits `value` into words. White space separates words outside quotes;
/// single quotes keep everything; inside double quotes only `\"` and `\\`
/// are escapes; outside quotes a backslash keeps the next character. The
/// shell characters `$` and the backquote (anywhere but in single quotes),
/// and `; & | < > ( )` (outside quotes) are refused. Nothing is expanded: `~`
/// and `*` stay as written.
pub fn words(value: &str) -> Result<Vec<String>, EditorError> {
    let mut out: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut started = false;
    let mut chars = value.chars();
    while let Some(c) = chars.next() {
        match c {
            c if c.is_whitespace() => {
                if started {
                    out.push(std::mem::take(&mut cur));
                    started = false;
                }
            }
            '\'' => {
                started = true;
                loop {
                    match chars.next() {
                        Some('\'') => break,
                        Some(c) => cur.push(c),
                        None => return Err(EditorError::Unfinished),
                    }
                }
            }
            '"' => {
                started = true;
                loop {
                    match chars.next() {
                        Some('"') => break,
                        Some('\\') => match chars.next() {
                            Some(e @ ('"' | '\\')) => cur.push(e),
                            Some(e) => {
                                cur.push('\\');
                                cur.push(e);
                            }
                            None => return Err(EditorError::Unfinished),
                        },
                        Some(c @ ('$' | '`')) => return Err(EditorError::ShellSyntax(c)),
                        Some(c) => cur.push(c),
                        None => return Err(EditorError::Unfinished),
                    }
                }
            }
            '\\' => {
                started = true;
                cur.push(chars.next().ok_or(EditorError::Unfinished)?);
            }
            c @ ('$' | '`' | ';' | '&' | '|' | '<' | '>' | '(' | ')') => {
                return Err(EditorError::ShellSyntax(c));
            }
            c => {
                started = true;
                cur.push(c);
            }
        }
    }
    if started {
        out.push(cur);
    }
    if out.is_empty() {
        return Err(EditorError::Empty);
    }
    Ok(out)
}

fn runs(p: &Path) -> bool {
    std::fs::metadata(p).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

/// The absolute path to start for `program`: itself when it starts with `/`
/// and is a program; otherwise the first program of that name in an absolute
/// folder of `path` (empty and relative entries are skipped).
pub fn find_program(program: &str, path: Option<&std::ffi::OsStr>) -> Result<PathBuf, EditorError> {
    if program.contains('/') {
        let p = Path::new(program);
        if !p.is_absolute() {
            return Err(EditorError::RelativeProgram);
        }
        return if runs(p) {
            Ok(p.to_path_buf())
        } else {
            Err(EditorError::NotFound)
        };
    }
    let path = path.ok_or(EditorError::NotFound)?;
    std::env::split_paths(path)
        .filter(|d| d.is_absolute())
        .map(|d| d.join(program))
        .find(|p| runs(p))
        .ok_or(EditorError::NotFound)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;

    fn w(v: &str) -> Result<Vec<String>, EditorError> {
        words(v)
    }

    // 이것을 실패시키는 것: `VISUAL`보다 `EDITOR`를 먼저 보는 것, 빈 값을 값으로 치는 것, 둘 다 없는데 기본
    // 편집기로 넘어가는 것, UTF-8이 아닌 값을 받는 것.
    #[test]
    fn visual_wins_and_empty_is_unset() {
        let s = |x: &str| Some(OsStr::new(x).to_owned());
        let (v, e) = (s("code -w"), s("vi"));
        assert_eq!(pick(v.as_deref(), e.as_deref()).unwrap(), "code -w");
        let empty = s("");
        assert_eq!(pick(empty.as_deref(), e.as_deref()).unwrap(), "vi");
        assert_eq!(pick(None, e.as_deref()).unwrap(), "vi");
        assert_eq!(pick(None, empty.as_deref()), Err(EditorError::NotSet));
        assert_eq!(pick(None, None), Err(EditorError::NotSet));
        use std::os::unix::ffi::OsStrExt;
        assert_eq!(
            pick(Some(OsStr::from_bytes(b"\xff")), None),
            Err(EditorError::NotText)
        );
    }

    // 이것을 실패시키는 것: 따옴표·역슬래시를 틀리게 푸는 것, 셸 문법(`; & | < > ( ) $ 백틱`)을 거절하지 않는 것,
    // 작은따옴표 안의 글자를 거절하는 것, `~`·`*`를 확장하거나 거절하는 것, 닫히지 않은 따옴표를 받는 것.
    #[test]
    fn words_are_split_and_unquoted_without_a_shell() {
        assert_eq!(w("vi").unwrap(), ["vi"]);
        assert_eq!(w("code -w").unwrap(), ["code", "-w"]);
        assert_eq!(w("  emacsclient   -t ").unwrap(), ["emacsclient", "-t"]);
        assert_eq!(
            w("\"/p with space/ed\" -f").unwrap(),
            ["/p with space/ed", "-f"]
        );
        assert_eq!(w("'a;b|c $x' d").unwrap(), ["a;b|c $x", "d"]);
        assert_eq!(w("a\\ b").unwrap(), ["a b"]);
        assert_eq!(w("\"a\\\"b\\\\c\"").unwrap(), ["a\"b\\c"]);
        assert_eq!(w("\"\" x").unwrap(), ["", "x"]);
        assert_eq!(w("~/bin/ed *.toml").unwrap(), ["~/bin/ed", "*.toml"]);
        for (bad, c) in [
            ("vi; touch x", ';'),
            ("vi && x", '&'),
            ("vi | x", '|'),
            ("vi > f", '>'),
            ("vi < f", '<'),
            ("$(x)", '$'),
            ("vi $HOME", '$'),
            ("vi `x`", '`'),
            ("\"$HOME/ed\"", '$'),
            ("\"`x`\"", '`'),
            ("(vi)", '('),
        ] {
            assert_eq!(w(bad), Err(EditorError::ShellSyntax(c)), "{bad}");
        }
        for bad in ["'abc", "\"abc", "abc\\"] {
            assert_eq!(w(bad), Err(EditorError::Unfinished), "{bad}");
        }
        assert_eq!(w("   "), Err(EditorError::Empty));
        assert_eq!(w(""), Err(EditorError::Empty));
    }

    fn scratch(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("bingsu-editor-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p.canonicalize().unwrap()
    }

    fn file(dir: &Path, name: &str, mode: u32) -> PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, b"#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
        p
    }

    // 이것을 실패시키는 것: 상대 경로 프로그램을 받는 것, `PATH`의 빈 항목·상대 항목에서 찾는 것(현재 폴더의
    // 프로그램 실행), 실행 비트 없는 파일·폴더를 받는 것, `PATH` 순서를 어기는 것.
    #[test]
    fn programs_are_found_only_in_absolute_places() {
        let a = scratch("a");
        let b = scratch("b");
        let ed_b = file(&b, "ed", 0o755);
        file(&a, "ed", 0o644);
        file(&a, "noexec", 0o644);
        std::fs::create_dir(a.join("dir")).unwrap();
        std::fs::set_permissions(a.join("dir"), std::fs::Permissions::from_mode(0o755)).unwrap();
        let path = std::env::join_paths([a.clone(), b.clone()]).unwrap();
        // The first `ed` in `a` has no execute bit: the one in `b` is taken.
        assert_eq!(find_program("ed", Some(&path)).unwrap(), ed_b);
        assert_eq!(
            find_program("noexec", Some(&path)),
            Err(EditorError::NotFound)
        );
        assert_eq!(find_program("dir", Some(&path)), Err(EditorError::NotFound));
        // Absolute, relative.
        assert_eq!(find_program(ed_b.to_str().unwrap(), None).unwrap(), ed_b);
        assert_eq!(
            find_program("./ed", Some(&path)),
            Err(EditorError::RelativeProgram)
        );
        assert_eq!(
            find_program("sub/ed", Some(&path)),
            Err(EditorError::RelativeProgram)
        );
        // Empty and relative entries of `PATH` are skipped, even where the program is: the program is a file
        // in the test's own folder, which "." and "" would name. (The folder is not changed: other tests run.)
        let name = format!(".bingsu-editor-test-{}", std::process::id());
        let here = std::env::current_dir().unwrap();
        file(&here, &name, 0o755);
        let tricky = std::env::join_paths([PathBuf::from(""), PathBuf::from(".")]).unwrap();
        let found = find_program(&name, Some(&tricky));
        let _ = std::fs::remove_file(here.join(&name));
        assert_eq!(found, Err(EditorError::NotFound));
        assert_eq!(find_program("ed", None), Err(EditorError::NotFound));
        for d in [a, b] {
            let _ = std::fs::remove_dir_all(d);
        }
    }
}
