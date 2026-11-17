//! The std::fmt placeholder grammar the address and Debug rules read format
//! strings with.

/// True if `text`, read as a format string, has a placeholder whose type is
/// `p`, with any fill, alignment, sign, `#`, `0`, width or precision
/// (`{:p}`, `{v:#p}`, `{:>20p}`, `{0:w$.*p}`). A placeholder counts only when
/// its argument (empty, an integer or an identifier) and its spec follow
/// the std::fmt grammar, so template text such as `{@icon:frame.top}` is not
/// one. A fill character comes before an alignment and may itself be `{` or
/// `}`; `{{` is a literal brace.
pub(super) fn formats_pointer(text: &str) -> bool {
    formats_type(text, |t| t == "p")
}

/// True if `text`, read as a format string, has a Debug placeholder
/// (`{:?}`, `{v:#?}`, `{:x?}`: a type that ends in `?`), with the same
/// grammar as formats_pointer.
pub(super) fn formats_debug(text: &str) -> bool {
    formats_type(text, |t| t.ends_with('?'))
}

/// True if a placeholder of `text` has a type for which `wanted` holds.
fn formats_type(text: &str, wanted: fn(&str) -> bool) -> bool {
    let chars: Vec<char> = text.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] != '{' {
            i += 1;
            continue;
        }
        if chars.get(i + 1) == Some(&'{') {
            i += 2;
            continue;
        }
        let mut j = i + 1;
        while j < chars.len() && chars[j] != ':' && chars[j] != '}' {
            j += 1;
        }
        if chars.get(j) != Some(&':') {
            i = j + 1;
            continue;
        }
        let mut k = j + 1;
        if matches!(chars.get(k + 1), Some('<' | '^' | '>')) {
            k += 2;
        }
        while k < chars.len() && chars[k] != '}' {
            k += 1;
        }
        let arg: String = chars[i + 1..j].iter().collect();
        let arg = arg.trim_end();
        let arg_ok = arg.is_empty()
            || arg.chars().all(|c| c.is_ascii_digit())
            || ident_len(&arg.chars().collect::<Vec<_>>(), 0) == arg.chars().count();
        if arg_ok && wanted(&spec_type(&chars[j + 1..k.min(chars.len())])) {
            return true;
        }
        i = k + 1;
    }
    false
}

/// Length of the identifier that starts at `at` (0 if none).
// Known: unicode-ident uses Unicode 18.0, while rustc uses 17.0; this
// conservative format-argument scan can recognize more identifiers.
fn ident_len(s: &[char], at: usize) -> usize {
    match s.get(at) {
        Some(c) if unicode_ident::is_xid_start(*c) || *c == '_' => {
            1 + s[at + 1..]
                .iter()
                .take_while(|c| unicode_ident::is_xid_continue(**c))
                .count()
        }
        _ => 0,
    }
}

/// A count at `at`: an integer, or an integer or identifier followed by `$`.
/// Returns the position after it (`at` itself when there is none).
fn count_end(s: &[char], at: usize) -> usize {
    let digits = s[at.min(s.len())..]
        .iter()
        .take_while(|c| c.is_ascii_digit())
        .count();
    if digits > 0 {
        return at + digits + usize::from(s.get(at + digits) == Some(&'$'));
    }
    let ident = ident_len(s, at);
    if ident > 0 && s.get(at + ident) == Some(&'$') {
        return at + ident + 1;
    }
    at
}

/// The type of a std::fmt spec (the text after `:`): what is left after
/// `[[fill]align][sign]['#']['0'][width]['.' [precision]]`. The callers ask
/// only whether it is exactly `p` (formats_pointer) or ends in `?`
/// (formats_debug), so other leftovers need no checking.
fn spec_type(s: &[char]) -> String {
    let mut k = if matches!(s.get(1), Some('<' | '^' | '>')) {
        2
    } else {
        usize::from(matches!(s.first(), Some('<' | '^' | '>')))
    };
    if matches!(s.get(k), Some('+' | '-')) {
        k += 1;
    }
    if s.get(k) == Some(&'#') {
        k += 1;
    }
    if s.get(k) == Some(&'0') && s.get(k + 1) != Some(&'$') {
        k += 1;
    }
    k = count_end(s, k);
    if s.get(k) == Some(&'.') {
        k += 1;
        // rustc also takes `.` with no precision (`{x:.p}` formats a pointer).
        if s.get(k) == Some(&'*') {
            k += 1;
        } else {
            k = count_end(s, k);
        }
    }
    let rest: String = s[k.min(s.len())..].iter().collect();
    rest.trim_end().to_owned()
}
