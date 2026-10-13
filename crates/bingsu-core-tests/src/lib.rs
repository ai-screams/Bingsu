//! Tests only (tests/). The crate exists so that proptest stays
//! out of bingsu-core's dependency graph (crates/bingsu-core/deny.toml).
//! It also holds the readers of the shell field grammar that several test
//! files share (spec section 3 "셸 경계의 요구 행동").
use bingsu_core::sanitize::is_removed;
use bingsu_core::shell_word::Shell;

/// `ESC [ (DIGIT / ";")* m` at `b[i..]`; returns the index after `m`.
fn sgr(b: &[u8], i: usize) -> Result<usize, String> {
    if b.get(i) != Some(&0x1b) || b.get(i + 1) != Some(&b'[') {
        return Err(format!("no SGR at {i}"));
    }
    let mut j = i + 2;
    while let Some(&c) = b.get(j) {
        match c {
            b'0'..=b'9' | b';' => j += 1,
            b'm' => return Ok(j + 1),
            _ => return Err(format!("byte {c:#x} inside SGR at {j}")),
        }
    }
    Err("unterminated SGR".into())
}

/// Reads one field back as `shell` would: markers must pair up with exactly
/// one SGR between them (fish: a bare SGR), and everything else is text.
/// Returns the text with zsh `%%` read as `%`.
pub fn parse_field(shell: Shell, b: &[u8]) -> Result<String, String> {
    let (open, close): (&[u8], &[u8]) = match shell {
        Shell::Zsh => (b"%{", b"%}"),
        Shell::Bash => (b"\x01", b"\x02"),
        Shell::Fish => (b"", b""),
    };
    let mut text = Vec::new();
    let mut i = 0;
    while i < b.len() {
        let rest = &b[i..];
        if !open.is_empty() && rest.starts_with(open) {
            i = sgr(b, i + open.len())?;
            if !b[i..].starts_with(close) {
                return Err(format!("marker opened without an SGR and a close at {i}"));
            }
            i += close.len();
        } else if shell == Shell::Fish && rest[0] == 0x1b {
            i = sgr(b, i)?;
        } else if shell == Shell::Zsh && rest[0] == b'%' {
            if rest.get(1) != Some(&b'%') {
                return Err(format!("lone % at {i}"));
            }
            text.push(b'%');
            i += 2;
        } else if rest[0] < 0x20 || rest[0] == 0x7f {
            return Err(format!("control byte {:#x} in text at {i}", rest[0]));
        } else {
            text.push(rest[0]);
            i += 1;
        }
    }
    let text = String::from_utf8(text).map_err(|e| e.to_string())?;
    if let Some(c) = text.chars().find(|&c| is_removed(c)) {
        return Err(format!("removed character {c:?} in text"));
    }
    Ok(text)
}

/// Reads a readline mode string back: double quotes around text in which
/// `\` starts one of `\\ \" \001 \002 \e`.
pub fn parse_readline(b: &[u8]) -> Result<Vec<u8>, String> {
    let inner = b
        .strip_prefix(b"\"")
        .and_then(|b| b.strip_suffix(b"\""))
        .ok_or("not in double quotes")?;
    let mut out = Vec::new();
    let mut i = 0;
    while i < inner.len() {
        let rest = &inner[i..];
        let (byte, n) = match rest {
            [b'\\', b'\\', ..] => (b'\\', 2),
            [b'\\', b'"', ..] => (b'"', 2),
            [b'\\', b'0', b'0', b'1', ..] => (1, 4),
            [b'\\', b'0', b'0', b'2', ..] => (2, 4),
            [b'\\', b'e', ..] => (0x1b, 2),
            [b'\\', ..] => return Err(format!("unknown escape at {i}")),
            [b'"', ..] => return Err(format!("bare quote at {i}")),
            [c, ..] if *c < 0x20 || *c == 0x7f => {
                return Err(format!("control byte {c:#x} at {i}"));
            }
            [c, ..] => (*c, 1),
            [] => unreachable!(),
        };
        out.push(byte);
        i += n;
    }
    Ok(out)
}
