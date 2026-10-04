//! One shell word, single-quoted, for embedding literals in init output
//! (spec section 4 "runtime root" 3, section 5 "connection").

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Shell {
    Zsh,
    Bash,
    Fish,
}

impl Shell {
    pub fn parse(s: &[u8]) -> Option<Self> {
        match s {
            b"zsh" => Some(Self::Zsh),
            b"bash" => Some(Self::Bash),
            b"fish" => Some(Self::Fish),
            _ => None,
        }
    }
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Zsh => "zsh",
            Self::Bash => "bash",
            Self::Fish => "fish",
        }
    }
}

/// bash/zsh: `'...'` with `'` as `'\''`. fish: `'...'` with `\` as `\\`
/// and `'` as `\'`. Bytes pass through unchanged otherwise.
pub fn encode_word(shell: Shell, word: &[u8], out: &mut Vec<u8>) {
    out.push(b'\'');
    for &b in word {
        match (shell, b) {
            (Shell::Fish, b'\\') => out.extend_from_slice(b"\\\\"),
            (Shell::Fish, b'\'') => out.extend_from_slice(b"\\'"),
            (Shell::Zsh | Shell::Bash, b'\'') => out.extend_from_slice(b"'\\''"),
            _ => out.push(b),
        }
    }
    out.push(b'\'');
}

#[cfg(test)]
mod tests {
    use super::*;

    fn e(sh: Shell, w: &str) -> String {
        let mut out = Vec::new();
        encode_word(sh, w.as_bytes(), &mut out);
        String::from_utf8(out).unwrap()
    }

    // Expected values transcribed from the 2026-10-04 round-trip probe.
    // 이것을 실패시키는 것: fish에서 역슬래시를 두 배로 하지 않는 것, bash·zsh에서 `'`를 `'\''`로 바꾸지 않는 것.
    #[test]
    fn posix_family_vectors() {
        for sh in [Shell::Bash, Shell::Zsh] {
            assert_eq!(e(sh, "a b"), "'a b'");
            assert_eq!(e(sh, "it's"), r"'it'\''s'");
            assert_eq!(e(sh, "with\\back"), r"'with\back'");
            assert_eq!(e(sh, "new\nline"), "'new\nline'");
            assert_eq!(e(sh, "''"), r"''\'''\'''");
            assert_eq!(e(sh, "$(echo pwn)`id`$HOME"), "'$(echo pwn)`id`$HOME'");
            assert_eq!(e(sh, ""), "''");
        }
    }

    #[test]
    fn fish_vectors() {
        assert_eq!(e(Shell::Fish, "it's"), r"'it\'s'");
        assert_eq!(e(Shell::Fish, "with\\back"), r"'with\\back'");
        assert_eq!(e(Shell::Fish, "end\\"), r"'end\\'");
        assert_eq!(e(Shell::Fish, "\\'"), r"'\\\''");
        assert_eq!(e(Shell::Fish, "''"), r"'\'\''");
    }

    #[test]
    fn non_utf8_bytes_pass_through() {
        let mut out = Vec::new();
        encode_word(Shell::Bash, b"/opt/\xff/bingsu", &mut out);
        assert_eq!(out, b"'/opt/\xff/bingsu'");
    }

    #[test]
    fn shell_parse() {
        assert_eq!(Shell::parse(b"zsh"), Some(Shell::Zsh));
        assert_eq!(Shell::parse(b"tcsh"), None);
        assert_eq!(Shell::Fish.as_str(), "fish");
    }
}
