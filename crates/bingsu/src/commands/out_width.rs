//! The width a command lays out its standard output at (`bingsu explain`,
//! `bingsu list presets --preview`): a width given on the command line, else
//! `COLUMNS` when it holds a whole number from 1 to 65535, else the columns of
//! the terminal standard output is on, else 80. Shells keep `COLUMNS` to
//! themselves unless it is exported, so in a terminal the answer is usually
//! the terminal's; through a pipe it is 80.
use std::ffi::OsStr;
use std::os::fd::AsFd as _;

const DEFAULT_WIDTH: u16 = 80;

/// Where the width came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WidthSource {
    Flag,
    Columns,
    Terminal,
    Default,
}

impl WidthSource {
    /// The JSON `width_source` word.
    pub(crate) fn word(self) -> &'static str {
        match self {
            Self::Flag => "flag",
            Self::Columns => "columns",
            Self::Terminal => "terminal",
            Self::Default => "default",
        }
    }
}

/// The width for standard output: `flag`, else `columns` (the value of
/// `COLUMNS`), else the columns of the terminal standard output is on (asked
/// only then), else 80.
pub(crate) fn stdout_width(flag: Option<u16>, columns: Option<&OsStr>) -> (u16, WidthSource) {
    width_of(flag, columns, || {
        super::tty::columns_of(std::io::stdout().as_fd())
    })
}

/// The rule of `stdout_width` with the terminal's answer passed in.
fn width_of(
    flag: Option<u16>,
    columns: Option<&OsStr>,
    terminal: impl FnOnce() -> Option<u16>,
) -> (u16, WidthSource) {
    if let Some(n) = flag {
        return (n, WidthSource::Flag);
    }
    // 이것을 실패시키는 것: COLUMNS=0을 받는 것(폭 0으로 판정), 숫자가 아닌 값에서 다음 출처로 가지 않는 것.
    let columns = columns
        .and_then(OsStr::to_str)
        .and_then(|v| v.parse::<u16>().ok())
        .filter(|n| *n > 0);
    if let Some(n) = columns {
        return (n, WidthSource::Columns);
    }
    match terminal() {
        Some(n) => (n, WidthSource::Terminal),
        None => (DEFAULT_WIDTH, WidthSource::Default),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;

    // 이것을 실패시키는 것: COLUMNS가 `--width`를, 터미널이 COLUMNS를 이기는 것, COLUMNS나 터미널을 읽지 않는 것,
    // 앞 출처가 있는데도 터미널에 묻는 것, 0·숫자 아님·65535 초과·빈 값의 COLUMNS를 폭으로 받는 것.
    #[test]
    fn width_comes_from_the_flag_then_columns_then_the_terminal_then_80() {
        let c = |v: &str| Some(OsString::from(v));
        let not_asked = || -> Option<u16> { panic!("the terminal was asked") };
        assert_eq!(
            width_of(Some(40), c("100").as_deref(), not_asked),
            (40, WidthSource::Flag)
        );
        assert_eq!(
            width_of(None, c("100").as_deref(), not_asked),
            (100, WidthSource::Columns)
        );
        for bad in [None, c(""), c("0"), c("abc"), c("70000"), c("-5"), c(" 90")] {
            assert_eq!(
                width_of(None, bad.as_deref(), || Some(120)),
                (120, WidthSource::Terminal),
                "{bad:?}"
            );
            assert_eq!(
                width_of(None, bad.as_deref(), || None),
                (80, WidthSource::Default),
                "{bad:?}"
            );
        }
    }
}
