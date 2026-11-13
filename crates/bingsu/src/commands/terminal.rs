//! What `bingsu doctor` asks a terminal: how many cells the cursor moves for
//! some probe characters (cursor position reports), and what its background
//! looks like (OSC 11). The flows here talk to anything that is a `Terminal`;
//! the one that opens `/dev/tty` and keeps its state restored is `tty`. No
//! `unsafe` here, and a fake terminal tests every path.
//!
//! One rule keeps a reply from being read as the answer to the wrong
//! question: a query that gets no answer ends the measurement. A late reply
//! to it would otherwise be taken for the reply to the next one.
use super::tty::{Answer, REPLY_TIMEOUT, ReplyEnd, Terminal};
use bingsu_core::color::osc11::{is_light, parse_osc11};
use bingsu_core::terminal_reply::parse_cpr;
use bingsu_core::terminal_width::{Cells, MIN_COLUMNS, PROBES};
use std::io;
use std::time::Instant;

/// Why there is no measurement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Why {
    /// No reply in time.
    Silent,
    /// A reply that is not the one asked for.
    Garbled,
    /// The cursor left the line (it wrapped or scrolled).
    Moved,
}

#[derive(Debug, PartialEq, Eq)]
pub enum WidthOutcome {
    Measured(Cells),
    /// The terminal is narrower than the probes need.
    TooNarrow(u16),
    NoAnswer(Why),
    Cancelled,
    Failed,
}

enum Stop {
    No(Why),
    Cancelled,
    Failed,
}

/// The cursor `(row, column)`, from one `ESC [ 6 n`. A reply that is shaped
/// like a position but cannot be one (a column past the terminal's width, as
/// the report `ESC [ 1 ; 2 R` of a modified F3 key can be) is a wrong reply.
fn cursor<T: Terminal + ?Sized>(t: &mut T, columns: Option<u16>) -> Result<(u16, u16), Stop> {
    let deadline = Instant::now() + REPLY_TIMEOUT;
    match t.query(b"\x1b[6n", ReplyEnd::Csi(b'R'), deadline) {
        Ok(Answer::Reply(r)) => parse_cpr(&r)
            .filter(|&(_, col)| columns.is_none_or(|c| col <= c))
            .ok_or(Stop::No(Why::Garbled)),
        Ok(Answer::Silent) => Err(Stop::No(Why::Silent)),
        Ok(Answer::Cancelled) => Err(Stop::Cancelled),
        Err(_) => Err(Stop::Failed),
    }
}

fn put<T: Terminal + ?Sized>(t: &mut T, bytes: &[u8]) -> Result<(), Stop> {
    t.write(bytes).map_err(|e| match e.kind() {
        io::ErrorKind::Interrupted => Stop::Cancelled,
        // The terminal does not take output: it does not answer either.
        io::ErrorKind::TimedOut => Stop::No(Why::Silent),
        _ => Stop::Failed,
    })
}

/// What the probes left on the screen: whether any probe character was
/// written, and how many lines above the current one they ran onto.
#[derive(Default)]
struct Mark {
    wrote: bool,
    up: u16,
}

fn probe_widths<T: Terminal + ?Sized>(t: &mut T, mark: &mut Mark) -> Result<Cells, Stop> {
    let columns = t.columns();
    let (mut row, mut col) = cursor(t, columns)?;
    if col != 1 {
        // Not at the start of a line: do not write over what the user has
        // there. A new line is where the probes go.
        put(t, b"\r\n")?;
        let (new_row, new_col) = cursor(t, columns)?;
        // The new line starts at column 1, on the same row (the screen
        // scrolled) or a later one.
        if new_col != 1 || new_row < row {
            return Err(Stop::No(Why::Garbled));
        }
        (row, col) = (new_row, new_col);
    }
    let mut cells: Cells = [0; PROBES.len()];
    for (probe, slot) in PROBES.iter().zip(cells.iter_mut()) {
        mark.wrote = true;
        put(t, probe.text.as_bytes())?;
        let (r, c) = cursor(t, columns)?;
        if r != row || c < col {
            // The characters ran onto another line (the terminal is narrower
            // than the probes need, or became so): those lines are cleared
            // too. On a screen that scrolled the row stays and the column
            // went back, which is one line.
            mark.up = if r > row { r - row } else { 1 };
            return Err(Stop::No(Why::Moved));
        }
        *slot = c - col;
        col = c;
    }
    Ok(cells)
}

/// Writes the probes and reads the cursor after each. The line is cleared
/// afterwards, whatever happened.
pub fn measure_widths<T: Terminal + ?Sized>(t: &mut T) -> WidthOutcome {
    if let Some(c) = t.columns()
        && c < MIN_COLUMNS
    {
        return WidthOutcome::TooNarrow(c);
    }
    let mut mark = Mark::default();
    let result = probe_widths(t, &mut mark);
    // Only what was written is cleared: a measurement that ended before the
    // first probe character must not erase what the user had on the line.
    // Also after a cancel (a write goes through after one; only a signal in
    // the middle of a write interrupts it), so Ctrl-C leaves no probe
    // characters on the line.
    if mark.wrote {
        let mut clear = b"\r\x1b[K".to_vec();
        for _ in 0..mark.up {
            clear.extend_from_slice(b"\x1b[A\x1b[K");
        }
        let _ = t.write(&clear);
    }
    match result {
        Ok(cells) => WidthOutcome::Measured(cells),
        Err(Stop::No(why)) => WidthOutcome::NoAnswer(why),
        Err(Stop::Cancelled) => WidthOutcome::Cancelled,
        Err(Stop::Failed) => WidthOutcome::Failed,
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum BackgroundOutcome {
    Dark,
    Light,
    NoAnswer(Why),
    Cancelled,
    Failed,
}

/// Asks for the background color (`OSC 11 ; ?`) and calls it light or dark.
pub fn measure_background<T: Terminal + ?Sized>(t: &mut T) -> BackgroundOutcome {
    let deadline = Instant::now() + REPLY_TIMEOUT;
    match t.query(b"\x1b]11;?\x1b\\", ReplyEnd::Osc(b"11;"), deadline) {
        Ok(Answer::Reply(r)) => match parse_osc11(&r) {
            Some(c) if is_light(c) => BackgroundOutcome::Light,
            Some(_) => BackgroundOutcome::Dark,
            None => BackgroundOutcome::NoAnswer(Why::Garbled),
        },
        Ok(Answer::Silent) => BackgroundOutcome::NoAnswer(Why::Silent),
        Ok(Answer::Cancelled) => BackgroundOutcome::Cancelled,
        Err(_) => BackgroundOutcome::Failed,
    }
}

#[cfg(test)]
pub(super) mod fake {
    use super::*;

    /// A terminal that moves a cursor by what it is told each probe takes.
    pub struct Fake {
        pub cells: Cells,
        pub row: u16,
        pub col: u16,
        pub columns: Option<u16>,
        /// Queries answered before the terminal goes quiet.
        pub answers: usize,
        pub cancel_at: Option<usize>,
        pub garble_at: Option<usize>,
        pub wrap_at_probe: Option<usize>,
        /// Like `wrap_at_probe`, on a screen that scrolls: the row stays.
        pub scroll_at_probe: Option<usize>,
        pub fail_writes: bool,
        /// The error kind a failed write gives.
        pub write_error: io::ErrorKind,
        /// Where a `\r\n` leaves the cursor, as (row change, column): the
        /// terminal's answer after the new line.
        pub newline: (i32, u16),
        pub background: &'static [u8],
        pub queries: usize,
        pub written: Vec<u8>,
        pub requests: Vec<Vec<u8>>,
    }

    impl Fake {
        pub fn new(cells: Cells) -> Self {
            Self {
                cells,
                row: 7,
                col: 1,
                columns: Some(80),
                answers: usize::MAX,
                cancel_at: None,
                garble_at: None,
                wrap_at_probe: None,
                scroll_at_probe: None,
                fail_writes: false,
                write_error: io::ErrorKind::BrokenPipe,
                newline: (1, 1),
                background: b"\x1b]11;rgb:1e1e/1e1e/2e2e\x1b\\",
                queries: 0,
                written: Vec::new(),
                requests: Vec::new(),
            }
        }
    }

    impl Terminal for Fake {
        fn query(&mut self, request: &[u8], _end: ReplyEnd, _d: Instant) -> io::Result<Answer> {
            let n = self.queries;
            self.queries += 1;
            self.requests.push(request.to_vec());
            if self.cancel_at == Some(n) {
                return Ok(Answer::Cancelled);
            }
            if n >= self.answers {
                return Ok(Answer::Silent);
            }
            if self.garble_at == Some(n) {
                return Ok(Answer::Reply(b"\x1b[A".to_vec()));
            }
            if request == b"\x1b]11;?\x1b\\" {
                return Ok(Answer::Reply(self.background.to_vec()));
            }
            Ok(Answer::Reply(
                format!("\x1b[{};{}R", self.row, self.col).into_bytes(),
            ))
        }

        fn write(&mut self, bytes: &[u8]) -> io::Result<()> {
            if self.fail_writes {
                return Err(io::Error::from(self.write_error));
            }
            self.written.extend_from_slice(bytes);
            if bytes == b"\r\n" {
                self.row = u16::try_from(i32::from(self.row) + self.newline.0).unwrap();
                self.col = self.newline.1;
            } else if bytes == b"\r\x1b[K" {
                self.col = 1;
            } else if let Some(i) = PROBES.iter().position(|p| p.text.as_bytes() == bytes) {
                if self.wrap_at_probe == Some(i) {
                    self.row += 1;
                    self.col = 1;
                }
                if self.scroll_at_probe == Some(i) {
                    self.col = 1;
                }
                self.col += self.cells[i];
            }
            Ok(())
        }

        fn columns(&self) -> Option<u16> {
            self.columns
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fake::Fake;
    use super::*;

    const NORMAL: Cells = [1, 2, 1, 1, 1, 2, 2, 2, 2, 1, 1, 1];

    // 이것을 실패시키는 것: 시험 글자마다 CPR을 읽고 그 차이를 칸 수로 삼지 않는 것, 시험 뒤 줄을 지우지 않는 것,
    // 기준 열(첫 CPR)을 1로 가정하는 것(바꿔 쓰는 것), 시험 글자를 표 순서와 다르게 쓰는 것.
    #[test]
    fn the_cursor_after_each_probe_gives_its_cells() {
        let mut t = Fake::new(NORMAL);
        assert_eq!(measure_widths(&mut t), WidthOutcome::Measured(NORMAL));
        let probes: Vec<u8> = PROBES.iter().flat_map(|p| p.text.bytes()).collect();
        assert_eq!(t.written, [probes, b"\r\x1b[K".to_vec()].concat());
        assert_eq!(t.queries, PROBES.len() + 1);
        // Another terminal, the same method.
        let wide = [1, 2, 2, 2, 2, 1, 1, 4, 1, 1, 1, 2];
        assert_eq!(
            measure_widths(&mut Fake::new(wide)),
            WidthOutcome::Measured(wide)
        );
    }

    // 이것을 실패시키는 것: 1열이 아닐 때 사용자의 반쯤 쓴 줄 위에 시험 글자를 쓰는 것(줄바꿈 없이 시작).
    #[test]
    fn a_half_written_line_is_left_alone() {
        let mut t = Fake::new(NORMAL);
        t.col = 12;
        assert_eq!(measure_widths(&mut t), WidthOutcome::Measured(NORMAL));
        assert!(t.written.starts_with(b"\r\n"), "{:?}", t.written);
        // At column 1 there is no new line.
        let mut t = Fake::new(NORMAL);
        measure_widths(&mut t);
        assert!(!t.written.starts_with(b"\r\n"));
    }

    // 이것을 실패시키는 것: 침묵한 뒤에도 더 묻는 것(늦은 응답이 다음 질의의 답이 됨), 침묵해도 줄을 지우지 않는 것,
    // 침묵을 오류나 측정값으로 돌려주는 것.
    #[test]
    fn the_first_silence_ends_the_measurement() {
        for answered in [0, 1, 5, PROBES.len()] {
            let mut t = Fake::new(NORMAL);
            t.answers = answered;
            assert_eq!(
                measure_widths(&mut t),
                WidthOutcome::NoAnswer(Why::Silent),
                "{answered}"
            );
            assert_eq!(t.queries, answered + 1, "no query after the silent one");
            if answered == 0 {
                // Nothing was written, so nothing is cleared: what the user had
                // on the line stays.
                assert!(t.written.is_empty(), "{:?}", t.written);
            } else {
                assert!(t.written.ends_with(b"\r\x1b[K"));
            }
        }
    }

    // 이것을 실패시키는 것: 엉뚱한 응답(화살표 키)을 CPR로 읽는 것, 취소를 침묵이나 측정으로 바꾸는 것,
    // 취소 뒤에 줄을 지우지 않는 것, 줄이 바뀌었는데(줄바꿈·스크롤) 칸 수를 믿는 것, 쓰기 실패를 침묵으로 읽는 것.
    #[test]
    fn a_wrong_reply_a_cancel_a_wrap_and_a_closed_terminal_end_it() {
        let mut t = Fake::new(NORMAL);
        t.garble_at = Some(3);
        assert_eq!(measure_widths(&mut t), WidthOutcome::NoAnswer(Why::Garbled));
        let mut t = Fake::new(NORMAL);
        t.cancel_at = Some(2);
        assert_eq!(measure_widths(&mut t), WidthOutcome::Cancelled);
        assert!(
            t.written.ends_with(b"\r\x1b[K"),
            "a cancel still clears the line"
        );
        // A wrap that leaves the column larger than before (probe 0) and one
        // that leaves it smaller (probe 4): the row alone tells the first.
        for at in [0, 4] {
            let mut t = Fake::new(NORMAL);
            t.wrap_at_probe = Some(at);
            assert_eq!(
                measure_widths(&mut t),
                WidthOutcome::NoAnswer(Why::Moved),
                "{at}"
            );
        }
        let mut t = Fake::new(NORMAL);
        t.fail_writes = true;
        assert_eq!(measure_widths(&mut t), WidthOutcome::Failed);
    }

    // 이것을 실패시키는 것: 측정이 첫 시험 글자 전에 끝났는데(터미널이 CPR을 무시, 첫 질의가 취소) 줄을 지워 사용자가 줄에 둔
    // 글을 없애는 것, 시험 글자가 다음 줄로 넘어갔는데 그 줄을 지우지 않아 글자가 남는 것(행이 바뀐 경우와 화면이 밀려 행이
    // 그대로인 경우 둘 다), 글자를 쓰지 않은 경우의 위 줄 지우기.
    #[test]
    fn only_what_was_written_is_cleared() {
        // Cancelled at the first question: nothing written, nothing cleared.
        let mut t = Fake::new(NORMAL);
        t.col = 12;
        t.cancel_at = Some(0);
        assert_eq!(measure_widths(&mut t), WidthOutcome::Cancelled);
        assert!(t.written.is_empty(), "{:?}", t.written);
        // Cancelled after the new line but before any probe character: the
        // cleared line is the new, empty one; nothing above it is touched.
        let mut t = Fake::new(NORMAL);
        t.col = 12;
        t.cancel_at = Some(1);
        assert_eq!(measure_widths(&mut t), WidthOutcome::Cancelled);
        assert_eq!(t.written, b"\r\n");
        // The probes ran onto the next line: that line is cleared too.
        let mut t = Fake::new(NORMAL);
        t.wrap_at_probe = Some(4);
        assert_eq!(measure_widths(&mut t), WidthOutcome::NoAnswer(Why::Moved));
        assert!(
            t.written.ends_with(b"\r\x1b[K\x1b[A\x1b[K"),
            "{:?}",
            t.written
        );
        // On a screen that scrolled the row stays and the column goes back.
        let mut t = Fake::new(NORMAL);
        t.scroll_at_probe = Some(4);
        assert_eq!(measure_widths(&mut t), WidthOutcome::NoAnswer(Why::Moved));
        assert!(
            t.written.ends_with(b"\r\x1b[K\x1b[A\x1b[K"),
            "{:?}",
            t.written
        );
    }

    // 이것을 실패시키는 것: 터미널 폭보다 큰 열의 응답(수식키를 누른 F3의 `ESC [ 1 ; 2 R`처럼 위치 모양인 키 입력)을 위치로
    // 믿는 것(`col <= columns` 검사를 지움), 새 줄 뒤의 열이 1이 아닌데 그 위치에서 재는 것, 새 줄 뒤 행이 이전 행보다
    // 앞서는데 재는 것, 폭을 모를 때(None) 검사로 막는 것.
    #[test]
    fn a_reply_that_cannot_be_a_position_is_a_wrong_reply() {
        // Wide characters push the column past a 40-column terminal.
        let mut t = Fake::new([1, 2, 20, 20, 20, 2, 2, 2, 2, 1, 1, 1]);
        t.columns = Some(MIN_COLUMNS);
        assert_eq!(measure_widths(&mut t), WidthOutcome::NoAnswer(Why::Garbled));
        // The same cells in a terminal that is wide enough, or of unknown width.
        for columns in [Some(80), None] {
            let mut t = Fake::new([1, 2, 20, 20, 20, 2, 2, 2, 2, 1, 1, 1]);
            t.columns = columns;
            assert!(
                matches!(measure_widths(&mut t), WidthOutcome::Measured(_)),
                "{columns:?}"
            );
        }
        // A new line that does not start at column 1, or that goes back up.
        let mut t = Fake::new(NORMAL);
        t.col = 5;
        t.newline = (1, 7);
        assert_eq!(measure_widths(&mut t), WidthOutcome::NoAnswer(Why::Garbled));
        let mut t = Fake::new(NORMAL);
        t.col = 5;
        t.newline = (-2, 1);
        assert_eq!(measure_widths(&mut t), WidthOutcome::NoAnswer(Why::Garbled));
        // A screen that scrolled keeps the row: that is fine.
        let mut t = Fake::new(NORMAL);
        t.col = 5;
        t.newline = (0, 1);
        assert!(matches!(measure_widths(&mut t), WidthOutcome::Measured(_)));
    }

    // 이것을 실패시키는 것: 출력을 받지 않는 터미널(쓰기 마감 초과, `TimedOut`)을 쓰기 실패(`Failed`)로 읽는 것(응답 없음이어야
    // 함), 신호가 끊은 쓰기(`Interrupted`)를 취소가 아닌 것으로 읽는 것, 닫힌 터미널의 쓰기 오류를 응답 없음으로 읽는 것.
    #[test]
    fn a_write_that_times_out_is_silence_and_one_that_is_cut_by_a_signal_is_a_cancel() {
        for (kind, want) in [
            (io::ErrorKind::TimedOut, WidthOutcome::NoAnswer(Why::Silent)),
            (io::ErrorKind::Interrupted, WidthOutcome::Cancelled),
            (io::ErrorKind::BrokenPipe, WidthOutcome::Failed),
        ] {
            let mut t = Fake::new(NORMAL);
            t.fail_writes = true;
            t.write_error = kind;
            assert_eq!(measure_widths(&mut t), want, "{kind:?}");
        }
    }

    // 이것을 실패시키는 것: 40칸보다 좁은 터미널에서 측정하는 것(줄바꿈으로 칸 수가 틀어짐), 폭을 모를 때 측정을 막는 것.
    #[test]
    fn a_narrow_terminal_is_not_measured() {
        let mut t = Fake::new(NORMAL);
        t.columns = Some(MIN_COLUMNS - 1);
        assert_eq!(
            measure_widths(&mut t),
            WidthOutcome::TooNarrow(MIN_COLUMNS - 1)
        );
        assert!(t.written.is_empty() && t.queries == 0);
        let mut t = Fake::new(NORMAL);
        t.columns = Some(MIN_COLUMNS);
        assert!(matches!(measure_widths(&mut t), WidthOutcome::Measured(_)));
        let mut t = Fake::new(NORMAL);
        t.columns = None;
        assert!(matches!(measure_widths(&mut t), WidthOutcome::Measured(_)));
    }

    // 이것을 실패시키는 것: 밝기 판정을 뒤집는 것, 형식이 틀린 응답을 밝기로 읽는 것, 침묵·취소를 구분하지 않는 것.
    #[test]
    fn the_background_is_light_or_dark_or_unknown() {
        let mut t = Fake::new(NORMAL);
        assert_eq!(measure_background(&mut t), BackgroundOutcome::Dark);
        assert_eq!(t.requests, [b"\x1b]11;?\x1b\\".to_vec()]);
        t.background = b"\x1b]11;rgb:ffff/ffff/ffff\x07";
        assert_eq!(measure_background(&mut t), BackgroundOutcome::Light);
        t.background = b"\x1b]11;bogus\x07";
        assert_eq!(
            measure_background(&mut t),
            BackgroundOutcome::NoAnswer(Why::Garbled)
        );
        let mut t = Fake::new(NORMAL);
        t.answers = 0;
        assert_eq!(
            measure_background(&mut t),
            BackgroundOutcome::NoAnswer(Why::Silent)
        );
        let mut t = Fake::new(NORMAL);
        t.cancel_at = Some(0);
        assert_eq!(measure_background(&mut t), BackgroundOutcome::Cancelled);
    }
}
