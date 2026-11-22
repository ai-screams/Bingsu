//! Keys from what a terminal in raw mode sends, for `bingsu setup`'s
//! editor. The bytes come from the terminal or from whatever reaches its
//! input (replies to queries, late replies, pasted text), so they are not
//! trusted: only keys the editor can bind come out, and the payload of a
//! sequence never becomes keys.
//!
//! A byte state machine with no clock of its own. The caller passes the
//! bytes of each read and the time they came ([`KeyReader::feed`]), asks
//! when time alone would change something ([`KeyReader::deadline`], the
//! limit for its wait) and then calls [`KeyReader::tick`]. A time is an
//! offset from any fixed point of the caller's monotonic clock; arithmetic
//! on it saturates.
//!
//! | State | Entered by | Ends | Bounds | Past a bound |
//! | -- | -- | -- | -- | -- |
//! | Ground | | | | |
//! | Esc | `ESC` | the next byte, or `ESC_WAIT` (30 ms) with none: the Esc key | 30 ms | the Esc key |
//! | Csi | `ESC [`, 0x9b | a final byte 0x40-0x7e | `SEQ_MAX` (32) bytes, `SEQ_TIME` (200 ms) | Drain |
//! | Ss3 | `ESC O`, 0x8f | as Csi | as Csi | Drain |
//! | Str | `ESC ]`, `ESC P`, `ESC _`, `ESC ^`, `ESC X`, 0x9d, 0x90, 0x9f, 0x9e, 0x98 | BEL, or ST (`ESC \`, 0x9c) | `STR_MAX` (4,096) bytes, `STR_TIME` (500 ms) | Drain |
//! | Paste | `ESC [ 200 ~` (or with 0x9b) | `ESC [ 201 ~` (or with 0x9b) | `PASTE_MAX` (1 MiB), `PASTE_TIME` (5 s) | Drain |
//! | Mouse | `ESC [ M` (no parameters) | three more bytes, whatever they are | `SEQ_TIME` from its ESC | Drain |
//! | Utf8 | 0xC2-0xF4 | the last continuation byte | 3 more bytes | |
//! | Drain | a bound passed, a string or a paste ended | `DRAIN_QUIET` (100 ms) with no input | | |
//!
//! Every state keeps a few counters, never the payload, so a 1 MiB paste
//! costs no memory. A sequence ends where its own grammar says, never
//! where a read ends: `ESC [`, a pause shorter than its bound, and `A` is
//! one Up key. Time bounds run from the sequence's ESC (from the first byte
//! of a late sequence, from the start mark of a paste).
//!
//! Drain drops everything until the input stays quiet for `DRAIN_QUIET`.
//! Going back to Ground as soon as a bound passed would read the rest of
//! that sequence (`q`, `s`, Enter) as keys. Draining after a string or a
//! paste ends has the same reason: both are sent by the terminal, not
//! typed, and a BEL inside text a terminal reflects back ends a string
//! early, and a paste can carry a fake end mark.
//!
//! Decided byte by byte:
//!
//! - Keys: printable ASCII (Space included), Enter (CR or LF: raw mode
//!   keeps `ICRNL`, so Enter mostly comes as LF), Tab, Backspace (DEL or
//!   BS), the arrows (`ESC [ A`-`D`, `ESC O A`-`D`), Shift-Tab (`ESC [ Z`),
//!   a lone Esc, and every other C0 control as `Ctrl`: Ctrl-C (0x03),
//!   Ctrl-D (0x04, a key in raw mode, never the end of input), Ctrl-L,
//!   Ctrl-Z (0x1a). End of input is the reader's business, not a byte.
//! - Dropped: other sequences (with parameters, unknown final bytes,
//!   late replies), ESC with a byte that starts no sequence (an Alt key),
//!   characters outside ASCII, invalid UTF-8, and everything inside Str,
//!   Paste and Drain, 0x03 and 0x1a included (a payload never cancels or
//!   stops the editor), and every key of a burst but Ctrl-C (below).
//! - Read again from Ground: the byte that breaks a UTF-8 character, and
//!   an ESC inside Csi or Ss3 (a new sequence begins). Otherwise
//!   `0xE2 ESC [ A` would lose the arrow, or the ESC of `ESC [ 200 ~`
//!   would be swallowed and its `2` would pick a value. Any other byte that
//!   breaks Csi or Ss3 drains.
//! - 8-bit (C1) controls: an introducer (0x9b CSI, 0x8f SS3, 0x9d OSC,
//!   0x90 DCS, 0x9f APC, 0x9e PM, 0x98 SOS) that is no part of a UTF-8
//!   character begins the same state as its `ESC` form (a C1 introducer
//!   counts as two bytes towards `SEQ_MAX`), and 0x9c ends a string as ST
//!   does; other C1 bytes are dropped. U+0080 to U+009F written in UTF-8
//!   (`C2 9D` for OSC) are the same C1 controls in Ground; inside a string
//!   they are payload (`C2 9C` ends nothing, and the string ends at its
//!   time bound). Inside a string or a paste a byte 0x80-0xbf that
//!   continues a UTF-8 character of the payload is payload, never 0x9c or
//!   the 0x9b of an 8-bit end mark (`Ŝ` is `C5 9C`). Without this, `0x9f`,
//!   a pause, Enter and `0x9c` would give an Enter key from a string. After
//!   ESC a byte outside ASCII is read again from Ground (the ESC is
//!   dropped), so `ESC 0x9d` cannot hide an OSC either.
//! - An X10 mouse report (`ESC [ M Cb Cx Cy`, left on by another program)
//!   takes three raw bytes after its `M`: they can be any byte (a column
//!   past 95 is 0x80 or above), and as keys `ESC [ M`, Space, `1` would
//!   step a value. A terminal that sends `ESC [ M` for F1 (SCO keys) loses
//!   the three keys typed next (or, when they come after the report's time
//!   bound, the keys of the drain that follows).
//! - Ss3 takes parameter bytes as Csi does: some terminals send
//!   `ESC O 5 A`, and the `5` would otherwise pick a value.
//! - ESC ESC: the first is the Esc key, the second begins again.
//! - Late sequences: once `ESC_WAIT` made an ESC the Esc key, a sequence
//!   introducer (`[`, `O`, `]`, `P`, `_`, `^`, `X`) as the very next byte,
//!   within `LATE_WAIT` (100 ms), is the late rest of that sequence and is
//!   dropped to its end; otherwise `ESC O A` split by a slow link would
//!   turn `O` into "outer, back one", and a split OSC 11 reply would pick
//!   values with its digits. A late `ESC [ 200 ~` still begins a paste.
//!
//! Pasting. With bracketed paste on (`CSI ? 2004 h`, the terminal marks a
//! paste with `ESC [ 200 ~` and `ESC [ 201 ~`) the whole paste is dropped.
//! Without the marks, pasting and typing cannot be told apart for sure; a
//! guess stands in: a read with `BURST` (4) or more keys counts as pasted
//! and its keys are dropped, all but a Ctrl-C in it. Every unit the reader
//! drops in Ground counts as a key here too: a Csi or Ss3 sequence or a
//! mouse report (one, however long), a sequence cut by a new ESC, a broken
//! or a whole character outside ASCII, a stray byte, an ESC dropped before
//! a byte outside ASCII. Strings and pastes do not count: they drain once
//! they end, and the drain drops what follows them.
//! Otherwise a paste padded with such units (`ESC [` again and again, 0xff,
//! Latin-1 text) would keep each read under `BURST` and let one key per
//! read through, a second Enter from a later read included.
//!
//! A Ctrl-C in a burst is kept: cancelling writes nothing, and with `ISIG`
//! off the 0x03 byte is the user's only quick way out, also when fast
//! typing comes in one read (a slow ssh link). After a burst the next read
//! is read as usual, with no drain: a paste longer than one read can leave
//! one to three keys in a read the read size cut short (its first or its
//! last), which costs less than dropping what is typed next over a slow
//! link. That is a weak guarantee, and a paste of up to three keys gets
//! through. So a key that loses something (`q` with changes, Enter on the
//! save screen) must be taken twice, and only a second press from a later
//! read (a later `feed` call) confirms: all keys of one `Keys` came in one
//! read. Two keys in one read are no confirmation: `qq`, or `\r\n`, which a
//! terminal in newline mode (LNM) sends for one Enter (`\n\n` after
//! `ICRNL`) and which comes out as two Enter keys. That check belongs to
//! the editor.
use core::time::Duration;

/// How long an ESC waits for the rest of a sequence before it is the Esc
/// key.
pub const ESC_WAIT: Duration = Duration::from_millis(30);
/// After `ESC_WAIT` made an ESC the Esc key, how long an introducer as the
/// next byte is still the late rest of that sequence.
pub const LATE_WAIT: Duration = Duration::from_millis(100);
/// How long the input must stay quiet before draining ends.
pub const DRAIN_QUIET: Duration = Duration::from_millis(100);
/// The longest Csi or Ss3 sequence, from ESC through the final byte.
pub const SEQ_MAX: usize = 32;
/// How long a Csi or Ss3 sequence may take, from its ESC.
pub const SEQ_TIME: Duration = Duration::from_millis(200);
/// The longest string (OSC, DCS, APC, PM, SOS) after its introducer,
/// through its terminator.
pub const STR_MAX: usize = 4096;
/// How long a string may take, from its ESC.
pub const STR_TIME: Duration = Duration::from_millis(500);
/// The longest bracketed paste after its start mark, through its end mark.
pub const PASTE_MAX: usize = 1 << 20;
/// How long a bracketed paste may take, from its start mark.
pub const PASTE_TIME: Duration = Duration::from_secs(5);
/// Keys in one read from which the read counts as pasted.
pub const BURST: usize = 4;

const ESC: u8 = 0x1b;
const BEL: u8 = 0x07;
/// Ctrl-C, the one key a burst keeps.
const CANCEL: Key = Key::Ctrl(b'c');
/// The paste end mark.
const PASTE_END: &[u8] = b"\x1b[201~";
/// The 8-bit CSI, which stands for the first two bytes of the end mark.
const CSI8: u8 = 0x9b;
/// The 8-bit ST.
const ST8: u8 = 0x9c;
/// The parameter bytes of the paste start mark, `ESC [ 200 ~`.
const PASTE_START: [u8; 3] = *b"200";
/// Bytes of a Csi or Ss3 sequence kept to tell its key: ESC, the
/// introducer and no more than this many parameter bytes.
const BODY: usize = 3;

/// One key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Key {
    /// Printable ASCII, from Space (0x20) to `~` (0x7e).
    Char(u8),
    /// CR or LF.
    Enter,
    Tab,
    /// Shift-Tab, `ESC [ Z`.
    BackTab,
    /// DEL (0x7f) or BS (0x08).
    Backspace,
    /// ESC with nothing after it for `ESC_WAIT`.
    Esc,
    Up,
    Down,
    Right,
    Left,
    /// Another C0 control byte, by its letter in lower case: `Ctrl(b'c')`
    /// is 0x03, `Ctrl(b'd')` 0x04, `Ctrl(b'l')` 0x0c, `Ctrl(b'z')` 0x1a,
    /// `Ctrl(b'@')` 0x00, `Ctrl(b'\\')` to `Ctrl(b'_')` 0x1c to 0x1f.
    Ctrl(u8),
}

/// The keys of one call: at most `BURST`, the Esc key that time ended
/// before the read first. The other keys came in that one read, so a
/// confirmation (a second press of a key that loses something) must come
/// from the keys of a later call: `\r\n` in one read, as a terminal in
/// newline mode sends for one Enter, is two Enter keys here. Two are equal
/// when their keys are.
#[derive(Clone, Copy, Debug)]
pub struct Keys {
    list: [Key; BURST],
    len: usize,
}

impl Keys {
    const NONE: Self = Self {
        list: [Key::Esc; BURST],
        len: 0,
    };

    pub fn as_slice(&self) -> &[Key] {
        self.list.get(..self.len).unwrap_or(&[])
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn push(&mut self, key: Key) {
        if let Some(slot) = self.list.get_mut(self.len) {
            *slot = key;
            self.len += 1;
        }
    }
}

impl PartialEq for Keys {
    fn eq(&self, other: &Self) -> bool {
        // 이것을 실패시키는 것: 배열 전체를 비교하는 것(쓰지 않은 칸의 값이 비교에 들어감).
        self.as_slice() == other.as_slice()
    }
}

impl Eq for Keys {}

impl<'a> IntoIterator for &'a Keys {
    type Item = &'a Key;
    type IntoIter = core::slice::Iter<'a, Key>;

    fn into_iter(self) -> Self::IntoIter {
        self.as_slice().iter()
    }
}

/// What a sequence after `ESC` is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Seq {
    Csi,
    Ss3,
}

/// A Csi or Ss3 sequence in progress: `len` bytes so far, from ESC, the
/// first `BODY` parameter bytes in `body`. `late`: the rest of a sequence
/// whose ESC was already the Esc key, so its key is dropped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct InSeq {
    kind: Seq,
    since: Duration,
    len: usize,
    body: [u8; BODY],
    late: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Ground,
    /// An ESC that came at `at`.
    Esc {
        at: Duration,
    },
    Seq(InSeq),
    /// `len` bytes after the introducer; `esc`: the last one was ESC;
    /// `cont`: continuation bytes of a UTF-8 character still to come.
    Str {
        since: Duration,
        len: usize,
        esc: bool,
        cont: u8,
    },
    /// `len` bytes after the start mark; `matched`: how much of the end
    /// mark the last bytes were; `cont` as for Str.
    Paste {
        since: Duration,
        len: usize,
        matched: usize,
        cont: u8,
    },
    /// `need` continuation bytes to come, the next one in `lo..=hi`.
    /// `c1`: the lead was 0xC2, so the character is U+0080 to U+00BF and a
    /// C1 control below U+00A0.
    Utf8 {
        need: u8,
        lo: u8,
        hi: u8,
        c1: bool,
    },
    /// The `left` raw bytes of an X10 mouse report (`ESC [ M` and three
    /// bytes) still to come; `since` as for the Csi it began as.
    Mouse {
        since: Duration,
        left: u8,
    },
    /// Dropping input until none comes for `DRAIN_QUIET` after `quiet_from`.
    Drain {
        quiet_from: Duration,
    },
}

/// The keys of one read as they are found.
struct Found {
    /// The Esc key that time ended before the read.
    before: Option<Key>,
    keys: [Key; BURST - 1],
    len: usize,
    /// Keys in this read, kept or dropped.
    count: usize,
    /// A Ctrl-C key in this read.
    cancel: bool,
}

impl Found {
    const fn new() -> Self {
        Self {
            before: None,
            keys: [Key::Esc; BURST - 1],
            len: 0,
            count: 0,
            cancel: false,
        }
    }

    /// One key of the read: `Some` to keep, `None` for a key that is
    /// dropped but counts towards a burst.
    fn key(&mut self, key: Option<Key>) {
        self.count = self.count.saturating_add(1);
        self.cancel |= key == Some(CANCEL);
        if let Some(key) = key {
            if let Some(slot) = self.keys.get_mut(self.len) {
                *slot = key;
                self.len += 1;
            }
        }
    }

    /// The read's keys; from a burst only Ctrl-C.
    fn keys(&self) -> Keys {
        let mut out = Keys::NONE;
        if let Some(key) = self.before {
            out.push(key);
        }
        if self.count < BURST {
            for &key in self.keys.get(..self.len).unwrap_or(&[]) {
                out.push(key);
            }
        } else if self.cancel {
            // 이것을 실패시키는 것: 묶음 안의 Ctrl-C까지 버리는 것(빠른 타이핑이 한 읽기에 묶이면 취소할 수 없음).
            out.push(CANCEL);
        }
        out
    }
}

/// The key reader. See the module comment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyReader {
    state: State,
    /// Until when an introducer as the next byte is the late rest of the
    /// sequence whose ESC time made the Esc key.
    late_until: Option<Duration>,
}

impl Default for KeyReader {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyReader {
    pub const fn new() -> Self {
        Self {
            state: State::Ground,
            late_until: None,
        }
    }

    /// The keys of one read, `bytes`, which came at `now`. A time bound
    /// that passed by `now` is applied first. Call it once per read: the
    /// burst guess and confirmations (see `Keys`) count on it.
    pub fn feed(&mut self, bytes: &[u8], now: Duration) -> Keys {
        let mut found = Found::new();
        found.before = self.expire(now);
        for &b in bytes {
            // A byte read again goes to Ground or Esc, which never ask for
            // it a third time.
            for _ in 0..2 {
                if !self.step(b, now, &mut found) {
                    break;
                }
            }
        }
        found.keys()
    }

    /// The keys that time alone makes by `now`: the Esc key when an ESC
    /// waited `ESC_WAIT`, or none. Called when `deadline` passes.
    pub fn tick(&mut self, now: Duration) -> Keys {
        let mut found = Found::new();
        found.before = self.expire(now);
        found.keys()
    }

    /// When time alone would change something (`tick` is due), or `None`
    /// while nothing waits on time.
    pub fn deadline(&self) -> Option<Duration> {
        match self.state {
            State::Ground | State::Utf8 { .. } => None,
            State::Esc { at } => Some(at.saturating_add(ESC_WAIT)),
            State::Seq(InSeq { since, .. }) | State::Mouse { since, .. } => {
                Some(since.saturating_add(SEQ_TIME))
            }
            State::Str { since, .. } => Some(since.saturating_add(STR_TIME)),
            State::Paste { since, .. } => Some(since.saturating_add(PASTE_TIME)),
            State::Drain { quiet_from } => Some(quiet_from.saturating_add(DRAIN_QUIET)),
        }
    }

    /// Forgets a sequence in progress, after the terminal was given back
    /// and taken again (a stop and a resume): what comes next is new input.
    pub fn reset(&mut self) {
        *self = Self::new();
    }

    /// Applies the time bounds that passed by `now`, as if each had been
    /// seen when it passed: the Esc key when an ESC waited long enough; a
    /// sequence past its bound drains from that bound, not from `now`, and
    /// a drain that ended by `now` (that one included) is over. At most two
    /// steps, so a late `tick` or `feed` ends where ticks on time would
    /// have.
    fn expire(&mut self, now: Duration) -> Option<Key> {
        // 이것을 실패시키는 것: 상한 비교를 `>`로 바꾸는 것(정확히 상한인 때에 넘기지 않음), 상한을 보지 않는 것(잘린
        // 시퀀스나 홀로 된 Esc가 끝나지 않음), Drain을 알아챈 때부터 세는 것(늦은 tick 뒤 친 키를 잃음).
        let past = |since: Duration, bound: Duration| now >= since.saturating_add(bound);
        let bound = match self.state {
            State::Esc { at } if past(at, ESC_WAIT) => {
                self.state = State::Ground;
                self.late_until = Some(at.saturating_add(ESC_WAIT).saturating_add(LATE_WAIT));
                return Some(Key::Esc);
            }
            State::Seq(InSeq { since, .. }) | State::Mouse { since, .. } => Some((since, SEQ_TIME)),
            State::Str { since, .. } => Some((since, STR_TIME)),
            State::Paste { since, .. } => Some((since, PASTE_TIME)),
            _ => None,
        };
        if let Some((since, bound)) = bound.filter(|&(since, bound)| past(since, bound)) {
            self.drain(since.saturating_add(bound));
        }
        if let State::Drain { quiet_from } = self.state {
            if past(quiet_from, DRAIN_QUIET) {
                self.state = State::Ground;
            }
        }
        None
    }

    fn drain(&mut self, now: Duration) {
        self.state = State::Drain { quiet_from: now };
    }

    /// One byte; `true` when it must be read again in the state it left.
    fn step(&mut self, b: u8, now: Duration, found: &mut Found) -> bool {
        match self.state {
            State::Ground => {
                self.ground(b, now, found);
                false
            }
            State::Esc { at } => self.after_esc(b, at, now, found),
            State::Seq(seq) => self.in_seq(b, seq, now, found),
            State::Str {
                since,
                len,
                esc,
                cont,
            } => {
                let len = len.saturating_add(1);
                let in_char = continues(cont, b);
                // 이것을 실패시키는 것: 길이 상한을 보지 않는 것, 끝난 뒤 Ground로 가는 것(반사된 글의 BEL 뒤가 키가 됨),
                // ESC 다음이 아닌 `\`로 끝내는 것, 0x9c로 끝내지 않는 것, UTF-8 글자의 이어지는 0x9c로 끝내는 것.
                if len > STR_MAX || b == BEL || (esc && b == b'\\') || (b == ST8 && !in_char) {
                    self.drain(now);
                } else {
                    self.state = State::Str {
                        since,
                        len,
                        esc: b == ESC,
                        cont: next_cont(cont, b),
                    };
                }
                false
            }
            State::Paste {
                since,
                len,
                matched,
                cont,
            } => {
                let len = len.saturating_add(1);
                // 이것을 실패시키는 것: 끝 표지 짝 맞추기에서 ESC로 다시 시작하지 않는 것(`ESC ESC [201~`를 놓침), 8비트
                // CSI의 끝 표지를 놓치는 것, UTF-8 글자의 이어지는 0x9b를 끝 표지로 읽는 것, 길이 상한을 보지 않는 것,
                // 끝난 뒤 Ground로 가는 것(가짜 끝 표지 뒤가 키가 됨).
                let matched = if PASTE_END.get(matched) == Some(&b) {
                    matched + 1
                } else if b == ESC {
                    1
                } else if b == CSI8 && !continues(cont, b) {
                    2
                } else {
                    0
                };
                if len > PASTE_MAX || matched == PASTE_END.len() {
                    self.drain(now);
                } else {
                    self.state = State::Paste {
                        since,
                        len,
                        matched,
                        cont: next_cont(cont, b),
                    };
                }
                false
            }
            State::Utf8 { need, lo, hi, c1 } => {
                // 이것을 실패시키는 것: 이어지는 바이트의 범위를 보지 않는 것(과장 부호화·대리 쌍·U+10FFFF 너머를 받음),
                // 깨는 바이트를 다시 읽지 않는 것(`0xE2 ESC [ A`의 ESC를 삼킴).
                if !(lo..=hi).contains(&b) {
                    self.state = State::Ground;
                    // 이것을 실패시키는 것: 깨진 글자를 묶음에 세지 않는 것(잘못된 UTF-8로 채운 붙여 넣기가 읽기마다 키를
                    // 흘림).
                    found.key(None);
                    return true;
                }
                if need > 1 {
                    self.state = State::Utf8 {
                        need: need - 1,
                        lo: 0x80,
                        hi: 0xbf,
                        c1: false,
                    };
                } else if c1 {
                    // U+0080 to U+00BF: a C1 control below U+00A0; any other
                    // is no introducer and drops as a character would.
                    // 이것을 실패시키는 것: UTF-8로 쓴 C1(`C2 9D`)을 보통 글자로 읽는 것(나뉜 OSC 답의 `11;rgb`가 키가 됨).
                    self.state = State::Ground;
                    self.c1(b, now, found);
                } else {
                    self.state = State::Ground;
                    // A character outside ASCII: no key of the editor.
                    found.key(None);
                }
                false
            }
            State::Mouse { since, left } => {
                // Any byte: the report's three bytes are raw (a column past
                // 95 is a byte 0x80 or above, a C1 introducer included).
                self.state = if left <= 1 {
                    State::Ground
                } else {
                    State::Mouse {
                        since,
                        left: left - 1,
                    }
                };
                false
            }
            State::Drain { .. } => {
                self.drain(now);
                false
            }
        }
    }

    fn ground(&mut self, b: u8, now: Duration, found: &mut Found) {
        // 이것을 실패시키는 것: 늦은 창을 보지 않는 것(나뉜 `ESC O A`의 `O`가 키가 됨), 창이 지나도 늦은 것으로
        // 보는 것(Esc 뒤 한참 뒤에 친 `O`를 잃음), 바로 다음 바이트가 아니어도 보는 것.
        let late = self.late_until.take().is_some_and(|until| now < until);
        if late {
            if let Some(state) = introduce(b, now, true) {
                self.state = state;
                return;
            }
        }
        match b {
            ESC => self.state = State::Esc { at: now },
            b'\r' | b'\n' => found.key(Some(Key::Enter)),
            b'\t' => found.key(Some(Key::Tab)),
            0x7f | 0x08 => found.key(Some(Key::Backspace)),
            0x00..=0x1f => found.key(Some(Key::Ctrl((b | 0x40).to_ascii_lowercase()))),
            0x20..=0x7e => found.key(Some(Key::Char(b))),
            // A C1 control (no character continues here): an introducer
            // begins its sequence as its ESC form does, others are dropped.
            // 이것을 실패시키는 것: C1 도입 바이트를 홀로 버리는 것(`0x9f \r 0x9c`의 Enter가 키가 됨).
            0x80..=0x9f => self.c1(b, now, found),
            0xc2 => {
                self.state = State::Utf8 {
                    need: 1,
                    lo: 0x80,
                    hi: 0xbf,
                    c1: true,
                };
            }
            0xc3..=0xdf => self.utf8(1, 0x80, 0xbf),
            0xe0 => self.utf8(2, 0xa0, 0xbf),
            0xed => self.utf8(2, 0x80, 0x9f),
            0xe1..=0xec | 0xee..=0xef => self.utf8(2, 0x80, 0xbf),
            0xf0 => self.utf8(3, 0x90, 0xbf),
            0xf4 => self.utf8(3, 0x80, 0x8f),
            0xf1..=0xf3 => self.utf8(3, 0x80, 0xbf),
            // 0xa0-0xc1, 0xf5-0xff: no character starts with them.
            // 이것을 실패시키는 것: 떠도는 바이트를 묶음에 세지 않는 것(0xff로 채운 붙여 넣기가 읽기마다 키를 흘림).
            _ => found.key(None),
        }
    }

    fn utf8(&mut self, need: u8, lo: u8, hi: u8) {
        self.state = State::Utf8 {
            need,
            lo,
            hi,
            c1: false,
        };
    }

    /// The C1 control `b` (0x80-0x9f), as a raw byte or as U+0080 to U+009F
    /// in UTF-8 (`b` up to 0xbf then, U+00A0 and above being no introducer):
    /// an introducer begins its sequence as its ESC form does, others are a
    /// dropped unit.
    fn c1(&mut self, b: u8, now: Duration, found: &mut Found) {
        if let Some(state) = introduce(b.wrapping_sub(0x40), now, false) {
            self.state = state;
        } else {
            // 이것을 실패시키는 것: 도입 바이트가 아닌 C1을 묶음에 세지 않는 것.
            found.key(None);
        }
    }

    /// The byte after an ESC that came at `at`, before `ESC_WAIT` passed;
    /// `true` when it must be read again from Ground.
    fn after_esc(&mut self, b: u8, at: Duration, now: Duration, found: &mut Found) -> bool {
        if let Some(state) = introduce(b, at, false) {
            self.state = state;
            return false;
        }
        // 이것을 실패시키는 것: ESC ESC의 둘째로 새로 시작하지 않는 것(`ESC ESC [ A`의 `[`, `A`가 키가 됨).
        if b == ESC {
            found.key(Some(Key::Esc));
            self.state = State::Esc { at: now };
            return false;
        }
        self.state = State::Ground;
        // 이것을 실패시키는 것: ESC 뒤 아스키 밖 바이트를 함께 버리는 것(`ESC 0x9f \r 0x9c`의 Enter가 키가 됨).
        if b >= 0x80 {
            // The ESC is dropped, a unit of its own; the byte is a C1 control
            // or a character.
            // 이것을 실패시키는 것: 버린 ESC를 묶음에 세지 않는 것(`q ESC é q`가 키 넷이 아니게 됨).
            found.key(None);
            return true;
        }
        // An Alt key, which the editor does not bind.
        found.key(None);
        false
    }

    /// The next byte of a Csi or Ss3 sequence.
    fn in_seq(&mut self, b: u8, mut seq: InSeq, now: Duration, found: &mut Found) -> bool {
        match b {
            0x20..=0x3f => {
                seq.len = seq.len.saturating_add(1);
                // 이것을 실패시키는 것: 길이 상한을 보지 않는 것, `>=`를 `>`로 바꾸는 것(마지막 바이트 자리가 없는
                // 33바이트 시퀀스를 받음).
                if seq.len >= SEQ_MAX {
                    self.drain(now);
                } else {
                    if let Some(slot) = seq.len.checked_sub(3).and_then(|i| seq.body.get_mut(i)) {
                        *slot = b;
                    }
                    self.state = State::Seq(seq);
                }
                false
            }
            0x40..=0x7e => {
                self.state = State::Ground;
                let params = seq.len.saturating_sub(2);
                let key = match (seq.kind, params, b) {
                    // 이것을 실패시키는 것: 매개 바이트를 보지 않는 것(`ESC [ 1 ; 5 A`를 위 화살표로 받음).
                    (_, 0, b'A') => Some(Key::Up),
                    (_, 0, b'B') => Some(Key::Down),
                    (_, 0, b'C') => Some(Key::Right),
                    (_, 0, b'D') => Some(Key::Left),
                    (Seq::Csi, 0, b'Z') => Some(Key::BackTab),
                    // 이것을 실패시키는 것: X10 마우스 보고의 세 바이트를 키로 읽는 것(`ESC [ M` 뒤 Space, `1`이 샘, 0x98이
                    // 문자열을 엶), 둘이나 넷을 먹는 것, 보고를 묶음에 세지 않는 것.
                    (Seq::Csi, 0, b'M') => {
                        self.state = State::Mouse {
                            since: seq.since,
                            left: 3,
                        };
                        found.key(None);
                        return false;
                    }
                    (Seq::Csi, 3, b'~') if seq.body == PASTE_START => {
                        self.state = State::Paste {
                            since: now,
                            len: 0,
                            matched: 0,
                            cont: 0,
                        };
                        return false;
                    }
                    _ => None,
                };
                // 이것을 실패시키는 것: 늦은 시퀀스의 키를 버리지 않는 것(늦게 온 `[A`가 위 화살표가 됨).
                found.key(if seq.late { None } else { key });
                false
            }
            // 이것을 실패시키는 것: 시퀀스 안의 ESC를 Drain으로 보내는 것(잘린 시퀀스 뒤의 화살표를 잃음), 다시 읽지
            // 않는 것.
            ESC => {
                self.state = State::Ground;
                // 이것을 실패시키는 것: 끊긴 시퀀스를 묶음에 세지 않는 것(`ESC [`를 되풀이해 채운 붙여 넣기가 읽기마다 키를
                // 흘림).
                found.key(None);
                true
            }
            _ => {
                self.drain(now);
                false
            }
        }
    }
}

/// `b` continues a UTF-8 character of a payload that needs `cont` more
/// bytes.
fn continues(cont: u8, b: u8) -> bool {
    cont > 0 && (0x80..=0xbf).contains(&b)
}

/// How many continuation bytes of a UTF-8 character of a payload are still
/// to come after `b`. Only the count: a payload is dropped, so the exact
/// ranges of the lead bytes do not matter here.
fn next_cont(cont: u8, b: u8) -> u8 {
    if continues(cont, b) {
        return cont - 1;
    }
    match b {
        0xc2..=0xdf => 1,
        0xe0..=0xef => 2,
        0xf0..=0xf4 => 3,
        _ => 0,
    }
}

/// The state that `b` begins after an ESC (at `since`), when it introduces
/// a sequence. `late`: the ESC was already the Esc key.
fn introduce(b: u8, since: Duration, late: bool) -> Option<State> {
    let seq = |kind| {
        State::Seq(InSeq {
            kind,
            since,
            len: 2,
            body: [0; BODY],
            late,
        })
    };
    match b {
        b'[' => Some(seq(Seq::Csi)),
        b'O' => Some(seq(Seq::Ss3)),
        b']' | b'P' | b'_' | b'^' | b'X' => Some(State::Str {
            since,
            len: 0,
            esc: false,
            cont: 0,
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests;
