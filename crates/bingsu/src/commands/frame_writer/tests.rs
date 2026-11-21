use super::*;
use std::collections::VecDeque;

/// What one `write_some` call of the fake terminal does.
#[derive(Clone, Copy)]
enum Step {
    /// Takes at most this many bytes (0: none now).
    Take(usize),
    Fail(ErrorKind),
}

/// A terminal that follows `script` (and takes everything once it ran
/// out), checks that each write is handed all that is left of the frame,
/// and records what it took and was told.
#[derive(Default)]
struct Fake {
    script: VecDeque<Step>,
    /// The wrapped frames it expects, one after another.
    whole: Vec<u8>,
    got: Vec<u8>,
    marks: Vec<bool>,
    calls: usize,
}

impl Fake {
    fn new(steps: &[Step]) -> Self {
        Self {
            script: steps.iter().copied().collect(),
            ..Self::default()
        }
    }

    fn expect(&mut self, frame: &[u8]) {
        self.whole.extend_from_slice(&wrapped(frame));
    }
}

impl Sink for Fake {
    fn write_some(&mut self, rest: &[u8]) -> std::io::Result<usize> {
        self.calls += 1;
        // 이것을 실패시키는 것: 남은 것 일부만 넘기는 것(세션이 반쪽 프레임을 끊김으로 보지 못함).
        assert_eq!(rest, &self.whole[self.got.len()..], "not all that is left");
        let n = match self.script.pop_front() {
            None => rest.len(),
            Some(Step::Take(n)) => n.min(rest.len()),
            Some(Step::Fail(kind)) => return Err(kind.into()),
        };
        self.got.extend_from_slice(&rest[..n]);
        Ok(n)
    }

    fn mark_synced(&mut self, on: bool) {
        self.marks.push(on);
    }
}

fn wrapped(frame: &[u8]) -> Vec<u8> {
    [SYNC_BEGIN, frame, SYNC_END].concat()
}

fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

// 이것을 실패시키는 것: 동기화 출력으로 감싸지 않는 것, 시작·끝 알림의 순서나 횟수가 다른 것, 끝난 뒤 쉬지 않는 것.
#[test]
fn a_frame_is_wrapped_and_its_ends_are_told() {
    let t = Instant::now();
    let mut w = FrameWriter::new();
    let mut sink = Fake::new(&[]);
    sink.expect(b"abc");
    w.begin(b"abc", t).unwrap();
    assert!(w.wants_write());
    assert!(matches!(w.flush(&mut sink, t), Flushed::Done));
    assert_eq!(sink.got, wrapped(b"abc"));
    assert_eq!(sink.marks, [true, false]);
    assert!(w.idle() && !w.wants_write());
    assert!(matches!(w.flush(&mut sink, t), Flushed::Done));
    assert_eq!(sink.calls, 1);
}

// 이것을 실패시키는 것: 받은 바이트 수만큼 나아가지 않는 것(같은 바이트를 두 번 보냄), 시작 알림을 쓰기마다 하는
// 것, 받지 않은 쓰기(0, EAGAIN, EINTR)를 오류나 진행으로 보는 것.
#[test]
fn partial_writes_and_refusals_go_on_where_they_stopped() {
    let t = Instant::now();
    let steps = [
        Step::Take(3),
        Step::Take(0),
        Step::Take(5),
        Step::Fail(ErrorKind::WouldBlock),
        Step::Take(1),
        Step::Fail(ErrorKind::Interrupted),
        Step::Take(2),
        Step::Take(0),
    ];
    let mut sink = Fake::new(&steps);
    let frame = b"\x1b[2;3Hhello\x1b[0m";
    sink.expect(frame);
    let mut w = FrameWriter::new();
    w.begin(frame, t).unwrap();
    let mut pending = 0;
    let done = loop {
        match w.flush(&mut sink, t) {
            Flushed::Pending => pending += 1,
            Flushed::Done => break true,
            other => panic!("{other:?}"),
        }
        assert!(pending < 10);
    };
    assert!(done);
    // Each refusal ended one flush: Take(0) twice, WouldBlock, Interrupted.
    assert_eq!(pending, 4);
    assert_eq!(sink.got, wrapped(frame));
    assert_eq!(sink.marks, [true, false]);
}

// 이것을 실패시키는 것: 정체 상한을 2 s가 아닌 값으로 보는 것, 비교를 `>`로 하는 것, 한 바이트라도 받으면 시계를 새로
// 하지 않는 것, 쉬는 동안 기한을 내는 것.
#[test]
fn a_terminal_that_takes_nothing_for_two_seconds_is_stalled() {
    let t = Instant::now();
    let mut sink = Fake::new(&[Step::Take(0); 8]);
    sink.expect(b"frame");
    let mut w = FrameWriter::new();
    assert_eq!(w.deadline(), None);
    assert!(!w.stalled(t + ms(5000)));
    w.begin(b"frame", t).unwrap();
    assert_eq!(w.deadline(), Some(t + STALL));
    assert!(matches!(w.flush(&mut sink, t + ms(1999)), Flushed::Pending));
    assert!(!w.stalled(t + ms(1999)));
    assert!(matches!(w.flush(&mut sink, t + STALL), Flushed::Stalled));
    assert!(w.stalled(t + STALL));

    // A byte taken at 1.5 s starts the time again.
    let mut sink = Fake::new(&[
        Step::Take(0),
        Step::Take(1),
        Step::Take(0),
        Step::Take(0),
        Step::Take(0),
    ]);
    sink.expect(b"frame");
    let mut w = FrameWriter::new();
    w.begin(b"frame", t).unwrap();
    assert!(matches!(w.flush(&mut sink, t + ms(100)), Flushed::Pending));
    assert!(matches!(w.flush(&mut sink, t + ms(1500)), Flushed::Pending));
    assert_eq!(w.deadline(), Some(t + ms(3500)));
    assert!(matches!(w.flush(&mut sink, t + ms(3499)), Flushed::Pending));
    assert!(matches!(w.flush(&mut sink, t + ms(3500)), Flushed::Stalled));
    // The frame stays pending: the caller ends.
    assert!(w.wants_write());
}

// 이것을 실패시키는 것: 쓰기 오류 뒤 프레임을 남기는 것(다음 프레임을 받지 않음), 끝 알림을 보내는 것.
#[test]
fn a_write_error_drops_the_frame() {
    let t = Instant::now();
    let mut sink = Fake::new(&[Step::Take(4), Step::Fail(ErrorKind::BrokenPipe)]);
    sink.expect(b"frame");
    let mut w = FrameWriter::new();
    w.begin(b"frame", t).unwrap();
    assert!(matches!(w.flush(&mut sink, t), Flushed::Gone(e) if e.kind() == ErrorKind::BrokenPipe));
    assert!(w.idle());
    assert_eq!(w.deadline(), None);
    assert_eq!(sink.marks, [true]);
}

// 이것을 실패시키는 것: 바뀜을 프레임 수만큼 쌓는 것, 쓰는 중에 새 프레임을 원하는 것, 끝난 뒤 밀린 바뀜을 잊는
// 것, 새 프레임을 시작해도 바뀜 표시를 지우지 않는 것.
#[test]
fn changes_while_a_frame_is_written_make_one_frame() {
    let t = Instant::now();
    let mut w = FrameWriter::new();
    assert!(!w.wants_frame());
    w.request();
    w.request();
    assert!(w.wants_frame());
    w.begin(b"one", t).unwrap();
    assert!(!w.wants_frame());
    for _ in 0..5 {
        w.request();
    }
    assert!(!w.wants_frame());
    assert_eq!(w.begin(b"two", t), Err(Refused::Busy));
    let mut sink = Fake::new(&[]);
    sink.expect(b"one");
    assert!(matches!(w.flush(&mut sink, t), Flushed::Done));
    assert!(w.wants_frame());
    sink.expect(b"two");
    w.begin(b"two", t).unwrap();
    assert!(!w.wants_frame());
    assert!(matches!(w.flush(&mut sink, t), Flushed::Done));
    assert!(!w.wants_frame());
    assert_eq!(sink.got, [wrapped(b"one"), wrapped(b"two")].concat());
}

// 이것을 실패시키는 것: 크기 상한을 보지 않는 것, 하나 어긋나게 보는 것.
#[test]
fn a_frame_over_the_cap_is_refused() {
    let t = Instant::now();
    let mut w = FrameWriter::new();
    assert_eq!(w.begin(&vec![b'x'; FRAME_MAX + 1], t), Err(Refused::TooBig));
    assert!(w.idle());
    assert_eq!(w.begin(&vec![b'x'; FRAME_MAX], t), Ok(()));
}

// 이것을 실패시키는 것: 한 번의 flush에서 쓰기 횟수에 상한이 없는 것(한 바이트씩 받는 터미널이 루프를 붙잡음).
#[test]
fn one_flush_makes_a_bounded_number_of_writes() {
    let t = Instant::now();
    let mut sink = Fake::new(&[Step::Take(1); 200]);
    sink.expect(&[b'x'; 100]);
    let mut w = FrameWriter::new();
    w.begin(&[b'x'; 100], t).unwrap();
    assert!(matches!(w.flush(&mut sink, t), Flushed::Pending));
    assert_eq!(sink.calls, WRITES_PER_FLUSH);
    assert_eq!(sink.got.len(), WRITES_PER_FLUSH);
}

// 이것을 실패시키는 것: 버린 뒤 남은 바이트를 계속 쓰는 것, 다시 그릴 프레임을 원하지 않는 것, 다음 프레임의 시작을
// 알리지 않는 것.
#[test]
fn discard_drops_the_frame_and_asks_for_a_whole_one() {
    let t = Instant::now();
    let mut sink = Fake::new(&[Step::Take(4), Step::Take(0)]);
    sink.expect(b"cut");
    let mut w = FrameWriter::new();
    w.begin(b"cut", t).unwrap();
    assert!(matches!(w.flush(&mut sink, t), Flushed::Pending));
    w.discard();
    assert!(w.idle() && w.wants_frame());
    assert_eq!(w.deadline(), None);
    assert!(matches!(w.flush(&mut sink, t), Flushed::Done));
    assert_eq!(sink.calls, 2);

    let mut sink = Fake::new(&[]);
    sink.expect(b"whole");
    w.begin(b"whole", t).unwrap();
    assert!(matches!(w.flush(&mut sink, t), Flushed::Done));
    assert_eq!(sink.got, wrapped(b"whole"));
    assert_eq!(sink.marks, [true, false]);
}

/// A terminal that says it took more than it was given.
struct Liar;

impl Sink for Liar {
    fn write_some(&mut self, rest: &[u8]) -> std::io::Result<usize> {
        Ok(rest.len() + 10)
    }
    fn mark_synced(&mut self, _: bool) {}
}

// 이것을 실패시키는 것: 끝 판정을 `==`로 하는 것(남은 길이보다 많이 받았다는 터미널에서 프레임이 끝나지 않음).
#[test]
fn a_count_past_the_end_is_the_end() {
    let t = Instant::now();
    let mut w = FrameWriter::new();
    w.begin(b"abc", t).unwrap();
    assert!(matches!(w.flush(&mut Liar, t), Flushed::Done));
    assert!(w.idle());
}
