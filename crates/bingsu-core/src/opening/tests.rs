#![cfg(test)]
use super::*;

fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

/// Glyphs a band may hold: the ramp's (a space is empty) and the snow's.
const GLYPHS: &[u8] = b" .:-=+*%#@";

/// Columns of `band` that hold a glyph in any row.
fn used_columns(band: &Band) -> Vec<u16> {
    (0..band.cols())
        .filter(|&x| (0..ROWS).any(|y| band.row(y)[usize::from(x)].ch != b' '))
        .collect()
}

// 이것을 실패시키는 것: 시드나 난수를 뽑는 차례를 바꾸는 것(점이 달라져 프레임이 다름은 골든이 잡음), 그리는 데 바깥
// 상태를 쓰는 것(같은 시각에 다른 프레임).
#[test]
fn the_same_time_draws_the_same_frame() {
    let (a, b) = (Bowl::new(), Bowl::new());
    assert_eq!(a, b);
    let inks = Inks::of(Mode::Dark);
    for t in [0, 700, 2300, 3333, 4400] {
        assert_eq!(a.draw(ms(t), 80, &inks), b.draw(ms(t), 80, &inks), "{t} ms");
        assert_eq!(a.draw(ms(t), 80, &inks), a.draw(ms(t), 80, &inks), "{t} ms");
    }
}

// 이것을 실패시키는 것: 어느 부분이 4.4 s 뒤에도 움직이는 것(토핑이 늦게 앉거나 눈이 계속 옴), 끝나기 전에 이미 멈추는
// 것(4.1 s의 마지막 토핑 튀기).
#[test]
fn every_frame_from_length_on_is_the_end_frame() {
    let bowl = Bowl::new();
    for mode in [Mode::Dark, Mode::Light] {
        let inks = Inks::of(mode);
        let end = bowl.draw(LENGTH, 80, &inks);
        for t in [ms(4250), ms(4401), ms(5000), ms(60_000), Duration::MAX] {
            assert_eq!(bowl.draw(t, 80, &inks), end, "{t:?}");
        }
        assert_ne!(bowl.draw(ms(4100), 80, &inks), end);
    }
}

// 이것을 실패시키는 것: 폭을 1–512 밖으로 두는 것, 줄 수가 7이 아닌 것, 빈 칸에 색을 두거나 글자 칸에 색을 빼는 것,
// 램프 밖 글자, 그릇이 가운데에 오지 않는 것.
#[test]
fn every_band_has_seven_rows_of_its_width() {
    let bowl = Bowl::new();
    let inks = Inks::of(Mode::Light);
    for cols in 40..=MAX_COLS {
        for t in [0, 1300, 2700, 3500, 4400] {
            let band = bowl.draw(ms(t), cols, &inks);
            assert_eq!(band.cols(), cols);
            for y in 0..ROWS {
                assert_eq!(band.row(y).len(), usize::from(cols), "{cols} {t} {y}");
                for c in band.row(y) {
                    assert!(GLYPHS.contains(&c.ch), "{cols} {t} {c:?}");
                    assert_eq!(c.ch == b' ', c.ink.is_none(), "{cols} {t} {c:?}");
                }
            }
            assert!(band.row(ROWS).is_empty());
        }
        // The full bowl sits in the middle.
        let used = used_columns(&bowl.draw(LENGTH, cols, &inks));
        let (l, r) = (used[0], used[used.len() - 1]);
        assert!(
            (i32::from(l) + i32::from(r) - (i32::from(cols) - 1)).abs() <= 2,
            "{cols}: {l}..{r}"
        );
    }
    assert_eq!(bowl.draw(LENGTH, 0, &inks).cols(), 1);
    assert_eq!(bowl.draw(LENGTH, u16::MAX, &inks).cols(), MAX_COLS);
}

/// Inks that tell the parts apart: the bowl and ice gray, the syrup red
/// (a > 0), the toppings green (a < 0).
fn marked() -> Inks {
    let gray = [0.7, 0.0, 0.0];
    Inks {
        base: [0.2, 0.0, 0.0],
        ice: gray,
        lip: gray,
        bowl: gray,
        syrup: [[0.6, 0.2, 0.0]; SYRUP_STEPS + 1],
        toppings: [[0.6, -0.2, 0.0]; 5],
    }
}

/// Cells of `band` whose color leans red (`> 0`) or green (`< 0`).
fn leaning(band: &Band, sign: f64) -> usize {
    (0..ROWS)
        .flat_map(|y| band.row(y).iter())
        .filter_map(|c| c.ink)
        .filter(|&ink| f64::from(oklab_q(ink).a as i32) / 1e6 * sign > 0.03)
        .count()
}

// 이것을 실패시키는 것: 부분의 시각을 바꾸는 것(얼음 채우기 2.6 s, 시럽 2.3 s부터, 눈 2.8 s까지, 토핑이 떨어지는
// 빠르기와 앉는 시각), 얼음이 처음부터 차 있는 것.
#[test]
fn the_parts_come_in_order() {
    let bowl = Bowl::new();
    let inks = marked();
    let at = |t: u64| bowl.draw(ms(t), 80, &inks);
    // Ice rises: more glyphs as it fills, none added after the fill.
    let glyphs = |b: &Band| {
        (0..ROWS)
            .flat_map(|y| b.row(y).iter())
            .filter(|c| c.ch != b' ')
            .count()
    };
    let empty_bowl = used_columns(&at(0)).len();
    assert!(glyphs(&at(2600)) > glyphs(&at(300)));
    assert!(empty_bowl > 0);
    // The syrup pours from 2.3 s.
    assert_eq!(leaning(&at(2290), 1.0), 0);
    assert!(leaning(&at(2700), 1.0) > 0);
    // The toppings fall in from high above: none in the band before 2.6 s
    // (the first lands at 3.2 s); all are on by the end.
    assert_eq!(leaning(&at(2590), -1.0), 0);
    assert!(leaning(&at(LENGTH.as_millis() as u64), -1.0) > 0);
    // Snow outside the bowl's columns: while it builds, and not after 2.8 s.
    let bowl_cols = used_columns(&at(4400));
    let snow = |t: u64| {
        used_columns(&at(t))
            .into_iter()
            .filter(|x| !bowl_cols.contains(x))
            .count()
    };
    assert!(snow(1000) > 0);
    assert_eq!(snow(2800), 0);
}

// 이것을 실패시키는 것: 색을 역할 token이 아닌 곳에서 가져오는 것, 얼음과 입술을 모드에 따라 바꾸지 않는 것, 토핑의
// token 차례를 바꾸는 것.
#[test]
fn inks_come_from_the_palette() {
    let named = |n: &str, m: Mode| lab(named_color(n, m, false).unwrap());
    for mode in [Mode::Dark, Mode::Light] {
        let inks = Inks::of(mode);
        assert_eq!(inks.base, named("neutral.base", mode));
        assert_eq!(inks.bowl, named("neutral.overlay", mode));
        assert_eq!(
            inks.syrup[0],
            mix_oklch(named("accent.red", mode), named("accent.pink", mode), 0.0)
        );
        let want = [
            "accent.pink",
            "accent.blue",
            "accent.mauve",
            "accent.yellow",
            "accent.green",
        ];
        for (got, name) in inks.toppings.iter().zip(want) {
            assert_eq!(*got, named(name, mode), "{name}");
        }
    }
    assert_eq!(Inks::of(Mode::Dark).ice, named("neutral.text", Mode::Dark));
    assert_eq!(
        Inks::of(Mode::Dark).lip,
        named("neutral.subtext", Mode::Dark)
    );
    assert_eq!(
        Inks::of(Mode::Light).ice,
        named("neutral.subtext", Mode::Light)
    );
    assert_eq!(
        Inks::of(Mode::Light).lip,
        named("neutral.text", Mode::Light)
    );
}

// 이것을 실패시키는 것: OKLCH 섞기가 짧은 쪽으로 돌지 않는 것(양쪽 방향), 회색에 다른 색의 색상을 주지 않는 것, 끝값이
// 두 색이 아닌 것.
#[test]
fn syrup_mixes_the_short_way_round() {
    let at = |deg: f64| {
        [
            0.7,
            0.1 * cos(deg * PI / 180.0),
            0.1 * sin(deg * PI / 180.0),
        ]
    };
    // Hue 170 to 190 degrees passes 180, not 0, either way round.
    let mid = mix_oklch(at(170.0), at(190.0), 0.5);
    assert!(mid[1] < -0.099 && mid[2].abs() < 1e-9, "{mid:?}");
    let back = mix_oklch(at(190.0), at(170.0), 0.5);
    assert!(back[1] < -0.099 && back[2].abs() < 1e-9, "{back:?}");
    // A gray takes the other color's hue.
    let gray = [0.7, 0.0, 0.0];
    let half = mix_oklch(gray, at(30.0), 0.5);
    assert!(
        (atan2(half[2], half[1]) - 30.0 * PI / 180.0).abs() < 1e-9,
        "{half:?}"
    );
    let a = mix_oklch(at(170.0), at(190.0), 0.0);
    assert!((a[1] - at(170.0)[1]).abs() < 1e-12 && (a[2] - at(170.0)[2]).abs() < 1e-12);
}

// 이것을 실패시키는 것: 끝난 뒤에도 프레임을 원하는 것, 30 fps보다 자주 원하는 것, 건너뛰기·멈춘 것을 끝 프레임으로
// 하지 않는 것, 시작 전 시각에서 거꾸로 세는 것.
#[test]
fn the_opening_runs_at_thirty_frames_and_ends() {
    let start = ms(10_000);
    let mut o = Opening::new(start);
    assert_eq!(o.at(start), Duration::ZERO);
    assert_eq!(o.at(ms(5)), Duration::ZERO);
    assert_eq!(o.at(start + ms(1000)), ms(1000));
    // Draw every frame when it is due: 30 a second, then nothing.
    let mut now = start;
    let mut frames = 0;
    while let Some(next) = o.next(now) {
        assert_eq!(next, now + FRAME);
        o.drawn(now);
        frames += 1;
        now = next;
        assert!(frames <= 200);
    }
    assert!(o.ended());
    assert_eq!(frames, 133, "frames until the end frame at 4.4 s");
    assert_eq!(o.at(now), LENGTH);
    // Drawn before the end: not over.
    let mut o = Opening::new(start);
    o.drawn(start + ms(4399));
    assert!(!o.ended());
    o.drawn(start + LENGTH);
    assert!(o.ended() && o.next(start + LENGTH).is_none());
}

// 이것을 실패시키는 것: 키 하나가 끝 프레임으로 넘기지 않는 것, 처음부터 멈춘 것이 움직이는 것, 끝 프레임을 그리기
// 전에 끝났다고 하는 것.
#[test]
fn a_key_or_no_motion_gives_the_end_frame() {
    let start = ms(1000);
    let mut o = Opening::new(start);
    o.skip();
    assert_eq!(o.at(start + ms(10)), LENGTH);
    assert!(!o.ended());
    assert!(o.next(start).is_some());
    o.drawn(start + ms(10));
    assert!(o.ended() && o.next(start + ms(10)).is_none());
    let mut still = Opening::still();
    assert_eq!(still.at(Duration::ZERO), LENGTH);
    assert!(!still.ended());
    still.drawn(Duration::ZERO);
    assert!(still.ended());
}

// 이것을 실패시키는 것: 못 그린 프레임을 세지 않는 것, 열 번이 아닌 수에서 끝내는 것, 그린 프레임이 수를 되돌리지 않는
// 것.
#[test]
fn ten_missed_frames_in_a_row_end_the_opening() {
    let start = ms(0);
    let mut o = Opening::new(start);
    for _ in 0..MISSED_MAX - 1 {
        o.missed();
    }
    assert_eq!(o.at(ms(100)), ms(100));
    o.drawn(ms(100));
    for _ in 0..MISSED_MAX - 1 {
        o.missed();
    }
    assert_eq!(
        o.at(ms(200)),
        ms(200),
        "a drawn frame starts the count again"
    );
    o.missed();
    assert_eq!(o.at(ms(200)), LENGTH);
    assert!(o.next(ms(200)).is_some());
    o.drawn(ms(233));
    assert!(o.ended());
}

// 이것을 실패시키는 것: 시계 끝에서 지금보다 늦지 않은 기한을 내는 것(포화 덧셈), 그 시각에 끝 프레임이 아닌 것, 바로
// 앞의 시각까지 끝으로 보는 것.
#[test]
fn a_clock_at_its_end_draws_the_end_frame_once_and_stops() {
    // Began at the clock's end: the one frame drawn is the end frame.
    let mut o = Opening::new(Duration::MAX);
    assert_eq!(o.at(Duration::MAX), LENGTH);
    o.drawn(Duration::MAX);
    assert!(o.ended());
    assert_eq!(o.next(Duration::MAX), None);
    // A frame missed less than one FRAME before the clock's end: no
    // deadline, and the next redraw draws the end frame.
    let near = Duration::MAX - Duration::from_nanos(1);
    let mut o = Opening::new(Duration::ZERO);
    o.missed();
    assert!(!o.ended());
    assert_eq!(o.next(near), None);
    assert_eq!(o.at(near), LENGTH);
    // One FRAME before the end still has a deadline ahead.
    let last = Duration::MAX - FRAME;
    let o = Opening::new(last);
    assert_eq!(o.next(last), Some(Duration::MAX));
    assert_eq!(o.at(last), Duration::ZERO);
}
