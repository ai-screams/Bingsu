//! OKLCH, OKLab and sRGB (spec section 1 crate table, F-06). Every
//! transcendental goes through the pure Rust `libm` (the std float methods
//! are disallowed in clippy.toml), and results are quantized at three fixed
//! points: 8-bit sRGB, OKLab in millionths, contrast in thousandths. Nothing
//! after those points uses floats, so native and wasm32 give the same bytes.
use libm::{cbrt, cos, pow, sin};

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Oklch {
    pub l: f64,
    pub c: f64,
    pub h: f64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Srgb8 {
    pub r: u8,
    pub g: u8,
    pub b: u8,
}

/// Quantization point 2: OKLab scaled by 1e6 and rounded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OklabQ {
    pub l: i64,
    pub a: i64,
    pub b: i64,
}

const GAMUT_EPS: f64 = 1e-7;

pub fn oklch_to_linear(c: Oklch) -> [f64; 3] {
    let h = c.h * core::f64::consts::PI / 180.0;
    let (a, b) = (c.c * cos(h), c.c * sin(h));
    let l_ = c.l + 0.396_337_777_4 * a + 0.215_803_757_3 * b;
    let m_ = c.l - 0.105_561_345_8 * a - 0.063_854_172_8 * b;
    let s_ = c.l - 0.089_484_177_5 * a - 1.291_485_548_0 * b;
    let (l, m, s) = (l_ * l_ * l_, m_ * m_ * m_, s_ * s_ * s_);
    [
        4.076_741_662_1 * l - 3.307_711_591_3 * m + 0.230_969_929_2 * s,
        -1.268_438_004_6 * l + 2.609_757_401_1 * m - 0.341_319_396_5 * s,
        -0.004_196_086_3 * l - 0.703_418_614_7 * m + 1.707_614_701_0 * s,
    ]
}

pub fn in_gamut(lin: [f64; 3]) -> bool {
    lin.iter()
        .all(|&v| (-GAMUT_EPS..=1.0 + GAMUT_EPS).contains(&v))
}

/// Lowers chroma at the same L and H until the color is inside sRGB
/// (gamut limiting, ADR-0004 rule 6). 40 halvings of a chroma below 0.5
/// leave an error under 1e-12, far below one 8-bit step.
pub fn clamp_chroma(c: Oklch) -> (Oklch, bool) {
    if in_gamut(oklch_to_linear(c)) {
        return (c, false);
    }
    let (mut lo, mut hi) = (0.0, c.c);
    for _ in 0..40 {
        let mid = (lo + hi) / 2.0;
        if in_gamut(oklch_to_linear(Oklch { c: mid, ..c })) {
            lo = mid;
        } else {
            hi = mid;
        }
    }
    (Oklch { c: lo, ..c }, true)
}

fn encode(v: f64) -> u8 {
    let v = v.clamp(0.0, 1.0);
    let e = if v <= 0.003_130_8 {
        12.92 * v
    } else {
        1.055 * pow(v, 1.0 / 2.4) - 0.055
    };
    // Quantization point 1. `as` saturates, and +0.5 then truncation rounds
    // half up the same way on every target.
    (e * 255.0 + 0.5) as u8
}

pub fn to_srgb8(lin: [f64; 3]) -> Srgb8 {
    Srgb8 {
        r: encode(lin[0]),
        g: encode(lin[1]),
        b: encode(lin[2]),
    }
}

/// OKLCH to 8-bit sRGB with gamut limiting; `true` when chroma was lowered.
pub fn oklch_to_srgb8(c: Oklch) -> (Srgb8, bool) {
    let (c, clipped) = clamp_chroma(c);
    (to_srgb8(oklch_to_linear(c)), clipped)
}

fn decode(v: u8) -> f64 {
    let c = f64::from(v) / 255.0;
    if c <= 0.040_45 {
        c / 12.92
    } else {
        pow((c + 0.055) / 1.055, 2.4)
    }
}

pub fn linear(s: Srgb8) -> [f64; 3] {
    [decode(s.r), decode(s.g), decode(s.b)]
}

fn q(v: f64) -> i64 {
    // Rounds half away from zero; |v| < 2, so the product fits.
    let x = v * 1e6;
    if x >= 0.0 {
        (x + 0.5) as i64
    } else {
        (x - 0.5) as i64
    }
}

pub fn oklab_q(s: Srgb8) -> OklabQ {
    let [r, g, b] = linear(s);
    let l = cbrt(0.412_221_470_8 * r + 0.536_332_536_3 * g + 0.051_445_992_9 * b);
    let m = cbrt(0.211_903_498_2 * r + 0.680_699_545_1 * g + 0.107_396_956_6 * b);
    let s_ = cbrt(0.088_302_461_9 * r + 0.281_718_837_6 * g + 0.629_978_700_5 * b);
    OklabQ {
        l: q(0.210_454_255_3 * l + 0.793_617_785_0 * m - 0.004_072_046_8 * s_),
        a: q(1.977_998_495_1 * l - 2.428_592_205_0 * m + 0.450_593_709_9 * s_),
        b: q(0.025_904_037_1 * l + 0.782_771_766_2 * m - 0.808_675_766_0 * s_),
    }
}

/// WCAG 2 contrast ratio in thousandths, rounded down (quantization point
/// 3). Text needs 4500, non-text marks 3000 (CLAUDE.md design rule 2).
pub fn contrast_milli(x: Srgb8, y: Srgb8) -> u32 {
    let lum = |s: Srgb8| {
        let [r, g, b] = linear(s);
        0.2126 * r + 0.7152 * g + 0.0722 * b
    };
    let (a, b) = (lum(x), lum(y));
    let (hi, lo) = if a >= b { (a, b) } else { (b, a) };
    ((hi + 0.05) / (lo + 0.05) * 1000.0) as u32
}

/// xterm's 256-color palette entry `i` for 16..=255 (0–15 belong to the
/// terminal's scheme and are never chosen by approximation).
pub fn xterm(i: u8) -> Srgb8 {
    const LEVEL: [u8; 6] = [0, 95, 135, 175, 215, 255];
    if i >= 232 {
        let v = 8 + 10 * (i - 232);
        return Srgb8 { r: v, g: v, b: v };
    }
    let n = i.saturating_sub(16);
    Srgb8 {
        r: LEVEL[usize::from(n / 36)],
        g: LEVEL[usize::from(n / 6 % 6)],
        b: LEVEL[usize::from(n % 6)],
    }
}

/// Nearest of entries 16..=255 by squared OKLab distance on the quantized
/// values; ties go to the lower index.
pub fn nearest_256(s: Srgb8) -> u8 {
    let t = oklab_q(s);
    let mut best = (i64::MAX, 16u8);
    for i in 16..=255u8 {
        let c = oklab_q(xterm(i));
        let d = (c.l - t.l).pow(2) + (c.a - t.a).pow(2) + (c.b - t.b).pow(2);
        if d < best.0 {
            best = (d, i);
        }
    }
    best.1
}

#[cfg(test)]
mod tests {
    use super::*;

    const BISECT_BITS: u64 = 4_598_487_577_005_436_111;
    const BISECT_BITS_2: u64 = 4_597_837_827_942_064_128;

    // 이것을 실패시키는 것: 변환 행렬·감마 오류. 기준값은 CSS Color 4의 OKLCH 예와 같은 계산이다.
    #[test]
    fn known_conversions() {
        assert_eq!(
            oklch_to_srgb8(Oklch {
                l: 1.0,
                c: 0.0,
                h: 0.0
            })
            .0,
            Srgb8 {
                r: 255,
                g: 255,
                b: 255
            }
        );
        assert_eq!(
            oklch_to_srgb8(Oklch {
                l: 0.0,
                c: 0.0,
                h: 0.0
            })
            .0,
            Srgb8 { r: 0, g: 0, b: 0 }
        );
        let red = oklab_q(Srgb8 { r: 255, g: 0, b: 0 });
        assert!(
            (red.l - 627_955).abs() <= 2
                && (red.a - 224_863).abs() <= 2
                && (red.b - 125_846).abs() <= 2,
            "{red:?}"
        );
    }

    // 이것을 실패시키는 것: 색역 밖 색을 그대로 두거나, 안의 색을 깎는 것.
    #[test]
    fn gamut_limiting() {
        let (_, clipped) = oklch_to_srgb8(Oklch {
            l: 0.76,
            c: 0.12,
            h: 255.0,
        });
        assert!(!clipped);
        let (c, clipped) = clamp_chroma(Oklch {
            l: 0.85,
            c: 0.3,
            h: 145.0,
        });
        assert!(clipped && c.c < 0.3 && in_gamut(oklch_to_linear(c)));
    }

    // 이것을 실패시키는 것: 대비 공식(0.05 더하기, 큰 쪽 분자)이나 내림 양자화가 틀린 것.
    #[test]
    fn contrast_values() {
        let w = Srgb8 {
            r: 255,
            g: 255,
            b: 255,
        };
        let k = Srgb8 { r: 0, g: 0, b: 0 };
        assert_eq!(contrast_milli(w, k), 21_000);
        assert_eq!(contrast_milli(k, w), 21_000);
        assert_eq!(contrast_milli(w, w), 1_000);
        assert_eq!(
            contrast_milli(
                Srgb8 {
                    r: 0x76,
                    g: 0x76,
                    b: 0x76
                },
                w
            ),
            4_542
        );
    }

    // 이것을 실패시키는 것: xterm 큐브·회색 단계 계산 오류, 0–15를 고르는 것, 동점에서 큰 번호를 고르는 것.
    #[test]
    fn xterm_and_nearest() {
        assert_eq!(xterm(16), Srgb8 { r: 0, g: 0, b: 0 });
        assert_eq!(xterm(196), Srgb8 { r: 255, g: 0, b: 0 });
        assert_eq!(
            xterm(231),
            Srgb8 {
                r: 255,
                g: 255,
                b: 255
            }
        );
        assert_eq!(xterm(232), Srgb8 { r: 8, g: 8, b: 8 });
        assert_eq!(
            xterm(255),
            Srgb8 {
                r: 238,
                g: 238,
                b: 238
            }
        );
        assert_eq!(nearest_256(Srgb8 { r: 255, g: 0, b: 0 }), 196);
        assert_eq!(nearest_256(Srgb8 { r: 0, g: 0, b: 0 }), 16);
        assert_eq!(
            nearest_256(Srgb8 {
                r: 128,
                g: 128,
                b: 128
            }),
            244
        );
    }

    fn rgb(r: u8, g: u8, b: u8) -> Srgb8 {
        Srgb8 { r, g, b }
    }

    // 이것을 실패시키는 것: OKLab 변환의 부호별 반올림(양수 +0.5, 음수 -0.5), 1e6 배율, 행렬 계수, 감마.
    // 기준값은 이 구현과 따로 쓴 Python(float, 같은 Ottosson 계수)이 낸 값이고 경계 0.05 안에 드는 값은 뺐다.
    #[test]
    fn oklab_q_exact_vectors() {
        let cases = [
            ((255, 255, 255), (1_000_000, 0, 0)),
            ((255, 0, 0), (627_955, 224_863, 125_846)),
            ((0, 255, 0), (866_440, -233_888, 179_498)),
            ((0, 0, 255), (452_014, -32_457, -311_528)),
            ((255, 255, 0), (967_983, -71_369, 198_570)),
            ((0, 255, 255), (905_399, -149_444, -39_398)),
            ((255, 0, 255), (701_674, 274_566, -169_156)),
            ((0x76, 0x76, 0x76), (565_836, 0, 0)),
            ((128, 128, 128), (599_871, 0, 0)),
            ((10, 20, 30), (186_989, -8_946, -23_704)),
            ((200, 100, 50), (613_838, 100_450, 100_742)),
            ((95, 135, 175), (609_926, -26_923, -70_722)),
            // 디코드 분기 경계(0.04045 * 255 = 10.31) 바로 위의 바이트들: 거듭제곱 구간이다.
            ((11, 11, 11), (149_577, 0, 0)),
            ((12, 12, 12), (154_340, 0, 0)),
            ((11, 0, 0), (93_928, 33_634, 18_824)),
            ((0, 12, 0), (133_726, -36_098, 27_704)),
            ((0, 0, 11), (67_611, -4_855, -46_597)),
        ];
        for ((r, g, b), (l, a, bb)) in cases {
            assert_eq!(oklab_q(rgb(r, g, b)), OklabQ { l, a, b: bb }, "{r},{g},{b}");
        }
    }

    // 이것을 실패시키는 것: 8비트 반올림(+0.5)을 자르기로 바꾸는 것, 포화 누락, 채널 순서 오류.
    #[test]
    fn quantize_to_8bit() {
        // 감마 인코딩 뒤 값이 100.6, 100.4, 0.5 바로 위/아래가 되는 선형 값을 따로 계산한다.
        let inv = |e255: f64| pow((e255 / 255.0 + 0.055) / 1.055, 2.4);
        assert_eq!(
            to_srgb8([inv(100.6), inv(100.4), inv(200.6)]),
            rgb(101, 100, 201)
        );
        assert_eq!(to_srgb8([2.0, -1.0, 1.0]), rgb(255, 0, 255));
        assert_eq!(to_srgb8([0.0, 1.0, 0.0]), rgb(0, 255, 0));
        // 분기 경계: 0.002 는 선형 구간(12.92 * v * 255 = 6.59 -> 7, 거듭제곱이면 6.17 -> 6)이고,
        // 0.0038 은 거듭제곱 구간(12.36 -> 12, 선형이면 12.52 -> 13), 0.0023 은 선형 구간(7.58 -> 8, 거듭제곱이면 7.38 -> 7)이다.
        assert_eq!(to_srgb8([0.002, 0.0038, 0.0023]), rgb(7, 12, 8));
        // 선형 구간: 12.92 * 0.001 * 255 = 3.29.
        assert_eq!(to_srgb8([0.001, 0.0, 0.0]).r, 3);
        assert_eq!(to_srgb8([0.0031308, 0.0, 0.0]).r, 10);
    }

    // 이것을 실패시키는 것: 색역 경계(±1e-7 포함)의 비교 방향·채널 누락.
    #[test]
    fn in_gamut_edges() {
        assert!(
            in_gamut([0.0, 0.0, 0.0]) && in_gamut([1.0, 1.0, 1.0]) && in_gamut([0.5, 0.2, 0.9])
        );
        assert!(in_gamut([1.0 + GAMUT_EPS, 0.0, 0.0]) && in_gamut([0.0, -GAMUT_EPS, 0.0]));
        for i in 0..3 {
            let mut hi = [0.5; 3];
            hi[i] = 1.0 + 1e-6;
            let mut lo = [0.5; 3];
            lo[i] = -1e-6;
            assert!(!in_gamut(hi) && !in_gamut(lo), "channel {i}");
        }
    }

    // 이것을 실패시키는 것: 이분 탐색 횟수(40)·방향, 색역 안 색을 깎는 것, 반환 플래그.
    // 기준값 0.2673393222091364는 따로 쓴 Python 이분 탐색(40회)이 낸 값이다.
    #[test]
    fn clamp_chroma_bisection() {
        let (c, clipped) = clamp_chroma(Oklch {
            l: 0.85,
            c: 0.3,
            h: 145.0,
        });
        assert!(clipped);
        assert!((c.c - 0.267_339_322_209_136_4).abs() < 1e-9, "{}", c.c);
        assert_eq!((c.l, c.h), (0.85, 145.0));
        assert!(in_gamut(oklch_to_linear(c)));
        // 경계에서 1e-11 위는 색역 밖이다: 탐색 횟수가 모자라면 틈이 이보다 크다.
        assert!(!in_gamut(oklch_to_linear(Oklch {
            c: c.c + 1e-11,
            ..c
        })));
        // 40회 결과의 비트까지 고정한다(native와 wasm32가 같아야 한다).
        assert_eq!(c.c.to_bits(), BISECT_BITS);
        // 첫 입력은 41회째가 값을 바꾸지 않으므로(탐색이 이미 수렴), 41회에서 값이 달라지는 입력을 하나 더 고정한다.
        // 기준값 0.240635501844963도 따로 쓴 Python 이분 탐색이 낸 값이다.
        let (c2, _) = clamp_chroma(Oklch {
            l: 0.6,
            c: 0.25,
            h: 30.0,
        });
        assert!((c2.c - 0.240_635_501_844_963).abs() < 1e-9, "{}", c2.c);
        assert_eq!(c2.c.to_bits(), BISECT_BITS_2);
        // 색역 안이면 그대로, 같은 값이다.
        let inside = Oklch {
            l: 0.5,
            c: 0.1,
            h: 30.0,
        };
        assert_eq!(clamp_chroma(inside), (inside, false));
        // 채도 0은 L 0..1에서 항상 안이다.
        assert!(
            !clamp_chroma(Oklch {
                l: 1.0,
                c: 0.0,
                h: 0.0
            })
            .1
        );
    }

    // 이것을 실패시키는 것: OKLCH 전체 경로(행렬·감마·색역 제한)의 값과 clipped 플래그.
    // 기준값은 따로 쓴 Python 구현이 낸 값이다.
    #[test]
    fn oklch_exact_vectors() {
        let cases = [
            ((0.78, 0.12, 60.0), (239, 164, 100), false),
            ((0.5, 0.2, 270.0), (59, 81, 211), false),
            ((0.76, 0.12, 255.0), (124, 180, 252), false),
            ((0.85, 0.3, 145.0), (0, 248, 71), true),
            ((0.6, 0.25, 30.0), (238, 19, 0), true),
            ((0.9, 0.4, 200.0), (97, 247, 255), true),
            ((0.3, 0.1, 320.0), (67, 24, 76), false),
            ((0.5, 0.0, 0.0), (99, 99, 99), false),
        ];
        for ((l, c, h), (r, g, b), clipped) in cases {
            assert_eq!(
                oklch_to_srgb8(Oklch { l, c, h }),
                (rgb(r, g, b), clipped),
                "{l} {c} {h}"
            );
        }
    }

    // 이것을 실패시키는 것: 순방향과 역방향 변환 어느 한쪽의 계수 오류(왕복이 어긋난다).
    #[test]
    fn roundtrip_through_oklch() {
        // 채널이 0이나 255인 색은 뺀다: 그 색은 색역 경계 위라서 양자화 오차만으로 밖에 놓이고,
        // 같은 L·H에서 채도를 낮추면 오히려 더 벗어나는 구간(파랑 첨점)이 있어 이분 탐색이 크게 물러난다.
        for r in (25..=230u8).step_by(41) {
            for g in (25..=230u8).step_by(41) {
                for b in (25..=230u8).step_by(41) {
                    let o = oklab_q(rgb(r, g, b));
                    let (a, bb) = (o.a as f64 / 1e6, o.b as f64 / 1e6);
                    let c = Oklch {
                        l: o.l as f64 / 1e6,
                        c: libm::sqrt(a * a + bb * bb),
                        h: libm::atan2(bb, a) * 180.0 / core::f64::consts::PI,
                    };
                    let c = Oklch {
                        h: if c.h < 0.0 { c.h + 360.0 } else { c.h },
                        ..c
                    };
                    let (back, clipped) = oklch_to_srgb8(c);
                    assert!(!clipped, "{r},{g},{b}");
                    let d = |x: u8, y: u8| x.abs_diff(y);
                    assert!(
                        d(back.r, r) <= 1 && d(back.g, g) <= 1 && d(back.b, b) <= 1,
                        "{r},{g},{b} -> {back:?}"
                    );
                }
            }
        }
    }

    // 이것을 실패시키는 것: 휘도 계수, 내림 대신 반올림, 선형화 계수.
    // 기준값은 따로 쓴 Python이 낸 값이다(3943.81 은 반올림이면 3944가 된다).
    #[test]
    fn contrast_exact_vectors() {
        let w = rgb(255, 255, 255);
        for (c, want) in [
            (rgb(255, 0, 0), 3_998),
            (rgb(0, 255, 0), 1_372),
            (rgb(0, 0, 255), 8_592),
            (rgb(0x8f, 0xb8, 0xf0), 2_042),
            (rgb(10, 20, 30), 18_555),
            (rgb(200, 100, 50), 3_943),
            (rgb(0x77, 0x77, 0x77), 4_478),
        ] {
            assert_eq!(contrast_milli(c, w), want, "{c:?}");
            assert_eq!(contrast_milli(w, c), want, "{c:?}");
        }
    }

    // 이것을 실패시키는 것: 큐브 단계값(0, 95, 135, 175, 215, 255)·회색 단계(8 + 10k)·경계 번호.
    // 기대값은 xterm 규칙(큐브 0/55+40k, 회색 8+10k)을 표 대신 식으로 쓴 것이다.
    #[test]
    fn xterm_table_by_formula() {
        let lv = |k: u8| if k == 0 { 0 } else { 55 + 40 * k };
        for i in 16..=231u8 {
            let n = i - 16;
            assert_eq!(xterm(i), rgb(lv(n / 36), lv(n / 6 % 6), lv(n % 6)), "{i}");
        }
        for i in 232..=255u8 {
            let v = 8 + 10 * (i - 232);
            assert_eq!(xterm(i), rgb(v, v, v), "{i}");
        }
    }

    // 이것을 실패시키는 것: 후보 범위(16..=255)의 양 끝, 동점에서 높은 번호를 고르는 것.
    // 동점 표적은 전수 탐색(16.7M 색)으로 찾았다: 22개이며 아래 둘은 인접(237/238)과 비인접(102/244) 경우다.
    #[test]
    fn nearest_256_ends_and_ties() {
        assert_eq!(nearest_256(rgb(238, 238, 238)), 255);
        assert_eq!(nearest_256(rgb(255, 255, 255)), 231);
        assert_eq!(nearest_256(rgb(8, 8, 8)), 232);
        assert_eq!(nearest_256(rgb(7, 68, 99)), 237);
        assert_eq!(nearest_256(rgb(119, 134, 145)), 102);
        // 15 간격 격자 표본(5,832색(18^3))에서 0..=15를 고르지 않는다.
        for r in (0..=255u8).step_by(15) {
            for g in (0..=255u8).step_by(15) {
                for b in (0..=255u8).step_by(15) {
                    assert!(nearest_256(rgb(r, g, b)) >= 16);
                }
            }
        }
    }
}
