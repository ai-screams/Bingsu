//! Byte goldens of the shaved-ice opening (`bingsu_core::opening`): frame
//! hashes at fixed times and widths in both modes, and the glyphs of the
//! 80-column end frame. A change to the scene changes these on purpose:
//! look at the new end frame, then pin the new values.
use bingsu_core::color::palette::Mode;
use bingsu_core::opening::{Band, Bowl, Inks, LENGTH, ROWS};
use core::time::Duration;

/// FNV-1a over every cell: glyph, then the ink's three bytes or a marker
/// for none.
fn hash(band: &Band) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    let mut eat = |b: u8| {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    };
    for y in 0..ROWS {
        for c in band.row(y) {
            eat(c.ch);
            match c.ink {
                Some(i) => [1, i.r, i.g, i.b].into_iter().for_each(&mut eat),
                None => eat(0),
            }
        }
    }
    h
}

const TIMES_MS: [u64; 9] = [0, 500, 1300, 2000, 2600, 3000, 3600, 4000, 4400];
const WIDTHS: [u16; 5] = [40, 60, 80, 121, 512];

/// Hashes by mode, width (`WIDTHS`) and time (`TIMES_MS`).
const DARK: [[u64; 9]; 5] = [
    [
        0x0baed26bad56b6dd,
        0x7a87376377ea3337,
        0xecbca66a6e39b5ff,
        0x1a69799d5e3617e6,
        0x291ee5fb18ea6d80,
        0xf3fa21978f3f6a73,
        0x04478e3d8ec061b4,
        0x35a93bae8bb5b178,
        0x765bb4b41e3fbfe4,
    ],
    [
        0xd9832a1c7b9fe4c6,
        0xdcaee98e7038f162,
        0xfc91c45c98d25f0e,
        0xd0d169b9070a2712,
        0xe70c4910b1a17666,
        0xd9c163ef94e4c013,
        0x868f88eb26ee04a4,
        0x1b9d0043ae8da668,
        0x712b9c26e8524874,
    ],
    [
        0x9c11e11219a2b383,
        0x18748f67b7ae567d,
        0xf62d69d843e90f37,
        0x3255225713ffa64f,
        0xd42cf55e811a1687,
        0xf450c159dace71f3,
        0x6fabde2afa33f8d4,
        0xa8f41c4988f144d8,
        0x7a95eb92ee4d3204,
    ],
    [
        0xb8b64a21aad7a3cc,
        0x0e67df128b9e41a1,
        0x1a8bd5990e2dbbbd,
        0x1b918184a5ee8483,
        0x53ae0c131e4697ba,
        0x9e45ef42ed342a4e,
        0x8e11b4df3be38746,
        0x28e2127664da421c,
        0xac22ce66bc56c377,
    ],
    [
        0x9c02a35c5319518a,
        0x861f9d6c29ef5016,
        0x983a6a341d602c43,
        0xb06218b0b6af183a,
        0x382d4cd1ff59463a,
        0xc43377e9181ca4f3,
        0xcb005b0d46102f94,
        0xd759ebb9ef15c098,
        0x22c7029192bf0f44,
    ],
];
const LIGHT: [[u64; 9]; 5] = [
    [
        0x8f63a07c639c266f,
        0x85c817acc8299df6,
        0x6055aa3e15117dfc,
        0x2555e79928a17fbe,
        0x6482e048966a2b8a,
        0x3155a11a10345241,
        0x666b93430f8d6987,
        0x9584d8e64312eb1e,
        0x8a9d622be220d326,
    ],
    [
        0x18ed9117ef87144a,
        0x9ad37195a7e28226,
        0x033c4c528dca2c36,
        0x76bc0b6ae05ef3b2,
        0x79da19f66b60ffc3,
        0x73cb16e1364a9641,
        0xbeebd480e47f2887,
        0x5b741a24f157cf2e,
        0xe0a897f53739eb76,
    ],
    [
        0xd0277fc63dd378dd,
        0xf9592950f349e618,
        0x9595860180d5a9f9,
        0xfda17dfeee12d1b1,
        0xc5102e11c44955ed,
        0x7f548311619ae141,
        0xf1da878e0fa11b87,
        0xba1bd7893ed2b2fe,
        0x8f7efc80f9c12e46,
    ],
    [
        0x77f76c33637867a4,
        0x4e652b4d2d0d2b46,
        0xe55a735aec03fd34,
        0xf571e741da2ff5ef,
        0xbb403020722cd139,
        0x67db32ea1c0d6595,
        0x703f6304d6801ddb,
        0x18fa696d54ab33af,
        0x72f91e650c01ba49,
    ],
    [
        0xc1faa19f0053a961,
        0x29cd2b29b7981c7e,
        0x4c7ee1b025099f84,
        0x8b96cf04de270066,
        0x7526e6ef1a90e2ce,
        0x823804f77ea9c341,
        0x811f4e586eee7a87,
        0x60463b90bad334be,
        0xd88c069bed1a3986,
    ],
];

/// The 80-column end frame, the same glyphs in both modes (the ink does
/// not change a glyph). The approved study draws these glyphs too.
const END_80: [&str; 7] = [
    "                              .:-=*@@@@@@@@@#+=:.                               ",
    "                           :+%%#%%%%@#%##@@####%%+=.                            ",
    "                         -=%###%**%%%%*%#%%%%*%%#%#%=-                          ",
    "                         %@@###%%%%**%**#%%%%%%%%%@@@#                          ",
    "                          *#@#*%##%*+%###%##+#@#%#@#+                           ",
    "                           .+*+===+#***+++*#+==**+=.                            ",
    "                              .::-*#*+==++%#*-::.                               ",
];

// 이것을 실패시키는 것: 장면(점, 시각, 투영, 램프, 섞기, 색)을 바꾸는 것. 일부러 바꿨다면 새 끝 프레임을 보고 값을 다시
// 고정한다.
#[test]
fn frames_match_their_goldens() {
    let bowl = Bowl::new();
    for (mode, table) in [(Mode::Dark, &DARK), (Mode::Light, &LIGHT)] {
        let inks = Inks::of(mode);
        for (cols, row) in WIDTHS.iter().zip(table) {
            for (t, want) in TIMES_MS.iter().zip(row) {
                let got = hash(&bowl.draw(Duration::from_millis(*t), *cols, &inks));
                assert_eq!(
                    got, *want,
                    "{mode:?} {cols} columns at {t} ms: 0x{got:016x}"
                );
            }
        }
    }
    for mode in [Mode::Dark, Mode::Light] {
        let end = bowl.draw(LENGTH, 80, &Inks::of(mode));
        let rows: Vec<String> = (0..ROWS).map(|y| end.text(y)).collect();
        assert_eq!(rows, END_80, "{mode:?}");
    }
}
