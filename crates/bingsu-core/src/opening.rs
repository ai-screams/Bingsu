//! The shaved-ice opening of `bingsu setup`'s editor: a bowl that fills
//! with ice under falling snow, gets syrup and five toppings, in a band of
//! seven rows, over `LENGTH` (4.4 s). The only motion of the editor.
//!
//! A frame is a function of the time into the opening, the band's width
//! and the inks: [`Bowl::draw`] gives the same cells for the same input,
//! and every time from `LENGTH` on gives the end frame (the bowl full, no
//! snow). [`Opening`] holds when the opening began and whether it is over,
//! and says which time to draw and when the next frame is due; nothing
//! here reads a clock or writes to a terminal.
//!
//! How the editor runs it (the event loop is the CLI's):
//!
//! 1. `Bowl::new()` once (about 7,000 seeded points) and the inks of the
//!    mode the editor draws in (`Inks::of`).
//! 2. `Opening::new(now)`, or `Opening::still()` for `--no-motion` and a
//!    set `NO_COLOR` (the end frame from the start).
//! 3. A frame at once, then one when `Opening::next` says (at most 30 a
//!    second). A frame: when the frame writer is free,
//!    `Bowl::draw(opening.at(now), ...)` into the screen's rows 1-7, then
//!    `drawn(now)`; when the writer still holds the last frame, `missed`
//!    instead; ten in a row end the opening (a slow terminal or link), and
//!    the end frame is drawn next.
//! 4. Any key: `skip` (and the key's own command), and the screen is drawn
//!    again with the end frame. `next` is `None` once the end frame was
//!    drawn: no more timer, no more work.
//!
//! The picture is splatted from 3D points (bowl, ice, syrup, toppings,
//! tilted towards the viewer) onto the cells, each cell's glyph from its
//! density on the ramp ` .:-=+*%#@` and its color the points' inks mixed
//! in OKLab and faded towards the background as the density falls. The
//! glyphs carry the picture, so a monochrome screen (`NO_COLOR`) draws the
//! same band without the inks. All arithmetic is `f64` and `libm`, so
//! every platform draws the same bits.
//!
//! Contrast: the one exception to the design rule that non-text marks
//! reach 3:1 on the background. Faint cells fade towards it, as the
//! approved motion study does: over the 45 frames from 0 to 4.4 s at 80
//! columns, 2,857 of 9,281 drawn cells (31%) are under 3:1 on dark (lowest
//! 1.44:1, median 4.31:1) and 4,132 (45%) on light (lowest 1.51:1, median
//! 3.38:1). The bowl is decoration and carries no information; its shape
//! comes from the glyph ramp and stays the same without colors
//! (`NO_COLOR`); the fading is the approved look; a key skips the opening
//! and `--no-motion` turns it off. The editor's text keeps 4.5:1 and every
//! mark that means something keeps 3:1.
use crate::color::math::{Srgb8, lab_to_linear, oklab_q, to_srgb8};
use crate::color::palette::{Mode, TOKENS, named_color};
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::time::Duration;
use libm::{atan2, cbrt, cos, exp, floor, fmod, pow, sin, sqrt};

/// The band's height.
pub const ROWS: u16 = 7;
/// The widest band; a wider screen is drawn up to here.
pub const MAX_COLS: u16 = 512;
/// How long the opening takes. From here on every frame is the end frame.
pub const LENGTH: Duration = Duration::from_millis(4400);
/// The shortest time between two frames: 30 a second.
pub const FRAME: Duration = Duration::from_nanos(33_333_334);
/// Frames in a row the writer could not take before the opening ends.
pub const MISSED_MAX: u8 = 10;

/// A local constant, not an import: the purity gate counts imported values
/// as functions.
const PI: f64 = core::f64::consts::PI;

/// Glyphs by density, lightest first.
const RAMP: &[u8; 10] = b" .:-=+*%#@";

// The scene (from the approved motion study, direction 1): bowl radius,
// depth, dome height, tilt towards the viewer, dome curve, foot height.
const R: f64 = 1.0;
const DEPTH: f64 = 0.45;
const HMAX: f64 = 0.4;
const TILT: f64 = 0.25;
const DOME_K: f64 = 0.6;
const FOOT_Y: f64 = -0.53;
/// Points per kind; the counts set the density per cell.
const ICE: usize = 4200;
const WALL: usize = 1300;
const LIP: usize = 340;
const FOOT: usize = 260;
const SYRUP_TOP: usize = 360;
const DRIPS: [f64; 5] = [-0.95, -0.45, 0.05, 0.5, 1.0];
const PER_DRIP: usize = 60;
const PER_TOPPING: usize = 60;
const FLAKES: usize = 110;
/// The toppings' tokens, in landing order.
const TOPPINGS: [&str; 5] = ["host", "path", "git.branch", "duration", "prompt.ok"];
/// The syrup runs from the first to the second, in this many steps.
const SYRUP: [&str; 2] = ["accent.red", "accent.pink"];
const SYRUP_STEPS: usize = 8;
/// Points weigh this much less at seven rows (the same density per cell).
const WK: f64 = 0.6;

/// When each part moves, in seconds into the opening: the ice fills in
/// `FILL`, the syrup pours from `POUR_AT` for `POUR`, snow falls until
/// `SNOW_END`, topping `j` falls at `DROP` units a second to land at
/// `LAND + LAND_STEP * j` and bounces for `BOUNCE`.
const FILL: f64 = 2.6;
const POUR_AT: f64 = 2.3;
const POUR: f64 = 1.4;
const SNOW_END: f64 = 2.8;
const LAND: f64 = 3.2;
const LAND_STEP: f64 = 0.18;
const DROP: f64 = 2.2;
const BOUNCE: f64 = 0.3;

/// The colors the band is drawn with, from role tokens and palette names
/// of one mode, as OKLab.
#[derive(Clone, Debug, PartialEq)]
pub struct Inks {
    /// The screen background (`neutral.base`): faint cells fade into it.
    base: [f64; 3],
    ice: [f64; 3],
    lip: [f64; 3],
    bowl: [f64; 3],
    /// From `SYRUP[0]` to `SYRUP[1]`, mixed in OKLCH.
    syrup: [[f64; 3]; SYRUP_STEPS + 1],
    toppings: [[f64; 3]; 5],
}

impl Inks {
    /// The inks of `mode`: ice `neutral.text` on dark and `neutral.subtext`
    /// on light (the lip the other one), the bowl `neutral.overlay`, the
    /// syrup `accent.red` to `accent.pink`, the toppings the colors of the
    /// tokens `host`, `path`, `git.branch`, `duration`, `prompt.ok`.
    pub fn of(mode: Mode) -> Self {
        // Every name here is a palette color; black stands in for none.
        let black = Srgb8 { r: 0, g: 0, b: 0 };
        let named = |name: &str| lab(named_color(name, mode, false).unwrap_or(black));
        let (ice, lip) = match mode {
            Mode::Dark => ("neutral.text", "neutral.subtext"),
            Mode::Light => ("neutral.subtext", "neutral.text"),
        };
        let [red, pink] = SYRUP.map(named);
        let mut syrup = [[0.0; 3]; SYRUP_STEPS + 1];
        for (i, s) in syrup.iter_mut().enumerate() {
            *s = mix_oklch(red, pink, i as f64 / SYRUP_STEPS as f64);
        }
        let token = |name: &str| {
            let t = TOKENS.iter().find(|t| t.name == name);
            let color = t.map_or("neutral.text", |t| match mode {
                Mode::Dark => t.dark,
                Mode::Light => t.light,
            });
            named(color)
        };
        Self {
            base: named("neutral.base"),
            ice: named(ice),
            lip: named(lip),
            bowl: named("neutral.overlay"),
            syrup,
            toppings: TOPPINGS.map(token),
        }
    }
}

/// OKLab of `s`.
fn lab(s: Srgb8) -> [f64; 3] {
    let q = oklab_q(s);
    [q.l as f64 / 1e6, q.a as f64 / 1e6, q.b as f64 / 1e6]
}

/// `a` to `b` at `t` in OKLCH, the shorter way round the hue circle (a
/// gray takes the other color's hue), as OKLab.
fn mix_oklch(a: [f64; 3], b: [f64; 3], t: f64) -> [f64; 3] {
    let lch = |c: [f64; 3]| {
        let chroma = sqrt(c[1] * c[1] + c[2] * c[2]);
        (c[0], chroma, (chroma >= 1e-4).then(|| atan2(c[2], c[1])))
    };
    let (la, ca, ha) = lch(a);
    let (lb, cb, hb) = lch(b);
    let (ha, hb) = match (ha, hb) {
        (Some(x), Some(y)) => (x, y),
        (Some(x), None) | (None, Some(x)) => (x, x),
        (None, None) => (0.0, 0.0),
    };
    let mut d = hb - ha;
    if d > PI {
        d -= 2.0 * PI;
    } else if d < -PI {
        d += 2.0 * PI;
    }
    let (l, c, h) = (la + (lb - la) * t, ca + (cb - ca) * t, ha + d * t);
    [l, c * cos(h), c * sin(h)]
}

/// One point of the scene.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Point {
    /// Shaved ice, shown once the fill passed `order`; `rim` brightens the
    /// edge of the heap.
    Ice {
        at: [f64; 3],
        w: f64,
        order: f64,
        rim: f64,
    },
    /// The bowl: wall, lip and foot. `back`: on the far side, hidden once
    /// the ice rises past it.
    Bowl {
        at: [f64; 3],
        w: f64,
        rim: f64,
        lip: bool,
        back: bool,
    },
    /// Syrup, shown once the pour passed `order`; `g` along the run of
    /// colors.
    Syrup {
        at: [f64; 3],
        w: f64,
        order: f64,
        g: f64,
    },
    /// A topping's grain, around its center.
    Topping { j: usize, d: [f64; 3], w: f64 },
}

/// A snowflake falling during the build: across at `u`, falling at speed
/// `v` from phase `p`, swaying by `sw`.
#[derive(Clone, Copy, Debug, PartialEq)]
struct Flake {
    u: f64,
    v: f64,
    p: f64,
    sw: f64,
}

/// The seeded random numbers of the study (mulberry32): the same points
/// every time.
struct Seeded(u32);

impl Seeded {
    fn next(&mut self) -> f64 {
        self.0 = self.0.wrapping_add(0x6d2b_79f5);
        let s = self.0;
        let mut t = (s ^ (s >> 15)).wrapping_mul(1 | s);
        t = t.wrapping_add((t ^ (t >> 7)).wrapping_mul(61 | t)) ^ t;
        f64::from(t ^ (t >> 14)) / 4_294_967_296.0
    }
}

fn clamp01(v: f64) -> f64 {
    v.clamp(0.0, 1.0)
}

fn ease_out(t: f64) -> f64 {
    1.0 - pow(1.0 - t, 3.0)
}

/// The bowl's inside at radius `r` (negative: below the rim).
fn bowl_y(r: f64) -> f64 {
    -DEPTH * sqrt(f64::max(0.0, 1.0 - (r / R) * (r / R)))
}

/// The ice dome's top at radius `r`.
fn dome_y(r: f64) -> f64 {
    HMAX * pow(f64::max(0.0, 1.0 - (r / R) * (r / R)), DOME_K)
}

/// `x` rounded to the nearest whole number, halves up.
fn round(x: f64) -> f64 {
    floor(x + 0.5)
}

/// The scene's points, made once.
#[derive(Clone, Debug, PartialEq)]
pub struct Bowl {
    points: Vec<Point>,
    flakes: Vec<Flake>,
}

impl Default for Bowl {
    fn default() -> Self {
        Self::new()
    }
}

impl Bowl {
    pub fn new() -> Self {
        let mut rnd = Seeded(20_261_118);
        let mut points = Vec::with_capacity(
            ICE + WALL + LIP + FOOT + SYRUP_TOP + (DRIPS.len() + TOPPINGS.len()) * PER_DRIP,
        );
        // The random numbers are drawn in the study's order, so the points
        // are its points.
        for _ in 0..ICE {
            let r = R * 0.96 * sqrt(rnd.next());
            let th = rnd.next() * PI * 2.0;
            let (y0, y1) = (bowl_y(r), dome_y(r));
            let y = y0 + (y1 - y0) * rnd.next();
            let surface = y1 - y < 0.045;
            let order = clamp01((y + DEPTH) / (DEPTH + HMAX) * 0.9 + rnd.next() * 0.1);
            // The study drew a twinkle phase here.
            let _ = rnd.next();
            points.push(Point::Ice {
                at: [r * sin(th), y, r * cos(th)],
                w: if surface { 0.15 } else { 0.06 },
                order,
                rim: if surface {
                    pow(sin(th).abs(), 4.0)
                } else {
                    0.0
                },
            });
        }
        for _ in 0..WALL {
            let v = sqrt(rnd.next());
            let th = rnd.next() * PI * 2.0;
            let r = 1.04 * R * sin(v * PI / 2.0);
            let y = -DEPTH * 1.05 * cos(v * PI / 2.0) - 0.01;
            points.push(Point::Bowl {
                at: [r * sin(th), y, r * cos(th)],
                w: 0.06,
                rim: pow(sin(th).abs(), 4.0),
                lip: false,
                back: cos(th) < 0.0,
            });
        }
        for _ in 0..LIP {
            let th = rnd.next() * PI * 2.0;
            let r = R * (1.04 + rnd.next() * 0.04);
            let y = rnd.next() * 0.02;
            points.push(Point::Bowl {
                at: [r * sin(th), y, r * cos(th)],
                w: 0.22,
                rim: 1.0,
                lip: true,
                back: cos(th) < 0.0,
            });
        }
        for _ in 0..FOOT {
            let th = rnd.next() * PI * 2.0;
            let r = 0.3 + rnd.next() * 0.07;
            let y = FOOT_Y + rnd.next() * 0.1;
            points.push(Point::Bowl {
                at: [r * sin(th), y, r * cos(th)],
                w: 0.07,
                rim: pow(sin(th).abs(), 4.0),
                lip: false,
                back: false,
            });
        }
        for _ in 0..SYRUP_TOP {
            let r = 0.3 * R * sqrt(rnd.next());
            let th = rnd.next() * PI * 2.0;
            points.push(Point::Syrup {
                at: [r * sin(th), dome_y(r) + 0.02, r * cos(th)],
                w: 0.07,
                order: (r / 0.3) * 0.35,
                g: r / 0.3,
            });
        }
        for th0 in DRIPS {
            let len = 0.7 + 0.3 * rnd.next();
            for _ in 0..PER_DRIP {
                let s = rnd.next() * len;
                let th = th0 + (rnd.next() - 0.5) * 0.06;
                let (r, y) = if s < 0.75 {
                    let r = 0.28 * R + (R - 0.28 * R) * (s / 0.75);
                    (r, dome_y(r) + 0.02)
                } else {
                    (R * 1.07, -(s - 0.75) * 0.7)
                };
                points.push(Point::Syrup {
                    at: [r * sin(th), y, r * cos(th)],
                    w: 0.09,
                    order: 0.35 + 0.65 * s,
                    g: 0.5 + 0.5 * s,
                });
            }
        }
        for j in 0..TOPPINGS.len() {
            for _ in 0..PER_TOPPING {
                let u = rnd.next() * 2.0 - 1.0;
                let a = rnd.next() * PI * 2.0;
                let rr = 0.07 * cbrt(rnd.next());
                let ring = sqrt(1.0 - u * u);
                points.push(Point::Topping {
                    j,
                    d: [rr * ring * cos(a), rr * u * 0.8, rr * ring * sin(a)],
                    w: 0.2,
                });
            }
        }
        let mut rnd = Seeded(7);
        let flakes = (0..FLAKES)
            .map(|_| Flake {
                u: rnd.next(),
                v: 3.0 + rnd.next() * 4.0,
                p: rnd.next(),
                sw: rnd.next() * 6.0,
            })
            .collect();
        Self { points, flakes }
    }

    /// The band at `time` into the opening, `cols` wide (1 to `MAX_COLS`;
    /// outside that, the nearest), drawn with `inks`. The bowl is centered;
    /// at seven rows it is about 28 columns wide, and a narrower band shows
    /// its middle.
    pub fn draw(&self, time: Duration, cols: u16, inks: &Inks) -> Band {
        let cols = cols.clamp(1, MAX_COLS);
        let w = usize::from(cols);
        let h = usize::from(ROWS);
        let tb = time.as_secs_f64();
        let mut acc = Acc::new(w, h);
        let rows = f64::from(ROWS);
        let sy = (rows - 0.4) / 1.02;
        let sx = sy * 2.0;
        let cx = (f64::from(cols) - 1.0) / 2.0;
        let (ca, sa) = (cos(TILT), sin(TILT));
        let rim_row = 0.2 + (HMAX * ca + 0.06) * sy;
        let fill = ease_out(clamp01(tb / FILL));
        let pour = clamp01((tb - POUR_AT) / POUR);
        let proj = |p: [f64; 3]| [cx + p[0] * sx, rim_row - (p[1] * ca - p[2] * sa) * sy];
        let behind_wall =
            |x: f64, py: f64| x.abs() < R && py > rim_row + sqrt(1.0 - x * x) * sa * sy - 0.2;
        // The top of the ice in each column: snow does not fall through it.
        let mut top = vec![1e9_f32; w];
        for p in &self.points {
            match *p {
                Point::Ice {
                    at,
                    w: pw,
                    order,
                    rim,
                } => {
                    if order > fill {
                        continue;
                    }
                    let [px, py] = proj(at);
                    if at[1] < 0.0 && behind_wall(at[0], py) {
                        continue;
                    }
                    acc.splat(px, py, pw * WK * (1.0 + 1.6 * rim), inks.ice, 1.0);
                    let xi = round(px);
                    if xi >= 0.0 && xi < f64::from(cols) {
                        let t = &mut top[xi as usize];
                        if py < f64::from(*t) {
                            *t = py as f32;
                        }
                    }
                }
                Point::Bowl {
                    at,
                    w: pw,
                    rim,
                    lip,
                    back,
                } => {
                    if back && fill > (at[1] + DEPTH) / (DEPTH + HMAX) {
                        continue;
                    }
                    let [px, py] = proj(at);
                    if back && behind_wall(at[0], py) {
                        continue;
                    }
                    let ink = if lip { inks.lip } else { inks.bowl };
                    acc.splat(px, py, pw * WK * (1.0 + 2.0 * rim), ink, 1.2);
                }
                Point::Syrup {
                    at,
                    w: pw,
                    order,
                    g,
                } => {
                    if order > pour {
                        continue;
                    }
                    let step = round(g * SYRUP_STEPS as f64).clamp(0.0, SYRUP_STEPS as f64);
                    let [px, py] = proj(at);
                    acc.splat(px, py, pw * WK, inks.syrup[step as usize], 2.5);
                }
                Point::Topping { j, d, w: pw } => {
                    // Falling from high above: out of the band until shortly
                    // before it lands.
                    let land = LAND + LAND_STEP * j as f64;
                    let th = j as f64 * (PI * 2.0 / 5.0) + 0.5;
                    let rr = 0.32;
                    let mut by = dome_y(rr) + 0.06;
                    if tb < land {
                        by += (land - tb) * DROP;
                    } else if tb < land + BOUNCE {
                        by += 0.05 * sin((tb - land) / BOUNCE * PI);
                    }
                    let at = [rr * sin(th) + d[0], by + d[1], rr * cos(th) + d[2]];
                    let [px, py] = proj(at);
                    let ink = inks.toppings.get(j).copied().unwrap_or(inks.ice);
                    acc.splat(px, py, pw * WK, ink, 6.0);
                }
            }
        }
        let mut band = Band {
            cols,
            cells: vec![Cell::EMPTY; w * h],
        };
        for (i, cell) in band.cells.iter_mut().enumerate() {
            let b = f64::from(acc.b[i]);
            if b <= 0.0 {
                continue;
            }
            let density = 1.0 - exp(-b * 0.75);
            if density < 0.05 {
                continue;
            }
            let ww = f64::from(acc.ww[i]);
            let ink = [
                f64::from(acc.wl[i]) / ww,
                f64::from(acc.wa[i]) / ww,
                f64::from(acc.wb[i]) / ww,
            ];
            let level = floor(density * 10.0).clamp(1.0, 9.0) as usize;
            *cell = Cell {
                ch: RAMP[level],
                ink: Some(fade(inks.base, ink, 0.3 + 0.7 * density)),
            };
        }
        if tb < SNOW_END {
            for f in &self.flakes {
                let x = round(f.u * (f64::from(cols) - 1.0) + 0.8 * sin(tb * 1.3 + f.sw));
                let y = fmod(tb * f.v * 0.6 + f.p * rows * 3.0, rows + 2.0) - 1.0;
                if x < 0.0 || x >= f64::from(cols) || y < 0.0 || y >= rows {
                    continue;
                }
                let x = x as usize;
                if y >= f64::from(top[x]) - 0.5 {
                    continue;
                }
                let i = (y as usize) * w + x;
                if acc.b[i] > 0.02 {
                    continue;
                }
                let ch = if f.v > 5.5 {
                    b'*'
                } else if f.v > 4.2 {
                    b':'
                } else {
                    b'.'
                };
                band.cells[i] = Cell {
                    ch,
                    ink: Some(fade(inks.base, inks.ice, 0.3 + 0.25 * (f.v - 3.0) / 4.0)),
                };
            }
        }
        band
    }
}

/// `ink` faded towards `base`: `m` 1 is the ink, 0 the background.
fn fade(base: [f64; 3], ink: [f64; 3], m: f64) -> Srgb8 {
    let mix = |i: usize| base[i] + (ink[i] - base[i]) * m;
    to_srgb8(lab_to_linear(mix(0), mix(1), mix(2)))
}

/// What the points left in each cell: their weight and their inks times
/// weight and material. `f32` as the study kept them.
struct Acc {
    cols: usize,
    rows: usize,
    b: Vec<f32>,
    wl: Vec<f32>,
    wa: Vec<f32>,
    wb: Vec<f32>,
    ww: Vec<f32>,
}

impl Acc {
    fn new(cols: usize, rows: usize) -> Self {
        let n = cols * rows;
        Self {
            cols,
            rows,
            b: vec![0.0; n],
            wl: vec![0.0; n],
            wa: vec![0.0; n],
            wb: vec![0.0; n],
            ww: vec![0.0; n],
        }
    }

    /// A point at `(px, py)` spread over the four cells around it.
    fn splat(&mut self, px: f64, py: f64, w: f64, ink: [f64; 3], mat: f64) {
        let (fx, fy) = (px - 0.5, py - 0.5);
        let (x, y) = (floor(fx), floor(fy));
        let (ax, ay) = (fx - x, fy - y);
        self.add(x, y, w * (1.0 - ax) * (1.0 - ay), ink, mat);
        self.add(x + 1.0, y, w * ax * (1.0 - ay), ink, mat);
        self.add(x, y + 1.0, w * (1.0 - ax) * ay, ink, mat);
        self.add(x + 1.0, y + 1.0, w * ax * ay, ink, mat);
    }

    fn add(&mut self, x: f64, y: f64, w: f64, ink: [f64; 3], mat: f64) {
        if x < 0.0 || y < 0.0 || x >= self.cols as f64 || y >= self.rows as f64 || w <= 0.0 {
            return;
        }
        let i = y as usize * self.cols + x as usize;
        let put = |v: &mut f32, d: f64| *v = (f64::from(*v) + d) as f32;
        put(&mut self.b[i], w);
        put(&mut self.wl[i], w * mat * ink[0]);
        put(&mut self.wa[i], w * mat * ink[1]);
        put(&mut self.wb[i], w * mat * ink[2]);
        put(&mut self.ww[i], w * mat);
    }
}

/// One cell of the band: an ASCII glyph and its color, or nothing (`ch`
/// is a space and `ink` is `None`: the screen shows through).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cell {
    pub ch: u8,
    pub ink: Option<Srgb8>,
}

impl Cell {
    pub const EMPTY: Self = Self {
        ch: b' ',
        ink: None,
    };
}

/// `ROWS` rows of cells, `cols` each. The editor copies it into its grid
/// at rows 1-7: a cell with `ink` as one ASCII character drawn in that
/// color (`Ink::Rgb` in true color, `Ink::Indexed(nearest_256(..))` in 256
/// colors, the default color without `NO_COLOR` colors), an empty cell
/// left as the screen has it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Band {
    cols: u16,
    cells: Vec<Cell>,
}

impl Band {
    pub fn cols(&self) -> u16 {
        self.cols
    }

    /// Row `y` (0 to `ROWS` - 1); empty past the last row.
    pub fn row(&self, y: u16) -> &[Cell] {
        let w = usize::from(self.cols);
        let at = usize::from(y) * w;
        self.cells.get(at..at + w).unwrap_or(&[])
    }

    /// Row `y`'s glyphs.
    pub fn text(&self, y: u16) -> String {
        self.row(y).iter().map(|c| char::from(c.ch)).collect()
    }
}

/// When the opening began and whether it is over: which time to draw, and
/// when the next frame is due.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Opening {
    start: Duration,
    /// Skipped by a key, ended by a slow terminal, or still from the start.
    over: bool,
    /// The end frame was drawn: no frame is due any more.
    ended: bool,
    /// Frames in a row that the writer could not take.
    missed: u8,
}

impl Opening {
    /// An opening that began at `start` (the caller's clock).
    pub const fn new(start: Duration) -> Self {
        Self {
            start,
            over: false,
            ended: false,
            missed: 0,
        }
    }

    /// No motion (`--no-motion`, a set `NO_COLOR`): the end frame at once.
    pub const fn still() -> Self {
        Self {
            start: Duration::ZERO,
            over: true,
            ended: false,
            missed: 0,
        }
    }

    /// A key: jump to the end frame.
    pub fn skip(&mut self) {
        self.over = true;
    }

    /// The time into the opening to draw at `now`: `LENGTH` once it is
    /// over or its time ran out, and at a clock so near its end that no
    /// later frame could be timed (see `next`).
    pub fn at(&self, now: Duration) -> Duration {
        // 이것을 실패시키는 것: 다음 프레임을 잡을 수 없는 시각에 끝 프레임이 아닌 것(타이머가 끝난 뒤 중간 프레임이 남음).
        if self.over || now.checked_add(FRAME).is_none() {
            return LENGTH;
        }
        now.saturating_sub(self.start).min(LENGTH)
    }

    /// When the next frame is due after one drawn or missed at `now`: one
    /// `FRAME` later (at most 30 a second, also for the end frame after a
    /// skip, so a busy writer is not asked in a loop). `None` once the end
    /// frame was drawn, and when one `FRAME` past `now` is past the clock's
    /// end: a deadline that is not ahead of `now` would make the caller's
    /// wait return at once, again and again. The frame drawn there is the
    /// end frame (`at`); one that could not be drawn comes with the next
    /// redraw, which draws the end frame too.
    pub fn next(&self, now: Duration) -> Option<Duration> {
        // 이것을 실패시키는 것: 포화 덧셈으로 지금보다 늦지 않은 기한을 내는 것(호출자가 쉬지 않고 깨어남).
        if self.ended {
            return None;
        }
        now.checked_add(FRAME)
    }

    /// The frame of `now` was drawn.
    pub fn drawn(&mut self, now: Duration) {
        self.missed = 0;
        if self.at(now) >= LENGTH {
            self.ended = true;
        }
    }

    /// A frame came due while the terminal still held the last one: it is
    /// not drawn. `MISSED_MAX` in a row end the opening.
    pub fn missed(&mut self) {
        self.missed = self.missed.saturating_add(1);
        if self.missed >= MISSED_MAX {
            self.over = true;
        }
    }

    /// The end frame was drawn: nothing moves any more.
    pub fn ended(&self) -> bool {
        self.ended
    }
}

#[cfg(test)]
mod tests;
