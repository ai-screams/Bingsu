//! The front end's decisions as pure functions (sans-IO): argv bytes in,
//! record bytes out. The `bingsu prompt` adapter in crates/bingsu
//! (src/prompt.rs) only turns the process arguments into bytes, calls
//! `staged::prepare`, carries out the reads the plan names, calls
//! `finish`, writes the record and exits; it decides nothing.
//!
//! The N4 snapshot consumer is in `staged` (pre-filter held-fd preparation,
//! followed by bounded reads under the option-3 syscall budget). An envelope without `--shell` (a hook older than the renderer)
//! gets the shell-neutral minimal record.
use crate::color::palette::Mode;
use crate::color::sgr::ColorDepth;
use crate::config::compile::CompiledConfig;
use crate::default_theme::DefaultTheme;
use crate::envelope::{self, Envelope, EnvelopeError};
use crate::field::BUILTIN;
use crate::layout::{Inputs, Options};
use crate::record::{Fields, encode_b1, write_minimal_b1};
use crate::recorder::NoopRecorder;
use crate::render::{Target, render_prompt, to_b1_fields};
use crate::shell_values;
use crate::shell_word::Shell;
use crate::status::Status;
use crate::width::WidthProfile;
use alloc::vec::Vec;

/// Snapshot continuation and selection; the CLI retains descriptors before confinement.
pub mod staged;

/// Absolute prompt deadlines and write progress, without OS observations.
pub mod output;

/// Appends the record of `fields`; a field the encoder refuses (a renderer
/// defect: the B1 grammar is the producer's promise) gives the minimal
/// record with `error:internal` instead. `encode_b1` checks every field
/// before it writes, so a refusal leaves `out` as it was.
fn encode_or_internal(fields: &Fields<'_>, status: Status, out: &mut Vec<u8>) {
    if encode_b1(fields, status, out).is_err() {
        write_minimal_b1(Status::ERROR_INTERNAL, out);
    }
}

fn render(parsed: &Envelope, shell: Shell, status: Status, out: &mut Vec<u8>) {
    // Display-only envelope observation; absent/garbled falls back to dark.
    // Built-in constants (test default_theme_builds); were it ever to fail,
    // the adapter's panic fallback gives the same `error:internal` record.
    let theme =
        DefaultTheme::new(parsed.colorfgbg.unwrap_or(Mode::Dark)).expect("built-in default theme");
    let c = shell_values::collect(parsed);
    let inputs = Inputs {
        catalog: BUILTIN,
        values: &c.values,
        facts: &c.facts,
        setup: theme.setup(),
    };
    let t = Target {
        shell,
        depth: if parsed.truecolor {
            ColorDepth::TrueColor
        } else {
            ColorDepth::Ansi256
        },
        options: Options {
            width: parsed.width,
            profile: WidthProfile::DEFAULT,
            icons: crate::default_theme::ICONS,
            use_last_column: false,
        },
    };
    let r = render_prompt(&theme.theme(), &inputs, &t, &mut NoopRecorder);
    encode_or_internal(&to_b1_fields(&r), status, out);
}

/// Shared snapshot/default rendering. Only the staged consumer enables P10;
/// the legacy adapter remains disconnected pending its syscall-budget ruling.
pub fn render_selected(
    parsed: &Envelope,
    shell: Shell,
    status: Status,
    compiled: Option<&CompiledConfig>,
    mode: Mode,
    collection: Option<&crate::collection::response::Completed>,
    out: &mut Vec<u8>,
) {
    render_selected_with_catalog(
        parsed,
        shell,
        status,
        compiled,
        mode,
        collection,
        &crate::collection::selection::PRODUCT,
        out,
    );
}

#[allow(
    clippy::too_many_arguments,
    reason = "fixed pure renderer inputs and adapter catalog"
)]
fn render_selected_with_catalog(
    parsed: &Envelope,
    shell: Shell,
    status: Status,
    compiled: Option<&CompiledConfig>,
    mode: Mode,
    collection: Option<&crate::collection::response::Completed>,
    catalog: &crate::collection::selection::Catalog<'_>,
    out: &mut Vec<u8>,
) {
    let default;
    let setup;
    let (theme, setup, options, duration_min) = if let Some(c) = compiled {
        setup = c.setup();
        (
            c.theme_for(mode),
            setup.as_slice(),
            Options {
                width: parsed.width,
                profile: c.profile,
                icons: c.icons,
                use_last_column: c.use_last_column,
            },
            c.duration_min_ms,
        )
    } else {
        let Ok(d) = DefaultTheme::new(mode) else {
            write_minimal_b1(Status::ERROR_INTERNAL, out);
            return;
        };
        default = d;
        (
            default.theme(),
            default.setup(),
            Options {
                width: parsed.width,
                profile: WidthProfile::DEFAULT,
                icons: crate::default_theme::ICONS,
                use_last_column: false,
            },
            shell_values::DURATION_MIN_MS,
        )
    };
    let mut collected = shell_values::collect_with_duration_min(parsed, duration_min);
    let mask = compiled.map_or(0, |c| catalog.worker_mask(c, parsed.width, false));
    crate::collection::merge(&mut collected, collection, mask);
    let inputs = Inputs {
        catalog: catalog.segments,
        values: &collected.values,
        facts: &collected.facts,
        setup,
    };
    let target = Target {
        shell,
        depth: if parsed.truecolor {
            ColorDepth::TrueColor
        } else {
            ColorDepth::Ansi256
        },
        options,
    };
    let notice = (status != Status::OK_NONE).then_some(crate::render::Notice::Warning);
    let rendered = crate::render::render_prompt_with_notice(
        &theme,
        &inputs,
        &target,
        notice,
        &mut NoopRecorder,
    );
    encode_or_internal(&to_b1_fields(&rendered), status, out);
}

/// The legacy adapter plan, which carries only a parsed envelope. The snapshot
/// continuation uses `staged::ReadPlan`, whose read and ownership state is private.
pub struct ReadPlan {
    parsed: Result<Envelope, EnvelopeError>,
}

/// What the adapter observed while carrying out a `ReadPlan`, one field per
/// planned read (none in Part V). The adapter fills it mechanically.
#[derive(Default)]
pub struct Observed {}

/// What the connected adapter does next: write `record` and exit. The helper
/// already starts before the filter; no response grants process creation.
/// `staged::Response` additionally carries the snapshot's execution eligibility.
pub struct Response {
    pub record: Vec<u8>,
}

/// Step one of the front end: parse the `bingsu prompt` arguments (after the
/// word `prompt`) and say what to read.
pub fn prepare(argv: &[&[u8]]) -> ReadPlan {
    ReadPlan {
        parsed: envelope::parse(argv),
    }
}

/// Step two: the record is empty when no supported record version was
/// negotiated, the minimal record with `error:bad-args` for a malformed
/// envelope, else the rendered prompt (or the shell-neutral minimal record
/// without `--shell`).
pub fn finish(plan: ReadPlan, _observed: Observed) -> Response {
    let mut out = Vec::with_capacity(4096);
    match plan.parsed {
        Err(EnvelopeError::NoSupportedRecordVersion) => {}
        Err(EnvelopeError::BadArgs(_)) => write_minimal_b1(Status::ERROR_BAD_ARGS, &mut out),
        Ok(parsed) => {
            let status = if parsed.runtime_root.is_none() {
                Status::DEGRADED_RUNTIME_ROOT
            } else {
                Status::OK_NONE
            };
            match parsed.shell {
                Some(shell) => render(&parsed, shell, status, &mut out),
                None => write_minimal_b1(status, &mut out),
            }
        }
    }
    Response { record: out }
}

/// `prepare` then `finish` with nothing observed: the whole front end while
/// nothing needs reading (Part V), and the shape tests and benches call.
pub fn respond(argv: &[&[u8]]) -> Vec<u8> {
    finish(prepare(argv), Observed::default()).record
}

/// What the adapter writes after `respond` panicked (unwind): the minimal
/// record with `error:internal` when the envelope negotiated B1 by the
/// parser's own pair rule (a `--record` in value position negotiates
/// nothing), else nothing (spec section 6 rule 2).
pub fn after_panic(argv: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    if envelope::record_version(argv).is_ok() {
        write_minimal_b1(Status::ERROR_INTERNAL, &mut out);
    }
    out
}

/// What became of the Linux seccomp filter before the core runs (decision
/// P18 as revised 2026-10-15).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sandbox {
    /// The filter is on.
    Installed,
    /// The kernel was built without seccomp (`PR_GET_SECCOMP` answers
    /// EINVAL), or the platform has none (macOS): the prompt renders.
    Absent,
    /// The question failed otherwise, or installing failed with any errno
    /// (EINVAL included: a defect in our filter): the core does not run.
    Blocked,
}

/// Whether the core may run after `enter_sandbox` reported `s`.
pub fn runs_core(s: Sandbox) -> bool {
    !matches!(s, Sandbox::Blocked)
}

/// What the adapter writes when the filter was refused (`Sandbox::Blocked`,
/// decision P18): the core does not run, so the record is the minimal one
/// with `degraded:sandbox` when the envelope negotiated B1 by the parser's
/// own pair rule, else nothing.
pub fn without_sandbox(argv: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    if envelope::record_version(argv).is_ok() {
        write_minimal_b1(Status::DEGRADED_SANDBOX, &mut out);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b(a: &[&'static str]) -> Vec<&'static [u8]> {
        a.iter().map(|s| s.as_bytes()).collect()
    }

    const B1_INTERNAL: &[u8] = b"B1\x1f8\x1f> \x1f\x1f\x1f\x1f\x1f\x1f\x1ferror:internal\x1e";

    // 이것을 실패시키는 것: 패닉 뒤 협상을 쌍 규칙 없이 하는 것(raw.windows(2)), 협상이 없는데 레코드를 내는 것.
    #[test]
    fn after_panic_follows_the_pair_rule() {
        let ok = b(&["--ctx", "1", "--record", "B1", "--width", "80"]);
        assert_eq!(after_panic(&ok), B1_INTERNAL);
        // `--record B1` here is the value of --keymap and then a stray word.
        let hidden = b(&["--ctx", "1", "--width", "80", "--keymap", "--record", "B1"]);
        assert_eq!(after_panic(&hidden), b"");
    }

    // 이것을 실패시키는 것: 막힌 필터에서 core를 돌리는 것, 커널에 seccomp가 없을 때(또는 macOS) 렌더하지 않는 것.
    #[test]
    fn only_a_refused_filter_stops_the_core() {
        assert!(runs_core(Sandbox::Installed));
        assert!(runs_core(Sandbox::Absent));
        assert!(!runs_core(Sandbox::Blocked));
    }

    // 이것을 실패시키는 것: 기본 아이콘 집합을 nerd로 되돌리는 것(글꼴이 없으면 네모, 판정 P20), 기본 테마가 East Asian
    // Ambiguous 글자(예: U+25B6)를 쓰는 것(CJK 터미널이 두 칸으로 그려 정렬이 어긋남).
    #[test]
    fn default_prompt_glyphs_are_one_cell_under_both_profiles() {
        use crate::width::{WidthProfile, str_width};
        let a2 = WidthProfile::new(2, 2).unwrap();
        let long =
            "/home/u/a-very-long-folder-name-that-goes-on/and-another-deep-level/x/y/z/w/v/u/t";
        let mut seen = alloc::collections::BTreeSet::new();
        for shell in ["zsh", "bash", "fish"] {
            for width in ["120", "50"] {
                for status in ["0", "1"] {
                    for keymap in ["main", "vicmd"] {
                        for pwd in ["/srv/p", "/home/u/proj/src", long] {
                            let rec = respond(&b(&[
                                "--ctx",
                                "1",
                                "--record",
                                "B1",
                                "--width",
                                width,
                                "--runtime-root=1:2:/r",
                                "--home=/home/u",
                                "--shell",
                                shell,
                                "--pwd",
                                pwd,
                                "--status",
                                status,
                                "--jobs",
                                "2",
                                "--duration-ms",
                                "65000",
                                "--keymap",
                                keymap,
                            ]));
                            let s = alloc::string::String::from_utf8_lossy(&rec).into_owned();
                            seen.extend(s.chars().filter(|c| !c.is_ascii()));
                        }
                    }
                }
            }
        }
        assert!(
            seen.contains(&'\u{2717}') && seen.contains(&'\u{276E}'),
            "{seen:?}"
        );
        for c in seen {
            assert!(
                !('\u{E000}'..='\u{F8FF}').contains(&c),
                "{c:?} is private use"
            );
            // U+2026: the spec's truncation ellipsis, chosen by the width
            // profile itself (width::ellipsis); decision P21.
            if c == '\u{2026}' {
                continue;
            }
            let mut buf = [0u8; 4];
            let t = c.encode_utf8(&mut buf);
            assert_eq!(str_width(t, WidthProfile::DEFAULT), 1, "{c:?}");
            assert_eq!(str_width(t, a2), 1, "{c:?} is East Asian Ambiguous");
        }
    }

    // 이것을 실패시키는 것: 필터 없이 최소 레코드가 아닌 것을 내는 것, 다른 상태를 쓰는 것, 협상이 없는데 레코드를 내는 것.
    #[test]
    fn without_sandbox_is_the_degraded_minimal_record() {
        let ok = b(&[
            "--ctx", "1", "--record", "B1", "--width", "80", "--shell", "zsh",
        ]);
        assert_eq!(
            without_sandbox(&ok),
            b"B1\x1f8\x1f> \x1f\x1f\x1f\x1f\x1f\x1f\x1fdegraded:sandbox\x1e"
        );
        let hidden = b(&["--ctx", "1", "--width", "80", "--keymap", "--record", "B1"]);
        assert_eq!(without_sandbox(&hidden), b"");
    }

    // 이것을 실패시키는 것: 거부된 필드 뒤 최소 레코드를 쓰지 않는 것, 다른 상태로 쓰는 것, 앞의 바이트를 지우는 것.
    #[test]
    fn refused_field_gives_internal_minimal_record() {
        let mut out = b"pre".to_vec();
        let f = Fields {
            left: b"a\nb",
            ..Fields::default()
        };
        encode_or_internal(&f, Status::OK_NONE, &mut out);
        assert_eq!(&out[..3], b"pre");
        assert_eq!(&out[3..], B1_INTERNAL);
    }

    // 이것을 실패시키는 것: `--shell` 없는 봉투에 셸별 바이트를 내는 것, 있는 봉투에 최소 레코드를 내는 것.
    #[test]
    fn renders_only_when_the_shell_is_known() {
        let old = respond(&b(&[
            "--ctx",
            "1",
            "--record",
            "B1",
            "--width",
            "80",
            "--runtime-root=1:2:/r",
        ]));
        assert_eq!(old, b"B1\x1f8\x1f> \x1f\x1f\x1f\x1f\x1f\x1f\x1fok:none\x1e");
        let new = respond(&b(&[
            "--ctx",
            "1",
            "--record",
            "B1",
            "--width",
            "80",
            "--runtime-root=1:2:/r",
            "--shell",
            "zsh",
            "--pwd",
            "/x/proj",
        ]));
        let s = alloc::string::String::from_utf8_lossy(&new);
        assert!(
            s.starts_with("B1\x1f8\x1f") && s.ends_with("ok:none\x1e"),
            "{s:?}"
        );
        assert!(s.contains("proj") && s.contains('\u{276F}'), "{s:?}");
    }

    // 이것을 실패시키는 것: core에 호출 사이 상태(전역 카운터 등)가 생겨 같은 입력이 다른 바이트를 내는 것.
    #[test]
    fn repeated_calls_give_the_same_bytes() {
        let cases = [
            b(&[
                "--ctx", "1", "--record", "B1", "--width", "80", "--shell", "zsh", "--pwd", "/x/p",
            ]),
            b(&["--ctx", "1", "--record", "B1", "--width", "80"]),
            b(&["--ctx", "1", "--record", "B1", "--width", "x"]),
        ];
        for argv in &cases {
            let first = respond(argv);
            for _ in 0..300 {
                assert_eq!(respond(argv), first);
            }
        }
    }
}
