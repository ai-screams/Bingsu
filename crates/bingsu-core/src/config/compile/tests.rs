#![cfg(test)]
use super::*;
use crate::color::sgr::ColorDepth;
use crate::config::exec_units::layout_verdict;
use crate::config::keys;
use crate::config::merge::KeyClass;
use crate::config::report::tests::{codes_of, read};
use crate::default_theme::DefaultTheme;
use crate::diag::{Place, SourceId};
use crate::field::{Field, FieldValue, Value as FValue, segment};
use crate::layout::{Inputs, Options};
use crate::recorder::NoopRecorder;
use crate::render::{RenderedPrompt, Target, render_prompt};
use crate::shell_word::Shell;
use crate::shorten::{Anchor, PathFacts};

fn compiled(user: &str) -> CompiledConfig {
    let r = read(user, &[]);
    let codes = codes_of(&r);
    r.snapshot.unwrap_or_else(|| panic!("{codes:?}"))
}

fn draw(
    theme: Theme<'_>,
    setup: &[SegmentSetup<'_>],
    icons: IconSet,
    width: u16,
) -> RenderedPrompt {
    let i = |id| BUILTIN.iter().position(|s| s.id == id).unwrap();
    let mut values = vec![None; BUILTIN.len()];
    let mut facts = vec![None; BUILTIN.len()];
    let ch = segment("char").unwrap();
    values[i("char")] = Some(FValue::new(b"", vec![Field::ABSENT; ch.fields.len()]));
    let dir = segment("dir").unwrap();
    values[i("dir")] = Some(FValue::new(b"", vec![Field::ABSENT; dir.fields.len()]));
    let steps: [&[u8]; 2] = [b"Works", b"bingsu"];
    facts[i("dir")] = Some(PathFacts::new(Anchor::Home, &steps, None, &[]));
    let du = segment("duration").unwrap();
    values[i("duration")] = Some(FValue::new(
        b"3.0s",
        vec![Field::known(FieldValue::Duration { ms: 3000 }); du.fields.len()],
    ));
    let inputs = Inputs {
        catalog: BUILTIN,
        values: &values,
        facts: &facts,
        setup,
    };
    let t = Target {
        shell: Shell::Zsh,
        depth: ColorDepth::Ansi256,
        options: Options {
            width,
            profile: WidthProfile::DEFAULT,
            icons,
            use_last_column: false,
        },
    };
    render_prompt(&theme, &inputs, &t, &mut NoopRecorder)
}

// 이것을 실패시키는 것: 내장 원본(BUILTIN_TOML)과 Part V의 default_theme이 다른 프롬프트를 그리는 것
// (설정이 없는 사용자의 프롬프트가 바뀜).
#[test]
fn builtin_source_draws_the_default_theme() {
    let r = read("", &[]);
    assert!(r.diagnostics.is_empty(), "{:?}", codes_of(&r));
    let c = r.snapshot.unwrap();
    let d = DefaultTheme::new(Mode::Dark).unwrap();
    for w in [120, 59, 40] {
        assert_eq!(
            draw(c.theme(), &c.setup(), c.icons, w),
            draw(d.theme(), d.setup(), crate::default_theme::ICONS, w),
            "width {w}"
        );
    }
    assert_eq!(
        (c.icons, c.profile, c.duration_min_ms),
        (IconSet::Unicode, WidthProfile::DEFAULT, 2000)
    );
    for variant in &c.variants {
        let segments: Vec<_> = variant
            .iter()
            .flat_map(|line| line.nodes())
            .filter_map(|node| {
                if let crate::template::compile::Node::Segment { seg, .. } = node {
                    Some(*seg)
                } else {
                    None
                }
            })
            .collect();
        assert_eq!(segments.iter().filter(|seg| **seg == 3).count(), 1);
        let git = segments.iter().position(|seg| *seg == 3).unwrap();
        assert_eq!(segments[git - 1], 1);
    }
}

// 이것을 실패시키는 것: 사용자 파일의 값(아이콘·폭·한쪽 배열)을 쓰지 않거나, 쓰지 않은 부분까지 내장 값을 버리는 것.
#[test]
fn user_keys_change_only_what_they_write() {
    let c = compiled(
        "icons = \"nerd\"\n[width]\nambiguous = 2\n[layout.line1]\nright = []\n[segment.duration]\nmin = \"500ms\"\n",
    );
    assert_eq!(
        (c.icons, c.profile.ambiguous(), c.duration_min_ms),
        (IconSet::Nerd, 2, 500)
    );
    let d = compiled("");
    let a = draw(c.theme(), &c.setup(), IconSet::Unicode, 120);
    let b = draw(d.theme(), &d.setup(), IconSet::Unicode, 120);
    assert_ne!(a.upper, b.upper);
    assert_eq!(a.left, b.left);
    assert!(String::from_utf8_lossy(&a.upper).contains("bingsu"));
}

// 이것을 실패시키는 것: auto 팔레트를 도우미의 화면 모드 하나로 고정하거나 명시 모드를 무시하는 것.
#[test]
fn both_display_palettes_survive_compilation() {
    let c = compiled("");
    assert_ne!(c.palette, c.light_palette);
    for mode in [Mode::Dark, Mode::Light] {
        let d = DefaultTheme::new(mode).unwrap();
        assert_eq!(c.theme_for(mode).palette, d.theme().palette);
    }
    let m = crate::config::check::tests::merged_with("", &[]);
    assert_eq!(compile(&m, &m, Mode::Dark), compile(&m, &m, Mode::Light));
    for (text, palette) in [("dark", &c.palette), ("light", &c.light_palette)] {
        let fixed = compiled(&alloc::format!("[colors]\nmode = '{text}'\n"));
        assert_eq!(&fixed.palette, palette);
        assert_eq!(&fixed.light_palette, palette);
    }
}

// 이것을 실패시키는 것: 템플릿에서 꺼진 내장 참조·빈 그룹을 남기거나 플러그인 참조까지 조용히 버리는 것.
#[test]
fn templates_omit_disabled_builtins_and_reject_unknown_plugins() {
    let c = compiled(
        "[segment.git]\nenabled = false\n[style]\ntemplate = '{dir}{@group}<{git}>{@end}{@nl}{char}'\n",
    );
    let git = BUILTIN.iter().position(|d| d.id == "git").unwrap();
    for lines in &c.variants {
        assert!(lines.iter().flat_map(|l| l.nodes()).all(|n| !matches!(n,
            Node::Segment { seg, .. } | Node::Field { seg, .. } if usize::from(*seg) == git)));
    }
    assert_eq!(
        c.variants[0],
        compiled("[style]\ntemplate = '{dir}{@nl}{char}'\n").variants[0]
    );
    assert!(
        read("[style]\ntemplate = '{dir}{acme/unknown}'\n", &[])
            .snapshot
            .is_none()
    );
}

/// Every shape key, a file that sets it away from the built-in value.
const EFFECTS: &[(&str, &str)] = &[
    ("colors.knobs.accent_c", "[colors.knobs]\naccent_c = 0.2\n"),
    ("colors.knobs.accent_l", "[colors.knobs]\naccent_l = 0.5\n"),
    ("colors.knobs.hue", "[colors.knobs]\nhue = 100\n"),
    ("colors.mode", "[colors]\nmode = \"light\"\n"),
    (
        "colors.override.*",
        "[colors.override]\n\"git.dirty\" = \"#ff0000\"\n",
    ),
    ("colors.roles.*", "[colors.roles]\npath = \"accent.red\"\n"),
    ("icons", "icons = \"nerd\"\n"),
    ("layout.fill", "[layout]\nfill = \"dot\"\n"),
    ("layout.frame", "[layout]\nframe = \"line\"\n"),
    ("layout.line1.enabled", "[layout.line1]\nenabled = false\n"),
    ("layout.line1.left", "[layout.line1]\nleft = [\"dir\"]\n"),
    ("layout.line1.right", "[layout.line1]\nright = []\n"),
    ("layout.line2.enabled", "[layout.line2]\nenabled = false\n"),
    (
        "layout.line2.left",
        "[layout.line2]\nleft = [\"dir\", \"char\"]\n",
    ),
    ("layout.line2.right", "[layout.line2]\nright = [\"time\"]\n"),
    (
        "layout.use_last_column",
        "[layout]\nuse_last_column = true\n",
    ),
    (
        "layout.when.*.line1.enabled",
        "[layout.when.wide.line1]\nenabled = false\n",
    ),
    (
        "layout.when.*.line1.left",
        "[layout.when.wide.line1]\nleft = [\"dir\"]\n",
    ),
    (
        "layout.when.*.line1.right",
        "[layout.when.wide.line1]\nright = [\"time\"]\n",
    ),
    (
        "layout.when.*.line2.enabled",
        "[layout.when.wide.line2]\nenabled = false\n",
    ),
    (
        "layout.when.*.line2.left",
        "[layout.when.wide.line2]\nleft = [\"duration\", \"char\"]\n",
    ),
    (
        "layout.when.*.line2.right",
        "[layout.when.wide.line2]\nright = [\"time\"]\n",
    ),
    (
        "layout.when.*.max_cols",
        "[layout.when.narrow]\nmax_cols = 40\n",
    ),
    (
        "layout.when.*.min_cols",
        "[layout.when.narrow]\nmin_cols = 10\n",
    ),
    ("layout.when.*.order", "[layout.when.narrow]\norder = 1\n"),
    (
        "layout.when.*.style.preset",
        "[layout.when.wide.style]\npreset = \"lean\"\n",
    ),
    (
        "segment.dir.shorten",
        "[segment.dir]\nshorten = [\"depth\"]\n",
    ),
    ("segment.dir.when", "[segment.dir]\nwhen = \"always\"\n"),
    ("segment.duration.min", "[segment.duration]\nmin = \"5s\"\n"),
    ("style.preset", "[style]\npreset = \"lean\"\n"),
    ("style.separator", "[style]\nseparator = \"round\"\n"),
    ("width.ambiguous", "[width]\nambiguous = 2\n"),
    ("width.emoji", "[width]\nemoji = 1\n"),
    (
        "style.template",
        "[style]\ntemplate = \"{dir}{@nl}{char}\"\n",
    ),
    (
        "layout.when.*.style.template",
        "[layout.when.wide.style]\ntemplate = \"{dir}{@nl}{char}\"\n",
    ),
];
/// Shape keys that cannot change the output yet, and why.
const NO_EFFECT: [(&str, &str); 4] = [
    (
        "theme",
        "one built-in theme: the only accepted value is the default",
    ),
    (
        "colors.flavor",
        "one flavor: the only accepted value is the default",
    ),
    (
        "segment.*.text",
        "a text segment shows only where a layout draws it",
    ),
    ("layout.transient", "planned for M4 and M5; N503 says so"),
];

// 받아 놓고 쓰지 않는 키는 조용한 무시다(스펙 6절 규칙 5가 가장 나쁘다고 한 실패).
// 이것을 실패시키는 것: 모양 키를 검사만 하고 컴파일에 잇지 않는 것, 새 모양 키를 이 표에 더하지 않는 것.
#[test]
fn every_shape_key_changes_the_compiled_config() {
    use crate::config::keys::{KEYS, Ty};
    let base = compiled("");
    for k in KEYS
        .iter()
        .filter(|k| k.class == KeyClass::Shape && k.ty != Ty::Table)
    {
        let effect = EFFECTS.iter().find(|(p, _)| *p == k.path);
        let none = NO_EFFECT.iter().find(|(p, _)| *p == k.path);
        match (effect, none) {
            (Some((_, src)), None) => {
                // Band keys are tried on a band of their own, against the
                // same band without the key.
                let wide = "[layout.when.wide]\nmin_cols = 100\n";
                let (with, without) = if src.contains("layout.when.wide") {
                    (alloc::format!("{wide}{src}"), compiled(wide))
                } else {
                    (String::from(*src), base.clone())
                };
                assert!(compiled(&with) != without, "{} has no effect", k.path);
            }
            (None, Some(_)) => {}
            _ => panic!("{} must be in exactly one of EFFECTS and NO_EFFECT", k.path),
        }
    }
    // A planned key is accepted with a notice, not an error.
    let r = read("[layout]\ntransient = \"char\"\n", &[]);
    assert!(r.snapshot.is_some());
    assert_eq!(codes_of(&r), [codes::KEY_PLANNED]);
}

/// One drawn command segment with `body` as its keys. Its `[layout.line1]`
/// is the user's, so the built-in narrow band's template notes N504.
fn command_seg(body: &str) -> String {
    alloc::format!(
        "[segment.\"custom/k\"]\nkind = \"command\"\n{body}[layout.line1]\nleft = [\"custom/k\"]\n"
    )
}

/// The compile result even when an error withholds the snapshot: what
/// the unit's verdict is and which codes compiling adds.
fn compiled_anyway(user: &str) -> (Option<NotRun>, Vec<crate::diag::DiagCode>) {
    let r = read(user, &[]);
    let mut f = crate::config::source::tests::files(&[]);
    let g = crate::config::source::load(
        vec![
            crate::config::report::tests::builtin(),
            crate::config::source::tests::opened("root", user, 1),
        ],
        &mut f,
        [0, 3, 0],
    )
    .unwrap();
    let m = crate::config::merge::merge(&g, &[], &keys::slot);
    let (c, _) = compile(&m, &m, Mode::Dark).unwrap();
    (c.exec_units[0].not_run.clone(), codes_of(&r))
}

// 명시 허용(`unsafe_shell = true`) 없는 `shell`은 컴파일 오류 E211이고 그 단위는 실행 대상이 아니다.
// 이것을 실패시키는 것: command_form의 E211 push를 지우는 것(오류 없이 snapshot 발행),
// exec_units의 ShellNotAllowed 분기를 지우는 것(not_run None).
#[test]
fn test_shell_without_unsafe_rejected() {
    for allow in ["", "unsafe_shell = false\n"] {
        let user = command_seg(&alloc::format!(
            "shell = \"kubectl ctx | head -1\"\n{allow}"
        ));
        let (not_run, codes) = compiled_anyway(&user);
        assert_eq!(not_run, Some(NotRun::ShellNotAllowed), "{allow:?}");
        assert!(
            codes.contains(&codes::SHELL_NOT_ALLOWED),
            "{allow:?} {codes:?}"
        );
        assert!(read(&user, &[]).snapshot.is_none(), "{allow:?}");
    }
}

// 양성 대조: 명시 허용이 있으면 경고 W409만 내고 실행 대상이다.
// 이것을 실패시키는 것: W409 push를 지우는 것, 허용 판정을 `== Some(false)`로 뒤집는 것.
#[test]
fn test_shell_with_unsafe_warns_and_runs() {
    let r = read(
        &command_seg("shell = \"kubectl ctx | head -1\"\nunsafe_shell = true\n"),
        &[],
    );
    assert_eq!(
        codes_of(&r),
        [
            codes::UNSAFE_SHELL_USED,
            codes::BAND_TEMPLATE_REPLACES_LINES
        ]
    );
    let c = r.snapshot.unwrap();
    assert_eq!(c.exec_units[0].not_run, None);
}

// `command`와 `shell`을 함께 쓰거나 `shell` 없이 `unsafe_shell = true`만 쓰면 E212다.
// 이것을 실패시키는 것: 두 conflict push 중 하나를 지우는 것.
#[test]
fn test_command_and_shell_together_rejected() {
    let both = command_seg("command = [\"k\"]\nshell = \"k\"\nunsafe_shell = true\n");
    assert!(codes_of(&read(&both, &[])).contains(&codes::COMMAND_FORM_CONFLICT));
    let alone = command_seg("command = [\"k\"]\nunsafe_shell = true\n");
    assert_eq!(
        codes_of(&read(&alone, &[])),
        [
            codes::COMMAND_FORM_CONFLICT,
            codes::BAND_TEMPLATE_REPLACES_LINES
        ]
    );
    // `unsafe_shell = false` alone says nothing to conflict with.
    let off = command_seg("command = [\"k\"]\nunsafe_shell = false\n");
    assert_eq!(
        codes_of(&read(&off, &[])),
        [codes::BAND_TEMPLATE_REPLACES_LINES]
    );
}

// 실행할 것이 없는 command 세그먼트(command·shell 둘 다 없음, `command = []`)는 E212다.
// 이것을 실패시키는 것: 두 경우의 진단 push를 각각 지우는 것.
#[test]
fn test_command_segment_needs_something_to_run() {
    for body in ["", "command = []\n", "timeout = \"200ms\"\n"] {
        let r = read(&command_seg(body), &[]);
        assert_eq!(
            codes_of(&r),
            [
                codes::COMMAND_FORM_CONFLICT,
                codes::BAND_TEMPLATE_REPLACES_LINES
            ],
            "{body:?}"
        );
        assert!(r.snapshot.is_none(), "{body:?}");
    }
    let r = read(&command_seg("command = [\"k\"]\n"), &[]);
    assert_eq!(codes_of(&r), [codes::BAND_TEMPLATE_REPLACES_LINES]);
}

// `shell` 텍스트 안의 자리표시자는 E213이다(허용이 있어도).
// 이것을 실패시키는 것: shell 분기의 자리표시자 검사를 지우는 것.
#[test]
fn test_shell_mode_rejects_placeholder() {
    let r = read(
        &command_seg("shell = \"echo {dir}\"\nunsafe_shell = true\n"),
        &[],
    );
    assert!(
        codes_of(&r).contains(&codes::PLACEHOLDER_NOT_WHOLE),
        "{:?}",
        codes_of(&r)
    );
    assert!(r.snapshot.is_none());
    // Other braces are shell syntax, not placeholders.
    let r = read(
        &command_seg("shell = \"echo {a,b} ${HOME}\"\nunsafe_shell = true\n"),
        &[],
    );
    assert_eq!(
        codes_of(&r),
        [
            codes::UNSAFE_SHELL_USED,
            codes::BAND_TEMPLATE_REPLACES_LINES
        ]
    );
}

// 자리표시자는 argv 원소 하나 전체로만 쓴다. 원소 전체 `{dir}`과 다른 중괄호(awk)는 받는다.
// 이것을 실패시키는 것: `v != PLACEHOLDER` 조건을 지우는 것(전체 원소도 거부),
// `contains`를 `starts_with`로 바꾸는 것(`a{dir}` 통과).
#[test]
fn test_placeholder_mid_string_rejected() {
    let r = read(&command_seg("command = [\"ls\", \"a{dir}\"]\n"), &[]);
    assert_eq!(
        codes_of(&r),
        [
            codes::PLACEHOLDER_NOT_WHOLE,
            codes::BAND_TEMPLATE_REPLACES_LINES
        ]
    );
    assert!(r.snapshot.is_none());
    let ok = read(
        &command_seg("command = [\"awk\", \"{print $1}\", \"{dir}\"]\n"),
        &[],
    );
    assert_eq!(codes_of(&ok), [codes::BAND_TEMPLATE_REPLACES_LINES]);
}

// `cwd = "untrusted-current"`는 경고 W410, 목록 밖 값은 E203이다.
// 이것을 실패시키는 것: W410 push를 지우는 것, W410을 `neutral`에도 내는 것, cwd 키를 다시 자유 문자열로 두는 것.
#[test]
fn test_untrusted_current_warns() {
    let r = read(
        &command_seg("command = [\"k\"]\ncwd = \"untrusted-current\"\n"),
        &[],
    );
    assert_eq!(
        codes_of(&r),
        [
            codes::CWD_UNTRUSTED_CURRENT,
            codes::BAND_TEMPLATE_REPLACES_LINES
        ]
    );
    assert!(r.snapshot.is_some());
    let r = read(&command_seg("command = [\"k\"]\ncwd = \"neutral\"\n"), &[]);
    assert_eq!(codes_of(&r), [codes::BAND_TEMPLATE_REPLACES_LINES]);
    let r = read(&command_seg("command = [\"k\"]\ncwd = \"/w\"\n"), &[]);
    assert_eq!(codes_of(&r), [codes::BAD_VALUE]);
}

// 형식이 방어다: 컴파일 검사를 우회해 `unsafe_shell = false`인 shell 정책을 실행 대상으로 넣은 스냅샷도
// 허가 형식으로 옮길 변형이 없어 허가 목록에 들어가지 못한다(대상 카나리 단언은 허가를 만드는 C 단계 몫).
// 이것을 실패시키는 것: from_config의 UnsafeShell 갈래에서 `unsafe_shell: true` 조건을 지우는 것,
// shell이 있어도 Argv로 옮기는 것(`shell: None` 조건 삭제), argv와 shell이 함께 있어도 UnsafeShell로 옮기는 것,
// 빈 argv를 Argv로 옮기는 것.
#[test]
fn test_plain_shell_never_reaches_grant() {
    use crate::command::wire::Policy;
    let mut c = compiled(&command_seg("command = [\"k\"]\n"));
    let grantable = |c: &CompiledConfig| -> Vec<Policy> {
        c.exec_units
            .iter()
            .filter(|u| u.not_run.is_none())
            .filter_map(|u| Policy::from_config(&u.policy))
            .collect()
    };
    assert_eq!(
        grantable(&c),
        [Policy::Argv {
            argv: vec![b"k".to_vec()]
        }]
    );
    // An empty argv has no grant form either (argc 0).
    let mut empty = c.clone();
    empty.exec_units[0].policy = ExecPolicy::Command {
        argv: Vec::new(),
        cwd: None,
        env_allow: Vec::new(),
        shell: None,
        unsafe_shell: false,
    };
    assert_eq!(grantable(&empty), []);
    for (argv, allowed) in [
        (vec![], false),
        (vec![String::from("k")], false),
        (vec![String::from("k")], true),
    ] {
        c.exec_units[0].policy = ExecPolicy::Command {
            argv,
            cwd: None,
            env_allow: Vec::new(),
            shell: Some(String::from("kubectl ctx | head -1")),
            unsafe_shell: allowed,
        };
        assert_eq!(c.exec_units[0].not_run, None);
        let fixture = crate::snapshot_codec::decode_compiled(
            &crate::snapshot_codec::encode_compiled(&c).unwrap(),
        )
        .unwrap();
        assert_eq!(grantable(&fixture), [], "{:?}", c.exec_units[0].policy);
    }
    // Control: the explicit allowance alone has a grant form.
    c.exec_units[0].policy = ExecPolicy::Command {
        argv: Vec::new(),
        cwd: None,
        env_allow: Vec::new(),
        shell: Some(String::from("kubectl ctx | head -1")),
        unsafe_shell: true,
    };
    assert_eq!(
        grantable(&c),
        [Policy::UnsafeShell {
            script: b"kubectl ctx | head -1".to_vec()
        }]
    );
}

// 감독이 끝내 거부할 env_allow 이름(실행기 주입, 언어·셸 시작 설정)은 config check에서 오류다.
// 표는 감독의 것(`command::grant`)을 그대로 쓴다.
// 이것을 실패시키는 것: config 쪽 금지 검사를 지우는 것, 접두사 비교만 빠진 판정을 쓰는 것.
#[test]
fn env_allow_forbidden_names_rejected() {
    let names = crate::command::grant::FORBIDDEN
        .iter()
        .map(|n| core::str::from_utf8(n).unwrap())
        .chain(["LD_PRELOAD", "DYLD_INSERT_LIBRARIES", "BASH_FUNC_x%%"]);
    for name in names {
        let r = read(
            &command_seg(&alloc::format!(
                "command = [\"k\"]\nenv_allow = [\"{name}\"]\n"
            )),
            &[],
        );
        assert_eq!(
            codes_of(&r),
            [codes::BAD_VALUE, codes::BAND_TEMPLATE_REPLACES_LINES],
            "{name}"
        );
        assert!(r.snapshot.is_none(), "{name}");
    }
    // Credentials may come back (they are warned about later).
    let r = read(
        &command_seg("command = [\"k\"]\nenv_allow = [\"SSH_AUTH_SOCK\", \"LDX\"]\n"),
        &[],
    );
    assert_eq!(codes_of(&r), [codes::BAND_TEMPLATE_REPLACES_LINES]);
}

// env_allow 이름은 비지 않고 `=`·NUL이 없다(정제 환경의 `NAME=VALUE\0` 틀을 깨지 않게).
// 이것을 실패시키는 것: 빈 이름·`=`·NUL 조건 중 하나를 지우는 것.
#[test]
fn env_allow_names_are_variable_names() {
    for bad in ["", "A=B", "A\\u0000B"] {
        let r = read(
            &command_seg(&alloc::format!(
                "command = [\"k\"]\nenv_allow = [\"{bad}\"]\n"
            )),
            &[],
        );
        assert_eq!(
            codes_of(&r),
            [codes::BAD_VALUE, codes::BAND_TEMPLATE_REPLACES_LINES],
            "{bad:?}"
        );
    }
    let r = read(
        &command_seg("command = [\"k\"]\nenv_allow = [\"KUBECONFIG\"]\n"),
        &[],
    );
    assert_eq!(codes_of(&r), [codes::BAND_TEMPLATE_REPLACES_LINES]);
}

// 이것을 실패시키는 것: 실행 정책 필드(cwd·env_allow·timeout·cache·shell)와 키별 출처를 snapshot에서 버리는 것.
// 그리는(실행될 수 있는) 명령·언어 segment는 설정 하나에 32개까지다(명령 응답의 항목 상한). 그리지
// 않는 선언은 세지 않고, 좁은 폭 구간 하나에서만 그리거나 필드 참조로만 그리는 단위도 센다. 이것을 실패시키는
// 것: 상한 검사를 지우는 것, 상한을 33 이상으로 두는 것, 그리지 않는 선언까지 세는 것, 좁은 폭에서만 그리는
// 단위를 빼는 것, language 단위를 세지 않는 것.
#[test]
fn at_most_32_drawn_exec_units() {
    let declare = |from: usize, n: usize| {
        (from..from + n)
            .map(|i| {
                alloc::format!(
                    "[segment.\"custom/c{i:03}\"]\nkind = \"command\"\ncommand = [\"true\"]\n"
                )
            })
            .collect::<String>()
    };
    let draw = |n: usize| {
        let ids: Vec<String> = (0..n)
            .map(|i| alloc::format!("\"custom/c{i:03}\""))
            .collect();
        alloc::format!("[layout.line1]\nleft = [{}]\n", ids.join(", "))
    };
    let drawn = |c: &CompiledConfig| c.exec_units.iter().filter(|u| u.not_run.is_none()).count();
    // 32 drawn beside 200 declared and not drawn: valid.
    let ok = read(&(declare(0, 232) + &draw(32)), &[]);
    let c = ok.snapshot.expect("32 drawn");
    assert_eq!((c.exec_units.len(), drawn(&c)), (232, 32));
    // 33 drawn: E203.
    let over = read(&(declare(0, 33) + &draw(33)), &[]);
    assert!(over.snapshot.is_none());
    assert!(
        codes_of(&over).contains(&codes::BAD_VALUE),
        "{:?}",
        codes_of(&over)
    );
    // 32 drawn on the line, the 33rd only in a narrow band's template,
    // through a field reference: counted.
    let narrow = declare(0, 33)
        + &draw(32)
        + "[layout.when.narrow.style]\ntemplate = \"{custom/c032.value}{char}\"\n";
    let banded = read(&narrow, &[]);
    assert!(banded.snapshot.is_none(), "{:?}", codes_of(&banded));
    assert!(codes_of(&banded).contains(&codes::BAD_VALUE));
    // The diagnostic names the drawn count and says "drawn".
    let d = over
        .diagnostics
        .iter()
        .find(|d| d.code == codes::BAD_VALUE)
        .unwrap();
    let arg = |name: &str| {
        d.args
            .iter()
            .find(|a| a.name == name)
            .map(|a| a.value.clone())
            .unwrap_or_default()
    };
    assert_eq!(arg("found"), "33 drawn");
    assert!(arg("expected").contains("drawn"), "{}", arg("expected"));
    // 33 drawn, one turned off: 32 may run.
    let off = declare(0, 33).replacen(
        "kind = \"command\"\n",
        "kind = \"command\"\nenabled = false\n",
        1,
    ) + &draw(33);
    assert!(
        read(&off, &[]).snapshot.is_some(),
        "{:?}",
        codes_of(&read(&off, &[]))
    );
    // A language unit runs its interpreter, so it counts like a command:
    // 32 drawn languages compile, a 33rd is refused.
    let languages = |n: usize| {
        (0..n)
            .map(|i| {
                alloc::format!(
                    "[segment.\"custom/c{i:03}\"]\nkind = \"language\"\ndetect_files = [\"deno.json\"]\ninterpreter = \"deno\"\n"
                )
            })
            .collect::<String>()
            + &draw(n)
    };
    let ok = read(&languages(32), &[]);
    let codes = codes_of(&ok);
    let c = ok.snapshot.unwrap_or_else(|| panic!("{codes:?}"));
    assert_eq!(drawn(&c), 32);
    assert!(read(&languages(33), &[]).snapshot.is_none());
}

// C5: env segment는 실행 단위가 아니라 32개 상한에 세지 않는다. 실행 가능한 command 32개와 그리는 env 하나는
// compile되고 실행 단위는 정확히 32개다. 이것을 실패시키는 것: env를 실행 단위로 만들거나 상한 계수에 넣는 것.
#[test]
fn an_env_segment_is_not_an_exec_unit() {
    let mut src: String = (0..32)
        .map(|i| {
            alloc::format!(
                "[segment.\"custom/c{i:03}\"]\nkind = \"command\"\ncommand = [\"true\"]\n"
            )
        })
        .collect();
    src.push_str("[segment.\"custom/e\"]\nkind = \"env\"\nenv = \"E\"\n");
    let ids: Vec<String> = (0..32)
        .map(|i| alloc::format!("\"custom/c{i:03}\""))
        .collect();
    src.push_str(&alloc::format!(
        "[layout.line1]\nleft = [{}, \"custom/e\"]\n",
        ids.join(", ")
    ));
    let r = read(&src, &[]);
    let codes = codes_of(&r);
    let c = r.snapshot.unwrap_or_else(|| panic!("{codes:?}"));
    assert_eq!(c.exec_units.len(), 32);
    assert!(c.exec_units.iter().all(|u| u.not_run.is_none()));
    assert!(
        c.custom
            .iter()
            .any(|s| s.kind == CustomKind::Env("E".into()))
    );
}

#[test]
fn exec_units_keep_their_whole_policy() {
    let c = compiled(
        "[segment.\"custom/k\"]\nkind = \"command\"\ncommand = [\"k\", \"x\"]\ncwd = \"neutral\"\nenv_allow = [\"KUBECONFIG\"]\ntimeout = \"200ms\"\ncache = \"30s\"\n[layout.line1]\nleft = [\"custom/k\"]\n",
    );
    let u = &c.exec_units[0];
    let want = ExecPolicy::Command {
        argv: vec![String::from("k"), String::from("x")],
        cwd: Some(String::from("neutral")),
        env_allow: vec![String::from("KUBECONFIG")],
        shell: None,
        unsafe_shell: false,
    };
    assert_eq!(
        (&u.policy, u.timeout_ms, u.cache_ms, &u.not_run),
        (&want, Some(200), Some(30_000), &None)
    );
    // The trusted reference that lets it run, and where it shows.
    let r = &u.approved_by[0];
    assert_eq!((r.band, r.line, r.side), (None, 1, Side::Left));
    assert_eq!(r.origin.map(|o| o.source), Some(crate::diag::SourceId(1)));
    assert_eq!(u.approved_by, u.shown_at);
    let keys: Vec<&str> = u.origins.iter().map(|(k, _)| k.as_str()).collect();
    assert_eq!(
        keys,
        ["kind", "command", "cwd", "env_allow", "timeout", "cache"]
    );
    let c = compiled(
        "[segment.\"custom/l\"]\nkind = \"language\"\ndetect_files = [\"deno.json\", \"deno.jsonc\"]\ninterpreter = \"deno\"\nversion = [\"--version\"]\ncwd = \"neutral\"\nenv_allow = [\"DENO_DIR\"]\n[layout.line1]\nleft = [\"custom/l\"]\n",
    );
    assert_eq!(
        c.exec_units[0].policy,
        ExecPolicy::Language {
            interpreter: Some("deno".into()),
            version_argv: vec!["--version".into()],
            detect_files: vec!["deno.json".into(), "deno.jsonc".into()],
            cwd: Some("neutral".into()),
            env_allow: vec!["DENO_DIR".into()],
        }
    );
}

// 사용자 정의 language segment의 키 검사(D3c 판정): detect_files는 1–16개의 파일 이름이고 각각 경로 한
// 마디(수집 작업 프로세스가 찾을 수 있는 이름)이며 같은 이름은 한 번만, interpreter는 비지 않고 NUL이 없으며,
// version 인자에 NUL이 없다. 둘 중 하나라도 없으면 오류다. 이것을 실패시키는 것: 개수 검사를 지우거나 상한을
// 바꾸는 것, 이름 검사(name_ok)를 지우는 것, 중복 검사를 지우는 것, interpreter·detect_files 필수를 지우는 것,
// 빈 interpreter나 NUL을 받는 것, version의 NUL을 받는 것.
#[test]
fn language_keys_are_checked() {
    let lang = |keys: &str| {
        alloc::format!(
            "[segment.\"custom/l\"]\nkind = \"language\"\n{keys}[layout.line1]\nleft = [\"custom/l\"]\n"
        )
    };
    let names = |n: usize| {
        (0..n)
            .map(|i| alloc::format!("\"m{i}\""))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let good = "interpreter = \"deno\"\nversion = [\"--version\"]\n";
    let ok = [
        alloc::format!("detect_files = [\"deno.json\"]\n{good}"),
        alloc::format!("detect_files = [{}]\n{good}", names(16)),
        "detect_files = [\"a\"]\ninterpreter = \"/opt/deno/bin/deno\"\n".into(),
    ];
    // The unit's layout line is the user's, so the built-in narrow template notes N504.
    let only_later = |r: &crate::config::report::ConfigReport| {
        codes_of(r) == [codes::BAND_TEMPLATE_REPLACES_LINES]
    };

    for keys in ok {
        let r = read(&lang(&keys), &[]);
        assert!(only_later(&r), "{keys}: {:?}", codes_of(&r));
        assert!(r.snapshot.is_some(), "{keys}");
    }
    let bad = [
        good.into(),
        alloc::format!("detect_files = []\n{good}"),
        alloc::format!("detect_files = [{}]\n{good}", names(17)),
        alloc::format!("detect_files = [\"a/b\"]\n{good}"),
        alloc::format!("detect_files = [\"..\"]\n{good}"),
        alloc::format!("detect_files = [\".\"]\n{good}"),
        alloc::format!("detect_files = [\"a\\u0000b\"]\n{good}"),
        alloc::format!("detect_files = [\"{}\"]\n{good}", "x".repeat(256)),
        alloc::format!("detect_files = [\"a\", \"b\", \"a\"]\n{good}"),
        "detect_files = [\"a\"]\n".into(),
        "detect_files = [\"a\"]\ninterpreter = \"\"\n".into(),
        "detect_files = [\"a\"]\ninterpreter = \"de\\u0000no\"\n".into(),
        "detect_files = [\"a\"]\ninterpreter = \"deno\"\nversion = [\"--v\\u0000\"]\n".into(),
        alloc::format!("detect_files = [\"a\"]\n{good}env_allow = [\"LD_PRELOAD\"]\n"),
        alloc::format!("detect_files = [\"a\"]\n{good}env_allow = [\"A=B\"]\n"),
    ];
    for keys in bad {
        let r = read(&lang(&keys), &[]);
        assert!(
            codes_of(&r).contains(&codes::BAD_VALUE),
            "{keys}: {:?}",
            codes_of(&r)
        );
        assert!(r.snapshot.is_none(), "{keys}");
    }
    // cwd and env_allow as a command's (D3c-2): the current folder is warned.
    let r = read(
        &lang(&alloc::format!(
            "detect_files = [\"a\"]\n{good}cwd = \"untrusted-current\"\nenv_allow = [\"DENO_DIR\"]\n"
        )),
        &[],
    );
    assert_eq!(
        codes_of(&r),
        [
            codes::CWD_UNTRUSTED_CURRENT,
            codes::BAND_TEMPLATE_REPLACES_LINES
        ]
    );
    assert!(r.snapshot.is_some());
    // 255 bytes is one name still.
    let r = read(
        &lang(&alloc::format!(
            "detect_files = [\"{}\"]\n{good}",
            "x".repeat(255)
        )),
        &[],
    );
    assert!(only_later(&r), "{:?}", codes_of(&r));
}

// 이것을 실패시키는 것: 안전 검사에 실패한 파일의 실행 키로 명령을 켜는 것(이름은 알려야 함).
#[test]
fn unsafe_file_commands_do_not_run() {
    let seg = "[segment.\"custom/k\"]\nkind = \"command\"\ncommand = [\"k\"]\n";
    let r = read(
        "extends = [\"unsafe-mine\"]\n[layout.line1]\nleft = [\"custom/k\"]\n",
        &[("unsafe-mine", seg)],
    );
    let c = r.snapshot.unwrap();
    assert_eq!(
        c.exec_units[0].not_run,
        Some(NotRun::UnsafeFile {
            key: String::from("kind")
        })
    );
    assert!(
        r.diagnostics
            .iter()
            .any(|d| d.code == codes::NOT_RUN_UNSAFE_FILE)
    );
}

// 템플릿은 프리셋·옵션·줄을 대신한다. 템플릿 옆에 쓴 줄은 쓰이지 않으니 알림 N501로 알린다.
// 이것을 실패시키는 것: 템플릿을 무시하는 것, 템플릿 옆의 줄을 말없이 버리는 것.
#[test]
fn a_template_replaces_lines_and_says_so() {
    let c = compiled("[style]\ntemplate = \"{dir}{@nl}{char}\"\n");
    assert_ne!(c.variants[0], compiled("").variants[0]);
    let r = read(
        "[style]\ntemplate = \"{dir}{@nl}{char}\"\n[layout.line1]\nleft = [\"git\"]\n",
        &[],
    );
    assert!(
        codes_of(&r).contains(&codes::TEMPLATE_REPLACES_STYLE),
        "{:?}",
        codes_of(&r)
    );
}

/// One N504: its band, widths and lines arguments, and its place.
type BandNote<'a> = (Option<&'a str>, Option<&'a str>, Option<&'a str>, Place);

fn band_notes(r: &crate::config::report::ConfigReport) -> Vec<BandNote<'_>> {
    r.diagnostics
        .iter()
        .filter(|d| d.code == codes::BAND_TEMPLATE_REPLACES_LINES)
        .map(|d| {
            let arg = |k: &str| {
                d.args
                    .iter()
                    .find(|a| a.name == k)
                    .map(|a| a.value.as_str())
            };
            (arg("band"), arg("widths"), arg("lines"), d.at)
        })
        .collect()
}

// A band's own template draws in place of the lines it takes from `[layout]` (N504): said for
// lines a user file wrote, at the place they were written, with the band and its widths.
// 이것을 실패시키는 것: 사용자 줄이 내장 narrow 템플릿에 밀리는데 말하지 않는 것, 구간 이름·폭·줄 이름을
// 틀리게 적는 것, 노트를 사용자 줄이 아닌 곳에 두는 것.
#[test]
fn a_band_template_over_user_lines_says_so() {
    let user = "[layout.line1]\nleft = [\"dir\"]\nright = [\"time\"]\n";
    let r = read(user, &[]);
    let notes = band_notes(&r);
    assert_eq!(notes.len(), 1, "{:?}", codes_of(&r));
    let (band, widths, lines, at) = notes[0];
    assert_eq!(
        (band, widths, lines),
        (Some("narrow"), Some("0-59"), Some("layout.line1"))
    );
    assert!(
        matches!(at, Place::Source { id, .. } if id == SourceId(1)),
        "{at:?}"
    );
    // Both lines, when the user wrote both.
    let both = read(
        "[layout.line1]\nleft = [\"dir\"]\n[layout.line2]\nleft = [\"char\"]\n",
        &[],
    );
    assert_eq!(
        band_notes(&both)[0].2,
        Some("layout.line1 and layout.line2")
    );
    // A band template another file writes (here a trusted one, "t") over the user's lines is
    // the same surprise.
    let other_file = read(
        "extends = [\"t\"]\n[layout.line1]\nleft = [\"dir\"]\n",
        &[(
            "t",
            "[layout.when.mid]\nmin_cols = 60\nmax_cols = 79\n[layout.when.mid.style]\ntemplate = \"{dir}{@nl}{char}\"\n",
        )],
    );
    let bands: Vec<_> = band_notes(&other_file).iter().map(|n| (n.0, n.1)).collect();
    assert_eq!(
        bands,
        [(Some("narrow"), Some("0-59")), (Some("mid"), Some("60-79"))]
    );
}

// N504 stays quiet where nothing is lost or the user chose it.
// 이것을 실패시키는 것: 내장 줄만 있는 설정(설정 없음)에 내는 것, 템플릿과 같은 파일이 쓴 줄에 내는 것,
// 구간이 직접 쓴 줄을 N504에도 넣는 것, 기본 레이아웃에서 물려받은 템플릿에 내는 것, 어느 폭에서도
// 골라지지 않는 구간에 내는 것.
#[test]
fn a_band_template_note_only_for_lines_it_takes_away() {
    assert!(band_notes(&read("", &[])).is_empty());
    let own = read(
        "[layout.line1]\nleft = [\"dir\"]\n[layout.when.narrow.style]\ntemplate = \"{dir}{@nl}{char}\"\n",
        &[],
    );
    assert!(band_notes(&own).is_empty(), "{:?}", codes_of(&own));
    // The band writes line 1 itself (N501's case); only line 2 is taken from the user's layout.
    let written = read(
        "[layout.line1]\nleft = [\"dir\"]\n[layout.line2]\nleft = [\"char\"]\n[layout.when.narrow.line1]\nleft = [\"git\"]\n",
        &[],
    );
    let n = band_notes(&written);
    assert_eq!(n.len(), 1, "{:?}", codes_of(&written));
    assert_eq!(n[0].2, Some("layout.line2"));
    assert!(codes_of(&written).contains(&codes::TEMPLATE_REPLACES_STYLE));
    // A user band without a template of its own takes the default template (from a theme
    // here, so the file check alone would not keep quiet): that is N501's case in the
    // default layout, not N504's.
    let inherited = read(
        "extends = [\"t\"]\n[layout.line1]\nleft = [\"dir\"]\n[layout.when.mid]\nmin_cols = 60\nmax_cols = 79\n",
        &[("t", "[style]\ntemplate = \"{dir}{@nl}{char}\"\n")],
    );
    assert!(codes_of(&inherited).contains(&codes::TEMPLATE_REPLACES_STYLE));
    let names: Vec<_> = band_notes(&inherited).iter().map(|n| n.0).collect();
    assert!(!names.contains(&Some("mid")), "{names:?}");
    // A band no width chooses replaces nothing.
    let never = read(
        "extends = [\"t\"]\n[layout.line1]\nleft = [\"dir\"]\n",
        &[(
            "t",
            "[layout.when.inner]\nmin_cols = 10\nmax_cols = 20\norder = 2\n[layout.when.inner.style]\ntemplate = \"{dir}{@nl}{char}\"\n[layout.when.narrow]\norder = 1\n",
        )],
    );
    assert!(codes_of(&never).contains(&codes::BAND_NEVER_CHOSEN));
    let names: Vec<_> = band_notes(&never).iter().map(|n| n.0).collect();
    assert_eq!(names, [Some("narrow")]);
}

// `layout.when.<band>.enabled = false` turns a band off: its widths go to the next band that
// fits, else to the default layout (here the user's lines at 59 as at 60, the built-in narrow
// being the only band). Without the key, or with `true`, nothing changes.
// 이것을 실패시키는 것: 꺼진 구간을 구간 고르기·폭 표(bands_of)에 남기는 것, 그 variant를 컴파일(layouts)에
// 남기는 것, 59/60 경계에서 다른 variant를 고르는 것, 꺼진 구간에 N504·W407을 내는 것, `true`를 끔으로 읽는 것.
#[test]
fn a_band_turned_off_draws_the_default_layout_at_its_widths() {
    let user = "[layout.line1]\nleft = [\"dir\"]\nright = [\"time\"]\n";
    let on = read(user, &[]);
    let off = read(
        &alloc::format!("{user}[layout.when.narrow]\nenabled = false\n"),
        &[],
    );
    let runs = |r: &crate::config::report::ConfigReport| -> Vec<(u16, u16, Option<String>)> {
        r.widths
            .iter()
            .map(|w| (w.from, w.to, w.band.clone()))
            .collect()
    };
    assert_eq!(
        runs(&on),
        [(0, 59, Some(String::from("narrow"))), (60, u16::MAX, None)]
    );
    assert_eq!(runs(&off), [(0, u16::MAX, None)]);
    assert!(codes_of(&on).contains(&codes::BAND_TEMPLATE_REPLACES_LINES));
    assert_eq!(codes_of(&off), []);
    let (c_on, c_off) = (on.snapshot.unwrap(), off.snapshot.unwrap());
    assert_eq!((c_on.bands.len(), c_on.variants.len()), (1, 2));
    assert_eq!((c_off.bands.len(), c_off.variants.len()), (0, 1));
    for (w, band) in [(59, Some(0)), (60, None)] {
        assert_eq!(
            crate::bands::select(&c_on.band_order, &c_on.bands, w),
            band,
            "{w}"
        );
        assert_eq!(
            crate::bands::select(&c_off.band_order, &c_off.bands, w),
            None,
            "{w}"
        );
    }
    assert_eq!(c_off.variants[0], c_on.variants[0]);
    let explicit = read(
        &alloc::format!("{user}[layout.when.narrow]\nenabled = true\n"),
        &[],
    );
    assert_eq!(explicit.snapshot.unwrap().variants, c_on.variants);
}

/// The built-in theme, the trusted `root`, then `unsafe_text` from a file that failed the
/// safety check (Unsafe), applied after `root`.
fn read_with_unsafe(root: &str, unsafe_text: &str) -> crate::config::report::ConfigReport {
    use crate::config::source::tests::{files, opened};
    crate::config::report::report(
        vec![
            crate::config::report::tests::builtin(),
            opened("root", root, 1),
            opened("unsafe-band", unsafe_text, 2),
        ],
        &mut files(&[]),
        [0, 3, 0],
        Mode::Dark,
    )
}

const BAND_OFF: &str = "[layout.when.narrow]\nenabled = false\n";
const BAND_ON: &str = "[layout.when.narrow]\nenabled = true\n";

/// The band chosen in each run of the width table.
fn band_runs(r: &crate::config::report::ConfigReport) -> Vec<Option<String>> {
    r.widths.iter().map(|w| w.band.clone()).collect()
}

// A file that failed the safety check neither turns a band off nor turns back on a band a
// trusted file turned off: `enabled` is read from the trusted sources alone. One test per case.
// 이것을 실패시키는 것(세 시험 모두): `enabled`를 전체 병합(안전 검사에 실패한 파일 포함)에서 읽는 것.
#[test]
fn an_unsafe_true_does_not_turn_back_on_a_trusted_false() {
    let r = read_with_unsafe(BAND_OFF, BAND_ON);
    assert!(r.snapshot.is_some(), "{:?}", codes_of(&r));
    assert_eq!(band_runs(&r), [None]);
}

#[test]
fn an_unsafe_false_does_not_turn_a_band_off() {
    assert_eq!(
        band_runs(&read_with_unsafe("", BAND_OFF)),
        [Some(String::from("narrow")), None]
    );
}

#[test]
fn an_unsafe_false_does_not_override_a_trusted_true() {
    assert_eq!(
        band_runs(&read_with_unsafe(BAND_ON, BAND_OFF)),
        [Some(String::from("narrow")), None]
    );
}

// Every place that walks the bands takes the trusted on/off: here a trusted band `b` that a
// file failing the safety check tries to turn off draws a text and a command segment of the
// user's at 100 columns and up.
// 이것을 실패시키는 것: 컴파일 variant(layouts)가 전체 병합의 켜짐/꺼짐을 읽는 것(variant 수가 구간 수 + 1과
// 어긋남), 사용자 세그먼트의 그려짐(custom_segments의 drawn)이나 명령 실행의 그려짐(exec_units의 drawn)이
// 그것을 읽는 것(text 세그먼트가 빠지거나 명령이 실행되지 않음).
#[test]
fn every_band_walk_takes_the_trusted_on_or_off() {
    let root = "[segment.\"custom/t\"]\nkind = \"text\"\ntext = \"T\"\n\
        [segment.\"custom/k\"]\nkind = \"command\"\ncommand = [\"k\"]\n\
        [layout.when.b]\nmin_cols = 100\nenabled = true\n\
        [layout.when.b.line1]\nleft = [\"custom/t\", \"custom/k\", \"char\"]\n";
    let r = read_with_unsafe(root, "[layout.when.b]\nenabled = false\n");
    let runs = band_runs(&r);
    let c = r.snapshot.unwrap();
    assert_eq!(c.variants.len(), c.bands.len() + 1);
    assert_eq!(
        runs,
        [Some(String::from("narrow")), None, Some(String::from("b"))]
    );
    assert!(c.custom.iter().any(|u| u.id == "custom/t"));
    let unit = c.exec_units.iter().find(|u| u.id == "custom/k").unwrap();
    assert_eq!(unit.not_run, None);
}

// The width table that `config check` shows when the settings do not compile takes the
// trusted on/off too.
// 이것을 실패시키는 것: 컴파일이 실패했을 때의 폭 표(report의 대체 경로)가 전체 병합의 켜짐/꺼짐을 읽는 것.
#[test]
fn the_width_table_without_a_snapshot_takes_the_trusted_on_or_off() {
    let r = read_with_unsafe(&alloc::format!("colr = 1\n{BAND_OFF}"), BAND_ON);
    assert!(r.snapshot.is_none());
    assert_eq!(band_runs(&r), [None]);
}

// The first band that fits a width still wins: with narrow off, a band of the user's that
// also covers 59 columns is chosen there, and the default layout only past it.
// 이것을 실패시키는 것: 꺼진 구간의 폭을 다른 구간을 보지 않고 바로 기본 레이아웃으로 보내는 것.
#[test]
fn a_band_turned_off_leaves_its_widths_to_the_next_band() {
    let wide = "[layout.when.wide]\nmax_cols = 79\n[layout.when.wide.line1]\nleft = [\"dir\"]\n";
    let runs = |r: &crate::config::report::ConfigReport| -> Vec<(u16, u16, Option<String>)> {
        r.widths
            .iter()
            .map(|w| (w.from, w.to, w.band.clone()))
            .collect()
    };
    let s = |t: &str| Some(String::from(t));
    let on = read(wide, &[]);
    assert_eq!(
        runs(&on),
        [
            (0, 59, s("narrow")),
            (60, 79, s("wide")),
            (80, u16::MAX, None)
        ]
    );
    let off = read(
        &alloc::format!("{wide}[layout.when.narrow]\nenabled = false\n"),
        &[],
    );
    assert_eq!(runs(&off), [(0, 79, s("wide")), (80, u16::MAX, None)]);
    let c = off.snapshot.unwrap();
    assert_eq!(crate::bands::select(&c.band_order, &c.bands, 59), Some(0));
}

// Only a trusted file turns a band off: from a theme the key is dropped with W401 and the band
// stays.
// 이것을 실패시키는 것: `layout.when.*.enabled`를 모양 전용 키로 두는 것(남의 테마가 구간을 끔).
#[test]
fn only_a_trusted_file_turns_a_band_off() {
    let r = read(
        "extends = [\"shape-t\"]\n",
        &[("shape-t", "[layout.when.narrow]\nenabled = false\n")],
    );
    assert!(
        r.diagnostics.iter().any(|d| {
            d.code == codes::EXEC_KEY_IGNORED
                && d.args
                    .iter()
                    .any(|a| a.name == "key" && a.value == "layout.when.narrow.enabled")
        }),
        "{:?}",
        r.diagnostics
    );
    let widths: Vec<_> = r.widths.iter().map(|w| w.band.as_deref()).collect();
    assert_eq!(widths, [Some("narrow"), None]);
}

// 이것을 실패시키는 것: 꺼진 내장 세그먼트를 그리거나 수집 mask에 남기는 것, 그려지는 세그먼트를 mask에서 빠뜨리는 것.
#[test]
fn collect_mask_follows_drawn_and_enabled_segments() {
    let bit = |id| 1u32 << BUILTIN.iter().position(|d| d.id == id).unwrap();
    let c = compiled("");
    assert_ne!(c.collect_mask & bit("git"), 0);
    let c = compiled("[segment.git]\nenabled = false\n");
    assert_eq!(c.collect_mask & bit("git"), 0);
    assert_ne!(c.variants, compiled("").variants, "git is not drawn");
    let git = BUILTIN.iter().position(|d| d.id == "git").unwrap();
    assert!(
        c.variants
            .iter()
            .flatten()
            .flat_map(|l| l.nodes())
            .all(|n| !matches!(n,
        Node::Segment { seg, .. } | Node::Field { seg, .. } if usize::from(*seg) == git))
    );
    let c = compiled(
        "[layout.line1]\nleft = [\"dir\"]\nright = []\n[layout.when.narrow.style]\ntemplate = \"{dir}{@nl}{char}\"\n",
    );
    assert_eq!(c.collect_mask & bit("git"), 0);
}

// 이것을 실패시키는 것: 팔레트·구간 오류를 내장 위치로 알리는 것(사용자 파일의 그 키를 가리켜야 함).
#[test]
fn derived_errors_point_at_the_key() {
    let src = "[colors.roles]\npath = \"accent.nope\"\n";
    let r = read(src, &[]);
    let d = r
        .diagnostics
        .iter()
        .find(|d| d.code == codes::BAD_VALUE)
        .unwrap();
    let Place::Source { id, span } = d.at else {
        panic!("{:?}", d.at)
    };
    assert_eq!(
        (id, span.start as usize),
        (
            crate::diag::SourceId(1),
            src.find("\"accent.nope\"").unwrap()
        )
    );
    let src = "[layout.when.a]\nmin_cols = 1\nmax_cols = 70\n";
    let r = read(src, &[]);
    let d = r
        .diagnostics
        .iter()
        .find(|d| d.code == codes::BAD_VALUE)
        .unwrap();
    assert!(
        matches!(
            d.at,
            Place::Source {
                id: crate::diag::SourceId(1),
                ..
            }
        ),
        "{:?}",
        d.at
    );
}

fn unit_ref(band: Option<u16>) -> Vec<LayoutRef> {
    vec![LayoutRef {
        band,
        line: 1,
        side: Side::Left,
        origin: None,
    }]
}

// 이것을 실패시키는 것: `>= band_count` 비교를 `>`로 바꾸는 것(인덱스가 구간 수와 같은 참조를 아는 구간으로
// 취급), 신뢰 참조나 표시 참조 한쪽의 검사를 지우는 것.
#[test]
fn test_unknown_band_index_never_runs() {
    let set: BTreeSet<Option<u16>> = [None, Some(0), Some(1), Some(2)].into();
    let all = Reach::new(set.clone(), set);
    // Two bands: indexes 0 and 1 exist, 2 does not (even though a width "chooses" it here).
    let verdict = |a, s| layout_verdict(&unit_ref(a), &unit_ref(s), 2, &all);
    assert_eq!(verdict(Some(1), None), None);
    assert_eq!(verdict(Some(2), None), Some(NotRun::UnknownBand));
    assert_eq!(verdict(None, Some(2)), Some(NotRun::UnknownBand));
    assert_eq!(verdict(Some(u16::MAX), Some(0)), Some(NotRun::UnknownBand));
}

const UNIT: &str = "[segment.\"custom/u\"]\nkind = \"command\"\ncommand = [\"u\"]\n";

// 이것을 실패시키는 것: 도달 가능성 필터를 지워 폭이 고를 수 없는 구간(다른 구간에 가려진 구간, 구간이 모든 폭을
// 덮어 쓸 수 없게 된 기본 레이아웃)에만 그려진 단위를 실행하는 것. 양성 대조: 같은 구간이 고를 수 있으면 실행한다.
#[test]
fn test_unreachable_band_unit_not_run() {
    let run = |layout: &str| {
        compiled(&alloc::format!("{UNIT}{layout}")).exec_units[0]
            .not_run
            .clone()
    };
    let hidden = "[layout.when.hidden]\nmin_cols = 120\nmax_cols = 130\n[layout.when.hidden.line1]\nleft = [\"custom/u\", \"char\"]\n";
    // Reachable: no other band takes widths 120 to 130 first.
    assert_eq!(
        run(&alloc::format!(
            "[layout.line1]\nleft = [\"char\"]\n{hidden}"
        )),
        None
    );
    // `cover` has the lower order and takes every width, so `hidden` is never chosen.
    let cover = "[layout.when.cover]\norder = 1\n";
    let hidden = hidden.replace("min_cols", "order = 2\nmin_cols");
    assert_eq!(
        run(&alloc::format!(
            "[layout.line1]\nleft = [\"char\"]\n{cover}{hidden}"
        )),
        Some(NotRun::NotInTrustedLayout)
    );
    // The default layout draws the unit, but a band takes every width.
    assert_eq!(
        run(
            "[layout.line1]\nleft = [\"custom/u\", \"char\"]\n[layout.when.cover]\norder = 1\n[layout.when.cover.line1]\nleft = [\"char\"]\n"
        ),
        Some(NotRun::NotInTrustedLayout)
    );
}

// 이것을 실패시키는 것: 승인 참조의 도달 가능성을 전체 병합으로 판정하는 것(모양 전용 파일이 구간의 폭만 바꿔
// 신뢰 설정에서 가려진 구간을 되살린다). 양성 대조: 같은 모양 파일이 없으면 가려진 채로, 신뢰 설정 안에서 도달 가능하면 실행.
#[test]
fn test_shape_only_file_cannot_make_a_hidden_band_approve() {
    let root = alloc::format!(
        "{UNIT}[layout.line1]\nleft = [\"char\"]\n[layout.when.cover]\norder = 1\n[layout.when.hidden]\norder = 2\nmin_cols = 120\nmax_cols = 130\n[layout.when.hidden.line1]\nleft = [\"custom/u\", \"char\"]\n"
    );
    let shape = "[layout.when.cover]\nmax_cols = 100\n";
    let not_run = |extends: &str, list: &[(&'static str, &str)]| {
        let r = read(&alloc::format!("{extends}{root}"), list);
        let codes = codes_of(&r);
        r.snapshot.unwrap_or_else(|| panic!("{codes:?}")).exec_units[0]
            .not_run
            .clone()
    };
    assert_eq!(not_run("", &[]), Some(NotRun::NotInTrustedLayout));
    assert_eq!(
        not_run("extends = [\"shape-order\"]\n", &[("shape-order", shape)]),
        Some(NotRun::NotInTrustedLayout)
    );
}

// C5: 모양 전용 파일이 구간 폭만 바꿔 신뢰 설정에서 가려진 구간을 되살려도, 그 구간에만 있는 env segment는
// 그리지 않는다(명령 쪽 시험과 같은 모양). 양성 대조: 신뢰 설정 안에서 닿는 구간이면 그린다. 이것을 실패시키는
// 것: env의 승인 참조 도달을 전체 병합의 구간으로 판정하는 것.
#[test]
fn test_shape_only_file_cannot_make_a_hidden_band_show_env() {
    const E: &str = "[segment.\"custom/e\"]\nkind = \"env\"\nenv = \"E\"\n";
    let root = |hidden_min: u16| {
        alloc::format!(
            "{E}[layout.line1]\nleft = [\"char\"]\n[layout.when.cover]\norder = 1\n[layout.when.hidden]\norder = 2\nmin_cols = {hidden_min}\nmax_cols = 130\n[layout.when.hidden.line1]\nleft = [\"custom/e\", \"char\"]\n"
        )
    };
    let shown = |src: &str, list: &[(&'static str, &str)]| {
        let r = read(src, list);
        let codes = codes_of(&r);
        !r.snapshot
            .unwrap_or_else(|| panic!("{codes:?}"))
            .custom
            .is_empty()
    };
    let shape = "[layout.when.cover]\nmax_cols = 100\n";
    assert!(!shown(&root(120), &[]));
    assert!(!shown(
        &alloc::format!("extends = [\"shape-order\"]\n{}", root(120)),
        &[("shape-order", shape)]
    ));
    // Without the cover band the trusted config reaches the hidden band:
    // it shows.
    assert!(shown(
        &root(120).replacen("[layout.when.cover]\norder = 1\n", "", 1),
        &[]
    ));
}

fn exec_not_run(root: &str, shape: &str) -> Vec<Option<NotRun>> {
    let src = alloc::format!("extends = [\"shape-x\"]\n{root}");
    let r = read(&src, &[("shape-x", shape)]);
    let codes = codes_of(&r);
    let c = r.snapshot.unwrap_or_else(|| panic!("{codes:?}"));
    let mut units: Vec<_> = c
        .exec_units
        .iter()
        .map(|u| (u.id.clone(), u.not_run.clone()))
        .collect();
    units.sort_by(|a, b| a.0.cmp(&b.0));
    units.into_iter().map(|u| u.1).collect()
}

// 이것을 실패시키는 것: 신뢰 merge의 구간 번호를 전체 merge의 번호로 이름 없이 복사하는 것(모양 파일이 앞에
// 구간을 더해 번호가 밀리면 승인돼야 할 단위가 거부되고 거부돼야 할 단위가 승인된다).
#[test]
fn test_trusted_band_index_maps_by_name() {
    let two = |name: &str, order: u8, unit: &str| {
        alloc::format!(
            "[layout.when.{name}]\norder = {order}\nmin_cols = 100\nmax_cols = 110\n[layout.when.{name}.line1]\nleft = [\"{unit}\", \"char\"]\n"
        )
    };
    let unit =
        |id: &str| alloc::format!("[segment.\"{id}\"]\nkind = \"command\"\ncommand = [\"u\"]\n");
    // Trusted: `gone` (index 0) is shadowed by `live` (index 1) on the same widths.
    let root = alloc::format!(
        "{}{}[layout.line1]\nleft = [\"char\"]\n{}{}",
        unit("custom/neg"),
        unit("custom/pos"),
        two("gone", 2, "custom/neg"),
        two("live", 1, "custom/pos"),
    );
    // The shape-only file adds a band that sorts first, so every index shifts by one.
    let shape = "[layout.when.early]\nmin_cols = 300\n";
    // Units sorted by id: custom/neg, custom/pos.
    assert_eq!(
        exec_not_run(&root, shape),
        [Some(NotRun::NotInTrustedLayout), None]
    );
}

// 이것을 실패시키는 것: 신뢰 merge의 구간이 정렬에 실패할 때 전체 merge의 도달 가능성으로 대신하는 것(모양 파일의
// `order`가 신뢰 설정이 풀지 못한 구간 겹침을 풀어 명령을 되살린다). 양성 대조는 위 시험과 앞의 시험이 맡는다.
#[test]
fn test_unorderable_trusted_bands_approve_nothing() {
    let root = alloc::format!(
        "{UNIT}[layout.line1]\nleft = [\"char\"]\n[layout.when.a]\nmin_cols = 100\nmax_cols = 110\n[layout.when.a.line1]\nleft = [\"custom/u\", \"char\"]\n[layout.when.b]\nmin_cols = 105\nmax_cols = 115\n"
    );
    // Crossing ranges need `order`; only the shape-only file gives it.
    let shape = "[layout.when.a]\norder = 1\n[layout.when.b]\norder = 2\n";
    assert_eq!(
        exec_not_run(&root, shape),
        [Some(NotRun::NotInTrustedLayout)]
    );
}

// 이것을 실패시키는 것: 표시 참조의 도달 가능성 검사를 `shown_at.is_empty()`로 약화하는 것(모양 전용 파일이
// 모든 폭을 덮는 구간에서 줄을 바꿔 명령을 화면에서 지웠는데도 신뢰 설정의 승인만으로 실행된다).
// 양성 대조: 같은 신뢰 설정에 모양 파일이 없으면 실행한다.
#[test]
fn test_shape_only_cover_band_hides_the_unit() {
    let root = alloc::format!("{UNIT}[layout.line1]\nleft = [\"custom/u\", \"char\"]\n");
    let cover = "[layout.when.cover]\norder = 0\n[layout.when.cover.line1]\nleft = [\"char\"]\n";
    assert_eq!(exec_not_run(&root, "").as_slice(), [None]);
    assert_eq!(
        exec_not_run(&root, cover),
        [Some(NotRun::NotInTrustedLayout)]
    );
}
