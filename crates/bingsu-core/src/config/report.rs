//! One read of the config, end to end (spec section 2 "합치는 순서"): load
//! → merge → check → compile, with every diagnostic, the width table and
//! the snapshot in one report. `config check` (N5) shows it, the refresh
//! helper (N2) publishes its snapshot; neither can drop a warning on the
//! way, because there is only this one result.
//!
//! Rule 5 after the merge: a check or compile error whose place is a
//! shape-only source drops that source, and what it brought in, and the
//! read starts again without it. Each round drops at least one of at most
//! 32 sources, so it ends. An error in a trusted source rejects the read
//! (no snapshot; the caller keeps the last good one).
use crate::color::palette::Mode;
use crate::config::check::check;
use crate::config::compile::{CompiledConfig, bands_of, compile};
use crate::config::keys;
use crate::config::merge::merge;
use crate::config::source::{Found, LoadReport, Resolver, Root, Status, Trust, load};
use crate::diag::{Diagnostic, Place, Severity, SourceId};
use crate::diag_codes as codes;
use crate::diag_widths::WidthRun;
use alloc::collections::BTreeSet;
use alloc::vec::Vec;

#[derive(Debug)]
pub struct ConfigReport {
    /// Every file met (`SourceId(i)` is index i), for showing places.
    pub files: Vec<Found>,
    /// Files applied, in order (after any rule-5 drops).
    pub order: Vec<SourceId>,
    /// Errors, warnings and notes of every step, by severity, then file
    /// and place.
    pub diagnostics: Vec<Diagnostic>,
    /// The band chosen at each width (`config check` shows it).
    pub widths: Vec<WidthRun>,
    /// `None` when an error remains.
    pub snapshot: Option<CompiledConfig>,
}

fn source_of(d: &Diagnostic) -> Option<SourceId> {
    match d.at {
        Place::Source { id, .. } => Some(id),
        _ => None,
    }
}

/// `id` and every file whose placing path goes through it.
fn below(files: &[Found], id: SourceId) -> Vec<SourceId> {
    files
        .iter()
        .filter(|f| f.id == id || f.via.contains(&id))
        .map(|f| f.id)
        .collect()
}

fn sorted(mut d: Vec<Diagnostic>) -> Vec<Diagnostic> {
    let key = |d: &Diagnostic| {
        let (src, at) = match d.at {
            Place::Source { id, span } => (id.0, span.start),
            Place::Foreign { file, span } => (u32::MAX - 1 - file, span.start),
            Place::Builtin => (u32::MAX, 0),
        };
        (d.code.severity, src, at)
    };
    d.sort_by_key(key);
    // The same diagnostic from two rounds is shown once.
    let mut seen = BTreeSet::new();
    d.iter()
        .filter(|x| {
            let place = match x.at {
                Place::Builtin => (0, 0, 0, 0),
                Place::Source { id, span } => (1, id.0, span.start, span.end),
                Place::Foreign { file, span } => (2, file, span.start, span.end),
            };
            seen.insert((
                x.code,
                place,
                x.args
                    .iter()
                    .map(|a| (a.name, a.value.as_str()))
                    .collect::<Vec<_>>(),
                x.fix
                    .as_ref()
                    .map(|f| (f.span.start, f.span.end, f.text.as_str())),
                &x.via,
            ))
        })
        .cloned()
        .collect()
}

/// Reads the config from `roots` (built-in first). `version` is this
/// bingsu's version. `auto` is retained for caller compatibility; the
/// snapshot holds both display palettes (S-11).
pub fn report<R: Into<Root>>(
    roots: Vec<R>,
    resolver: &mut dyn Resolver,
    version: [u32; 3],
    auto: Mode,
) -> ConfigReport {
    let mut loaded: LoadReport = match load(roots, resolver, version) {
        Ok(r) => r,
        Err(e) => {
            let mut d = e.errors;
            d.extend(e.warnings);
            return ConfigReport {
                files: e.files,
                order: Vec::new(),
                diagnostics: sorted(d),
                widths: Vec::new(),
                snapshot: None,
            };
        }
    };
    let mut skip: Vec<SourceId> = Vec::new();
    // What earlier rounds said about the sources they dropped: kept, so the
    // report shows why each was dropped and everything else it had.
    let mut dropped_notes: Vec<Diagnostic> = Vec::new();
    loop {
        let full = merge(&loaded, &skip, &keys::slot);
        let untrusted: Vec<SourceId> = loaded
            .files
            .iter()
            .filter(|f| f.trust != Trust::Executable)
            .map(|f| f.id)
            .collect();
        let trusted = merge(&loaded, &untrusted, &keys::slot);
        let mut diags = full.warnings.clone();
        diags.extend(check(&full));
        let mut compiled = None;
        if diags.iter().all(|d| d.severity() != Severity::Error) {
            match compile(&full, &trusted, auto) {
                Ok((c, notes)) => {
                    diags.extend(notes);
                    compiled = Some(c);
                }
                Err(errors) => diags.extend(errors),
            }
        }
        for d in &mut diags {
            if let Some(f) = source_of(d).and_then(|id| loaded.get(id)) {
                d.via = f.via.clone();
            }
        }
        // Errors placed in a shape-only source: drop it (and what it brought
        // in) and merge again.
        let mut drop = Vec::new();
        for d in diags.iter().filter(|d| d.severity() == Severity::Error) {
            if let Some(id) = source_of(d) {
                let shape = loaded.get(id).is_some_and(|f| f.trust == Trust::ShapeOnly);
                if shape && !skip.contains(&id) && !drop.contains(&id) {
                    drop.push(id);
                }
            }
        }
        if drop.is_empty() {
            for id in &skip {
                if let Some(f) = loaded.files.get_mut(id.0 as usize) {
                    f.status = Status::Dropped;
                }
            }
            let order: Vec<SourceId> = loaded
                .order
                .iter()
                .copied()
                .filter(|id| !skip.contains(id))
                .collect();
            let failed = diags.iter().any(|d| d.severity() == Severity::Error);
            // The width table does not wait for the snapshot: bands that
            // order are shown even when another key is wrong.
            let widths = match &compiled {
                Some(c) => c.widths.clone(),
                None => bands_of(&full).map(|b| b.widths).unwrap_or_default(),
            };
            let mut all = loaded.warnings;
            all.extend(dropped_notes);
            all.extend(diags);
            let snapshot = if failed { None } else { compiled };
            return ConfigReport {
                files: loaded.files,
                order,
                widths,
                diagnostics: sorted(all),
                snapshot,
            };
        }
        let mut gone: Vec<SourceId> = Vec::new();
        for id in drop {
            for k in below(&loaded.files, id) {
                // A trusted file is never dropped through another's error.
                if loaded.get(k).is_some_and(|f| f.trust != Trust::Executable)
                    && !skip.contains(&k)
                    && !gone.contains(&k)
                {
                    gone.push(k);
                }
            }
            let mut w = Diagnostic::new(
                codes::SHAPE_FILE_DROPPED,
                Place::Source {
                    id,
                    span: Default::default(),
                },
            );
            let first = diags
                .iter()
                .find(|d| d.severity() == Severity::Error && source_of(d) == Some(id));
            w = w.arg(
                "reason",
                first.map_or(alloc::string::String::new(), |d| {
                    alloc::format!("{}", d.code)
                }),
            );
            w.via = loaded.get(id).map(|f| f.via.clone()).unwrap_or_default();
            dropped_notes.push(w);
        }
        // Every diagnostic placed in what goes now, errors and warnings alike.
        dropped_notes.extend(
            diags
                .into_iter()
                .filter(|d| source_of(d).is_some_and(|s| gone.contains(&s))),
        );
        skip.extend(gone);
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::config::compile::{BUILTIN_TOML, NotRun};
    use crate::config::source::tests::{files, opened};
    use crate::config::source::{FileKey, Opened};
    use crate::diag::DiagCode;
    use alloc::vec;

    pub(crate) fn builtin() -> Opened {
        Opened {
            key: FileKey { dev: 0, ino: 0 },
            bytes: BUILTIN_TOML.as_bytes().to_vec(),
            trust: Trust::Executable,
            display: b"(built-in)".to_vec(),
        }
    }

    /// The built-in theme, then `root` (trusted), then the named files.
    pub(crate) fn read(root: &str, list: &[(&'static str, &str)]) -> ConfigReport {
        let mut f = files(list);
        report(
            vec![builtin(), opened("root", root, 1)],
            &mut f,
            [0, 3, 0],
            Mode::Dark,
        )
    }

    pub(crate) fn codes_of(r: &ConfigReport) -> Vec<DiagCode> {
        r.diagnostics.iter().map(|d| d.code).collect()
    }

    // 이것을 실패시키는 것: 같은 진단을 여러 번 보이거나 인자·수정·경로가 다른 진단까지 합치는 것.
    #[test]
    fn diagnostic_deduplication_keeps_distinct_messages() {
        let base = Diagnostic::new(codes::BAD_VALUE, Place::Builtin).arg("key", "icons");
        let other = Diagnostic::new(codes::BAD_VALUE, Place::Builtin).arg("key", "width");
        let mut fix = base.clone();
        fix.fix = Some(crate::diag::Fix {
            span: Default::default(),
            text: "unicode".into(),
        });
        let mut via = base.clone();
        via.via.push(SourceId(1));
        let got = sorted(alloc::vec![
            base.clone(),
            other.clone(),
            base.clone(),
            fix.clone(),
            via.clone()
        ]);
        assert_eq!(got, [base, other, fix, via]);
    }

    // 규칙 5를 합친 뒤에도: 모양 전용 파일의 타입·값·모르는 키·종류 오류와 컴파일 오류는 그 파일만 버린다.
    // 이것을 실패시키는 것: 모양 전용 파일의 오류로 snapshot을 막는 것, 버린 파일의 값을 남기는 것,
    // 신뢰 파일의 같은 오류를 경고로 낮추는 것.
    #[test]
    fn shape_only_errors_drop_only_that_file() {
        let bad = [
            "icons = 5\n",
            "[colors]\nmode = \"neon\"\n",
            "[width]\nambiguous = 3\n",
            "[layout.when.a]\nmin_cols = 1\n[layout.when.b]\nmin_cols = 1\n",
            "[colors.roles]\npath = \"no.such.color\"\n",
        ];
        for b in bad {
            let r = read(
                "extends = [\"shape-t\"]\n[style]\npreset = \"lean\"\n",
                &[("shape-t", b)],
            );
            assert!(r.snapshot.is_some(), "{b}: {:?}", codes_of(&r));
            assert!(codes_of(&r).contains(&codes::SHAPE_FILE_DROPPED), "{b}");
            assert_eq!(r.order.len(), 2, "{b}: the shape-only file is not applied");
            // The same text in the trusted root is an error.
            let r = read(b, &[]);
            assert!(r.snapshot.is_none(), "{b}");
        }
        // Unknown keys from a shape-only file are left out key by key.
        let r = read(
            "extends = [\"shape-t\"]\n",
            &[("shape-t", "nonsense = 1\nicons = \"nerd\"\n")],
        );
        assert_eq!(r.snapshot.unwrap().icons, crate::icons::IconSet::Nerd);
    }

    fn nodes_of(r: &ConfigReport) -> Vec<Vec<crate::template::compile::Node>> {
        let c = r
            .snapshot
            .as_ref()
            .unwrap_or_else(|| panic!("{:?}", codes_of(r)));
        c.variants[0].iter().map(|l| l.nodes().to_vec()).collect()
    }

    // 템플릿 안의 `custom/…`는 그 참조만 빠진다: 선언된 것은 N502, 선언 안 된 것은 W408. 참조가 그것뿐인 그룹도 빠진다.
    // 이것을 실패시키는 것: 템플릿의 참조를 선언 검사에서 빼는 것, 참조를 지우지 않고 컴파일해 설정을 거부하는 것,
    // 빈 그룹을 남기는 것(그룹은 참조가 있어야 컴파일된다), 다른 참조가 있는 그룹까지 지우는 것.
    #[test]
    fn custom_ids_in_a_template_drop_only_that_reference() {
        let decl = "[segment.\"custom/t\"]\nkind = \"text\"\ntext = \"hi\"\n";
        let tpl = |t: &str| alloc::format!("[style]\ntemplate = \"{t}\"\n");
        let want = nodes_of(&read(&tpl("{dir} {@group}<{git}>{@end}{@nl}{char}"), &[]));
        let with = "{@group}[{custom/t}]{@end}{dir} {@group}<{git}{custom/t.x}>{@end}{@nl}{char}";
        for (head, code) in [
            (decl, codes::CUSTOM_DRAWN_LATER),
            ("", codes::CUSTOM_UNDECLARED),
        ] {
            let r = read(&(alloc::string::String::from(head) + &tpl(with)), &[]);
            assert_eq!(nodes_of(&r), want, "{head}");
            assert!(codes_of(&r).contains(&code), "{head}: {:?}", codes_of(&r));
            assert_eq!(r.order.len(), 2);
        }
        // A theme template that names an undeclared one keeps the theme.
        let r = read("extends = [\"shape-t\"]\n", &[("shape-t", &tpl(with))]);
        assert_eq!(nodes_of(&r), want);
        assert!(codes_of(&r).contains(&codes::CUSTOM_UNDECLARED));
        assert!(!codes_of(&r).contains(&codes::SHAPE_FILE_DROPPED));
        assert_eq!(r.order.len(), 3);
    }

    // 테마는 모양을 바꿀 수 있지만 프롬프트를 지울 수는 없다: 모양 전용 템플릿이 필수 세그먼트(`char`·`dir`)를 하나도 그리지 않으면
    // 그 원본만 버리고 신뢰 레이아웃을 쓴다. 빈 템플릿, 선택 세그먼트만 남은 템플릿, 구간 템플릿 모두.
    // 이것을 실패시키는 것: 앵커 검사를 빼는 것, 그 검사를 신뢰 파일에도 거는 것, 필수 세그먼트 대신 아무 세그먼트나 앵커로 세는 것.
    #[test]
    fn a_theme_template_cannot_erase_the_prompt() {
        let trusted = read("", &[]).snapshot.unwrap();
        for theme in [
            "[style]\ntemplate = \"\"\n",
            "[style]\ntemplate = \"{git}{@group} {venv}{@end}\"\n",
            "[layout.when.narrow.style]\ntemplate = \"\"\n",
        ] {
            let r = read("extends = [\"shape-t\"]\n", &[("shape-t", theme)]);
            let c = r
                .snapshot
                .as_ref()
                .unwrap_or_else(|| panic!("{theme}: {:?}", codes_of(&r)));
            assert!(codes_of(&r).contains(&codes::SHAPE_FILE_DROPPED), "{theme}");
            assert_eq!(c.variants, trusted.variants, "{theme}");
        }
        // The user may write such a template for themselves.
        let r = read("[style]\ntemplate = \"{git}\"\n", &[]);
        assert!(r.snapshot.is_some() && !codes_of(&r).contains(&codes::SHAPE_FILE_DROPPED));
    }

    // 이것을 실패시키는 것: 출력 없는 불리언·없을 수 있는 필드 참조를 필수 앵커로 인정하는 것.
    #[test]
    fn fields_alone_are_not_required_anchors() {
        let trusted = read("", &[]).snapshot.unwrap();
        for template in ["{char.failed}", "{dir.path}", "{@group}{char.failed}{@end}"] {
            crate::template::compile::compile(template, crate::field::BUILTIN).unwrap();
            let theme = alloc::format!("[layout.when.narrow.style]\ntemplate = '{template}'\n");
            let r = read("extends = ['shape-t']\n", &[("shape-t", &theme)]);
            assert!(
                codes_of(&r).contains(&codes::SHAPE_FILE_DROPPED),
                "{template}"
            );
            assert_eq!(r.snapshot.unwrap(), trusted, "{template}");
        }
        for template in ["{char}", "{dir}", "{char.failed}{char}"] {
            crate::template::compile::compile(template, crate::field::BUILTIN).unwrap();
            let theme = alloc::format!("[layout.when.narrow.style]\ntemplate = '{template}'\n");
            let r = read("extends = ['shape-t']\n", &[("shape-t", &theme)]);
            assert!(r.snapshot.is_some());
            assert!(!codes_of(&r).contains(&codes::SHAPE_FILE_DROPPED));
        }
    }

    // 이것을 실패시키는 것: 생성에 사용한 frame/fill/separator의 출처를 잃어 신뢰 설정 전체를 거부하는 것.
    #[test]
    fn generated_template_overflow_isolates_style_option_origins() {
        let line = |ids: &[&str], right: &str| {
            alloc::format!(
                "[layout.line1]\nleft = [{}]\nright = [{right}]\n",
                ids.iter()
                    .map(|id| alloc::format!("'{id}'"))
                    .collect::<Vec<_>>()
                    .join(",")
            )
        };
        let frame_user = line(&vec!["dir"; 156], "");
        let separator_user = alloc::format!(
            "[style]\nseparator = 'flat'\n{}",
            line(&vec!["dir"; 157], "")
        );
        let mut fill_ids = vec!["dir"; 154];
        fill_ids[..3].fill("duration");
        fill_ids[3] = "status";
        let fill_user = alloc::format!("[layout]\nfill = 'dot'\n{}", line(&fill_ids, "'time'"));
        for (user, shape) in [
            (frame_user, "[layout]\nframe = 'line'\n"),
            (separator_user, "[style]\nseparator = 'triangle'\n"),
            (fill_user, "[layout]\nfill = 'space'\n"),
        ] {
            let baseline = read(&user, &[]).snapshot.unwrap();
            let r = read_late(&user, shape);
            assert!(
                codes_of(&r).contains(&codes::SHAPE_FILE_DROPPED),
                "{shape}: {:?}",
                r.diagnostics
            );
            assert_eq!(r.files[2].status, Status::Dropped);
            assert_eq!(r.order, [SourceId(0), SourceId(1)]);
            assert_eq!(r.snapshot.unwrap(), baseline, "{shape}");
        }
    }

    // 사용자 레이아웃이 테마의 사용자 세그먼트를 쓰는데 테마가 그 선언을 없애거나 테마가 통째로 빠지면,
    // 설정 전체가 아니라 그 세그먼트만 숨긴다(경고 W408).
    // 이것을 실패시키는 것: 선언 없는 참조를 오류로 내는 것.
    #[test]
    fn a_theme_that_drops_a_segment_hides_only_that_segment() {
        let user = "extends = [\"shape-t\"]\n[layout.line1]\nleft = [\"custom/t\", \"dir\"]\n";
        for theme in [
            "",
            "icons = 5\n[segment.\"custom/t\"]\nkind = \"text\"\ntext = \"hi\"\n",
        ] {
            let r = read(user, &[("shape-t", theme)]);
            assert!(r.snapshot.is_some(), "{theme}: {:?}", codes_of(&r));
            assert!(codes_of(&r).contains(&codes::CUSTOM_UNDECLARED), "{theme}");
        }
    }

    /// The built-in theme, the user's root, then a shape-only root after it.
    fn read_late(user: &str, shape: &str) -> ConfigReport {
        let mut f = files(&[]);
        report(
            vec![
                builtin(),
                opened("root", user, 1),
                opened("shape-late", shape, 2),
            ],
            &mut f,
            [0, 3, 0],
            Mode::Dark,
        )
    }

    // 모양 전용 파일이 고친 구간 값(`min_cols` 등) 때문에 난 구간 오류는 그 파일에 붙는다(보안 R-I1).
    // 이것을 실패시키는 것: 구간 오류를 구간 표를 처음 만든 원본(내장·사용자)에 붙이는 것.
    #[test]
    fn band_values_from_a_shape_only_file_drop_only_that_file() {
        for (user, shape) in [
            ("", "[layout.when.narrow]\nmin_cols = 60\n"),
            ("", "[layout.when.narrow]\nmin_cols = 100\nmax_cols = 59\n"),
            (
                "[layout.when.wide]\nmin_cols = 100\n",
                "[layout.when.wide]\nmin_cols = 1\n",
            ),
        ] {
            let r = read_late(user, shape);
            assert!(r.snapshot.is_some(), "{shape}: {:?}", codes_of(&r));
            assert!(codes_of(&r).contains(&codes::SHAPE_FILE_DROPPED), "{shape}");
        }
    }

    // 안전 검사에 실패한 파일의 내장 세그먼트 `enabled`는 수집을 다시 켜지 못한다(도구 I2).
    // 이것을 실패시키는 것: 내장 세그먼트 `enabled`의 출처를 보지 않는 것.
    #[test]
    fn unsafe_builtin_enabled_turns_the_segment_off() {
        let mut f = files(&[]);
        let r = report(
            vec![
                builtin(),
                opened("root", "[segment.git]\nenabled = false\n", 1),
                opened("unsafe-late", "[segment.git]\nenabled = true\n", 2),
            ],
            &mut f,
            [0, 3, 0],
            Mode::Dark,
        );
        let git = 1u32
            << crate::field::BUILTIN
                .iter()
                .position(|d| d.id == "git")
                .unwrap();
        assert_eq!(r.snapshot.as_ref().unwrap().collect_mask & git, 0);
        assert!(codes_of(&r).contains(&codes::NOT_RUN_UNSAFE_FILE));
    }

    // 재병합 전 회차의 진단(버린 파일의 실행 키 경고, 그 파일의 오류 여럿)이 보고에 남는다(도구 I3).
    // 이것을 실패시키는 것: 마지막 회차의 진단만 내는 것, 버린 파일의 첫 오류만 남기는 것.
    #[test]
    fn diagnostics_of_dropped_rounds_are_kept() {
        let shape =
            "icons = 5\n[width]\nambiguous = 3\n[segment.\"custom/k\"]\ncommand = [\"x\"]\n";
        let r = read_late("", shape);
        let c = codes_of(&r);
        assert!(r.snapshot.is_some());
        for want in [
            codes::WRONG_TYPE,
            codes::BAD_VALUE,
            codes::EXEC_KEY_IGNORED,
            codes::SHAPE_FILE_DROPPED,
        ] {
            assert!(c.contains(&want), "{want:?} in {c:?}");
        }
    }

    // 다른 키에 오류가 있어도 구간이 해석되면 폭 대입 표를 보인다(도구 I4).
    // 이것을 실패시키는 것: 폭 표를 snapshot 컴파일이 성공할 때만 채우는 것.
    #[test]
    fn the_width_table_survives_other_errors() {
        let r = read("icons = 5\n", &[]);
        assert!(r.snapshot.is_none());
        assert_eq!(r.widths.len(), 2);
    }

    fn runs(r: &ConfigReport) -> Vec<Option<NotRun>> {
        r.snapshot
            .as_ref()
            .unwrap()
            .exec_units
            .iter()
            .map(|u| u.not_run.clone())
            .collect()
    }

    const SEG: &str = "[segment.\"custom/k\"]\nkind = \"command\"\ncommand = [\"k\"]\n";

    // 이것을 실패시키는 것: 뒤 모양 원본의 enabled·템플릿·배열을 실행 승인으로 삼거나 Unsafe 별칭의 실행 출처를 잃는 것.
    #[test]
    fn late_shape_sources_and_unsafe_aliases_never_grant_execution() {
        let shown = "[layout.line1]\nleft = ['dir', 'custom/k']\n";
        let user = alloc::format!("{SEG}{shown}enabled = false\n");
        for shape in [
            "[layout.line1]\nenabled = true\n",
            "[style]\ntemplate = '{dir}{custom/k}'\n",
        ] {
            assert_eq!(
                runs(&read_late(&user, shape)),
                [Some(NotRun::NotInTrustedLayout)]
            );
        }
        for shape in [
            "[layout.line1]\nleft = ['dir']\n",
            "[layout.line1]\nenabled = false\n",
            "[style]\ntemplate = '{dir}'\n",
        ] {
            assert_eq!(
                runs(&read_late(&alloc::format!("{SEG}{shown}"), shape)),
                [Some(NotRun::NotInTrustedLayout)]
            );
        }
        for key in [
            "enabled = true",
            "enabled = {}",
            "kind = 'language'",
            "command = ['evil']",
            "timeout = '3600s'",
        ] {
            let user = alloc::format!("{SEG}enabled = false\n{shown}");
            let shape = alloc::format!("[segment.\"custom/k\"]\n{key}\n");
            let r = read_late(&user, &shape);
            assert_eq!(runs(&r), [Some(NotRun::Disabled)], "{key}");
            assert!(codes_of(&r).contains(&codes::EXEC_KEY_IGNORED));
        }
        // One identity first registered as a shape-only root, then Unsafe.
        let shape = opened("shape-alias", SEG, 2);
        let unsafe_file = opened("unsafe-alias", SEG, 2);
        let r = report(
            vec![builtin(), opened("root", shown, 1), shape, unsafe_file],
            &mut files(&[]),
            [0, 3, 0],
            Mode::Dark,
        );
        assert!(matches!(&runs(&r)[0], Some(NotRun::UnsafeFile { .. })));
        assert!(codes_of(&r).contains(&codes::NOT_RUN_UNSAFE_FILE));
    }

    // 이것을 실패시키는 것: 검사·컴파일 진단이 승리한 값의 원본·범위·extends 경로를 잃는 것.
    #[test]
    fn diagnostics_keep_winning_key_origins_and_chains() {
        let unsafe_text = "[segment.\"custom/k\"]\ntimeout = '5s'\n";
        let r = read(
            &alloc::format!("extends = ['parent']\n{SEG}[layout.line1]\nleft = ['custom/k']\n"),
            &[
                ("parent", "extends = ['unsafe-leaf']\n"),
                ("unsafe-leaf", unsafe_text),
            ],
        );
        let d = r
            .diagnostics
            .iter()
            .find(|d| d.code == codes::NOT_RUN_UNSAFE_FILE)
            .unwrap();
        let leaf = r
            .files
            .iter()
            .find(|f| f.opened.display == b"unsafe-leaf")
            .unwrap();
        let Place::Source { id, span } = d.at else {
            panic!()
        };
        assert_eq!(id, leaf.id);
        assert_eq!(
            &leaf.opened.bytes[span.start as usize..span.end as usize],
            b"'5s'"
        );
        assert_eq!(d.via, leaf.via);
        assert_eq!(d.via.len(), 2);
        let r = read(
            "extends = ['parent']\n",
            &[("parent", "extends = ['bad']\n"), ("bad", "icons = 5\n")],
        );
        let d = r
            .diagnostics
            .iter()
            .find(|d| d.code == codes::WRONG_TYPE)
            .unwrap();
        assert_eq!(d.via.len(), 2);
        let r = read(
            "[segment.\"custom/t\"]\nkind='text'\ntext='hi'\n[style]\ntemplate='{dir}{custom/t}'\n",
            &[],
        );
        let d = r
            .diagnostics
            .iter()
            .find(|d| d.code == codes::CUSTOM_DRAWN_LATER)
            .unwrap();
        assert!(matches!(
            d.at,
            Place::Source {
                id: SourceId(1),
                ..
            }
        ));
    }

    // 실행 집합 = 신뢰 출처가 그린 줄의 명령 ∩ 실제로 그려지는 줄의 명령.
    // 이것을 실패시키는 것: 모양 전용 파일이 줄을 켜거나(`enabled = true`) 명령을 더해 실행을 켜는 것,
    // 한쪽 배열을 바꿨다고 다른 쪽 신뢰 명령을 끄는 것, 숨긴 줄의 명령을 실행하는 것, 구간 줄을 빠뜨리는 것.
    #[test]
    fn execution_needs_a_trusted_and_drawn_reference() {
        let user = |extra: &str| alloc::format!("extends = [\"shape-t\"]\n{SEG}{extra}");
        // Trusted left, shape-only changes the right side: still runs.
        let r = read(
            &user("[layout.line1]\nleft = [\"custom/k\", \"dir\"]\n"),
            &[("shape-t", "[layout.line1]\nright = [\"time\"]\n")],
        );
        assert_eq!(runs(&r), [None]);
        // Trusted line turned off; shape-only turns it on: does not run.
        let r = read(
            &user("[layout.line1]\nleft = [\"custom/k\"]\nenabled = false\n"),
            &[("shape-t", "[layout.line1]\nenabled = true\n")],
        );
        assert_eq!(runs(&r), [Some(NotRun::NotInTrustedLayout)]);
        // Trusted line on; shape-only turns it off: hidden, does not run.
        let r = read(
            &user("[layout.line1]\nleft = [\"custom/k\"]\n"),
            &[("shape-t", "[layout.line1]\nenabled = false\n")],
        );
        assert_eq!(runs(&r), [Some(NotRun::NotInTrustedLayout)]);
        // Only a shape-only layout names it: does not run.
        let r = read(
            &user(""),
            &[("shape-t", "[layout.line1]\nleft = [\"custom/k\"]\n")],
        );
        assert_eq!(runs(&r), [Some(NotRun::NotInTrustedLayout)]);
        // A trusted band names it: runs.
        let r = read(
            &user(
                "[layout.when.wide]\nmin_cols = 100\n[layout.when.wide.line2]\nleft = [\"custom/k\", \"char\"]\n",
            ),
            &[("shape-t", "")],
        );
        assert_eq!(runs(&r), [None]);
        // A shape-only `enabled = {}` is left out at the merge.
        let r = read(
            &alloc::format!(
                "extends = [\"shape-t\"]\n{SEG}enabled = false\n[layout.line1]\nleft = [\"custom/k\"]\n"
            ),
            &[("shape-t", "[segment.\"custom/k\"]\nenabled = {}\n")],
        );
        assert_eq!(runs(&r), [Some(NotRun::Disabled)]);
    }

    // 이것을 실패시키는 것: 모양 전용 파일의 값 모양(표 대 값)을 키 표와 맞추지 않는 것
    // (`segment."custom/k" = 1`로 세그먼트를 지우거나 `command = {}`로 argv를 비움).
    #[test]
    fn shape_only_values_must_fit_the_table() {
        let user = alloc::format!("{SEG}[layout.line1]\nleft = [\"custom/k\"]\n");
        for shape in [
            "segment = 1\n",
            "[segment]\n\"custom/k\" = 1\n",
            "[segment.\"custom/k\"]\ncommand = {}\n",
        ] {
            let mut f = files(&[]);
            let r = report(
                vec![
                    builtin(),
                    opened("root", &user, 1),
                    opened("shape-late", shape, 2),
                ],
                &mut f,
                [0, 3, 0],
                Mode::Dark,
            );
            let c = r.snapshot.unwrap_or_else(|| panic!("{shape}"));
            assert!(
                r.diagnostics
                    .iter()
                    .any(|d| d.code == codes::EXEC_KEY_IGNORED),
                "{shape}"
            );
            assert!(
                !r.diagnostics
                    .iter()
                    .any(|d| d.code == codes::SHAPE_FILE_DROPPED),
                "{shape}"
            );
            assert!(
                matches!(&c.exec_units[0].policy, crate::config::compile::ExecPolicy::Command { argv, .. } if argv == &["k"]),
                "{shape}"
            );
            assert_eq!(c.exec_units[0].not_run, None, "{shape}");
        }
    }

    // 이것을 실패시키는 것: 발견한 파일을 catalog에서 빠뜨리는 것(진단 위치를 못 보임),
    // 단계마다의 경고를 보고에서 잃는 것.
    #[test]
    fn the_report_keeps_every_file_and_diagnostic() {
        let r = read(
            "extends = [\"shape-t\", \"broken\"]\n",
            &[("shape-t", "x = [\n"), ("broken", "y = [\n")],
        );
        assert!(r.snapshot.is_none());
        let names: Vec<&[u8]> = r
            .files
            .iter()
            .map(|f| f.opened.display.as_slice())
            .collect();
        assert_eq!(names, [&b"(built-in)"[..], b"root", b"shape-t", b"broken"]);
        assert!(codes_of(&r).contains(&codes::TOML_SYNTAX));
        assert!(codes_of(&r).contains(&codes::SHAPE_FILE_DROPPED));
        let r = read(
            "extends = [\"shape-t\"]\n",
            &[("shape-t", "[segment.\"custom/k\"]\nkind = \"env\"\n")],
        );
        assert!(
            codes_of(&r).contains(&codes::ENV_SEGMENT_IGNORED),
            "{:?}",
            codes_of(&r)
        );
        // Errors first.
        let sev: Vec<Severity> = r.diagnostics.iter().map(|d| d.severity()).collect();
        assert!(sev.windows(2).all(|w| w[0] <= w[1]));
    }

    // 폭 대입 표(S4): 모든 폭에 어느 구간이 쓰이는지와, 한 번도 쓰이지 않는 구간.
    // 이것을 실패시키는 것: 경계를 하나 어긋나게 나누거나, 완전히 가려진 구간을 알리지 않는 것.
    #[test]
    fn width_table_and_unreachable_bands() {
        let r = read("", &[]);
        let w: Vec<(u16, u16, Option<&str>)> = r
            .widths
            .iter()
            .map(|x| (x.from, x.to, x.band.as_deref()))
            .collect();
        assert_eq!(w, [(0, 59, Some("narrow")), (60, u16::MAX, None)]);
        // A band inside narrow with a lower order... narrow covers 0–59; a
        // user band 10–20 ordered after narrow is never chosen.
        let r = read(
            "[layout.when.inner]\nmin_cols = 10\nmax_cols = 20\norder = 2\n[layout.when.narrow]\norder = 1\n",
            &[],
        );
        assert!(
            codes_of(&r).contains(&codes::BAND_NEVER_CHOSEN),
            "{:?}",
            codes_of(&r)
        );
        let r = read("[layout.when.wide]\nmin_cols = 100\n", &[]);
        let w: Vec<(u16, u16, Option<&str>)> = r
            .widths
            .iter()
            .map(|x| (x.from, x.to, x.band.as_deref()))
            .collect();
        assert_eq!(
            w,
            [
                (0, 59, Some("narrow")),
                (60, 99, None),
                (100, u16::MAX, Some("wide"))
            ]
        );
    }
}
