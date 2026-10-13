//! Layer 1 property (spec section 3 "긴 이름 줄이기"): every built-in
//! shortener result passes core's own validation, for any names.
use bingsu_core::shorten::{
    Anchor, Keep, Method, PathFacts, ShortenRequest, Source, run_builtin, shorten, validate,
};
use bingsu_core::width::WidthProfile;
use proptest::prelude::*;

/// Names mixing ASCII, Hangul (precomposed and NFD), combining marks,
/// ambiguous-width, emoji sequences, private use and control bytes.
fn name() -> impl Strategy<Value = Vec<u8>> {
    let atoms = prop::sample::select(vec![
        "a",
        "Z",
        "-",
        "/",
        "%",
        "!",
        "한",
        "\u{1112}\u{1161}\u{11AB}",
        "e\u{0301}",
        "\u{2026}",
        "\u{2500}",
        "\u{1F600}",
        "\u{1F3F3}\u{FE0F}\u{200D}\u{1F308}",
        "\u{1F1F0}\u{1F1F7}",
        "\u{E0B0}",
        "\u{1b}[31m",
        "\u{202E}",
        "\u{FFFD}",
    ]);
    prop::collection::vec(atoms, 0..40).prop_map(|v| v.concat().into_bytes())
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, ..ProptestConfig::default() })]

    // 이것을 실패시키는 것: 내장 줄이기 방식이 core의 검증(원래 없는 글자, 빈 조각)을 통과하지 못하는 결과를 내는 것.
    #[test]
    fn builtin_results_validate(steps in prop::collection::vec(name(), 1..8), text in name(), m in 0usize..6) {
        let raw: Vec<&[u8]> = steps.iter().map(Vec::as_slice).collect();
        let f = PathFacts::new(Anchor::Root, &raw, Some(0), &[]);
        let method = [Method::None, Method::Depth(2), Method::Abbrev(1), Method::Unique, Method::Repo, Method::Truncate { max: 8, keep: Keep::End }][m];
        let clean = bingsu_core::sanitize::sanitize(&text);
        for source in [Source::Path(&f), Source::Text(&clean)] {
            let req = ShortenRequest { source, budget: u32::MAX, profile: WidthProfile::DEFAULT, method };
            if let Some(r) = run_builtin(&req) {
                if r.text().is_empty() { continue; }
                prop_assert!(validate(&req, &r).is_ok(), "{:?} {:?}", method, r);
            }
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 128, ..ProptestConfig::default() })]

    // Folder names are outside input: any bytes (unsanitized, invalid UTF-8,
    // multi-byte boundaries, very long) must neither panic nor give a result
    // over the budget.
    // 이것을 실패시키는 것: 줄이기 사슬이 칸 상한(budget 이하 또는 가장 좁은 유효 결과)을 넘기거나 정제를 건너뛰는 것.
    #[test]
    fn hostile_bytes_stay_bounded(
        steps in prop::collection::vec(prop::collection::vec(any::<u8>(), 0..300), 0..12),
        long in 0usize..3,
        budget in 1u32..80,
        repo in prop::option::of(0usize..14),
    ) {
        let mut steps = steps;
        if long > 0 {
            // One name far past the 4,096-cell cap, built from multi-byte chars.
            steps.push("\u{D55C}\u{1F3F3}\u{FE0F}\u{200D}\u{1F308}e\u{0301}".repeat(1500 * long).into_bytes());
        }
        let raw: Vec<&[u8]> = steps.iter().map(Vec::as_slice).collect();
        let f = PathFacts::new(Anchor::Home, &raw, repo, &[]);
        let methods = [
            Method::Repo,
            Method::Unique,
            Method::Abbrev(1),
            Method::Depth(1),
            Method::Truncate { max: 40, keep: Keep::End },
        ];
        for profile in [WidthProfile::DEFAULT, WidthProfile::new(2, 2).unwrap()] {
            if let Some((r, i, w)) = shorten(Source::Path(&f), &methods, budget, profile) {
                let req = ShortenRequest { source: Source::Path(&f), budget: u32::MAX, profile, method: methods[i] };
                prop_assert_eq!(validate(&req, &r), Ok(w));
                // Never wider than the narrowest chain member: the last
                // method (truncate, max 40) caps every result at 40 cells.
                prop_assert!(w <= budget.max(40), "w={} budget={}", w, budget);
            }
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 48, ..ProptestConfig::default() })]

    // `unique` with siblings: sanitize twins, an entry equal to the step,
    // 255/256/257 raw entries and names of 4,095/4,096/4,097 cells. The
    // result validates, and when every step has 257 raw entries (past the
    // reader's stop) it equals `abbrev 1`.
    // 이것을 실패시키는 것: 형제 상한(256) 경계를 틀리게 두는 것, 정제 충돌·긴 이름에서 검증을 통과하지 못하는 결과를 내는 것.
    #[test]
    fn unique_with_siblings_validates(
        steps in prop::collection::vec(prop::collection::vec(any::<u8>(), 1..40), 1..5),
        name_len in prop::sample::select(vec![0usize, 4095, 4096, 4097]),
        total in prop::sample::select(vec![1usize, 2, 255, 256, 257]),
    ) {
        let mut steps = steps;
        if name_len > 0 {
            let at = steps.len() - 1;
            steps.insert(at, vec![b'a'; name_len]);
        }
        let raw: Vec<&[u8]> = steps.iter().map(Vec::as_slice).collect();
        let lists: Vec<Vec<Vec<u8>>> = steps
            .iter()
            .map(|me| {
                let mut v = vec![me.clone()];
                let mut twin = me.clone();
                twin.push(0x1b);
                v.push(twin);
                let mut i = 0u32;
                while v.len() < total {
                    let mut o = me.clone();
                    o.extend_from_slice(&i.to_le_bytes());
                    v.push(o);
                    i += 1;
                }
                v.truncate(total.max(1));
                v
            })
            .collect();
        let refs: Vec<Vec<&[u8]>> = lists.iter().map(|l| l.iter().map(Vec::as_slice).collect()).collect();
        let sibs: Vec<Option<&[&[u8]]>> = refs.iter().map(|r| Some(r.as_slice())).collect();
        let f = PathFacts::new(Anchor::Root, &raw, None, &sibs);
        let req = ShortenRequest { source: Source::Path(&f), budget: u32::MAX, profile: WidthProfile::DEFAULT, method: Method::Unique };
        let r = run_builtin(&req).unwrap();
        prop_assert!(validate(&req, &r).is_ok(), "{:?}", r);
        if total == 257 {
            let ab = ShortenRequest { method: Method::Abbrev(1), ..req };
            prop_assert_eq!(r, run_builtin(&ab).unwrap());
        }
    }
}

/// Like `name` without "/" (a step is one path component) and with the
/// sequences where byte and grapheme prefixes differ.
fn seg() -> impl Strategy<Value = Vec<u8>> {
    let atoms = prop::sample::select(vec![
        "a",
        "b",
        "e",
        "e\u{0301}",
        "\u{0301}",
        "\u{1F1F0}",
        "\u{1F1F0}\u{1F1F7}",
        "\u{1F468}",
        "\u{1F468}\u{200D}\u{1F469}",
        "\u{1112}\u{1161}\u{11AB}",
        "\u{1b}",
        "\u{7f}",
        "\u{FFFD}",
        "%",
    ]);
    prop::collection::vec(atoms, 1..6).prop_map(|v| v.concat().into_bytes())
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, ..ProptestConfig::default() })]

    // The unique prefix is a byte-exact property: unless the whole name is
    // returned, no other sibling (after sanitizing) starts with it.
    // 이것을 실패시키는 것: grapheme 문자열 단위 LCP, LCP 경계 off-by-one(반환한 접두사로 시작하는 형제가 남음).
    #[test]
    fn unique_prefix_matches_no_sibling(
        steps in prop::collection::vec(seg(), 2..5),
        others in prop::collection::vec(seg(), 0..5),
        cuts in prop::collection::vec(0usize..8, 0..4),
    ) {
        let lists: Vec<Vec<Vec<u8>>> = steps
            .iter()
            .map(|me| {
                let mut v = vec![me.clone()];
                v.extend(others.iter().cloned());
                for &c in &cuts {
                    // A byte prefix of the step (may cut inside a grapheme or a code point).
                    v.push(me[..c.min(me.len())].to_vec());
                    let mut ext = me.clone();
                    ext.extend_from_slice(&others.first().cloned().unwrap_or_default());
                    v.push(ext);
                }
                v
            })
            .collect();
        let refs: Vec<Vec<&[u8]>> = lists.iter().map(|l| l.iter().map(Vec::as_slice).collect()).collect();
        let mut sibs: Vec<Option<&[&[u8]]>> = refs.iter().map(|r| Some(r.as_slice())).collect();
        let raw: Vec<&[u8]> = steps.iter().map(Vec::as_slice).collect();
        sibs[0] = Some(refs[0].as_slice());
        let f = PathFacts::new(Anchor::Root, &raw, None, &sibs);
        let req = ShortenRequest { source: Source::Path(&f), budget: u32::MAX, profile: WidthProfile::DEFAULT, method: Method::Unique };
        let r = run_builtin(&req).unwrap();
        prop_assert!(validate(&req, &r).is_ok());
        let clean = |b: &[u8]| { let s = bingsu_core::sanitize::sanitize(b); if s.is_empty() { "\u{FFFD}".to_string() } else { s } };
        let text = r.text();
        let parts: Vec<&str> = text.split('/').skip(1).collect();
        prop_assert_eq!(parts.len(), steps.len());
        for (i, me) in steps.iter().enumerate().take(steps.len() - 1) {
            let full = clean(me);
            if parts[i] == full { continue; }
            let mut dropped = false;
            for o in &lists[i] {
                if !dropped && o == me { dropped = true; continue; }
                prop_assert!(!clean(o).starts_with(parts[i]), "step {} piece {:?} sibling {:?}", i, parts[i], clean(o));
            }
        }
    }
}
