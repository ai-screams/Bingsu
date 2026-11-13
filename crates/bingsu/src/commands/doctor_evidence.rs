//! The evidence a shell hands `bingsu doctor` on its standard input (the
//! shell function `bingsu_doctor`), and the checks made of it. Facts only a
//! shell has: its version, the order of its hook functions, the words the
//! last prompt call was given. Nothing here reads the environment, a path or
//! a file, and nothing starts a program.
//!
//! One record: ten fields ended by 0x1f, the record by 0x1e, at most 64 KiB.
//! A list field joins its items with 0x1d. The last field says whether the
//! shell had to replace a separator character found in a hook function name. A record that does not have this
//! shape is refused whole, and only the checks that needed it say so.
use super::doctor::{Finding, Status};
use bingsu_core::{diag_codes as codes, record::RecordVersion, sanitize::sanitize};

/// The most bytes of a record doctor reads (one more is read to see it is over).
pub(super) const MAX: usize = 64 * 1024;
const MAGIC: &[u8] = b"doctor-evidence-v1";
const FIELDS: usize = 10;

/// What the shell said.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Evidence {
    pub shell: Vec<u8>,
    pub version: Vec<u8>,
    /// The session id init made (32 lowercase hex digits), or what the
    /// shell passed in its place; the breaker check reads it, no other.
    pub session: Vec<u8>,
    pub ctx: Vec<u8>,
    pub record: Vec<u8>,
    pub precmd: Vec<Vec<u8>>,
    pub preexec: Vec<Vec<u8>>,
    pub envelope: Vec<Vec<u8>>,
    /// A hook function name held a separator character (0x1d, 0x1e or 0x1f):
    /// the shell replaced it, so the order of the hooks cannot be judged.
    pub separators: bool,
}

/// Whether the shell passed evidence.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Given {
    /// No `--evidence-stdin`: doctor was started outside the shell function.
    No,
    /// A record that is not one: the reason.
    Bad(&'static str),
    Yes(Evidence),
}

fn list(field: &[u8]) -> Vec<Vec<u8>> {
    if field.is_empty() {
        Vec::new()
    } else {
        field.split(|&b| b == 0x1d).map(<[u8]>::to_vec).collect()
    }
}

pub(super) fn parse(bytes: &[u8]) -> Given {
    if bytes.len() > MAX {
        return Given::Bad("it is longer than 64 KiB");
    }
    let Some(body) = bytes.strip_suffix(&[0x1e]) else {
        return Given::Bad("it does not end with its end mark");
    };
    if body.contains(&0x1e) {
        return Given::Bad("it holds more than one record");
    }
    let fields: Vec<&[u8]> = body.split(|&b| b == 0x1f).collect();
    if fields.len() != FIELDS {
        return Given::Bad("it does not have the ten fields");
    }
    if fields[0] != MAGIC {
        return Given::Bad("it is not a record of this version");
    }
    let separators = match fields[9] {
        b"" => false,
        b"1" => true,
        _ => return Given::Bad("its last field is neither empty nor 1"),
    };
    Given::Yes(Evidence {
        shell: fields[1].to_vec(),
        version: fields[2].to_vec(),
        session: fields[3].to_vec(),
        ctx: fields[4].to_vec(),
        record: fields[5].to_vec(),
        precmd: list(fields[6]),
        preexec: list(fields[7]),
        envelope: list(fields[8]),
        separators,
    })
}

fn shown(b: &[u8]) -> String {
    let cut = &b[..b.len().min(80)];
    sanitize(cut)
}

const ASK: &str = "run the shell function bingsu_doctor in your shell to check this";

fn without(given: &Given, what: &str) -> Option<Finding> {
    match given {
        Given::No => Some(Finding {
            status: Status::Unknown,
            text: format!("{what} not confirmed: no shell passed it; {ASK}"),
            fix: None,
        }),
        Given::Bad(why) => Some(Finding {
            status: Status::Unknown,
            text: format!("{what} not confirmed: the shell's evidence is refused ({why})"),
            fix: None,
        }),
        Given::Yes(_) => None,
    }
}

fn found(status: Status, text: String, fix: Option<bingsu_core::diag::DiagCode>) -> Finding {
    Finding { status, text, fix }
}

// ---- the session ---------------------------------------------------------------------

/// The session id the shell passed, in the shape of one (so it can stand in a
/// path), or the finding that says it is not there. The breaker check reads
/// the breaker of this session and of no other.
pub(super) fn session_of(given: &Given) -> Result<Vec<u8>, Finding> {
    if let Some(f) = without(given, "the collection breaker") {
        return Err(f);
    }
    let Given::Yes(e) = given else {
        unreachable!("`without` answered every other case")
    };
    if super::collection_breaker::session_valid(&e.session) {
        Ok(e.session.clone())
    } else {
        Err(found(
            Status::Unknown,
            "the collection breaker is not confirmed: the shell passed no session id of the right shape, and the breaker of another session is never shown in its place".into(),
            None,
        ))
    }
}

// ---- shell and its version -----------------------------------------------------

/// `major.minor` at the start of what the shell reported, or `None`.
fn major_minor(version: &[u8]) -> Option<(u32, u32)> {
    let text = std::str::from_utf8(version).ok()?;
    let mut parts = text.split('.');
    let major: u32 = parts.next()?.parse().ok()?;
    let minor_text = parts.next()?;
    let digits: String = minor_text
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    Some((major, digits.parse().ok()?))
}

pub(super) fn judge_shell(given: &Given) -> Finding {
    if let Some(f) = without(given, "shell version") {
        return f;
    }
    let Given::Yes(e) = given else {
        unreachable!("`without` answered every other case")
    };
    if e.shell != b"zsh" {
        return found(
            Status::Unknown,
            format!("shell {} is not one this check knows", shown(&e.shell)),
            None,
        );
    }
    match major_minor(&e.version) {
        None => found(
            Status::Unknown,
            format!(
                "zsh reported a version that is not read as numbers: {}",
                shown(&e.version)
            ),
            None,
        ),
        Some((major, minor)) if (major, minor) < (5, 8) => found(
            Status::Warn,
            format!(
                "zsh {} is older than 5.8, the oldest bingsu is tested with",
                shown(&e.version)
            ),
            Some(codes::ZSH_TOO_OLD),
        ),
        Some(_) => found(
            Status::Ok,
            format!("zsh {} (as the shell reported it)", shown(&e.version)),
            None,
        ),
    }
}

// ---- hook compatibility ----------------------------------------------------------

pub(super) fn judge_compat(given: &Given) -> Finding {
    if let Some(f) = without(given, "hook compatibility") {
        return f;
    }
    let Given::Yes(e) = given else {
        unreachable!("`without` answered every other case")
    };
    let record_ok = RecordVersion::parse(&e.record).is_some();
    let ctx_ok = e.ctx == b"1";
    if record_ok && ctx_ok {
        return found(
            Status::Ok,
            format!(
                "the hook asks for record {} and envelope {}, which this bingsu reads",
                shown(&e.record),
                shown(&e.ctx)
            ),
            None,
        );
    }
    found(
        Status::Fail,
        format!(
            "the hook asks for record {} and envelope {}; this bingsu reads record B1 and envelope 1",
            shown(&e.record),
            shown(&e.ctx)
        ),
        Some(codes::RECORD_VERSION_UNSUPPORTED),
    )
}

// ---- hook order --------------------------------------------------------------------

const SAVE: &[u8] = b"_bingsu_save";
const INSTALL: &[u8] = b"_bingsu_install";
const PREEXEC: &[u8] = b"_bingsu_preexec";

pub(super) fn judge_order(given: &Given) -> Finding {
    if let Some(f) = without(given, "hook order") {
        return f;
    }
    let Given::Yes(e) = given else {
        unreachable!("`without` answered every other case")
    };
    if e.separators {
        return found(
            Status::Unknown,
            "hook order not confirmed: a hook function name holds a separator character, which the shell's record cannot carry".into(),
            None,
        );
    }
    let times =
        |list: &[Vec<u8>], name: &[u8]| list.iter().filter(|f| f.as_slice() == name).count();
    let mut problems: Vec<String> = Vec::new();
    match e.precmd.first() {
        Some(f) if f == SAVE => {}
        Some(f) => problems.push(format!(
            "the first precmd function is {}, not _bingsu_save",
            shown(f)
        )),
        None => problems.push("there are no precmd functions".into()),
    }
    match e.precmd.last() {
        Some(l) if l == INSTALL => {}
        Some(l) => problems.push(format!(
            "the last precmd function is {}, not _bingsu_install",
            shown(l)
        )),
        None => {}
    }
    // Once each: a second copy draws the prompt twice or runs the capture again.
    for (list, name, label) in [
        (&e.precmd, SAVE, "precmd"),
        (&e.precmd, INSTALL, "precmd"),
        (&e.preexec, PREEXEC, "preexec"),
    ] {
        match times(list, name) {
            1 => {}
            0 if label == "preexec" => {
                problems.push("_bingsu_preexec is not a preexec function".into())
            }
            0 => {}
            n => problems.push(format!("{} is in {label} {n} times, not once", shown(name))),
        }
    }
    if problems.is_empty() {
        return found(
            Status::Ok,
            "the capture hook is first and the install hook is last in precmd, each once".into(),
            None,
        );
    }
    found(
        Status::Warn,
        problems.join("; "),
        Some(codes::HOOK_ORDER_CHANGED),
    )
}

// ---- the envelope --------------------------------------------------------------------

const ORDER: [&[u8]; 5] = [
    b"--width",
    b"--status",
    b"--pipestatus",
    b"--jobs",
    b"--keymap",
];

pub(super) fn judge_envelope(given: &Given) -> Finding {
    if let Some(f) = without(given, "the last envelope") {
        return f;
    }
    let Given::Yes(e) = given else {
        unreachable!("`without` answered every other case")
    };
    if e.envelope.is_empty() {
        return found(
            Status::Unknown,
            "no prompt has been drawn in this shell yet, so there is no envelope to show".into(),
            None,
        );
    }
    let words: &[Vec<u8>] = &e.envelope;
    let mut problem: Option<String> = None;
    if words.len() % 2 != 0 {
        problem = Some("a word has no value".into());
    }
    let mut keys: Vec<&[u8]> = ORDER.to_vec();
    if words.len() >= 12 {
        keys.push(b"--duration-ms");
    }
    if problem.is_none() && words.len() != keys.len() * 2 {
        problem = Some(format!(
            "it has {} fields, expected {} or {}",
            words.len() / 2,
            ORDER.len(),
            ORDER.len() + 1
        ));
    }
    if problem.is_none() {
        for (i, key) in keys.iter().enumerate() {
            let k = &words[2 * i];
            if k != key {
                problem = Some(format!(
                    "field {} is {}, expected {}",
                    i + 1,
                    shown(k),
                    sanitize(key)
                ));
                break;
            }
        }
    }
    // The values are judged by the parser the prompt uses, not by a second set of rules here.
    if problem.is_none() {
        let mut argv: Vec<&[u8]> = vec![b"--ctx", b"1", b"--record", b"B1"];
        argv.extend(words.iter().map(Vec::as_slice));
        if let Err(err) = bingsu_core::envelope::parse(&argv) {
            problem = Some(format!("the prompt would refuse it: {err:?}"));
        }
    }
    let line: Vec<String> = words.iter().map(|w| shown(w)).collect();
    match problem {
        None => found(
            Status::Ok,
            format!("the last prompt call was given {}", line.join(" ")),
            None,
        ),
        Some(p) => found(
            Status::Warn,
            format!("the last prompt call was given {}: {p}", line.join(" ")),
            Some(codes::ENVELOPE_UNEXPECTED),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(fields: [&str; 10]) -> Vec<u8> {
        let mut out = fields.join("\x1f").into_bytes();
        out.push(0x1e);
        out
    }

    fn good() -> [&'static str; 10] {
        [
            "doctor-evidence-v1",
            "zsh",
            "5.9",
            "0123456789abcdef0123456789abcdef",
            "1",
            "B1",
            "_bingsu_save\x1dother\x1d_bingsu_install",
            "_bingsu_preexec",
            "--width\x1d80\x1d--status\x1d0\x1d--pipestatus\x1d0\x1d--jobs\x1d0\x1d--keymap\x1dmain",
            "",
        ]
    }

    fn given(f: [&str; 10]) -> Given {
        parse(&record(f))
    }

    fn is(f: &Finding, status: Status, code: Option<bingsu_core::diag::DiagCode>) {
        assert_eq!((f.status, f.fix), (status, code), "{}", f.text);
    }

    // 이것을 실패시키는 것: 끝 표지·필드 수·버전 머리·크기 상한·두 번째 레코드를 검사하지 않는 것, 목록 구분자를 못 가르는 것.
    #[test]
    fn a_record_is_refused_unless_it_has_the_shape() {
        let Given::Yes(e) = given(good()) else {
            panic!("the good record parses")
        };
        assert_eq!(e.precmd.len(), 3);
        assert_eq!(e.envelope.len(), 10);
        let mut no_end = record(good());
        no_end.pop();
        let mut two = record(good());
        two.extend(record(good()));
        let mut few = good();
        few[8] = "";
        let nine = [good()[..9].join("\x1f").into_bytes(), vec![0x1e]].concat();
        let mut flag = good();
        flag[9] = "yes";
        let mut other = good();
        other[0] = "doctor-evidence-v2";
        let big = vec![b'a'; MAX + 1];
        for bad in [no_end, two, nine, record(other), record(flag), big] {
            assert!(matches!(parse(&bad), Given::Bad(_)), "{bad:?}");
        }
        // An empty list field is an empty list, not a list of one empty name.
        let Given::Yes(e) = given(few) else { panic!() };
        assert!(e.envelope.is_empty());
    }

    // 이것을 실패시키는 것: 증거 없음·형식 오류를 정상으로 매기는 것, 5.8 미만을 정상으로, 버전 글자를 숫자로 못 읽을 때 경고로 매기는 것.
    #[test]
    fn the_shell_version_is_only_what_the_shell_said() {
        is(&judge_shell(&Given::No), Status::Unknown, None);
        is(&judge_shell(&Given::Bad("x")), Status::Unknown, None);
        for v in ["5.8", "5.9", "5.9.0.1-dev", "6.0"] {
            let mut f = good();
            f[2] = v;
            is(&judge_shell(&given(f)), Status::Ok, None);
        }
        for v in ["5.7.1", "4.3.17"] {
            let mut f = good();
            f[2] = v;
            is(
                &judge_shell(&given(f)),
                Status::Warn,
                Some(codes::ZSH_TOO_OLD),
            );
        }
        for v in ["", "five", "/opt/zsh/5.9"] {
            let mut f = good();
            f[2] = v;
            is(&judge_shell(&given(f)), Status::Unknown, None);
        }
        let mut f = good();
        f[1] = "fish";
        is(&judge_shell(&given(f)), Status::Unknown, None);
    }

    // 이것을 실패시키는 것: 모르는 레코드·봉투 버전을 정상으로 매기는 것.
    #[test]
    fn a_hook_asking_for_another_record_fails() {
        is(&judge_compat(&given(good())), Status::Ok, None);
        for (ctx, rec) in [("2", "B1"), ("1", "B2"), ("1", "")] {
            let mut f = good();
            f[4] = ctx;
            f[5] = rec;
            is(
                &judge_compat(&given(f)),
                Status::Fail,
                Some(codes::RECORD_VERSION_UNSUPPORTED),
            );
        }
        is(&judge_compat(&Given::No), Status::Unknown, None);
    }

    // 이것을 실패시키는 것: 저장 hook이 맨 앞이 아니거나 설치 hook이 맨 끝이 아니거나 preexec hook이 없어도 정상으로 매기는 것,
    // 가로챈 함수 이름을 문구에서 빼는 것.
    #[test]
    fn hook_order_names_what_moved() {
        is(&judge_order(&given(good())), Status::Ok, None);
        let mut f = good();
        f[6] = "other\x1d_bingsu_save\x1d_bingsu_install";
        let w = judge_order(&given(f));
        is(&w, Status::Warn, Some(codes::HOOK_ORDER_CHANGED));
        assert!(
            w.text.contains("first precmd function is other"),
            "{}",
            w.text
        );
        let mut f = good();
        f[6] = "_bingsu_save\x1d_bingsu_install\x1dlate";
        let w = judge_order(&given(f));
        is(&w, Status::Warn, Some(codes::HOOK_ORDER_CHANGED));
        assert!(
            w.text.contains("last precmd function is late"),
            "{}",
            w.text
        );
        let mut f = good();
        f[7] = "";
        is(
            &judge_order(&given(f)),
            Status::Warn,
            Some(codes::HOOK_ORDER_CHANGED),
        );
        let mut f = good();
        f[6] = "";
        is(
            &judge_order(&given(f)),
            Status::Warn,
            Some(codes::HOOK_ORDER_CHANGED),
        );
    }

    // 이것을 실패시키는 것: bingsu hook 함수가 두 번 들어 있어도 순서를 정상으로 보는 것(설치 hook 둘 = 프롬프트 두 번),
    // 구분 글자가 든 이름에서 순서를 판정하는 것(모름이어야 한다), 플래그 없는 레코드를 모름으로 보는 것.
    #[test]
    fn a_hook_twice_is_a_problem_and_a_separator_is_unknown() {
        for (precmd, preexec, what) in [
            (
                "_bingsu_save\x1d_bingsu_install\x1dplugin\x1d_bingsu_install",
                "_bingsu_preexec",
                "_bingsu_install is in precmd 2 times",
            ),
            (
                "_bingsu_save\x1d_bingsu_save\x1d_bingsu_install",
                "_bingsu_preexec",
                "_bingsu_save is in precmd 2 times",
            ),
            (
                "_bingsu_save\x1d_bingsu_install",
                "_bingsu_preexec\x1d_bingsu_preexec",
                "_bingsu_preexec is in preexec 2 times",
            ),
        ] {
            let mut f = good();
            f[6] = precmd;
            f[7] = preexec;
            let w = judge_order(&given(f));
            is(&w, Status::Warn, Some(codes::HOOK_ORDER_CHANGED));
            assert!(w.text.contains(what), "{}", w.text);
        }
        let mut f = good();
        f[9] = "1";
        let w = judge_order(&given(f));
        is(&w, Status::Unknown, None);
        assert!(w.text.contains("separator"), "{}", w.text);
    }

    // 이것을 실패시키는 것: 필드를 빼거나 순서를 바꾸거나 값 모양을 바꾼 봉투를 정상으로 매기는 것, 선택 필드(`--duration-ms`)를
    // 거부하는 것, 봉투가 아직 없을 때를 경고로 매기는 것.
    #[test]
    fn the_envelope_must_have_the_known_fields() {
        is(&judge_envelope(&given(good())), Status::Ok, None);
        let with_duration = "--width\x1d80\x1d--status\x1d0\x1d--pipestatus\x1d0,1\x1d--jobs\x1d2\x1d--keymap\x1dvicmd\x1d--duration-ms\x1d15";
        let mut f = good();
        f[8] = with_duration;
        is(&judge_envelope(&given(f)), Status::Ok, None);
        let mut f = good();
        f[8] = "";
        is(&judge_envelope(&given(f)), Status::Unknown, None);
        let sixty_five = vec!["0"; 65].join(",");
        let long_pipestatus = format!(
            "--width\x1d80\x1d--status\x1d0\x1d--pipestatus\x1d{sixty_five}\x1d--jobs\x1d0\x1d--keymap\x1dmain"
        );
        let mut f = good();
        f[8] = &long_pipestatus;
        is(
            &judge_envelope(&given(f)),
            Status::Warn,
            Some(codes::ENVELOPE_UNEXPECTED),
        );
        for bad in [
            // a field gone
            "--width\x1d80\x1d--status\x1d0\x1d--pipestatus\x1d0\x1d--keymap\x1dmain",
            // swapped
            "--status\x1d0\x1d--width\x1d80\x1d--pipestatus\x1d0\x1d--jobs\x1d0\x1d--keymap\x1dmain",
            // a value the prompt's parser refuses (a width it cannot read is only "unknown" to it, so it is not here)
            "--width\x1d80\x1d--status\x1d0\x1d--pipestatus\x1d0\x1d--jobs\x1d0\x1d--keymap\x1dMAIN",
            // numbers the prompt's own parser refuses (what the hook never sends, but a rewriter could)
            "--width\x1d80\x1d--status\x1d256\x1d--pipestatus\x1d0\x1d--jobs\x1d0\x1d--keymap\x1dmain",
            "--width\x1d80\x1d--status\x1d0\x1d--pipestatus\x1d256\x1d--jobs\x1d0\x1d--keymap\x1dmain",
            "--width\x1d80\x1d--status\x1d0\x1d--pipestatus\x1d0\x1d--jobs\x1d9999999999\x1d--keymap\x1dmain",
            // an extra field that is not --duration-ms
            "--width\x1d80\x1d--status\x1d0\x1d--pipestatus\x1d0\x1d--jobs\x1d0\x1d--keymap\x1dmain\x1d--x\x1d1",
            // a word with no value
            "--width\x1d80\x1d--status",
        ] {
            let mut f = good();
            f[8] = bad;
            is(
                &judge_envelope(&given(f)),
                Status::Warn,
                Some(codes::ENVELOPE_UNEXPECTED),
            );
        }
    }

    // 이것을 실패시키는 것: 증거의 제어 문자를 문구에 그대로 내보내는 것.
    #[test]
    fn evidence_is_sanitized_when_shown() {
        let mut f = good();
        f[2] = "5.9\u{1b}[2J";
        let t = judge_shell(&given(f)).text;
        assert!(!t.contains('\u{1b}'), "{t:?}");
    }
}
