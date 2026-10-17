//! `bingsu reload`: read the settings again now and publish them through the
//! same N2 engine, lock and source evidence as the refresh helper. Exit 0:
//! applied or already current; 1: the settings are invalid (the last good
//! ones stay); 2: usage; 3: not finished (busy, deadline, resources).
use super::{
    clock::SystemClock,
    ctx::{self, Applied, EXIT_FAILED, EXIT_UNFINISHED, EXIT_USAGE, User},
    messages::{MsgId, en},
};
use std::ffi::OsString;
use std::process::ExitCode;

/// The words for each way an application can end: stdout text for success,
/// stderr text and exit code otherwise.
pub fn report(applied: &Applied, what: &str) -> Result<String, (String, u8)> {
    match applied {
        Applied::Published {
            generation,
            left_out,
        } => {
            let mut text =
                format!("bingsu: {what}; new settings published (generation {generation})\n");
            for p in left_out {
                text.push_str(&format!(
                    "bingsu: left out, nothing in it runs: {}\n",
                    ctx::show(p)
                ));
            }
            Ok(text)
        }
        Applied::Unchanged { generation } => Ok(format!(
            "bingsu: {what}; the settings did not change (generation {generation})\n"
        )),
        Applied::Invalid => Err((en(MsgId::ReloadInvalid).to_owned(), EXIT_FAILED)),
        Applied::Busy => Err((en(MsgId::ReloadBusy).to_owned(), EXIT_UNFINISHED)),
        Applied::Incomplete => Err((en(MsgId::ReloadIncomplete).to_owned(), EXIT_UNFINISHED)),
        Applied::Unavailable(m) => Err((
            en(*m).to_owned(),
            if *m == MsgId::UnconfirmedRoot {
                EXIT_FAILED
            } else {
                EXIT_UNFINISHED
            },
        )),
    }
}

pub fn run(args: &[OsString]) -> ExitCode {
    if !args.is_empty() {
        eprintln!("usage: bingsu reload");
        return ctx::code(EXIT_USAGE);
    }
    let Some(started) = ctx::start() else {
        eprintln!("{}", en(MsgId::ReloadIncomplete));
        return ctx::code(EXIT_UNFINISHED);
    };
    let _deadline = match ctx::arm_deadline(
        ctx::COMMAND_LIMIT,
        format!("{}\n", en(MsgId::DeadlineReached)),
    ) {
        Ok(d) => d,
        Err(code) => return ctx::code(code),
    };
    let Some(user) = User::current() else {
        eprintln!("{}", en(MsgId::NoHome));
        return ctx::code(EXIT_FAILED);
    };
    let roots = match ctx::roots_for_publishing(&user) {
        Ok(r) => r,
        Err((text, code)) => {
            eprintln!("{text}");
            return ctx::code(code);
        }
    };
    let applied = ctx::apply(&roots, &user, started, &mut SystemClock);
    match report(&applied, "reloaded") {
        Ok(text) => {
            if ctx::print(&text) {
                ExitCode::SUCCESS
            } else {
                ctx::code(EXIT_FAILED)
            }
        }
        Err((text, code)) => {
            eprintln!("{text}");
            ctx::code(code)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    // 이것을 실패시키는 것: 끝 종류마다 종료 코드(확인된 실패 1, 미완료 3)를 바꾸는 것, 빠진 파일 경고에 경로 제어 바이트를 그대로 내는 것,
    // 빠진 파일을 알리지 않는 것.
    #[test]
    fn every_ending_has_its_words_and_exit_code() {
        let text = report(
            &Applied::Published {
                generation: 7,
                left_out: vec![PathBuf::from("/c/we\u{1b}[31mird.toml")],
            },
            "reloaded",
        )
        .unwrap();
        assert_eq!(
            text,
            "bingsu: reloaded; new settings published (generation 7)\nbingsu: left out, nothing in it runs: /c/we[31mird.toml\n"
        );
        assert_eq!(
            report(&Applied::Unchanged { generation: 7 }, "applied").unwrap(),
            "bingsu: applied; the settings did not change (generation 7)\n"
        );
        let code = |a: Applied| report(&a, "x").unwrap_err().1;
        assert_eq!(code(Applied::Invalid), 1);
        assert_eq!(code(Applied::Busy), 3);
        assert_eq!(code(Applied::Incomplete), 3);
        assert_eq!(code(Applied::Unavailable(MsgId::NoRuntimeRoot)), 3);
        assert_eq!(code(Applied::Unavailable(MsgId::UnconfirmedRoot)), 1);
    }
}
