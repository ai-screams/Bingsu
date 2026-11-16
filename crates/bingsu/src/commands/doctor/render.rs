//! The table and JSON forms of the rows, and the exit code.
use super::*;

// ---- output ----------------------------------------------------------------------

/// The text of a run: one line per check and a summary line.
pub(super) fn render(rows: &[(&Item, Finding)]) -> String {
    use std::fmt::Write as _;
    let mut out = String::from("bingsu doctor\n");
    for (item, f) in rows {
        let code = f
            .fix
            .map(|c| format!(" ({c}; bingsu help {c})"))
            .unwrap_or_default();
        let _ = writeln!(
            out,
            "  {:<8}{:<16}{}{}",
            f.status.word(),
            item.title,
            sanitize(f.text.as_bytes()),
            code
        );
    }
    let n = |s: Status| rows.iter().filter(|(_, f)| f.status == s).count();
    let _ = writeln!(
        out,
        "result: {} ok, {} warning(s), {} failed, {} unknown, {} skipped",
        n(Status::Ok),
        n(Status::Warn),
        n(Status::Fail),
        n(Status::Unknown),
        n(Status::Skipped)
    );
    out
}

/// 1 when any check failed, else 0 (a warning or an unknown is not a failure).
pub(super) fn exit_of(rows: &[(&Item, Finding)]) -> u8 {
    u8::from(rows.iter().any(|(_, f)| f.status == Status::Fail))
}

fn write_details(w: &mut bingsu_core::diag_json::Writer, d: &Details) {
    w.key("details").begin_object();
    match d {
        Details::Width {
            cells,
            recommended,
            inside_tmux,
        } => {
            w.key("probes").begin_array();
            for (p, c) in PROBES.iter().zip(cells) {
                w.begin_object();
                w.key("name").string(p.name);
                w.key("cells").number(u64::from(*c));
                w.end_object();
            }
            w.end_array();
            w.key("recommended").begin_object();
            for (k, v) in [
                ("ambiguous", recommended.ambiguous),
                ("emoji", recommended.emoji),
            ] {
                w.key(k);
                match v {
                    Some(n) => w.number(u64::from(n)),
                    None => w.null(),
                };
            }
            w.end_object();
            w.key("inside_tmux").boolean(*inside_tmux);
        }
        Details::Background { terminal, prompt } => {
            w.key("terminal").string(mode_word(*terminal));
            w.key("prompt").string(mode_word(*prompt));
            w.key("colors_mode").string("auto");
        }
    }
    w.end_object();
}

/// The JSON document of a run: the same rows as the text, as data. A
/// finding's `fix` is its diagnostic code. No value of the environment is in
/// a `Finding`, so none can be here.
pub(super) fn render_json(rows: &[(&Item, Finding)], error: Option<&str>) -> String {
    use bingsu_core::diag_json::{SCHEMA, Writer};
    // A run that could not make its checks is invalid too (`error` says why).
    let code = if error.is_some() { 1 } else { exit_of(rows) };
    let mut w = Writer::new();
    w.begin_object();
    w.key("schema").number(u64::from(SCHEMA));
    w.key("command").string("doctor");
    w.key("result")
        .string(if code == 0 { "valid" } else { "invalid" });
    w.key("items").begin_array();
    for (item, f) in rows {
        w.begin_object();
        w.key("id").string(item.id);
        w.key("title").string(item.title);
        w.key("status").string(f.status.word());
        w.key("text").string(&f.text);
        w.key("fix")
            .opt_string(f.fix.map(|c| c.to_string()).as_deref());
        if let Some(d) = &f.details {
            write_details(&mut w, d);
        }
        w.end_object();
    }
    w.end_array();
    w.key("exit_code").number(u64::from(code));
    w.key("error").opt_string(error);
    w.end_object();
    w.finish()
}
