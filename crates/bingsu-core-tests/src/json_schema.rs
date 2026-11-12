//! Checks JSON texts against `schema/diag-output-v1.json` with the schema
//! test validator (`scripts/check_json_schema.py`; `BINGSU_SCHEMA_PY` is the
//! python of the venv made from `scripts/schema-requirements.txt`).
//! Shared by `#[path]` with the CLI tests; standard library only.
#![allow(dead_code)]
use std::io::Write as _;
use std::process::{Command, Stdio};

#[allow(clippy::disallowed_methods, reason = "a test switch, not a path")]
fn python() -> std::ffi::OsString {
    std::env::var_os("BINGSU_SCHEMA_PY").unwrap_or_else(|| "python3".into())
}

fn quote(text: &str) -> String {
    let mut out = String::from("\"");
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[allow(clippy::disallowed_methods, reason = "a test feeding a child's stdin")]
/// `Ok` when every document passes (against `$defs/<def>` when given), else
/// the validator's complaints.
pub fn validate(def: Option<&str>, documents: &[&str]) -> Result<(), String> {
    let script = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../scripts/check_json_schema.py"
    );
    let docs: Vec<String> = documents.iter().map(|d| quote(d)).collect();
    let request = format!(
        "{{\"def\":{},\"documents\":[{}]}}",
        def.map_or("null".to_owned(), quote),
        docs.join(",")
    );
    let mut child = Command::new(python())
        .args(["-I", script])
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("cannot start the validator: {e}"))?;
    child
        .stdin
        .take()
        .unwrap()
        .write_all(request.as_bytes())
        .map_err(|e| e.to_string())?;
    let out = child.wait_with_output().map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "{}\n(install scripts/schema-requirements.txt into a venv and set BINGSU_SCHEMA_PY to its python)",
            String::from_utf8_lossy(&out.stderr)
        ))
    }
}
