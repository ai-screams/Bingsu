//! Uses each dependency on a real path so LTO keeps representative code.
use unicode_segmentation::UnicodeSegmentation;
use unicode_width::UnicodeWidthStr;

#[derive(serde::Deserialize, Debug)]
#[allow(dead_code)]
struct Cfg {
    theme: Option<String>,
    layout: Option<toml::Table>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let text = std::fs::read_to_string(&args[1])?;
    let cfg: Cfg = toml::from_str(&text)?;
    let width: usize = text.graphemes(true).map(UnicodeWidthStr::width).sum();
    let repo = gix::open(&args[2])?;
    let changed = repo
        .status(gix::progress::Discard)?
        .into_iter(None)?
        .count();
    #[cfg(feature = "regex")]
    let matched = regex::Regex::new(&args[3])?.is_match(&text);
    #[cfg(not(feature = "regex"))]
    let matched = false;
    #[cfg(feature = "yaml-json")]
    let docs = {
        let y: serde_json::Value = serde_saphyr::from_str(&std::fs::read_to_string(&args[4])?)?;
        let j: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&args[5])?)?;
        usize::from(y.is_object()) + usize::from(j.is_object())
    };
    #[cfg(not(feature = "yaml-json"))]
    let docs = 0;
    println!("{cfg:?} {width} {changed} {matched} {docs}");
    Ok(())
}
