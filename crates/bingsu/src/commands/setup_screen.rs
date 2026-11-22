//! What `bingsu setup`'s editor takes from this machine once, at the start,
//! to draw the preview the way the prompt would: the folder as the shell
//! shows it and the color mode with bingsu's words for why.
use bingsu_core::color::palette::Mode;
use bingsu_core::envelope::{colorfgbg_mode, display_mode};
use std::ffi::OsStr;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

/// The folder the preview shows: `$PWD`, the folder as the shell shows it
/// (links kept), when it is absolute and is the folder `cwd` is (same
/// device and inode); else `cwd`.
pub(crate) fn sample_folder(pwd: Option<&OsStr>, cwd: &Path) -> PathBuf {
    let same = |p: &Path| {
        let (Ok(a), Ok(b)) = (std::fs::metadata(p), std::fs::metadata(cwd)) else {
            return false;
        };
        (a.dev(), a.ino()) == (b.dev(), b.ino())
    };
    match pwd.map(Path::new) {
        Some(p) if p.is_absolute() && same(p) => p.to_path_buf(),
        _ => cwd.to_path_buf(),
    }
}

/// The mode the preview draws in for the colors row's `word` (`auto`,
/// `dark` or `light`), and why in bingsu's words. `auto` reads
/// `COLORFGBG` as the prompt does (`envelope::display_mode`).
pub(crate) fn preview_mode(word: &str, colorfgbg: Option<&OsStr>) -> (Mode, String) {
    let name = |m: Mode| match m {
        Mode::Dark => "dark",
        Mode::Light => "light",
    };
    match word {
        "dark" => (Mode::Dark, String::from("dark")),
        "light" => (Mode::Light, String::from("light")),
        _ => {
            let seen = colorfgbg.and_then(|v| colorfgbg_mode(v.as_encoded_bytes()));
            let mode = display_mode(seen);
            let why = if seen.is_some() {
                "COLORFGBG"
            } else {
                "no COLORFGBG"
            };
            (mode, format!("auto: {} ({why})", name(mode)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // 이것을 실패시키는 것: 링크로 들어온 같은 폴더의 $PWD 대신 물리 경로를 보이는 것, 다른 폴더를 가리키는 $PWD나
    // 상대 경로, 없는 경로의 $PWD를 믿는 것.
    #[test]
    fn the_shell_folder_is_shown_when_it_is_this_folder() {
        let d = std::env::temp_dir().join(format!("bingsu-sf-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let real = d.join("real");
        let other = d.join("other");
        std::fs::create_dir_all(&real).unwrap();
        std::fs::create_dir_all(&other).unwrap();
        let link = d.join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let cwd = std::fs::canonicalize(&real).unwrap();
        let pick = |p: &Path| sample_folder(Some(p.as_os_str()), &cwd);
        assert_eq!(pick(&link), link);
        assert_eq!(pick(&other), cwd);
        // Relative, even when it leads here from the process's folder.
        let here = std::env::current_dir().unwrap();
        let mut relative = PathBuf::new();
        for _ in here.components().skip(1) {
            relative.push("..");
        }
        relative.push(link.strip_prefix("/").unwrap());
        assert!(std::fs::metadata(&relative).is_ok());
        assert_eq!(pick(&relative), cwd);
        assert_eq!(pick(&d.join("gone")), cwd);
        assert_eq!(sample_folder(None, &cwd), cwd);
        let _ = std::fs::remove_dir_all(&d);
    }

    // 이것을 실패시키는 것: auto에서 COLORFGBG를 보지 않는 것, 읽을 수 없는 값을 근거로 적는 것, 정한 모드에 COLORFGBG를
    // 적용하는 것.
    #[test]
    fn the_mode_and_its_reason() {
        fn fgbg(s: &str) -> Option<&OsStr> {
            Some(OsStr::new(s))
        }
        assert_eq!(
            preview_mode("auto", None),
            (Mode::Dark, String::from("auto: dark (no COLORFGBG)"))
        );
        assert_eq!(
            preview_mode("auto", fgbg("0;15")),
            (Mode::Light, String::from("auto: light (COLORFGBG)"))
        );
        assert_eq!(
            preview_mode("auto", fgbg("x")),
            (Mode::Dark, String::from("auto: dark (no COLORFGBG)"))
        );
        assert_eq!(
            preview_mode("dark", fgbg("0;15")),
            (Mode::Dark, String::from("dark"))
        );
        assert_eq!(
            preview_mode("light", None),
            (Mode::Light, String::from("light"))
        );
    }
}
