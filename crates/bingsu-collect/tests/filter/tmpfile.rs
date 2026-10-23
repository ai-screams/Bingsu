//! Linux fixture selection, including filesystems without O_TMPFILE support.
use std::path::{Path, PathBuf};

pub(super) fn select(
    name: &str,
    temp: PathBuf,
    extra: Option<PathBuf>,
    mut probe: impl FnMut(&Path) -> std::io::Result<()>,
) -> Result<PathBuf, String> {
    let mut failures = Vec::new();
    for base in [Some(temp), Some(PathBuf::from("/dev/shm")), extra]
        .into_iter()
        .flatten()
    {
        let directory = base.join(name);
        match probe(&directory) {
            Ok(()) => return Ok(directory),
            Err(error) => failures.push(format!("{}: {error}", directory.display())),
        }
    }
    Err(format!(
        "BLOCKED: no writable test filesystem supports O_TMPFILE; tried {}; set BINGSU_B3_TMPDIR to a directory on a supporting filesystem",
        failures.join("; ")
    ))
}

// 이것을 실패시키는 것: 첫 실패에서 중단·탐침 생략·후보 순서 변경·모든 실패를 성공으로 처리하는 것.
#[test]
fn selection_probes_candidates_and_reports_all_failures() {
    let expected = ["/test-temp/b3", "/dev/shm/b3", "/override/b3"].map(PathBuf::from);
    for success in 0..=3 {
        let mut visited = Vec::new();
        let result = select("b3", "/test-temp".into(), Some("/override".into()), |dir| {
            visited.push(dir.to_owned());
            if visited.len() == success + 1 {
                Ok(())
            } else {
                Err(std::io::Error::from_raw_os_error(95))
            }
        });
        assert_eq!(visited, expected[..(success + 1).min(3)]);
        if success < 3 {
            assert_eq!(result.unwrap(), expected[success]);
        } else {
            let error = result.unwrap_err();
            for path in &expected {
                assert!(error.contains(path.to_str().unwrap()), "{error}");
            }
            for detail in ["BLOCKED", "O_TMPFILE", "95", "BINGSU_B3_TMPDIR"] {
                assert!(error.contains(detail), "{error}");
            }
        }
    }
    let mut attempts = 0;
    assert!(
        select("b3", "/test-temp".into(), None, |_| {
            attempts += 1;
            Err(std::io::Error::from_raw_os_error(95))
        })
        .is_err()
    );
    assert_eq!(attempts, 2);
}
