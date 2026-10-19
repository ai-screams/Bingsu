//! Pure, narrow pre-filter handoff. No configuration parsing or rendering.
use crate::{
    envelope::{self, Envelope, EnvelopeError},
    fs_trust::GroupPin,
    root_arg::parse_decimal,
};
use alloc::{format, string::String, vec::Vec};

pub fn encode_groups(pins: &[GroupPin]) -> String {
    let mut out = String::from("1");
    for p in pins {
        out.push_str(&format!(";{},{},{},{}", p.dev, p.ino, p.gid, p.mode));
    }
    out
}
pub fn decode_groups(word: &[u8], components: usize) -> Result<Vec<GroupPin>, EnvelopeError> {
    let bad = || EnvelopeError::BadArgs("runtime groups");
    let mut parts = word.split(|b| *b == b';');
    if parts.next() != Some(b"1") {
        return Err(bad());
    }
    let mut pins = Vec::new();
    for part in parts {
        if pins.len() >= components {
            return Err(bad());
        }
        let mut nums = Vec::new();
        for text in part.split(|b| *b == b',') {
            nums.push(parse_decimal(text).ok_or_else(bad)?);
        }
        if nums.len() != 4 {
            return Err(bad());
        }
        let p = GroupPin {
            dev: nums[0],
            ino: nums[1],
            gid: u32::try_from(nums[2]).map_err(|_| bad())?,
            mode: u32::try_from(nums[3]).map_err(|_| bad())?,
        };
        if p.mode > 0o177777
            || pins
                .iter()
                .any(|v: &GroupPin| (v.dev, v.ino) == (p.dev, p.ino))
        {
            return Err(bad());
        }
        pins.push(p);
    }
    Ok(pins)
}

/// Only fixed roots, group pins, home, level and a display cwd cross the
/// boundary. Two-word display fields cannot smuggle a root option as a value.
pub fn words<'a>(raw: &[&'a [u8]]) -> Result<Vec<&'a [u8]>, EnvelopeError> {
    let mut out: Vec<&[u8]> = alloc::vec![b"--ctx", b"1", b"--record", b"B1", b"--width", b"0"];
    let mut i = 0;
    while i < raw.len() {
        let a = raw[i];
        if envelope::is_value_flag(a) {
            let v = raw
                .get(i + 1)
                .ok_or(EnvelopeError::BadArgs("missing value"))?;
            if a == b"--pwd" {
                out.extend([a, *v]);
            }
            i += 2;
        } else {
            if [
                b"--runtime-root=".as_slice(),
                b"--runtime-groups=",
                b"--config-root=",
                b"--config-root-written=",
                b"--state-root=",
                b"--log-root=",
                b"--home=",
                b"--log-level=",
            ]
            .iter()
            .any(|p| a.starts_with(p))
                || a == b"--config-root-shape-only"
            {
                out.push(a);
            }
            i += 1;
        }
    }
    let checked = validate(&out)?;
    if let Some(word) = out
        .iter_mut()
        .find(|word| word.starts_with(b"--log-level="))
    {
        *word = match checked.log_level {
            envelope::LogLevel::Off => b"--log-level=off",
            envelope::LogLevel::Error => b"--log-level=error",
            envelope::LogLevel::Info => b"--log-level=info",
            envelope::LogLevel::DebugLog => b"--log-level=debug",
        };
    }
    Ok(out)
}
pub fn validate(raw: &[&[u8]]) -> Result<Envelope, EnvelopeError> {
    let e = envelope::parse(raw)?;
    if e.runtime_root.is_none()
        || e.config_root.is_none()
        || e.config_root_written.is_none()
        || e.state_root.is_none()
        || e.home.is_none()
    {
        return Err(EnvelopeError::BadArgs("helper roots"));
    }
    Ok(e)
}

#[cfg(test)]
mod tests {
    use super::*;
    // 이것을 실패시키는 것: group 숫자 문법·중복 inode·범위·구성 요소 수 검사를 지우는 것.
    #[test]
    fn group_words() {
        let p = GroupPin {
            dev: 1,
            ino: 2,
            gid: 3,
            mode: 0o40775,
        };
        assert_eq!(
            decode_groups(encode_groups(&[p]).as_bytes(), 1).unwrap(),
            [p]
        );
        assert!(decode_groups(b"1", 0).unwrap().is_empty());
        for bad in [
            b"2".as_slice(),
            b"1;01,2,3,4",
            b"1;1,2,3",
            b"1;1,2,3,4,5",
            b"1;1,2,4294967296,4",
            b"1;1,2,3,65536",
            b"1;18446744073709551616,2,3,4",
            b"1;1,2,3,4;1,2,3,5",
            b"1;",
        ] {
            assert!(decode_groups(bad, 2).is_err(), "{bad:?}");
        }
        assert!(decode_groups(b"1;1,2,3,4", 0).is_err());
    }
    // 이것을 실패시키는 것: 화면 값이 root로 넘어가거나 shape-only·log-level·pwd 전달이 빠지는 것.
    #[test]
    fn narrow_handoff() {
        let raw: &[&[u8]] = &[
            b"--host",
            b"--config-root=/attack",
            b"--runtime-root=1:2:/r",
            b"--config-root=/c",
            b"--config-root-written=/c",
            b"--state-root=/s",
            b"--home=/h",
            b"--config-root-shape-only",
            b"--log-level=info",
            b"--pwd",
            b"/repo",
        ];
        let w = words(raw).unwrap();
        let e = validate(&w).unwrap();
        assert_eq!(e.config_root.as_deref(), Some(b"/c".as_slice()));
        assert!(e.config_root_shape_only);
        assert!(e.host.is_none());
        assert_eq!(e.log_level, envelope::LogLevel::Info);
        assert_eq!(e.pwd.as_deref(), Some(b"/repo".as_slice()));
        assert!(words(&[]).is_err());
        for field in [
            b"--runtime-root=".as_slice(),
            b"--config-root=",
            b"--config-root-written=",
            b"--state-root=",
            b"--home=",
        ] {
            let missing: Vec<_> = w
                .iter()
                .copied()
                .filter(|a| !a.starts_with(field))
                .collect();
            assert!(words(&missing).is_err(), "{field:?}");
        }
        let mut group = raw.to_vec();
        group.push(b"--runtime-groups=1;1,2,3,16893");
        assert_eq!(
            validate(&words(&group).unwrap())
                .unwrap()
                .runtime_groups
                .len(),
            1
        );
        group.push(b"--runtime-groups=1");
        assert!(words(&group).is_err());
        let mut log = raw.to_vec();
        log.push(b"--log-root=/state/log");
        assert_eq!(
            validate(&words(&log).unwrap()).unwrap().log_root.as_deref(),
            Some(b"/state/log".as_slice())
        );
        assert!(words(&[b"--host"]).is_err());
        // 이것을 실패시키는 것: 매 prompt의 debug 수준을 init/off 값으로 고정하는 것.
        let mut debug = raw.to_vec();
        let level_at = debug
            .iter()
            .position(|word| word.starts_with(b"--log-level="))
            .unwrap();
        debug[level_at] = b"--log-level=debug";
        assert!(
            words(&debug)
                .unwrap()
                .contains(&b"--log-level=debug".as_slice())
        );
        let mut unknown = raw.to_vec();
        let at = unknown
            .iter()
            .position(|w| w.starts_with(b"--log-level="))
            .unwrap();
        unknown[at] = b"--log-level=/attack";
        assert!(
            words(&unknown)
                .unwrap()
                .contains(&b"--log-level=off".as_slice())
        );
        let mut duplicate = raw.to_vec();
        duplicate.push(b"--state-root=/other");
        assert!(words(&duplicate).is_err());
    }
}
