//! Producer layer of the hostile-value matrix (tests/hostile/classes.tsv).
use bingsu_core::record::{Encoded, Fields, encode_b1};
use bingsu_core::status::Status;

fn replace(hay: &[u8], from: &[u8], to: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(hay.len());
    let mut i = 0;
    while i < hay.len() {
        if hay[i..].starts_with(from) {
            out.extend_from_slice(to);
            i += from.len();
        } else {
            out.push(hay[i]);
            i += 1;
        }
    }
    out
}

fn payload(spec: &str) -> Vec<u8> {
    if let Some(rest) = spec.strip_prefix("repeat:") {
        let (byte, n) = rest.split_once(':').unwrap();
        return vec![u8::from_str_radix(byte, 16).unwrap(); n.parse().unwrap()];
    }
    let raw: Vec<u8> = (0..spec.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&spec[i..i + 2], 16).unwrap())
        .collect();
    replace(&raw, b"CANARY", b"/tmp/x")
}

// 이것을 실패시키는 것: 행렬의 producer 열과 다르게 받거나 거부하거나 대체하는 인코더.
#[test]
fn producer_column_matches() {
    let text = include_str!("../../../tests/hostile/classes.tsv");
    let declared: usize = text
        .lines()
        .find_map(|l| l.strip_prefix("# rows\t"))
        .expect("'# rows<TAB>N' line")
        .parse()
        .unwrap();
    let mut rows = 0;
    for line in text
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
    {
        let c: Vec<&str> = line.split('\t').collect();
        let (class, want) = (c[0], c[3]);
        let p = payload(c[1]);
        let mut out = Vec::new();
        let got = match encode_b1(
            &Fields {
                left: &p,
                ..Fields::default()
            },
            Status::OK_NONE,
            &mut out,
        ) {
            Ok(Encoded::Full) => "accept",
            Ok(Encoded::ReplacedBySizeLimit) => "replaced",
            Err(_) => "reject",
        };
        assert_eq!(got, want, "{class}");
        rows += 1;
    }
    assert_eq!(rows, declared, "classes.tsv declares {declared} rows");
}
