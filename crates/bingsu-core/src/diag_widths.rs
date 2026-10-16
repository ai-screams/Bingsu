//! The width table of `config check` (spec section 2 "폭 구간별 레이아웃",
//! 검증 행): widths are a small integer range, so every width is tried and
//! the band it draws is shown as runs; a band no width chooses gets a
//! warning at the place it is written. The choice itself is
//! `bands::select` (M2), the one the renderer uses.
use crate::bands::{Band, selection_table, unreachable};
use crate::diag::{Diagnostic, Place};
use crate::diag_codes as codes;
use alloc::string::String;
use alloc::vec::Vec;

/// One run: widths `from..=to` draw band `band` (by name; `None` is the
/// default layout).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WidthRun {
    pub from: u16,
    pub to: u16,
    pub band: Option<String>,
}

/// The runs over all widths, and a warning for each band never chosen.
/// `names` and `places` are per band.
pub fn width_table(
    order: &[usize],
    bands: &[Band],
    names: &[String],
    places: &[Place],
) -> (Vec<WidthRun>, Vec<Diagnostic>) {
    let runs = selection_table(order, bands)
        .into_iter()
        .map(|(from, to, b)| WidthRun {
            from,
            to,
            band: b.and_then(|i| names.get(i).cloned()),
        })
        .collect();
    let notes = unreachable(order, bands)
        .into_iter()
        .map(|i| {
            Diagnostic::new(
                codes::BAND_NEVER_CHOSEN,
                places.get(i).copied().unwrap_or(Place::Builtin),
            )
            .arg("id", names.get(i).cloned().unwrap_or_default())
        })
        .collect();
    (runs, notes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bands::order_bands;

    fn band(min: Option<u16>, max: Option<u16>, order: Option<i32>) -> Band {
        Band {
            min_cols: min,
            max_cols: max,
            order,
        }
    }

    fn table(bands: &[Band]) -> (Vec<(u16, u16, Option<String>)>, usize) {
        let names: Vec<String> = (0..bands.len()).map(|i| alloc::format!("b{i}")).collect();
        let places = alloc::vec![Place::Builtin; bands.len()];
        let order = order_bands(bands).unwrap();
        let (runs, notes) = width_table(&order, bands, &names, &places);
        (
            runs.into_iter().map(|r| (r.from, r.to, r.band)).collect(),
            notes.len(),
        )
    }

    // 이것을 실패시키는 것: 경계를 하나 어긋나게 나누는 것, 완전히 가려진 구간을 알리지 않는 것,
    // 좁은 구간이 넓은 구간 안에 있을 때(거울상 함정) 선택을 잘못 보이는 것.
    #[test]
    fn runs_and_shadowed_bands() {
        let s = |x: &str| Some(alloc::string::String::from(x));
        // Boundaries are inclusive.
        let (runs, n) = table(&[band(None, Some(59), None)]);
        assert_eq!(
            (runs, n),
            (alloc::vec![(0, 59, s("b0")), (60, u16::MAX, None)], 0)
        );
        // A narrow band inside a wide one is chosen first (containment).
        let (runs, n) = table(&[
            band(Some(100), None, None),
            band(Some(120), Some(130), None),
        ]);
        assert_eq!(
            (runs, n),
            (
                alloc::vec![
                    (0, 99, None),
                    (100, 119, s("b0")),
                    (120, 130, s("b1")),
                    (131, u16::MAX, s("b0"))
                ],
                0
            )
        );
        // `order` puts the wide band first: the narrow one is never chosen.
        let (runs, n) = table(&[
            band(Some(100), None, Some(1)),
            band(Some(120), Some(130), Some(2)),
        ]);
        assert_eq!(
            (runs, n),
            (alloc::vec![(0, 99, None), (100, u16::MAX, s("b0"))], 1)
        );
    }

    // 이것을 실패시키는 것: W407의 코드·가려진 구간의 이름·원본 위치를 잃는 것.
    #[test]
    fn warnings_keep_band_names_and_places() {
        use crate::config::tree::Span;
        use crate::diag::{Severity, SourceId};
        let bands = [
            band(None, None, Some(1)),
            band(Some(120), Some(130), Some(2)),
        ];
        let names = [String::from("wide"), String::from("hidden")];
        let place = Place::Source {
            id: SourceId(3),
            span: Span { start: 17, end: 29 },
        };
        let (runs, notes) = width_table(
            &order_bands(&bands).unwrap(),
            &bands,
            &names,
            &[Place::Builtin, place],
        );
        assert_eq!(
            runs,
            [WidthRun {
                from: 0,
                to: u16::MAX,
                band: Some(String::from("wide"))
            }]
        );
        assert_eq!(
            notes,
            [Diagnostic::new(codes::BAND_NEVER_CHOSEN, place).arg("id", "hidden")]
        );
        assert_eq!(notes[0].severity(), Severity::Warning);
    }

    // 이것을 실패시키는 것: 빈 입력·길이가 다른 이름 및 위치 표를 받으면 패닉하거나 잘못된 기본값을 쓰는 것.
    #[test]
    fn missing_metadata_uses_defaults() {
        let (runs, notes) = width_table(&[], &[], &[], &[]);
        assert_eq!(
            runs,
            [WidthRun {
                from: 0,
                to: u16::MAX,
                band: None
            }]
        );
        assert!(notes.is_empty());
        let (runs, notes) = width_table(
            &[0],
            &[band(None, None, None), band(None, None, None)],
            &[],
            &[],
        );
        assert_eq!(
            runs,
            [WidthRun {
                from: 0,
                to: u16::MAX,
                band: None
            }]
        );
        assert_eq!(
            notes,
            [Diagnostic::new(codes::BAND_NEVER_CHOSEN, Place::Builtin).arg("id", "")]
        );
    }
}
