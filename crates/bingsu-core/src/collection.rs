//! Bounded collector protocol and fixed catalog admission.
use alloc::vec::Vec;
pub mod budget;
pub mod cwd_hash;
pub mod git;
pub mod path_facts;
pub mod response;
pub mod selection;
pub mod wire;

/// Merge only worker slots beyond the envelope builtin catalog. The caller
/// supplies the selected, non-redraw mask after checking response eligibility.
/// No collection value can replace envelope values or path facts. The explicit
/// no-repository marker clears the git display slot, while remaining present
/// in the stored response as stage A evidence.
pub fn merge(
    values: &mut crate::shell_values::Collected,
    response: Option<&response::Completed>,
    expected_mask: u32,
) {
    use crate::field::{self, Field, FieldValue, Value};
    use crate::width::WidthProfile;
    if expected_mask & (1 << git::SEGMENT) != 0
        && response
            .filter(|r| r.binding.mask == expected_mask)
            .is_some_and(|r| {
                r.updates.iter().any(|u| {
                    u.segment == git::SEGMENT
                        && u.value
                            .as_ref()
                            .is_some_and(|v| git::is_no_repo(v) && git::valid(v))
                })
            })
    {
        if let Some(slot) = values.values.get_mut(usize::from(git::SEGMENT)) {
            *slot = None;
        }
    }
    let mask = expected_mask & (u32::MAX << field::BUILTIN.len());
    if mask == 0 {
        return;
    }
    values.values.resize(32, None);
    for segment in field::BUILTIN.len()..32 {
        if mask & (1 << segment) == 0 {
            continue;
        }
        values.values[segment] = Some(Value::new(b"?", alloc::vec![Field::PENDING]));
    }
    let Some(response) = response.filter(|r| r.binding.mask == expected_mask) else {
        return;
    };
    for update in &response.updates {
        let segment = usize::from(update.segment);
        if segment >= 32 || mask & (1 << segment) == 0 {
            continue;
        }
        values.values[segment] = update.value.as_ref().map(|value| {
            let fields = value
                .fields
                .iter()
                .map(|f| {
                    let mut clean = match &f.value {
                        FieldValue::Text(t) => Field::text(
                            t.as_str().as_bytes(),
                            field::VALUE_MAX_CELLS,
                            WidthProfile::DEFAULT,
                        ),
                        _ => f.clone(),
                    };
                    clean.state = f.state;
                    clean
                })
                .collect();
            Value::new(value.text().as_bytes(), fields)
        });
    }
}

/// Reject masks outside the fixed catalog's worker grants or declared segments.
/// Empty selections do not create a request; nonempty requests also pass the
/// bounded wire checks.
pub fn request(
    catalog: &selection::Catalog<'_>,
    binding: wire::Binding,
    request_id: wire::RequestId,
    budget_ms: u32,
) -> Result<Option<wire::Request>, wire::ProtocolError> {
    if binding.mask == 0 {
        return Ok(None);
    }
    if binding.mask & !(catalog.workers & catalog.declared_mask()) != 0 {
        return Err(wire::ProtocolError::Schema);
    }
    let request = wire::Request {
        request_id,
        binding,
        budget_ms,
        environment: Vec::new(),
        global_excludes_known: false,
        global_excludes: Vec::new(),
    };
    request.encode_body()?;
    Ok(Some(request))
}
