//! Bounded collector protocol and fixed catalog admission.
use alloc::vec::Vec;
pub mod breaker;
pub mod budget;
pub mod cwd_hash;
pub mod git;
pub mod language;
pub mod manager;
pub mod path_facts;
pub mod response;
pub mod selection;
pub mod wire;

/// Merge a previously eligible completed response. The reader must first enforce
/// `completed_at < prompt_entry`; this boundary rechecks the exact binding and
/// the envelope's path query. Validate the entire update set before changing any
/// value. Only git and dir observations may augment envelope builtins.
pub fn merge(
    values: &mut crate::shell_values::Collected,
    response: Option<&response::Completed>,
    expected: &wire::Binding,
    pwd: &[u8],
    home: Option<&[u8]>,
) -> Result<(), wire::ProtocolError> {
    use crate::field::{self, Field, FieldValue};
    use wire::ProtocolError as E;
    if expected.cwd != pwd
        || expected.path_query
            != path_facts::PathQuery::for_path(pwd, home, expected.path_query.unique)
        || response.is_some_and(|r| !r.binding.matches(expected))
    {
        return Err(E::Schema);
    }
    let Some(response) = response else {
        pending(values, expected.mask);
        return Ok(());
    };
    let mut seen = 0u32;
    for update in &response.updates {
        let segment = usize::from(update.segment);
        if segment >= 32 || expected.mask & (1 << segment) == 0 {
            return Err(E::Schema);
        }
        if seen & (1 << segment) != 0 {
            return Err(E::Duplicate);
        }
        seen |= 1 << segment;
        if segment < field::BUILTIN.len() {
            if ![1, usize::from(git::SEGMENT)].contains(&segment) {
                return Err(E::Schema);
            }
            if let Some(value) = &update.value {
                value
                    .check(&field::BUILTIN[segment])
                    .map_err(|_| E::Schema)?;
                if segment == usize::from(git::SEGMENT) && !git::valid(value) {
                    return Err(E::Schema);
                }
            }
        }
        if let Some(facts) = &update.facts {
            if segment != 1 {
                return Err(E::Schema);
            }
            facts.validate(pwd)?;
        }
    }
    pending(values, expected.mask);
    for update in &response.updates {
        let segment = usize::from(update.segment);
        if segment == 1 {
            // dir.path and the path's logical names always come from the hook.
            if let Some(Some(dir)) = values.values.get_mut(1) {
                let decl = &field::BUILTIN[1];
                for name in ["in_repo", "readonly"] {
                    let i = decl.field_index(name).expect("fixed dir field");
                    let field = if let Some(facts) = &update.facts {
                        let observed = if name == "in_repo" {
                            facts.in_repo
                        } else {
                            facts.readonly
                        };
                        observed.map_or(Field::PENDING, |b| Field::known(FieldValue::Bool(b)))
                    } else {
                        update
                            .value
                            .as_ref()
                            .map_or(Field::PENDING, |v| v.fields[i].clone())
                    };
                    dir.fields[i] = field;
                }
            }
            if let Some(facts) = &update.facts {
                if let Some(slot) = values.facts.get_mut(1) {
                    *slot = Some(facts.to_path_facts(pwd, expected.path_query)?);
                }
            } else if let Some(Some(facts)) = values.facts.get_mut(1) {
                let readonly = update.value.as_ref().and_then(|v| {
                    let f = &v.fields[field::BUILTIN[1].field_index("readonly").unwrap()];
                    match (&f.value, f.state) {
                        (FieldValue::Bool(b), field::ValueState::Known) => Some(*b),
                        _ => None,
                    }
                });
                *facts = facts.clone().with_readonly(readonly);
            }
            continue;
        }
        values.values[segment] = update.value.as_ref().and_then(|value| {
            if segment == usize::from(git::SEGMENT) && git::is_no_repo(value) {
                None
            } else {
                Some(clean_value(
                    value,
                    field::BUILTIN.get(segment),
                    segment == usize::from(git::SEGMENT),
                ))
            }
        });
    }
    Ok(())
}

/// Missing git A stays hidden. Missing dir observations remain unknown.
pub(crate) fn pending(values: &mut crate::shell_values::Collected, mask: u32) {
    use crate::field::{self, Field, Value};
    if mask & (1 << git::SEGMENT) != 0 {
        values.values[usize::from(git::SEGMENT)] = None;
    }
    if mask & 2 != 0 {
        if let Some(Some(dir)) = values.values.get_mut(1) {
            for name in ["in_repo", "readonly"] {
                dir.fields[field::BUILTIN[1].field_index(name).unwrap()] = Field::PENDING;
            }
        }
        if let Some(Some(facts)) = values.facts.get_mut(1) {
            if facts.readonly().is_some() {
                *facts = facts.clone().with_readonly(None);
            }
        }
    }
    let custom = mask & (u32::MAX << field::BUILTIN.len());
    if custom != 0 {
        values.values.resize(32, None);
        for segment in field::BUILTIN.len()..32 {
            if custom & (1 << segment) != 0 {
                values.values[segment] = Some(Value::new(b"?", alloc::vec![Field::PENDING]));
            }
        }
    }
}

fn clean_value(
    value: &crate::field::Value,
    decl: Option<&crate::field::SegmentDecl>,
    git: bool,
) -> crate::field::Value {
    use crate::field::{self, Field, FieldType, FieldValue, Value};
    let fields = value
        .fields
        .iter()
        .enumerate()
        .map(|(i, f)| {
            let mut clean = match &f.value {
                FieldValue::Text(t) => {
                    let max = match decl.and_then(|d| d.fields.get(i)).map(|d| d.ty) {
                        Some(FieldType::Text { max_cells }) => max_cells,
                        _ => field::VALUE_MAX_CELLS,
                    };
                    Field::text(
                        t.as_str().as_bytes(),
                        max,
                        crate::width::WidthProfile::DEFAULT,
                    )
                }
                _ => f.clone(),
            };
            clean.state = f.state;
            clean
        })
        .collect();
    Value::new(if git { b"" } else { value.text().as_bytes() }, fields)
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
    request_with_languages(catalog, binding, request_id, budget_ms, Vec::new())
}

/// The `dir` segment's index: its worker reports the folder facts, the
/// repository root among them.
pub const DIR_SEGMENT: u16 = 1;

/// The builtin languages whose segments `drawn` (the layout's built-in
/// segment bits at this width) shows, each asked about on its own (D3a
/// rulings Q-A and Q6), in the language table's order.
pub fn builtin_languages(drawn: u32) -> Vec<language::LanguageQuery> {
    language::BUILTIN
        .iter()
        .filter(|b| {
            crate::field::BUILTIN
                .binary_search_by(|d| d.id.as_bytes().cmp(b.id))
                .is_ok_and(|i| drawn & 1u32.checked_shl(i as u32).unwrap_or(0) != 0)
        })
        .map(|b| b.query())
        .collect()
}

/// `request`, with `languages` asked about too: a round that draws only a
/// language segment still collects (its worker mask may be empty).
pub fn request_with_languages(
    catalog: &selection::Catalog<'_>,
    mut binding: wire::Binding,
    request_id: wire::RequestId,
    budget_ms: u32,
    languages: Vec<language::LanguageQuery>,
) -> Result<Option<wire::Request>, wire::ProtocolError> {
    // Fails without the language test: requests_follow_language_segments.
    if binding.mask == 0 && languages.is_empty() {
        return Ok(None);
    }
    // A round that asks about languages also asks for the folder facts: the
    // repository root they report bounds the builtin probes' PATH and
    // executable rules, whatever the layout draws (D3a review H1).
    // Fails without it: requests_follow_language_segments, and
    // test_builtin_probe_never_runs_from_the_repository.
    if !languages.is_empty() {
        binding.mask |= catalog.workers & (1 << DIR_SEGMENT);
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
        languages,
    };
    request.encode_body()?;
    Ok(Some(request))
}
