//! Bounded collector protocol and fixed catalog admission.
use alloc::vec::Vec;
pub mod cwd_hash;
pub mod response;
pub mod selection;
pub mod wire;

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
    };
    request.encode_body()?;
    Ok(Some(request))
}
