//! Bounded, single-exchange wire protocol. Errors never produce reply bytes.
use super::{
    cwd_hash, git,
    path_facts::{PathFactInput, PathQuery},
    response::Completed,
};
use crate::{
    field::{self, Field, FieldType, FieldValue, SegmentDecl, Value, ValueState},
    snapshot::{self, Clock, Identity},
    width::WidthProfile,
};
use alloc::{string::String, vec, vec::Vec};

pub const HEADER: usize = 80;
pub const FRAME_MAX: usize = 65_536;
pub const PAYLOAD_MAX: usize = FRAME_MAX - HEADER;
pub const STREAM_MAX: usize = 262_144;
pub const FEATURES: u64 = 3;
pub const TEXT_MAX: usize = 4_096;
pub const SEGMENTS_MAX: usize = 32;
pub const FIELDS_MAX: usize = 32;
pub const FRAMES_MAX: usize = 64;
pub const UPDATES_MAX: u8 = 16;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BuildId(pub [u8; 32]);
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RequestId(pub [u8; 32]);
pub const M3B_REQUEST_ID: RequestId = RequestId([0; 32]);
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Ready,
    RequestBegin,
    RequestChunk,
    RequestEnd,
    Update,
    Complete,
    Progress,
}
impl Kind {
    fn tag(self) -> u8 {
        match self {
            Self::Ready => 1,
            Self::RequestBegin => 2,
            Self::RequestChunk => 3,
            Self::RequestEnd => 4,
            Self::Update => 5,
            Self::Complete => 6,
            Self::Progress => 7,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProtocolError {
    Length,
    Magic,
    Version,
    Kind,
    Flags,
    Id,
    Duplicate,
    Order,
    Feature,
    Build,
    Budget,
    Schema,
    Checksum,
    Truncated,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Frame<'a> {
    pub kind: Kind,
    pub build_id: BuildId,
    pub request_id: RequestId,
    pub payload: &'a [u8],
}
/// Validate the header before reading any payload into the single fixed buffer.
pub fn frame_len(bytes: &[u8]) -> Result<usize, ProtocolError> {
    if bytes.len() < HEADER {
        return Err(ProtocolError::Length);
    }
    let payload = u32::from_le_bytes(bytes[12..16].try_into().unwrap()) as usize;
    let total = HEADER.checked_add(payload).ok_or(ProtocolError::Length)?;
    if total > FRAME_MAX {
        return Err(ProtocolError::Length);
    }
    if &bytes[..8] != b"BNGIPC05" {
        return Err(ProtocolError::Magic);
    }
    if bytes[8..10] != 5u16.to_le_bytes() {
        return Err(ProtocolError::Version);
    }
    if !(1..=7).contains(&bytes[10]) {
        return Err(ProtocolError::Kind);
    }
    if bytes[11] != 0 {
        return Err(ProtocolError::Flags);
    }
    Ok(total)
}
pub fn decode_frame(bytes: &[u8]) -> Result<Frame<'_>, ProtocolError> {
    // Slice length has precedence over all header discriminants.
    if bytes.len() < HEADER || bytes.len() > FRAME_MAX {
        return Err(ProtocolError::Length);
    }
    let payload = u32::from_le_bytes(bytes[12..16].try_into().unwrap()) as usize;
    if HEADER.checked_add(payload) != Some(bytes.len()) {
        return Err(ProtocolError::Length);
    }
    frame_len(bytes)?;
    let kind = match bytes[10] {
        1 => Kind::Ready,
        2 => Kind::RequestBegin,
        3 => Kind::RequestChunk,
        4 => Kind::RequestEnd,
        5 => Kind::Update,
        6 => Kind::Complete,
        7 => Kind::Progress,
        _ => return Err(ProtocolError::Kind),
    };
    Ok(Frame {
        kind,
        build_id: BuildId(bytes[16..48].try_into().unwrap()),
        request_id: RequestId(bytes[48..80].try_into().unwrap()),
        payload: &bytes[HEADER..],
    })
}
/// Decode the bytes held when EOF arrives. Empty EOF returns
/// [`ProtocolError::Truncated`], as required before Complete. After Complete,
/// [`Transcript::accept_bytes`] handles empty EOF as success.
///
/// The adapter must stop the exchange at the first `Err`: codec rejections are
/// transactional and do not latch a failure that blocks later calls.
pub fn decode_eof(bytes: &[u8]) -> Result<Frame<'_>, ProtocolError> {
    if bytes.len() < HEADER {
        return Err(ProtocolError::Truncated);
    }
    let len = frame_len(bytes)?;
    if bytes.len() < len {
        return Err(ProtocolError::Truncated);
    }
    decode_frame(bytes)
}
pub fn encode_frame(frame: Frame<'_>, out: &mut [u8; FRAME_MAX]) -> Result<usize, ProtocolError> {
    let len = frame_size(frame)?;
    out[..8].copy_from_slice(b"BNGIPC05");
    out[8..10].copy_from_slice(&5u16.to_le_bytes());
    out[10] = frame.kind.tag();
    out[11] = 0;
    out[12..16].copy_from_slice(&(frame.payload.len() as u32).to_le_bytes());
    out[16..48].copy_from_slice(&frame.build_id.0);
    out[48..80].copy_from_slice(&frame.request_id.0);
    out[HEADER..len].copy_from_slice(frame.payload);
    Ok(len)
}
fn frame_size(frame: Frame<'_>) -> Result<usize, ProtocolError> {
    let n = HEADER
        .checked_add(frame.payload.len())
        .ok_or(ProtocolError::Length)?;
    if n > FRAME_MAX {
        return Err(ProtocolError::Length);
    }
    Ok(n)
}
pub(crate) fn add_budget(a: usize, b: usize, max: usize) -> Result<usize, ProtocolError> {
    let n = a.checked_add(b).ok_or(ProtocolError::Budget)?;
    if n > max {
        return Err(ProtocolError::Budget);
    }
    Ok(n)
}
pub(crate) fn replace_budget(
    total: usize,
    old: usize,
    new: usize,
    max: usize,
) -> Result<usize, ProtocolError> {
    add_budget(
        total.checked_sub(old).ok_or(ProtocolError::Budget)?,
        new,
        max,
    )
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Binding {
    pub build_id: BuildId,
    pub snapshot: Identity,
    pub clock_kind: u8,
    pub domain: [u8; 16],
    pub resume: u64,
    pub config: Vec<u8>,
    pub state: Vec<u8>,
    pub cwd: Vec<u8>,
    pub mask: u32,
    pub path_query: PathQuery,
}
impl Binding {
    pub fn components(&self) -> [String; 3] {
        [
            String::from("collections-v1"),
            cwd_hash::address(&self.cwd),
            String::from("store"),
        ]
    }
    pub fn matches(&self, expected: &Binding) -> bool {
        self == expected
    }
    pub(crate) fn validate(&self) -> Result<(), ProtocolError> {
        for path in [&self.config, &self.state, &self.cwd] {
            validate_path(path)?;
        }
        self.path_query.validate(&self.cwd)?;
        if !matches!(self.clock_kind, 1 | 2)
            || snapshot::context_crc(&self.config, &self.state)
                .map_err(|_| ProtocolError::Schema)?
                != self.snapshot.context
        {
            return Err(ProtocolError::Schema);
        }
        Ok(())
    }
    pub(crate) fn encoded_len(&self) -> Result<usize, ProtocolError> {
        self.validate()?;
        self.len_from_paths()
    }
    // Length arithmetic only: decoding has already validated the borrowed paths.
    fn len_from_paths(&self) -> Result<usize, ProtocolError> {
        let mut n = 125;
        for path in [&self.config, &self.state, &self.cwd] {
            n = add_budget(n, path.len(), STREAM_MAX)?;
        }
        Ok(n)
    }
    pub(crate) fn put_identity(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.snapshot.boot);
        out.extend_from_slice(&self.snapshot.epoch);
        out.extend_from_slice(&self.snapshot.generation.to_le_bytes());
        out.extend_from_slice(&self.snapshot.source);
        out.extend_from_slice(&self.snapshot.context);
        out.push(self.clock_kind);
        out.extend_from_slice(&self.domain);
        out.extend_from_slice(&self.resume.to_le_bytes());
        out.extend_from_slice(&self.mask.to_le_bytes());
        self.path_query.put(out);
    }
    pub(crate) fn put_paths(&self, out: &mut Vec<u8>) {
        for path in [&self.config, &self.state, &self.cwd] {
            put_bytes(out, path);
        }
    }
    pub(crate) fn read_identity(
        build_id: BuildId,
        r: &mut Reader<'_>,
    ) -> Result<Self, ProtocolError> {
        Ok(Self {
            build_id,
            snapshot: Identity {
                boot: r.array()?,
                epoch: r.array()?,
                generation: r.u64()?,
                source: r.array()?,
                context: r.array()?,
            },
            clock_kind: r.u8()?,
            domain: r.array()?,
            resume: r.u64()?,
            mask: r.u32()?,
            path_query: PathQuery::read(r)?,
            config: Vec::new(),
            state: Vec::new(),
            cwd: Vec::new(),
        })
    }
    pub(crate) fn read_paths(&mut self, r: &mut Reader<'_>) -> Result<(), ProtocolError> {
        // Validate all three borrowed slices before any path allocation.
        let config = r.bytes(65_536, ProtocolError::Schema)?;
        let state = r.bytes(65_536, ProtocolError::Schema)?;
        let cwd = r.bytes(65_536, ProtocolError::Schema)?;
        for p in [config, state, cwd] {
            validate_path(p)?;
        }
        if snapshot::context_crc(config, state).map_err(|_| ProtocolError::Schema)?
            != self.snapshot.context
            || !matches!(self.clock_kind, 1 | 2)
        {
            return Err(ProtocolError::Schema);
        }
        self.path_query.validate(cwd)?;
        self.config = config.to_vec();
        self.state = state.to_vec();
        self.cwd = cwd.to_vec();
        Ok(())
    }
}
fn validate_path(p: &[u8]) -> Result<(), ProtocolError> {
    if p.len() > 65_536 || p.first() != Some(&b'/') || p.contains(&0) {
        Err(ProtocolError::Schema)
    } else {
        Ok(())
    }
}
/// Maximum helper-supplied global ignore file; it is data, never a path.
pub const GLOBAL_EXCLUDES_MAX: usize = 65_536;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub request_id: RequestId,
    pub binding: Binding,
    pub budget_ms: u32,
    pub environment: Vec<(Vec<u8>, Vec<u8>)>,
    /// False means the helper could not determine the complete global input.
    pub global_excludes_known: bool,
    pub global_excludes: Vec<u8>,
}
impl Request {
    fn body_len(&self) -> Result<usize, ProtocolError> {
        let n = Self::checked_body_len(self.binding.encoded_len()?, self.global_excludes.len())?;
        if !(1..=50).contains(&self.budget_ms) {
            return Err(ProtocolError::Budget);
        }
        if !self.environment.is_empty() {
            return Err(ProtocolError::Schema);
        }
        Ok(n)
    }
    fn checked_body_len(binding_len: usize, excludes_len: usize) -> Result<usize, ProtocolError> {
        let n = add_budget(binding_len - 32, 11, STREAM_MAX)?;
        if excludes_len > GLOBAL_EXCLUDES_MAX {
            return Err(ProtocolError::Budget);
        }
        let n = add_budget(n, excludes_len, STREAM_MAX)?;
        // Begin (12), chunk offsets (4 each), End (4), and every header
        // count against the unchanged directional stream cap.
        let chunks = n.div_ceil(FRAME_MAX - HEADER - 4);
        add_budget(n, (chunks + 2) * HEADER + 16 + 4 * chunks, STREAM_MAX)?;
        Ok(n)
    }
    pub fn encode_body(&self) -> Result<Vec<u8>, ProtocolError> {
        let n = self.body_len()?;
        let mut out = Vec::with_capacity(n);
        self.binding.put_identity(&mut out);
        out.extend_from_slice(&self.budget_ms.to_le_bytes());
        self.binding.put_paths(&mut out);
        out.extend_from_slice(&0u16.to_le_bytes());
        out.push(u8::from(self.global_excludes_known));
        put_bytes(&mut out, &self.global_excludes);
        checked_encoding(out, n)
    }
    pub fn decode_body(
        build_id: BuildId,
        request_id: RequestId,
        bytes: &[u8],
    ) -> Result<Self, ProtocolError> {
        if bytes.len() > STREAM_MAX {
            return Err(ProtocolError::Budget);
        }
        let mut r = Reader::new(bytes);
        let mut binding = Binding::read_identity(build_id, &mut r)?;
        let budget_ms = r.u32()?;
        if !(1..=50).contains(&budget_ms) {
            return Err(ProtocolError::Budget);
        }
        binding.read_paths(&mut r)?;
        if r.u16()? != 0 {
            return Err(ProtocolError::Schema);
        }
        let global_excludes_known = match r.u8()? {
            0 => false,
            1 => true,
            _ => return Err(ProtocolError::Schema),
        };
        let global_excludes = r.bytes(GLOBAL_EXCLUDES_MAX, ProtocolError::Budget)?;
        r.end()?;
        // read_paths checked path syntax, context CRC, clock and query; the
        // reader checked every remaining field. Only stream framing is left.
        // Do not call body_len here: it repeats the full binding validation.
        Self::checked_body_len(binding.len_from_paths()?, global_excludes.len())?;
        Ok(Self {
            request_id,
            binding,
            budget_ms,
            environment: Vec::new(),
            global_excludes_known,
            global_excludes: global_excludes.to_vec(),
        })
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EndReason {
    Complete,
    Deadline,
    Protocol,
    Resource,
    WorkerExit,
}
impl EndReason {
    pub(crate) fn tag(self) -> u8 {
        match self {
            Self::Complete => 0,
            Self::Deadline => 1,
            Self::Protocol => 2,
            Self::Resource => 3,
            Self::WorkerExit => 4,
        }
    }
    pub(crate) fn from_tag(tag: u8) -> Result<Self, ProtocolError> {
        match tag {
            0 => Ok(Self::Complete),
            1 => Ok(Self::Deadline),
            2 => Ok(Self::Protocol),
            3 => Ok(Self::Resource),
            4 => Ok(Self::WorkerExit),
            _ => Err(ProtocolError::Schema),
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Update {
    pub segment: u16,
    pub value: Option<Value>,
    pub facts: Option<PathFactInput>,
}
impl Update {
    pub fn encode(&self, binding: &Binding) -> Result<Vec<u8>, ProtocolError> {
        let schema = Schema::new(field::BUILTIN)?;
        let len = update_len(self, &schema, binding)?;
        if len > PAYLOAD_MAX {
            return Err(ProtocolError::Length);
        }
        let mut out = Vec::with_capacity(len);
        put_update(&mut out, self);
        checked_encoding(out, len)
    }
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Progress {
    pub stage_a_complete: bool,
    pub device: Option<u64>,
}
impl Progress {
    pub fn encode(self) -> [u8; 10] {
        let mut out = [0; 10];
        out[0] = u8::from(self.stage_a_complete);
        out[1] = u8::from(self.device.is_some());
        out[2..].copy_from_slice(&self.device.unwrap_or(0).to_le_bytes());
        out
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        let mut r = Reader::new(bytes);
        let value = Self::read(&mut r)?;
        r.end()?;
        Ok(value)
    }
    pub(crate) fn read(r: &mut Reader<'_>) -> Result<Self, ProtocolError> {
        let stage_a_complete = r.boolean()?;
        let present = r.boolean()?;
        let device = r.u64()?;
        if !present && device != 0 {
            return Err(ProtocolError::Schema);
        }
        Ok(Self {
            stage_a_complete,
            device: present.then_some(device),
        })
    }
}
/// The codec proves a valid A result preceded completion. For dir-only requests,
/// an observed discovery outcome is evidence even if sibling enumeration is partial.
pub(crate) fn stage_a_evidence(binding: &Binding, updates: &[Update], later: bool) -> bool {
    if binding.mask & (1 << git::SEGMENT) != 0 {
        updates
            .iter()
            .find(|u| u.segment == git::SEGMENT)
            .and_then(|u| u.value.as_ref())
            .is_some_and(|v| git::stage_a_evidence(v, later))
    } else if binding.mask & (1 << 1) != 0 {
        updates
            .iter()
            .find(|u| u.segment == 1)
            .and_then(|u| u.facts.as_ref())
            .is_some_and(|f| f.in_repo.is_some())
    } else {
        false
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct RequestDecoder {
    ready: Option<(BuildId, RequestId, u32)>,
    begun: bool,
    done: bool,
    total: usize,
    bytes: usize,
    body: Vec<u8>,
}
impl RequestDecoder {
    pub fn new() -> Self {
        Self::default()
    }
    /// Register the locally emitted Ready first. The adapter must not consume
    /// request bytes before protection and the complete Ready write succeed.
    pub fn accept(&mut self, frame: Frame<'_>) -> Result<Option<Request>, ProtocolError> {
        let size = frame_size(frame)?;
        if frame.kind == Kind::Ready {
            if self.ready.is_some() {
                return Err(ProtocolError::Duplicate);
            }
            let mask = ready_mask(frame.payload)?;
            self.ready = Some((frame.build_id, frame.request_id, mask));
            return Ok(None);
        }
        if frame.kind == Kind::RequestBegin && self.begun {
            return Err(ProtocolError::Duplicate);
        }
        let (build, id, mask) = self.ready.ok_or(ProtocolError::Order)?;
        if self.done
            || !matches!(
                frame.kind,
                Kind::RequestBegin | Kind::RequestChunk | Kind::RequestEnd
            )
            || (!self.begun && frame.kind != Kind::RequestBegin)
        {
            return Err(ProtocolError::Order);
        }
        identity(frame, build, id)?;
        let bytes = add_budget(self.bytes, size, STREAM_MAX)?;
        match frame.kind {
            Kind::RequestBegin => {
                let mut r = Reader::new(frame.payload);
                let total = r.u32()? as usize;
                if r.u64()? != FEATURES {
                    return Err(ProtocolError::Feature);
                }
                r.end()?;
                if total > STREAM_MAX {
                    return Err(ProtocolError::Budget);
                }
                // Reserve the bounded body once; rejected chunks cannot reallocate it.
                let body = Vec::with_capacity(total);
                self.total = total;
                self.body = body;
                self.begun = true;
            }
            Kind::RequestChunk => {
                let mut r = Reader::new(frame.payload);
                let offset = r.u32()? as usize;
                if offset != self.body.len() || r.remaining().is_empty() {
                    return Err(ProtocolError::Order);
                }
                let next = add_budget(self.body.len(), r.remaining().len(), STREAM_MAX)?;
                if next > self.total {
                    return Err(ProtocolError::Order);
                }
                self.body.extend_from_slice(r.remaining());
            }
            Kind::RequestEnd => {
                if self.body.len() != self.total {
                    return Err(ProtocolError::Order);
                }
                if frame.payload.len() != 4 {
                    return Err(ProtocolError::Schema);
                }
                if snapshot::crc32c(&[&self.body]) != frame.payload {
                    return Err(ProtocolError::Checksum);
                }
                let request = Request::decode_body(build, id, &self.body)?;
                if request.binding.mask & !mask != 0 {
                    return Err(ProtocolError::Schema);
                }
                self.done = true;
                self.bytes = bytes;
                self.body.clear();
                return Ok(Some(request));
            }
            _ => return Err(ProtocolError::Order),
        }
        self.bytes = bytes;
        Ok(None)
    }
}
fn identity(frame: Frame<'_>, build: BuildId, id: RequestId) -> Result<(), ProtocolError> {
    if frame.build_id != build {
        return Err(ProtocolError::Build);
    }
    if frame.request_id != id {
        return Err(ProtocolError::Id);
    }
    Ok(())
}
fn ready_mask(payload: &[u8]) -> Result<u32, ProtocolError> {
    let mut r = Reader::new(payload);
    if r.u64()? != FEATURES {
        return Err(ProtocolError::Feature);
    }
    let mask = r.u32()?;
    r.u32()?;
    r.u64()?;
    r.end()?;
    Ok(mask)
}
/// Copy type declarations and identify the fixed git schema for semantic checks.
/// No callbacks, capabilities or fixture behavior enter the codec.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Schema {
    fields: Vec<Vec<FieldType>>,
    git: bool,
}
impl Schema {
    pub(crate) fn new(catalog: &[SegmentDecl]) -> Result<Self, ProtocolError> {
        if catalog.len() > SEGMENTS_MAX {
            return Err(ProtocolError::Budget);
        }
        let mut fields = Vec::with_capacity(catalog.len());
        for segment in catalog {
            if segment.fields.len() > FIELDS_MAX {
                return Err(ProtocolError::Budget);
            }
            fields.push(segment.fields.iter().map(|f| f.ty).collect());
        }
        let git = catalog
            .get(usize::from(git::SEGMENT))
            .is_some_and(|d| d.id == "git");
        Ok(Self { fields, git })
    }
    fn segment(&self, segment: u16, mask: u32) -> Result<&[FieldType], ProtocolError> {
        let index = usize::from(segment);
        if index >= SEGMENTS_MAX || mask & (1u32 << index) == 0 {
            return Err(ProtocolError::Schema);
        }
        self.fields
            .get(index)
            .map(|v| v.as_slice())
            .ok_or(ProtocolError::Schema)
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transcript {
    request: Request,
    schema: Schema,
    ready: bool,
    sent: bool,
    complete: bool,
    bytes: usize,
    frames: usize,
    counts: [u8; 32],
    lengths: [usize; 32],
    stored: usize,
    progress: Progress,
    progress_seen: bool,
    updates: Vec<Update>,
}
impl Transcript {
    pub fn new(request: &Request) -> Self {
        Self::with_catalog(request, field::BUILTIN).expect("bounded builtin catalog")
    }
    pub fn with_catalog(request: &Request, catalog: &[SegmentDecl]) -> Result<Self, ProtocolError> {
        // A request carries segment indices in its mask. Check them before
        // copying declarations or paths, including the empty/full catalogs.
        if catalog.len() > SEGMENTS_MAX {
            return Err(ProtocolError::Budget);
        }
        let declared = u32::MAX.checked_shr(32 - catalog.len() as u32).unwrap_or(0);
        if request.binding.mask & !declared != 0 {
            return Err(ProtocolError::Schema);
        }
        request.body_len()?;
        let schema = Schema::new(catalog)?;
        Ok(Self {
            request: request.clone(),
            schema,
            ready: false,
            sent: false,
            complete: false,
            bytes: 0,
            frames: 0,
            counts: [0; 32],
            lengths: [0; 32],
            stored: 0,
            progress: Progress::default(),
            progress_seen: false,
            updates: Vec::new(),
        })
    }
    pub fn accept(&mut self, frame: Frame<'_>) -> Result<(), ProtocolError> {
        let size = frame_size(frame)?;
        if self.complete {
            return Err(ProtocolError::Order);
        }
        if frame.kind == Kind::Ready && self.ready {
            return Err(ProtocolError::Duplicate);
        }
        if (!self.ready && frame.kind != Kind::Ready)
            || (self.ready
                && (!self.sent
                    || !matches!(frame.kind, Kind::Update | Kind::Complete | Kind::Progress)))
        {
            return Err(ProtocolError::Order);
        }
        identity(
            frame,
            self.request.binding.build_id,
            self.request.request_id,
        )?;
        let bytes = add_budget(self.bytes, size, STREAM_MAX)?;
        let frames = add_budget(self.frames, 1, FRAMES_MAX)?;
        match frame.kind {
            Kind::Ready => {
                let mask = ready_mask(frame.payload)?;
                if self.request.binding.mask & !mask != 0 {
                    return Err(ProtocolError::Schema);
                }
                self.request.encode_body()?;
                self.ready = true;
            }
            Kind::Update => {
                let mut r = Reader::new(frame.payload);
                let update = read_update(&mut r, &self.schema, &self.request.binding, TEXT_MAX)?;
                r.end()?;
                let index = usize::from(update.segment);
                // A no-repository result is terminal for this discovery, even
                // before its A-complete Progress arrives. Never replace it with
                // a repository stage or erase its evidence with Hidden.
                if self.schema.git
                    && update.segment == git::SEGMENT
                    && self.updates.iter().any(|old| {
                        old.segment == git::SEGMENT
                            && matches!(&old.value, Some(v) if git::is_no_repo(v))
                    })
                    && !matches!(&update.value, Some(v) if git::is_no_repo(v))
                {
                    return Err(ProtocolError::Order);
                }
                let evidence_segment = if self.request.binding.mask & (1 << git::SEGMENT) != 0 {
                    git::SEGMENT
                } else {
                    1
                };
                if self.progress.stage_a_complete
                    && update.segment == evidence_segment
                    && !stage_a_evidence(
                        &self.request.binding,
                        core::slice::from_ref(&update),
                        true,
                    )
                {
                    return Err(ProtocolError::Order);
                }
                let count = self.counts[index]
                    .checked_add(1)
                    .ok_or(ProtocolError::Budget)?;
                if count > UPDATES_MAX {
                    return Err(ProtocolError::Budget);
                }
                let len = update_len(&update, &self.schema, &self.request.binding)?;
                let base = super::response::base_len(&self.request.binding)?;
                let limit = STREAM_MAX.checked_sub(base).ok_or(ProtocolError::Budget)?;
                let stored = replace_budget(self.stored, self.lengths[index], len, limit)?;
                if let Some(old) = self
                    .updates
                    .iter_mut()
                    .find(|u| u.segment == update.segment)
                {
                    *old = update;
                } else {
                    self.updates.push(update);
                }
                self.stored = stored;
                self.lengths[index] = len;
                self.counts[index] = count;
            }
            Kind::Progress => {
                let next = Progress::decode(frame.payload)?;
                if self.progress_seen && (self.progress.stage_a_complete || !next.stage_a_complete)
                {
                    return Err(ProtocolError::Order);
                }
                if self.progress_seen && next.device != self.progress.device {
                    return Err(ProtocolError::Schema);
                }
                if next.stage_a_complete
                    && !stage_a_evidence(&self.request.binding, &self.updates, false)
                {
                    return Err(ProtocolError::Order);
                }
                self.progress = next;
                self.progress_seen = true;
            }
            Kind::Complete => {
                if !frame.payload.is_empty() {
                    return Err(ProtocolError::Schema);
                }
                self.complete = true;
            }
            _ => return Err(ProtocolError::Order),
        }
        self.bytes = bytes;
        self.frames = frames;
        Ok(())
    }
    /// Accept an encoded frame or the bytes held when EOF arrives. Empty EOF
    /// before Complete returns [`ProtocolError::Truncated`]; after Complete it
    /// returns `Ok(())`. Even one trailing byte after Complete is a protocol
    /// violation.
    ///
    /// The adapter must stop the exchange at the first `Err`: a rejection leaves
    /// the transcript unchanged and does not latch a failure blocking later calls.
    pub fn accept_bytes(&mut self, bytes: &[u8]) -> Result<(), ProtocolError> {
        if self.complete {
            return if bytes.is_empty() {
                Ok(())
            } else {
                Err(ProtocolError::Order)
            };
        }
        self.accept(decode_eof(bytes)?)
    }
    pub fn request_sent(&mut self) -> Result<(), ProtocolError> {
        if !self.ready || self.sent || self.complete {
            return Err(ProtocolError::Order);
        }
        self.sent = true;
        Ok(())
    }
    // Spec collector-message rule (line 672): violations terminate collection;
    // deadline/publication rule 3 (line 709): the supervisor applies the deadline.
    // Neither gives Complete priority over a later supervisor termination. Keep
    // the supplied reason: Complete without EOF can still end at Deadline.
    pub fn finish(self, reason: EndReason, now: Clock) -> Result<Option<Completed>, ProtocolError> {
        if reason == EndReason::Complete && !self.complete {
            return Err(ProtocolError::Order);
        }
        let b = &self.request.binding;
        if now.kind != b.clock_kind
            || now.boot != b.snapshot.boot
            || now.domain != b.domain
            || now.resume != b.resume
        {
            return Err(ProtocolError::Schema);
        }
        add_budget(super::response::base_len(b)?, self.stored, STREAM_MAX)?;
        if self.updates.is_empty() {
            return Ok(None);
        }
        Ok(Some(Completed {
            request_id: self.request.request_id,
            binding: self.request.binding,
            completed_at_ns: now.now,
            reason,
            progress: self.progress,
            updates: self.updates,
        }))
    }
}
pub(crate) fn read_update(
    r: &mut Reader<'_>,
    schema: &Schema,
    binding: &Binding,
    text_limit: usize,
) -> Result<Update, ProtocolError> {
    let segment = r.u16()?;
    let types = schema.segment(segment, binding.mask)?;
    let value = read_value(r, types, text_limit)?;
    let facts = if r.boolean()? {
        if segment != 1 {
            return Err(ProtocolError::Schema);
        }
        Some(PathFactInput::decode(
            r.bytes(super::path_facts::ENCODED_MAX, ProtocolError::Budget)?,
            &binding.cwd,
        )?)
    } else {
        None
    };
    Ok(Update {
        segment,
        value,
        facts,
    })
}
fn read_value(
    r: &mut Reader<'_>,
    types: &[FieldType],
    text_limit: usize,
) -> Result<Option<Value>, ProtocolError> {
    let present = r.u8()?;
    if present == 0 {
        return Ok(None);
    }
    if present != 1 {
        return Err(ProtocolError::Schema);
    }
    let raw = r.bytes(text_limit, ProtocolError::Budget)?;
    let count = usize::from(r.u16()?);
    if count > FIELDS_MAX {
        return Err(ProtocolError::Budget);
    }
    let mut fields = vec![Field::PENDING; types.len()];
    let mut seen = 0u32;
    for _ in 0..count {
        let index = usize::from(r.u16()?);
        let ty = *types.get(index).ok_or(ProtocolError::Schema)?;
        if seen & (1u32 << index) != 0 {
            return Err(ProtocolError::Duplicate);
        }
        seen |= 1u32 << index;
        let state = match r.u8()? {
            0 => ValueState::Known,
            1 => ValueState::Pending,
            _ => return Err(ProtocolError::Schema),
        };
        let tag = r.u8()?;
        let mut field = match tag {
            0 => {
                let FieldType::Text { max_cells } = ty else {
                    return Err(ProtocolError::Schema);
                };
                Field::text(
                    r.bytes(text_limit, ProtocolError::Budget)?,
                    max_cells,
                    WidthProfile::DEFAULT,
                )
            }
            1 => Field::known(FieldValue::Count {
                n: r.u32()?,
                saturated: r.boolean()?,
            }),
            2 => Field::known(FieldValue::Int(i64::from_le_bytes(r.array()?))),
            3 => Field::known(FieldValue::Duration { ms: r.u64()? }),
            4 => Field::known(FieldValue::Bool(r.boolean()?)),
            5 => Field::ABSENT,
            _ => return Err(ProtocolError::Schema),
        };
        field.state = state;
        if !field.fits(ty) {
            return Err(ProtocolError::Schema);
        }
        fields[index] = field;
    }
    Ok(Some(Value::new(raw, fields)))
}
pub(crate) fn update_len(
    update: &Update,
    schema: &Schema,
    binding: &Binding,
) -> Result<usize, ProtocolError> {
    let types = schema.segment(update.segment, binding.mask)?;
    if schema.git
        && update.segment == git::SEGMENT
        && update.value.as_ref().is_some_and(|v| !git::valid(v))
    {
        return Err(ProtocolError::Schema);
    }
    let facts_len = if let Some(facts) = &update.facts {
        if update.segment != 1 {
            return Err(ProtocolError::Schema);
        }
        5 + facts.encoded_len(&binding.cwd)?
    } else {
        1
    };
    add_budget(
        value_len(update.value.as_ref(), types)?,
        facts_len,
        STREAM_MAX,
    )
}
fn value_len(value: Option<&Value>, types: &[FieldType]) -> Result<usize, ProtocolError> {
    let Some(value) = value else {
        return Ok(3);
    };
    if value.fields.len() > FIELDS_MAX {
        return Err(ProtocolError::Budget);
    }
    if value.fields.len() != types.len() {
        return Err(ProtocolError::Schema);
    }
    let mut len = add_budget(9, value.text().len(), STREAM_MAX)?;
    for (field, ty) in value.fields.iter().zip(types) {
        if !field.fits(*ty) {
            return Err(ProtocolError::Schema);
        }
        let n = match &field.value {
            FieldValue::Text(t) => add_budget(4, t.as_str().len(), STREAM_MAX)?,
            FieldValue::Count { .. } => 5,
            FieldValue::Int(_) | FieldValue::Duration { .. } => 8,
            FieldValue::Bool(_) => 1,
            FieldValue::Absent => 0,
        };
        len = add_budget(len, add_budget(4, n, STREAM_MAX)?, STREAM_MAX)?;
    }
    Ok(len)
}
pub(crate) fn put_update(out: &mut Vec<u8>, update: &Update) {
    out.extend_from_slice(&update.segment.to_le_bytes());
    put_value(out, update.value.as_ref());
    out.push(u8::from(update.facts.is_some()));
    if let Some(facts) = &update.facts {
        let at = out.len();
        out.extend_from_slice(&[0; 4]);
        facts.put(out);
        let len = (out.len() - at - 4) as u32;
        out[at..at + 4].copy_from_slice(&len.to_le_bytes());
    }
}
fn put_value(out: &mut Vec<u8>, value: Option<&Value>) {
    let Some(value) = value else {
        out.push(0);
        return;
    };
    out.push(1);
    put_bytes(out, value.text().as_bytes());
    out.extend_from_slice(&(value.fields.len() as u16).to_le_bytes());
    for (i, field) in value.fields.iter().enumerate() {
        out.extend_from_slice(&(i as u16).to_le_bytes());
        out.push(match field.state {
            ValueState::Known => 0,
            ValueState::Pending => 1,
        });
        match &field.value {
            FieldValue::Text(t) => {
                out.push(0);
                put_bytes(out, t.as_str().as_bytes());
            }
            FieldValue::Count { n, saturated } => {
                out.push(1);
                out.extend_from_slice(&n.to_le_bytes());
                out.push(u8::from(*saturated));
            }
            FieldValue::Int(n) => {
                out.push(2);
                out.extend_from_slice(&n.to_le_bytes());
            }
            FieldValue::Duration { ms } => {
                out.push(3);
                out.extend_from_slice(&ms.to_le_bytes());
            }
            FieldValue::Bool(v) => {
                out.push(4);
                out.push(u8::from(*v));
            }
            FieldValue::Absent => out.push(5),
        }
    }
}
/// A size calculation is part of the release wire contract, not a debug hint.
pub(crate) fn checked_encoding(out: Vec<u8>, expected: usize) -> Result<Vec<u8>, ProtocolError> {
    if out.len() != expected {
        return Err(ProtocolError::Length);
    }
    Ok(out)
}
pub(crate) fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
}
pub(crate) struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}
impl<'a> Reader<'a> {
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }
    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8], ProtocolError> {
        let end = self.at.checked_add(n).ok_or(ProtocolError::Schema)?;
        let out = self.bytes.get(self.at..end).ok_or(ProtocolError::Schema)?;
        self.at = end;
        Ok(out)
    }
    pub(crate) fn array<const N: usize>(&mut self) -> Result<[u8; N], ProtocolError> {
        Ok(self.take(N)?.try_into().unwrap())
    }
    pub(crate) fn u8(&mut self) -> Result<u8, ProtocolError> {
        Ok(self.array::<1>()?[0])
    }
    pub(crate) fn u16(&mut self) -> Result<u16, ProtocolError> {
        Ok(u16::from_le_bytes(self.array()?))
    }
    pub(crate) fn u32(&mut self) -> Result<u32, ProtocolError> {
        Ok(u32::from_le_bytes(self.array()?))
    }
    pub(crate) fn u64(&mut self) -> Result<u64, ProtocolError> {
        Ok(u64::from_le_bytes(self.array()?))
    }
    pub(crate) fn boolean(&mut self) -> Result<bool, ProtocolError> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(ProtocolError::Schema),
        }
    }
    pub(crate) fn bytes(
        &mut self,
        max: usize,
        error: ProtocolError,
    ) -> Result<&'a [u8], ProtocolError> {
        let n = self.u32()? as usize;
        if n > max {
            return Err(error);
        }
        self.take(n)
    }
    pub(crate) fn remaining(&self) -> &'a [u8] {
        &self.bytes[self.at..]
    }
    pub(crate) fn end(&self) -> Result<(), ProtocolError> {
        if self.at == self.bytes.len() {
            Ok(())
        } else {
            Err(ProtocolError::Schema)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ProtocolError, STREAM_MAX, add_budget, checked_encoding, replace_budget};
    // 이것을 실패시키는 것: checked_encoding의 길이 검사를 debug_assert로 바꾸는 것.
    // Run this test with --release as well; no debug assertion is involved.
    #[test]
    fn encoding_length_mismatch_is_a_release_error() {
        for expected in [0, 2] {
            assert_eq!(
                checked_encoding(alloc::vec![1], expected),
                Err(ProtocolError::Length)
            );
        }
        assert_eq!(checked_encoding(alloc::vec![1], 1), Ok(alloc::vec![1]));
    }
    // 이것을 실패시키는 것: 예산 덧셈 overflow 또는 교체 뺄셈 underflow를 wrap하는 것.
    #[test]
    fn budget_arithmetic_never_wraps() {
        assert_eq!(
            add_budget(usize::MAX, 1, usize::MAX),
            Err(ProtocolError::Budget)
        );
        assert_eq!(
            replace_budget(0, 1, 0, STREAM_MAX),
            Err(ProtocolError::Budget)
        );
        // 이것을 실패시키는 것: 뺄셈 wrap을 뒤의 작은 상한 검사로만 막는 것.
        assert_eq!(
            replace_budget(0, 1, 0, usize::MAX),
            Err(ProtocolError::Budget)
        );
        assert_eq!(
            replace_budget(usize::MAX, 0, 1, usize::MAX),
            Err(ProtocolError::Budget)
        );
    }
}
