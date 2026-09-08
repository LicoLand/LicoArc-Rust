use std::collections::BTreeMap;

use crate::{
    encoding::{self, CborValue},
    error::{Error, ErrorCode, Stage},
};

pub const MAX_PAYLOAD_BYTES: usize = 262_144;
pub const MAX_ATTACHMENTS: usize = 8;
pub const ATTACHMENT_CHUNK_BYTES: u64 = 65_536;
pub const MAX_ATTACHMENT_CHUNKS: u64 = 128;
pub const MAX_REQUEST_RANGES: usize = 32;
pub const MAX_REQUESTED_CHUNKS: u64 = 128;
pub const MAX_STATE_UPDATE: u64 = 64;
pub const MAX_RECOVERY_ROUND: u64 = 32;
pub const MAX_CONTROL_RECORD_BYTES: usize = 65_536;
const RESERVED_START: u32 = 4_294_901_760;
const ATTACHMENT_RECEIVE_STATE: u32 = 4_294_901_761;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum MessageKind {
    Event = 0,
    Request = 1,
    Response = 2,
    Error = 3,
    Cancel = 4,
    StreamChunk = 5,
}

#[derive(Clone, Eq, PartialEq)]
pub struct Attachment {
    pub id: [u8; 16],
    pub media_type: u32,
    pub byte_length: u64,
    pub content_digest: [u8; 32],
}

impl std::fmt::Debug for Attachment {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Attachment([REDACTED])")
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct Message {
    pub id: [u8; 16],
    pub kind: MessageKind,
    pub relates_to: Option<[u8; 16]>,
    pub content_type: u32,
    pub payload: Vec<u8>,
    pub extensions: BTreeMap<u32, Vec<u8>>,
    pub critical: Vec<u32>,
    pub chunk_index: Option<u64>,
    pub chunk_final: Option<bool>,
    pub attachment_id: Option<[u8; 16]>,
    pub attachments: Vec<Attachment>,
}

impl std::fmt::Debug for Message {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Message([REDACTED])")
    }
}

impl Message {
    pub fn validate(&self) -> Result<(), Error> {
        if self.payload.len() > MAX_PAYLOAD_BYTES || self.attachments.len() > MAX_ATTACHMENTS {
            return Err(validation(ErrorCode::BoundExceeded));
        }
        if self.extensions.len() > 16
            || self.extensions.iter().any(|(label, value)| {
                !(65_536..=2_147_483_647).contains(label) || value.len() > 4096
            })
            || self.critical.len() > 16
        {
            return Err(validation(ErrorCode::BoundExceeded));
        }
        if !self.critical.is_empty() {
            return Err(validation(ErrorCode::UnknownField));
        }
        let correlated = matches!(
            self.kind,
            MessageKind::Response
                | MessageKind::Error
                | MessageKind::Cancel
                | MessageKind::StreamChunk
        ) || (self.kind == MessageKind::Event
            && self.content_type == ATTACHMENT_RECEIVE_STATE);
        if correlated != self.relates_to.is_some() {
            return Err(validation(ErrorCode::InvalidTransition));
        }
        if self.content_type >= RESERVED_START && self.content_type != ATTACHMENT_RECEIVE_STATE {
            return Err(validation(ErrorCode::UnknownField));
        }
        let chunk = self.kind == MessageKind::StreamChunk;
        if chunk != self.chunk_index.is_some()
            || (!chunk && (self.chunk_final.is_some() || self.attachment_id.is_some()))
            || (chunk && (self.chunk_final.is_some() == self.attachment_id.is_some()))
        {
            return Err(validation(ErrorCode::InvalidTransition));
        }
        if self.content_type == ATTACHMENT_RECEIVE_STATE
            && (self.kind != MessageKind::Event
                || self.relates_to.is_none()
                || !self.attachments.is_empty()
                || ReceiveState::decode(&self.payload).is_err())
        {
            return Err(validation(ErrorCode::InvalidTransition));
        }
        if self
            .attachments
            .iter()
            .any(|attachment| attachment.byte_length > 8_388_608)
        {
            return Err(validation(ErrorCode::BoundExceeded));
        }
        let mut descriptors = BTreeMap::new();
        for attachment in &self.attachments {
            if let Some(previous) = descriptors.insert(attachment.id, attachment) {
                return Err(validation(if previous == attachment {
                    ErrorCode::InvalidRepresentation
                } else {
                    ErrorCode::Conflict
                }));
            }
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        encoding::encode(&self.as_cbor())
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let CborValue::Map(mut map) = encoding::decode(bytes)? else {
            return Err(validation(ErrorCode::InvalidRepresentation));
        };
        if map.keys().any(|key| !matches!(key, 0..=10)) {
            return Err(validation(ErrorCode::UnknownField));
        }
        let id = take_fixed::<16>(&mut map, 0)?;
        let kind = match take_unsigned(&mut map, 1)? {
            0 => MessageKind::Event,
            1 => MessageKind::Request,
            2 => MessageKind::Response,
            3 => MessageKind::Error,
            4 => MessageKind::Cancel,
            5 => MessageKind::StreamChunk,
            _ => return Err(validation(ErrorCode::UnknownField)),
        };
        let relates_to = take_optional_fixed::<16>(&mut map, 2)?;
        let content_type = u32::try_from(take_unsigned(&mut map, 3)?)
            .map_err(|_| validation(ErrorCode::BoundExceeded))?;
        let payload = take_bytes(&mut map, 4)?;
        let extensions = match map.remove(&5) {
            None => BTreeMap::new(),
            Some(CborValue::Map(values)) => values
                .into_iter()
                .map(|(key, value)| {
                    let key =
                        u32::try_from(key).map_err(|_| validation(ErrorCode::BoundExceeded))?;
                    let CborValue::Bytes(value) = value else {
                        return Err(validation(ErrorCode::InvalidRepresentation));
                    };
                    Ok((key, value))
                })
                .collect::<Result<_, Error>>()?,
            Some(_) => return Err(validation(ErrorCode::InvalidRepresentation)),
        };
        let critical = match map.remove(&6) {
            None => Vec::new(),
            Some(CborValue::Array(values)) => values
                .into_iter()
                .map(|value| match value {
                    CborValue::Unsigned(value) => {
                        u32::try_from(value).map_err(|_| validation(ErrorCode::BoundExceeded))
                    }
                    _ => Err(validation(ErrorCode::InvalidRepresentation)),
                })
                .collect::<Result<_, Error>>()?,
            Some(_) => return Err(validation(ErrorCode::InvalidRepresentation)),
        };
        let chunk_index = take_optional_unsigned(&mut map, 7)?;
        let chunk_final = take_optional_bool(&mut map, 8)?;
        let attachment_id = take_optional_fixed::<16>(&mut map, 9)?;
        let attachments = match map.remove(&10) {
            None => Vec::new(),
            Some(CborValue::Array(values)) => values
                .into_iter()
                .map(decode_attachment)
                .collect::<Result<_, _>>()?,
            Some(_) => return Err(validation(ErrorCode::InvalidRepresentation)),
        };
        if !map.is_empty() {
            return Err(validation(ErrorCode::UnknownField));
        }
        let message = Self {
            id,
            kind,
            relates_to,
            content_type,
            payload,
            extensions,
            critical,
            chunk_index,
            chunk_final,
            attachment_id,
            attachments,
        };
        message.validate()?;
        Ok(message)
    }

    fn as_cbor(&self) -> CborValue {
        let mut map = BTreeMap::from([
            (0, CborValue::Bytes(self.id.to_vec())),
            (1, CborValue::Unsigned(self.kind as u64)),
            (3, CborValue::Unsigned(u64::from(self.content_type))),
            (4, CborValue::Bytes(self.payload.clone())),
        ]);
        if let Some(value) = self.relates_to {
            map.insert(2, CborValue::Bytes(value.to_vec()));
        }
        if !self.extensions.is_empty() {
            map.insert(
                5,
                CborValue::Map(
                    self.extensions
                        .iter()
                        .map(|(key, value)| (u64::from(*key), CborValue::Bytes(value.clone())))
                        .collect(),
                ),
            );
        }
        if !self.critical.is_empty() {
            map.insert(
                6,
                CborValue::Array(
                    self.critical
                        .iter()
                        .map(|value| CborValue::Unsigned(u64::from(*value)))
                        .collect(),
                ),
            );
        }
        if let Some(value) = self.chunk_index {
            map.insert(7, CborValue::Unsigned(value));
        }
        if let Some(value) = self.chunk_final {
            map.insert(8, CborValue::Bool(value));
        }
        if let Some(value) = self.attachment_id {
            map.insert(9, CborValue::Bytes(value.to_vec()));
        }
        if !self.attachments.is_empty() {
            map.insert(
                10,
                CborValue::Array(
                    self.attachments
                        .iter()
                        .map(|item| {
                            CborValue::Map(BTreeMap::from([
                                (0, CborValue::Bytes(item.id.to_vec())),
                                (1, CborValue::Unsigned(u64::from(item.media_type))),
                                (2, CborValue::Unsigned(item.byte_length)),
                                (3, CborValue::Bytes(item.content_digest.to_vec())),
                            ]))
                        })
                        .collect(),
                ),
            );
        }
        CborValue::Map(map)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChunkRange {
    pub start: u64,
    pub end: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ReceiveOutcome {
    Pending = 0,
    Complete = 1,
    Cancelled = 2,
    Failed = 3,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceiveState {
    pub attachment_id: [u8; 16],
    pub ranges: Vec<ChunkRange>,
    pub state_update: u64,
    pub outcome: ReceiveOutcome,
    pub failure_code: Option<u64>,
    pub recovery_round: u64,
}

impl ReceiveState {
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_CONTROL_RECORD_BYTES {
            return Err(validation(ErrorCode::BoundExceeded));
        }
        let CborValue::Map(mut map) = encoding::decode(bytes)? else {
            return Err(validation(ErrorCode::InvalidRepresentation));
        };
        if map.keys().any(|key| !matches!(key, 0..=5)) {
            return Err(validation(ErrorCode::UnknownField));
        }
        let ranges = match map.remove(&1) {
            Some(CborValue::Array(values)) => values
                .into_iter()
                .map(|value| {
                    let CborValue::Map(mut range) = value else {
                        return Err(validation(ErrorCode::InvalidRepresentation));
                    };
                    let item = ChunkRange {
                        start: take_unsigned(&mut range, 0)?,
                        end: take_unsigned(&mut range, 1)?,
                    };
                    if !range.is_empty() {
                        return Err(validation(ErrorCode::UnknownField));
                    }
                    Ok(item)
                })
                .collect::<Result<_, Error>>()?,
            _ => return Err(validation(ErrorCode::InvalidRepresentation)),
        };
        let outcome = match take_unsigned(&mut map, 3)? {
            0 => ReceiveOutcome::Pending,
            1 => ReceiveOutcome::Complete,
            2 => ReceiveOutcome::Cancelled,
            3 => ReceiveOutcome::Failed,
            _ => return Err(validation(ErrorCode::UnknownField)),
        };
        let state = Self {
            attachment_id: take_fixed(&mut map, 0)?,
            ranges,
            state_update: take_unsigned(&mut map, 2)?,
            outcome,
            failure_code: take_optional_unsigned(&mut map, 4)?,
            recovery_round: take_unsigned(&mut map, 5)?,
        };
        if !map.is_empty() {
            return Err(validation(ErrorCode::UnknownField));
        }
        state.validate()?;
        Ok(state)
    }

    pub fn validate(&self) -> Result<(), Error> {
        if self.ranges.len() > MAX_REQUEST_RANGES
            || self.state_update > MAX_STATE_UPDATE
            || self.recovery_round > MAX_RECOVERY_ROUND
            || self.failure_code.is_some_and(|code| code > 14)
        {
            return Err(validation(ErrorCode::BoundExceeded));
        }
        let mut covered = 0_u64;
        let mut previous_end = None;
        for range in &self.ranges {
            if range.start >= range.end || previous_end.is_some_and(|end| range.start <= end) {
                return Err(validation(ErrorCode::InvalidRepresentation));
            }
            covered = covered
                .checked_add(range.end - range.start)
                .filter(|value| *value <= MAX_REQUESTED_CHUNKS)
                .ok_or_else(|| validation(ErrorCode::BoundExceeded))?;
            previous_end = Some(range.end);
        }
        let failed = matches!(
            self.outcome,
            ReceiveOutcome::Cancelled | ReceiveOutcome::Failed
        );
        if failed != self.failure_code.is_some()
            || self.ranges.is_empty() != (self.outcome == ReceiveOutcome::Complete)
        {
            return Err(validation(ErrorCode::InvalidTransition));
        }
        Ok(())
    }

    /// Validates a receive-state update. `completion_verified` is a caller-owned
    /// fact that the descriptor geometry and complete content digest were
    /// checked before an empty `Complete` state is committed.
    pub fn validate_successor(&self, next: &Self, completion_verified: bool) -> Result<(), Error> {
        self.validate()?;
        next.validate()?;
        if self.attachment_id != next.attachment_id
            || next.state_update < self.state_update
            || next.recovery_round < self.recovery_round
        {
            return Err(validation(ErrorCode::InvalidTransition));
        }
        if next.state_update == self.state_update {
            return if self == next {
                Ok(())
            } else {
                Err(validation(ErrorCode::Conflict))
            };
        }
        if self.outcome != ReceiveOutcome::Pending
            || (next.outcome == ReceiveOutcome::Complete && !completion_verified)
        {
            return Err(validation(ErrorCode::InvalidTransition));
        }
        Ok(())
    }
}

pub fn validate_attachment_chunk(
    byte_length: u64,
    chunk_index: u64,
    payload_length: usize,
) -> Result<(), Error> {
    let count = byte_length
        .checked_add(ATTACHMENT_CHUNK_BYTES - 1)
        .ok_or_else(|| validation(ErrorCode::BoundExceeded))?
        / ATTACHMENT_CHUNK_BYTES;
    if count > MAX_ATTACHMENT_CHUNKS || chunk_index >= count {
        return Err(validation(ErrorCode::BoundExceeded));
    }
    let offset = chunk_index
        .checked_mul(ATTACHMENT_CHUNK_BYTES)
        .ok_or_else(|| validation(ErrorCode::BoundExceeded))?;
    let expected = ATTACHMENT_CHUNK_BYTES.min(byte_length - offset);
    if u64::try_from(payload_length) != Ok(expected) {
        return Err(validation(ErrorCode::InvalidRepresentation));
    }
    Ok(())
}

fn decode_attachment(value: CborValue) -> Result<Attachment, Error> {
    let CborValue::Map(mut map) = value else {
        return Err(validation(ErrorCode::InvalidRepresentation));
    };
    let item = Attachment {
        id: take_fixed(&mut map, 0)?,
        media_type: u32::try_from(take_unsigned(&mut map, 1)?)
            .map_err(|_| validation(ErrorCode::BoundExceeded))?,
        byte_length: take_unsigned(&mut map, 2)?,
        content_digest: take_fixed(&mut map, 3)?,
    };
    if !map.is_empty() {
        return Err(validation(ErrorCode::UnknownField));
    }
    Ok(item)
}

fn take_bytes(map: &mut BTreeMap<u64, CborValue>, key: u64) -> Result<Vec<u8>, Error> {
    match map.remove(&key) {
        Some(CborValue::Bytes(value)) => Ok(value),
        _ => Err(validation(ErrorCode::InvalidRepresentation)),
    }
}

fn take_fixed<const N: usize>(
    map: &mut BTreeMap<u64, CborValue>,
    key: u64,
) -> Result<[u8; N], Error> {
    take_bytes(map, key)?
        .try_into()
        .map_err(|_| validation(ErrorCode::InvalidRepresentation))
}

fn take_optional_fixed<const N: usize>(
    map: &mut BTreeMap<u64, CborValue>,
    key: u64,
) -> Result<Option<[u8; N]>, Error> {
    map.remove(&key)
        .map(|value| match value {
            CborValue::Bytes(bytes) => bytes
                .try_into()
                .map_err(|_| validation(ErrorCode::InvalidRepresentation)),
            _ => Err(validation(ErrorCode::InvalidRepresentation)),
        })
        .transpose()
}

fn take_unsigned(map: &mut BTreeMap<u64, CborValue>, key: u64) -> Result<u64, Error> {
    match map.remove(&key) {
        Some(CborValue::Unsigned(value)) => Ok(value),
        _ => Err(validation(ErrorCode::InvalidRepresentation)),
    }
}

fn take_optional_unsigned(
    map: &mut BTreeMap<u64, CborValue>,
    key: u64,
) -> Result<Option<u64>, Error> {
    map.remove(&key)
        .map(|value| match value {
            CborValue::Unsigned(value) => Ok(value),
            _ => Err(validation(ErrorCode::InvalidRepresentation)),
        })
        .transpose()
}

fn take_optional_bool(map: &mut BTreeMap<u64, CborValue>, key: u64) -> Result<Option<bool>, Error> {
    map.remove(&key)
        .map(|value| match value {
            CborValue::Bool(value) => Ok(value),
            _ => Err(validation(ErrorCode::InvalidRepresentation)),
        })
        .transpose()
}

const fn validation(code: ErrorCode) -> Error {
    Error::terminal(code, Stage::Validation)
}
