use std::collections::BTreeMap;

use crate::{
    encoding::{self, CborValue, Limits},
    error::{Error, ErrorCode, Stage},
};

pub const MAX_PACKET_BYTES: usize = 524_288;
pub const MAX_FRAME_BYTES: usize = MAX_PACKET_BYTES + 128;

const TRANSPORT_LIMITS: Limits = Limits {
    depth: 4,
    collection_items: 5,
    encoded_bytes: MAX_FRAME_BYTES,
    raw_bytes: MAX_PACKET_BYTES,
    text_bytes: 0,
};
pub const MAX_INFLIGHT_DELIVERIES: u64 = 16;
pub const MAX_OUTSTANDING_SENDS: u64 = 16;
pub const NONCE_BYTES: usize = 32;
pub const MAILBOX_ID_BYTES: usize = 16;
pub const HANDLE_BYTES: usize = 32;
pub const DEVICE_KEY_BYTES: usize = 32;
pub const SIGNATURE_BYTES: usize = 64;
pub const MAX_REQUEST_ID: u64 = 4_294_967_295;
pub const MAX_RETRY_AFTER_MS: u64 = 60_000;

pub const FRAME_HELLO: u64 = 1;
pub const FRAME_SEND: u64 = 2;
pub const FRAME_ACK: u64 = 3;
pub const FRAME_CHALLENGE: u64 = 16;
pub const FRAME_READY: u64 = 17;
pub const FRAME_RESULT: u64 = 18;
pub const FRAME_DELIVER: u64 = 19;
pub const FRAME_DRAINED: u64 = 20;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FailureClass {
    InvalidRequest,
    TargetUnavailable,
    PacketTooLarge,
    MailboxFull,
    InternalUnavailable,
}

impl FailureClass {
    fn from_u64(value: u64) -> Result<Self, Error> {
        match value {
            0 => Ok(Self::InvalidRequest),
            1 => Ok(Self::TargetUnavailable),
            2 => Ok(Self::PacketTooLarge),
            3 => Ok(Self::MailboxFull),
            4 => Ok(Self::InternalUnavailable),
            _ => Err(validation(ErrorCode::UnknownField)),
        }
    }

    fn as_u64(self) -> u64 {
        match self {
            Self::InvalidRequest => 0,
            Self::TargetUnavailable => 1,
            Self::PacketTooLarge => 2,
            Self::MailboxFull => 3,
            Self::InternalUnavailable => 4,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportOutcome {
    Accepted,
    Rejected,
    Transient,
    Ambiguous,
}

impl TransportOutcome {
    fn as_u64(self) -> u64 {
        match self {
            Self::Accepted => 0,
            Self::Rejected => 1,
            Self::Transient => 2,
            Self::Ambiguous => 3,
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub enum ClientFrame {
    Hello {
        device_key: [u8; DEVICE_KEY_BYTES],
        signature: [u8; SIGNATURE_BYTES],
    },
    Send {
        request_id: u32,
        handle: [u8; HANDLE_BYTES],
        packet: Vec<u8>,
    },
    Ack {
        delivery_sequence: u64,
    },
}

#[derive(Clone, Eq, PartialEq)]
pub enum StationFrame {
    Challenge {
        nonce: [u8; NONCE_BYTES],
    },
    Ready {
        mailbox_id: [u8; MAILBOX_ID_BYTES],
    },
    Result {
        request_id: u32,
        outcome: TransportOutcome,
        failure_class: Option<FailureClass>,
        retry_after_ms: Option<u32>,
    },
    Deliver {
        delivery_sequence: u64,
        handle: [u8; HANDLE_BYTES],
        packet: Vec<u8>,
    },
    Drained,
}

impl std::fmt::Debug for ClientFrame {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ClientFrame([REDACTED])")
    }
}

impl std::fmt::Debug for StationFrame {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("StationFrame([REDACTED])")
    }
}

impl ClientFrame {
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let mut map = BTreeMap::new();
        match self {
            Self::Hello {
                device_key,
                signature,
            } => {
                map.insert(0, CborValue::Unsigned(FRAME_HELLO));
                map.insert(1, CborValue::Bytes(device_key.to_vec()));
                map.insert(2, CborValue::Bytes(signature.to_vec()));
            }
            Self::Send {
                request_id,
                handle,
                packet,
            } => {
                if packet.is_empty() || packet.len() > MAX_PACKET_BYTES {
                    return Err(validation(ErrorCode::BoundExceeded));
                }
                map.insert(0, CborValue::Unsigned(FRAME_SEND));
                map.insert(1, CborValue::Unsigned(u64::from(*request_id)));
                map.insert(2, CborValue::Bytes(handle.to_vec()));
                map.insert(3, CborValue::Bytes(packet.clone()));
            }
            Self::Ack { delivery_sequence } => {
                map.insert(0, CborValue::Unsigned(FRAME_ACK));
                map.insert(1, CborValue::Unsigned(*delivery_sequence));
            }
        }
        encode_checked(&map)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let map = decode_map(bytes)?;
        match map_type(&map)? {
            FRAME_HELLO => {
                require_keys(&map, &[0, 1, 2])?;
                Ok(Self::Hello {
                    device_key: fixed_bytes(&map, 1, DEVICE_KEY_BYTES)?,
                    signature: fixed_bytes(&map, 2, SIGNATURE_BYTES)?,
                })
            }
            FRAME_SEND => {
                require_keys(&map, &[0, 1, 2, 3])?;
                let request_id = bounded_unsigned(&map, 1, MAX_REQUEST_ID)? as u32;
                let packet = bytes_value(&map, 3)?;
                if packet.is_empty() || packet.len() > MAX_PACKET_BYTES {
                    return Err(validation(ErrorCode::BoundExceeded));
                }
                Ok(Self::Send {
                    request_id,
                    handle: fixed_bytes(&map, 2, HANDLE_BYTES)?,
                    packet,
                })
            }
            FRAME_ACK => {
                require_keys(&map, &[0, 1])?;
                Ok(Self::Ack {
                    delivery_sequence: unsigned_value(&map, 1)?,
                })
            }
            _ => Err(validation(ErrorCode::UnknownField)),
        }
    }
}

impl StationFrame {
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let mut map = BTreeMap::new();
        match self {
            Self::Challenge { nonce } => {
                map.insert(0, CborValue::Unsigned(FRAME_CHALLENGE));
                map.insert(1, CborValue::Bytes(nonce.to_vec()));
            }
            Self::Ready { mailbox_id } => {
                map.insert(0, CborValue::Unsigned(FRAME_READY));
                map.insert(1, CborValue::Bytes(mailbox_id.to_vec()));
            }
            Self::Result {
                request_id,
                outcome,
                failure_class,
                retry_after_ms,
            } => {
                map.insert(0, CborValue::Unsigned(FRAME_RESULT));
                map.insert(1, CborValue::Unsigned(u64::from(*request_id)));
                map.insert(2, CborValue::Unsigned(outcome.as_u64()));
                if let Some(class) = failure_class {
                    map.insert(3, CborValue::Unsigned(class.as_u64()));
                }
                if let Some(ms) = retry_after_ms {
                    map.insert(4, CborValue::Unsigned(u64::from(*ms)));
                }
            }
            Self::Deliver {
                delivery_sequence,
                handle,
                packet,
            } => {
                if packet.is_empty() || packet.len() > MAX_PACKET_BYTES {
                    return Err(validation(ErrorCode::BoundExceeded));
                }
                map.insert(0, CborValue::Unsigned(FRAME_DELIVER));
                map.insert(1, CborValue::Unsigned(*delivery_sequence));
                map.insert(2, CborValue::Bytes(handle.to_vec()));
                map.insert(3, CborValue::Bytes(packet.clone()));
            }
            Self::Drained => {
                map.insert(0, CborValue::Unsigned(FRAME_DRAINED));
            }
        }
        encode_checked(&map)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let map = decode_map(bytes)?;
        match map_type(&map)? {
            FRAME_CHALLENGE => {
                require_keys(&map, &[0, 1])?;
                Ok(Self::Challenge {
                    nonce: fixed_bytes(&map, 1, NONCE_BYTES)?,
                })
            }
            FRAME_READY => {
                require_keys(&map, &[0, 1])?;
                Ok(Self::Ready {
                    mailbox_id: fixed_bytes(&map, 1, MAILBOX_ID_BYTES)?,
                })
            }
            FRAME_RESULT => {
                if !map.contains_key(&0) || !map.contains_key(&1) || !map.contains_key(&2) {
                    return Err(validation(ErrorCode::UnknownField));
                }
                let keys = map.keys().copied().collect::<Vec<_>>();
                if keys.iter().any(|key| !(0..=4).contains(key)) {
                    return Err(validation(ErrorCode::UnknownField));
                }
                let request_id = bounded_unsigned(&map, 1, MAX_REQUEST_ID)? as u32;
                let outcome = match unsigned_value(&map, 2)? {
                    0 => TransportOutcome::Accepted,
                    1 => TransportOutcome::Rejected,
                    2 => TransportOutcome::Transient,
                    _ => return Err(validation(ErrorCode::UnknownField)),
                };
                let failure_class = optional_u64(&map, 3)?
                    .map(FailureClass::from_u64)
                    .transpose()?;
                let retry_after_ms = match optional_u64(&map, 4)? {
                    Some(ms) if ms <= MAX_RETRY_AFTER_MS => Some(ms as u32),
                    Some(_) => return Err(validation(ErrorCode::BoundExceeded)),
                    None => None,
                };
                Ok(Self::Result {
                    request_id,
                    outcome,
                    failure_class,
                    retry_after_ms,
                })
            }
            FRAME_DELIVER => {
                require_keys(&map, &[0, 1, 2, 3])?;
                let packet = bytes_value(&map, 3)?;
                if packet.is_empty() || packet.len() > MAX_PACKET_BYTES {
                    return Err(validation(ErrorCode::BoundExceeded));
                }
                Ok(Self::Deliver {
                    delivery_sequence: unsigned_value(&map, 1)?,
                    handle: fixed_bytes(&map, 2, HANDLE_BYTES)?,
                    packet,
                })
            }
            FRAME_DRAINED => {
                require_keys(&map, &[0])?;
                Ok(Self::Drained)
            }
            _ => Err(validation(ErrorCode::UnknownField)),
        }
    }
}

fn encode_checked(map: &BTreeMap<u64, CborValue>) -> Result<Vec<u8>, Error> {
    let encoded = encoding::encode_at(&CborValue::Map(map.clone()), &TRANSPORT_LIMITS)?;
    if encoded.len() > MAX_FRAME_BYTES {
        return Err(validation(ErrorCode::BoundExceeded));
    }
    Ok(encoded)
}

fn decode_map(bytes: &[u8]) -> Result<BTreeMap<u64, CborValue>, Error> {
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(validation(ErrorCode::BoundExceeded));
    }
    match encoding::decode_at(bytes, &TRANSPORT_LIMITS)? {
        CborValue::Map(map) => Ok(map),
        _ => Err(validation(ErrorCode::InvalidRepresentation)),
    }
}

fn map_type(map: &BTreeMap<u64, CborValue>) -> Result<u64, Error> {
    unsigned_option(map.get(&0))
}

fn require_keys(map: &BTreeMap<u64, CborValue>, expected: &[u64]) -> Result<(), Error> {
    let keys = map.keys().copied().collect::<Vec<_>>();
    if keys != expected {
        return Err(validation(ErrorCode::UnknownField));
    }
    Ok(())
}

fn unsigned_option(value: Option<&CborValue>) -> Result<u64, Error> {
    match value {
        Some(CborValue::Unsigned(value)) => Ok(*value),
        _ => Err(validation(ErrorCode::InvalidRepresentation)),
    }
}

fn unsigned_value(map: &BTreeMap<u64, CborValue>, label: u64) -> Result<u64, Error> {
    unsigned_option(map.get(&label))
}

fn bounded_unsigned(
    map: &BTreeMap<u64, CborValue>,
    label: u64,
    maximum: u64,
) -> Result<u64, Error> {
    let value = unsigned_value(map, label)?;
    if value > maximum {
        return Err(validation(ErrorCode::BoundExceeded));
    }
    Ok(value)
}

fn optional_u64(map: &BTreeMap<u64, CborValue>, label: u64) -> Result<Option<u64>, Error> {
    match map.get(&label) {
        None => Ok(None),
        Some(_) => Ok(Some(unsigned_value(map, label)?)),
    }
}

fn bytes_value(map: &BTreeMap<u64, CborValue>, label: u64) -> Result<Vec<u8>, Error> {
    match map.get(&label) {
        Some(CborValue::Bytes(value)) => Ok(value.clone()),
        _ => Err(validation(ErrorCode::InvalidRepresentation)),
    }
}

fn fixed_bytes<const N: usize>(
    map: &BTreeMap<u64, CborValue>,
    label: u64,
    length: usize,
) -> Result<[u8; N], Error> {
    let value = bytes_value(map, label)?;
    if value.len() != length {
        return Err(validation(ErrorCode::InvalidRepresentation));
    }
    value
        .try_into()
        .map_err(|_| validation(ErrorCode::InvalidRepresentation))
}

const fn validation(code: ErrorCode) -> Error {
    Error::terminal(code, Stage::Validation)
}
