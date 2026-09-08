use std::collections::{BTreeMap, BTreeSet};

use crate::{
    encoding::{self, CborValue},
    error::{Error, ErrorCode, Stage},
};

pub const MAX_PACKET_BYTES: usize = 524_288;
pub const MAX_CONTROL_BODY_BYTES: usize = 16_384;
pub const MAX_PATH_BYTES: usize = 128;
pub const MAX_HEADER_BYTES: usize = 2_048;

#[derive(Clone, Eq, PartialEq)]
pub struct TransportRequest<'a> {
    pub scheme: &'a str,
    pub tls_version: &'a str,
    pub tls_cipher_suite: &'a str,
    pub certificate_chain_valid: bool,
    pub http_version: &'a str,
    pub renegotiation: bool,
    pub method: &'a str,
    pub path: &'a str,
    pub query_present: bool,
    pub fragment_present: bool,
    pub early_data: bool,
    pub name_validated: bool,
    pub authority_present: bool,
    pub header_names_lowercase: bool,
    pub header_bytes: usize,
    pub operation_id: Option<[u8; 16]>,
    pub operation_id_canonical: bool,
    pub media_type: &'a str,
    pub media_type_parameters: bool,
    pub content_length: Option<usize>,
    pub content_length_canonical: bool,
    pub transfer_encoding: bool,
    pub content_encoding_identity: bool,
    pub trailers: bool,
    pub streaming: bool,
    pub body: &'a [u8],
}

impl std::fmt::Debug for TransportRequest<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("TransportRequest([REDACTED])")
    }
}

pub fn validate_endpoint_request(request: &TransportRequest<'_>) -> Result<(), Error> {
    if request.scheme != "https"
        || request.tls_version != "1.3"
        || !matches!(
            request.tls_cipher_suite,
            "TLS_AES_128_GCM_SHA256" | "TLS_AES_256_GCM_SHA384" | "TLS_CHACHA20_POLY1305_SHA256"
        )
        || !request.certificate_chain_valid
        || request.http_version != "2"
        || request.renegotiation
        || request.early_data
        || !request.name_validated
        || request.query_present
        || request.fragment_present
    {
        return Err(validation(ErrorCode::InvalidTransition));
    }
    if request.method != "POST"
        || request.path.len() > MAX_PATH_BYTES
        || !request.authority_present
        || !request.header_names_lowercase
        || request.header_bytes > MAX_HEADER_BYTES
        || request.operation_id.is_none()
        || !request.operation_id_canonical
    {
        return Err(validation(ErrorCode::UnknownField));
    }
    if request.content_length != Some(request.body.len())
        || !request.content_length_canonical
        || request.transfer_encoding
        || !request.content_encoding_identity
        || request.trailers
        || request.streaming
        || request.media_type_parameters
    {
        return Err(validation(ErrorCode::InvalidRepresentation));
    }
    let operation = operation_from_path(request.path)?;
    let submit = operation == Operation::Submit;
    let expected_media_type = if submit {
        "application/licoarc-protected-packet"
    } else {
        "application/licoarc-transport+cbor"
    };
    if request.media_type != expected_media_type {
        return Err(validation(ErrorCode::UnknownField));
    }
    let maximum = if submit {
        MAX_PACKET_BYTES
    } else {
        MAX_CONTROL_BODY_BYTES
    };
    if request.body.is_empty() || request.body.len() > maximum {
        return Err(validation(ErrorCode::BoundExceeded));
    }
    if !submit {
        let value = encoding::decode(request.body)?;
        validate_control_record(operation, &value)?;
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Operation {
    Affiliate,
    Reserve,
    Submit,
    Retrieve,
    Claim,
    Settle,
}

/// Validates one closed deterministic-CBOR control request. Carrier and
/// authentication facts remain caller-owned and are checked separately.
pub fn validate_control_record(operation: Operation, value: &CborValue) -> Result<(), Error> {
    if encoding::encode(value)?.len() > MAX_CONTROL_BODY_BYTES {
        return Err(validation(ErrorCode::BoundExceeded));
    }
    match operation {
        Operation::Affiliate => {
            let values = closed_map(value, 0..=1, &[0, 1])?;
            fixed_bytes(values.get(&0), 32)?;
            fixed_bytes(values.get(&1), 32)
        }
        Operation::Reserve => {
            let values = closed_map(value, 0..=3, &[0, 1, 2, 3])?;
            fixed_bytes(values.get(&0), 32)?;
            fixed_bytes(values.get(&1), 32)?;
            fixed_bytes(values.get(&2), 32)?;
            bounded_unsigned(values.get(&3), 1)
        }
        Operation::Retrieve => {
            let values = closed_map(value, 0..=2, &[0, 1, 2])?;
            fixed_bytes(values.get(&0), 32)?;
            unsigned(values.get(&1))?;
            fixed_bytes(values.get(&2), 32)
        }
        Operation::Claim => {
            let values = closed_map(value, 0..=0, &[0])?;
            let count = unsigned(values.get(&0))?;
            if !(1..=64).contains(&count) {
                return Err(validation(ErrorCode::BoundExceeded));
            }
            Ok(())
        }
        Operation::Settle => {
            let values = closed_map(value, 0..=2, &[0, 1, 2])?;
            fixed_bytes(values.get(&0), 32)?;
            unsigned(values.get(&1))?;
            let Some(CborValue::Array(settlements)) = values.get(&2) else {
                return Err(validation(ErrorCode::InvalidRepresentation));
            };
            if settlements.is_empty() || settlements.len() > 64 {
                return Err(validation(ErrorCode::BoundExceeded));
            }
            let mut item_ids = BTreeSet::new();
            for settlement in settlements {
                let values = closed_map(settlement, 0..=1, &[0, 1])?;
                let item_id: [u8; 32] = bytes(values.get(&0))?
                    .try_into()
                    .map_err(|_| validation(ErrorCode::InvalidRepresentation))?;
                if !item_ids.insert(item_id) {
                    return Err(validation(ErrorCode::InvalidRepresentation));
                }
                bounded_unsigned(values.get(&1), 1)?;
            }
            Ok(())
        }
        Operation::Submit => Err(validation(ErrorCode::InvalidRepresentation)),
    }
}

pub fn operation_from_path(path: &str) -> Result<Operation, Error> {
    match path {
        "/v1/affiliate" => Ok(Operation::Affiliate),
        "/v1/reserve" => Ok(Operation::Reserve),
        _ => {
            let suffixes = [
                ("/submit", Operation::Submit),
                ("/retrieve", Operation::Retrieve),
                ("/claim", Operation::Claim),
                ("/settle", Operation::Settle),
            ];
            let Some(rest) = path.strip_prefix("/v1/handles/") else {
                return Err(validation(ErrorCode::UnknownField));
            };
            for (suffix, operation) in suffixes {
                if let Some(handle) = rest.strip_suffix(suffix)
                    && handle.len() == 43
                    && handle
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
                    && handle
                        .as_bytes()
                        .last()
                        .is_some_and(|byte| matches!(byte, b'A' | b'Q' | b'g' | b'w'))
                {
                    return Ok(operation);
                }
            }
            Err(validation(ErrorCode::UnknownField))
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

pub fn classify_status(status: u16) -> Result<TransportOutcome, Error> {
    match status {
        200..=202 => Ok(TransportOutcome::Accepted),
        400 | 404 | 406 | 409 | 413 => Ok(TransportOutcome::Rejected),
        429 | 500 | 503 => Ok(TransportOutcome::Transient),
        504 => Ok(TransportOutcome::Ambiguous),
        _ => Err(validation(ErrorCode::UnknownField)),
    }
}

fn closed_map<'a>(
    value: &'a CborValue,
    allowed: std::ops::RangeInclusive<u64>,
    required: &[u64],
) -> Result<&'a BTreeMap<u64, CborValue>, Error> {
    let CborValue::Map(values) = value else {
        return Err(validation(ErrorCode::InvalidRepresentation));
    };
    if values.keys().any(|key| !allowed.contains(key))
        || required.iter().any(|key| !values.contains_key(key))
    {
        return Err(validation(ErrorCode::UnknownField));
    }
    Ok(values)
}

fn unsigned(value: Option<&CborValue>) -> Result<u64, Error> {
    match value {
        Some(CborValue::Unsigned(value)) => Ok(*value),
        _ => Err(validation(ErrorCode::InvalidRepresentation)),
    }
}

fn bounded_unsigned(value: Option<&CborValue>, maximum: u64) -> Result<(), Error> {
    if unsigned(value)? > maximum {
        return Err(validation(ErrorCode::BoundExceeded));
    }
    Ok(())
}

fn bytes(value: Option<&CborValue>) -> Result<&[u8], Error> {
    match value {
        Some(CborValue::Bytes(value)) => Ok(value),
        _ => Err(validation(ErrorCode::InvalidRepresentation)),
    }
}

fn fixed_bytes(value: Option<&CborValue>, length: usize) -> Result<(), Error> {
    if bytes(value)?.len() != length {
        return Err(validation(ErrorCode::InvalidRepresentation));
    }
    Ok(())
}

const fn validation(code: ErrorCode) -> Error {
    Error::terminal(code, Stage::Validation)
}
