use std::collections::BTreeMap;

use crate::error::{Error, ErrorCode, Stage};

const MAX_DEPTH: usize = 16;
const MAX_COLLECTION_ITEMS: usize = 64;
const MAX_ENCODED_BYTES: usize = 1_048_576;
const MAX_RAW_BYTES: usize = 262_144;
const MAX_TEXT_BYTES: usize = 4_096;
const MAX_INTEGER: u64 = 9_007_199_254_740_991;

/// Closed deterministic-CBOR value set used by the currently defined codecs.
#[derive(Clone, Eq, PartialEq)]
pub enum CborValue {
    Null,
    Unsigned(u64),
    Bytes(Vec<u8>),
    Text(String),
    Bool(bool),
    Array(Vec<CborValue>),
    Map(BTreeMap<u64, CborValue>),
}

impl std::fmt::Debug for CborValue {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("CborValue([REDACTED])")
    }
}

pub fn encode(value: &CborValue) -> Result<Vec<u8>, Error> {
    let length = encoded_length(value, 0)?;
    let mut output = Vec::with_capacity(length);
    encode_into(value, &mut output);
    Ok(output)
}

pub fn decode(bytes: &[u8]) -> Result<CborValue, Error> {
    decode_detailed(bytes).map_err(DecodeFailure::into_error)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DecodeFailure {
    BoundExceeded,
    IndefiniteLength,
    NegativeLabel,
    DuplicateLabel,
    TrailingBytes,
    NonCanonical,
    Invalid,
}

impl DecodeFailure {
    const fn into_error(self) -> Error {
        match self {
            Self::BoundExceeded => representation(ErrorCode::BoundExceeded),
            Self::NonCanonical => representation(ErrorCode::NonCanonicalRepresentation),
            Self::IndefiniteLength
            | Self::NegativeLabel
            | Self::DuplicateLabel
            | Self::TrailingBytes
            | Self::Invalid => representation(ErrorCode::InvalidRepresentation),
        }
    }
}

pub(crate) fn decode_detailed(bytes: &[u8]) -> Result<CborValue, DecodeFailure> {
    if bytes.len() > MAX_ENCODED_BYTES {
        return Err(DecodeFailure::BoundExceeded);
    }
    let mut decoder = Decoder { bytes, offset: 0 };
    let value = decoder.value(0)?;
    if decoder.offset != bytes.len() {
        return Err(DecodeFailure::TrailingBytes);
    }
    if encode(&value)
        .map_err(|_| DecodeFailure::BoundExceeded)?
        .as_slice()
        != bytes
    {
        return Err(DecodeFailure::NonCanonical);
    }
    Ok(value)
}

fn encoded_length(value: &CborValue, depth: usize) -> Result<usize, Error> {
    if depth > MAX_DEPTH {
        return Err(representation(ErrorCode::BoundExceeded));
    }
    let length = match value {
        CborValue::Null => 1,
        CborValue::Unsigned(value) if *value <= MAX_INTEGER => head_length(*value),
        CborValue::Unsigned(_) => return Err(representation(ErrorCode::BoundExceeded)),
        CborValue::Bytes(value) if value.len() <= MAX_RAW_BYTES => head_length(value.len() as u64)
            .checked_add(value.len())
            .ok_or_else(|| representation(ErrorCode::BoundExceeded))?,
        CborValue::Bytes(_) => return Err(representation(ErrorCode::BoundExceeded)),
        CborValue::Text(value) if value.len() <= MAX_TEXT_BYTES => head_length(value.len() as u64)
            .checked_add(value.len())
            .ok_or_else(|| representation(ErrorCode::BoundExceeded))?,
        CborValue::Text(_) => return Err(representation(ErrorCode::BoundExceeded)),
        CborValue::Bool(_) => 1,
        CborValue::Array(values) if values.len() <= MAX_COLLECTION_ITEMS => {
            collection_encoded_length(values.iter(), values.len(), depth)?
        }
        CborValue::Array(_) => return Err(representation(ErrorCode::BoundExceeded)),
        CborValue::Map(values) if values.len() <= MAX_COLLECTION_ITEMS => {
            let mut length = head_length(values.len() as u64);
            for (key, value) in values {
                if *key > MAX_INTEGER {
                    return Err(representation(ErrorCode::BoundExceeded));
                }
                let value_length = encoded_length(value, depth + 1)?;
                length = length
                    .checked_add(head_length(*key))
                    .and_then(|length| length.checked_add(value_length))
                    .ok_or_else(|| representation(ErrorCode::BoundExceeded))?;
            }
            length
        }
        CborValue::Map(_) => return Err(representation(ErrorCode::BoundExceeded)),
    };
    if length > MAX_ENCODED_BYTES {
        return Err(representation(ErrorCode::BoundExceeded));
    }
    Ok(length)
}

fn collection_encoded_length<'a>(
    values: impl Iterator<Item = &'a CborValue>,
    count: usize,
    depth: usize,
) -> Result<usize, Error> {
    let mut length = head_length(count as u64);
    for value in values {
        length = length
            .checked_add(encoded_length(value, depth + 1)?)
            .ok_or_else(|| representation(ErrorCode::BoundExceeded))?;
    }
    Ok(length)
}

const fn head_length(value: u64) -> usize {
    match value {
        0..=23 => 1,
        24..=0xff => 2,
        0x100..=0xffff => 3,
        0x1_0000..=0xffff_ffff => 5,
        _ => 9,
    }
}

fn encode_into(value: &CborValue, output: &mut Vec<u8>) {
    match value {
        CborValue::Null => output.push(0xf6),
        CborValue::Unsigned(value) => head(0, *value, output),
        CborValue::Bytes(value) => {
            head(2, value.len() as u64, output);
            output.extend_from_slice(value);
        }
        CborValue::Text(value) => {
            head(3, value.len() as u64, output);
            output.extend_from_slice(value.as_bytes());
        }
        CborValue::Bool(value) => output.push(if *value { 0xf5 } else { 0xf4 }),
        CborValue::Array(values) => {
            head(4, values.len() as u64, output);
            for value in values {
                encode_into(value, output);
            }
        }
        CborValue::Map(values) => {
            head(5, values.len() as u64, output);
            for (key, value) in values {
                head(0, *key, output);
                encode_into(value, output);
            }
        }
    }
}

fn head(major: u8, value: u64, output: &mut Vec<u8>) {
    let prefix = major << 5;
    match value {
        0..=23 => output.push(prefix | value as u8),
        24..=0xff => output.extend_from_slice(&[prefix | 24, value as u8]),
        0x100..=0xffff => {
            output.push(prefix | 25);
            output.extend_from_slice(&(value as u16).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            output.push(prefix | 26);
            output.extend_from_slice(&(value as u32).to_be_bytes());
        }
        _ => {
            output.push(prefix | 27);
            output.extend_from_slice(&value.to_be_bytes());
        }
    }
}

struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl Decoder<'_> {
    fn value(&mut self, depth: usize) -> Result<CborValue, DecodeFailure> {
        if depth > MAX_DEPTH {
            return Err(DecodeFailure::BoundExceeded);
        }
        let initial = self.byte()?;
        let major = initial >> 5;
        let additional = initial & 0x1f;
        match major {
            0 => {
                let value = self.argument(additional)?;
                if value > MAX_INTEGER {
                    return Err(DecodeFailure::BoundExceeded);
                }
                Ok(CborValue::Unsigned(value))
            }
            2 => {
                let length = usize::try_from(self.argument(additional)?)
                    .map_err(|_| DecodeFailure::BoundExceeded)?;
                if length > MAX_RAW_BYTES {
                    return Err(DecodeFailure::BoundExceeded);
                }
                let end = self
                    .offset
                    .checked_add(length)
                    .ok_or(DecodeFailure::BoundExceeded)?;
                let bytes = self
                    .bytes
                    .get(self.offset..end)
                    .ok_or(DecodeFailure::Invalid)?;
                self.offset = end;
                Ok(CborValue::Bytes(bytes.to_vec()))
            }
            3 => {
                let length = usize::try_from(self.argument(additional)?)
                    .map_err(|_| DecodeFailure::BoundExceeded)?;
                if length > MAX_TEXT_BYTES {
                    return Err(DecodeFailure::BoundExceeded);
                }
                let end = self
                    .offset
                    .checked_add(length)
                    .ok_or(DecodeFailure::BoundExceeded)?;
                let text = core::str::from_utf8(
                    self.bytes
                        .get(self.offset..end)
                        .ok_or(DecodeFailure::Invalid)?,
                )
                .map_err(|_| DecodeFailure::Invalid)?;
                self.offset = end;
                Ok(CborValue::Text(text.to_owned()))
            }
            4 => {
                let length = self.collection_length(additional)?;
                let mut values = Vec::with_capacity(length);
                for _ in 0..length {
                    values.push(self.value(depth + 1)?);
                }
                Ok(CborValue::Array(values))
            }
            5 => {
                let length = self.collection_length(additional)?;
                let mut values = BTreeMap::new();
                for _ in 0..length {
                    let key_initial = self.byte()?;
                    if key_initial >> 5 == 1 {
                        self.argument(key_initial & 0x1f)?;
                        return Err(DecodeFailure::NegativeLabel);
                    }
                    if key_initial >> 5 != 0 {
                        return Err(DecodeFailure::Invalid);
                    }
                    let key = self.argument(key_initial & 0x1f)?;
                    if key > MAX_INTEGER {
                        return Err(DecodeFailure::BoundExceeded);
                    }
                    if values.insert(key, self.value(depth + 1)?).is_some() {
                        return Err(DecodeFailure::DuplicateLabel);
                    }
                }
                Ok(CborValue::Map(values))
            }
            7 if initial == 0xf4 => Ok(CborValue::Bool(false)),
            7 if initial == 0xf5 => Ok(CborValue::Bool(true)),
            7 if initial == 0xf6 => Ok(CborValue::Null),
            1 | 6 => {
                self.argument(additional)?;
                Err(DecodeFailure::Invalid)
            }
            _ => Err(DecodeFailure::Invalid),
        }
    }

    fn collection_length(&mut self, additional: u8) -> Result<usize, DecodeFailure> {
        let length = usize::try_from(self.argument(additional)?)
            .map_err(|_| DecodeFailure::BoundExceeded)?;
        if length > MAX_COLLECTION_ITEMS {
            return Err(DecodeFailure::BoundExceeded);
        }
        Ok(length)
    }

    fn argument(&mut self, additional: u8) -> Result<u64, DecodeFailure> {
        match additional {
            value @ 0..=23 => Ok(u64::from(value)),
            24 => {
                let value = u64::from(self.byte()?);
                (value >= 24)
                    .then_some(value)
                    .ok_or(DecodeFailure::NonCanonical)
            }
            25 => {
                let value = u64::from(u16::from_be_bytes(self.array()?));
                (value > u64::from(u8::MAX))
                    .then_some(value)
                    .ok_or(DecodeFailure::NonCanonical)
            }
            26 => {
                let value = u64::from(u32::from_be_bytes(self.array()?));
                (value > u64::from(u16::MAX))
                    .then_some(value)
                    .ok_or(DecodeFailure::NonCanonical)
            }
            27 => {
                let value = u64::from_be_bytes(self.array()?);
                (value > u64::from(u32::MAX))
                    .then_some(value)
                    .ok_or(DecodeFailure::NonCanonical)
            }
            31 => Err(DecodeFailure::IndefiniteLength),
            _ => Err(DecodeFailure::Invalid),
        }
    }

    fn byte(&mut self) -> Result<u8, DecodeFailure> {
        let value = *self.bytes.get(self.offset).ok_or(DecodeFailure::Invalid)?;
        self.offset += 1;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], DecodeFailure> {
        let end = self
            .offset
            .checked_add(N)
            .ok_or(DecodeFailure::BoundExceeded)?;
        let bytes: [u8; N] = self
            .bytes
            .get(self.offset..end)
            .ok_or(DecodeFailure::Invalid)?
            .try_into()
            .map_err(|_| DecodeFailure::Invalid)?;
        self.offset = end;
        Ok(bytes)
    }
}

const fn representation(code: ErrorCode) -> Error {
    Error::terminal(code, Stage::Representation)
}
