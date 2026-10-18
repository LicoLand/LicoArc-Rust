use std::collections::BTreeMap;

use zeroize::Zeroize;

use crate::error::{Error, ErrorCode, Stage};

const MAX_DEPTH: usize = 16;
const MAX_COLLECTION_ITEMS: usize = 64;
const MAX_ENCODED_BYTES: usize = 1_048_576;
const MAX_RAW_BYTES: usize = 262_144;
const MAX_TEXT_BYTES: usize = 4_096;
const MAX_INTEGER: u64 = 9_007_199_254_740_991;

/// Codec bounds one caller may relax for its own durable envelope.
///
/// Wire codecs keep [`DEFAULT_LIMITS`]; the checkpoint layer passes
/// [`CHECKPOINT_LIMITS`] because its envelope legitimately holds collections
/// and byte strings far above wire bounds (skipped-key tables, prekey
/// maps, pending payloads). Relaxing is per call, so wire decoders keep the
/// tight limits they were proven against.
#[derive(Clone, Copy)]
pub(crate) struct Limits {
    pub(crate) depth: usize,
    pub(crate) collection_items: usize,
    pub(crate) encoded_bytes: usize,
    pub(crate) raw_bytes: usize,
    pub(crate) text_bytes: usize,
}

pub(crate) const DEFAULT_LIMITS: Limits = Limits {
    depth: MAX_DEPTH,
    collection_items: MAX_COLLECTION_ITEMS,
    encoded_bytes: MAX_ENCODED_BYTES,
    raw_bytes: MAX_RAW_BYTES,
    text_bytes: MAX_TEXT_BYTES,
};

/// The endpoint checkpoint envelope's own bounds: skipped-key and prekey
/// collections and pending payloads exceed wire limits by design, while the
/// envelope cap keeps any single checkpoint finite.
pub(crate) const CHECKPOINT_LIMITS: Limits = Limits {
    depth: MAX_DEPTH,
    collection_items: 1_024,
    encoded_bytes: 40 * 1024 * 1024,
    raw_bytes: 524_288,
    text_bytes: 0,
};

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

/// A value tree that wipes its byte payloads when it dies.
///
/// `CborValue` is a plain data enum with no secret lifecycle, so every
/// temporary tree that copies session keys or pending plaintext is guarded
/// here: the wrapper recursively zeroizes each `Bytes` payload on success
/// and on every error path.
pub(crate) struct WipedValue(pub(crate) CborValue);

impl WipedValue {
    /// An empty map under the guard.
    pub(crate) fn map() -> Self {
        Self(CborValue::Map(BTreeMap::new()))
    }

    /// An empty array under the guard.
    pub(crate) fn array() -> Self {
        Self(CborValue::Array(Vec::new()))
    }

    /// Inserts one entry; a `?` that fails after it still wipes the tree.
    pub(crate) fn insert(&mut self, key: u64, value: CborValue) {
        let CborValue::Map(map) = &mut self.0 else {
            unreachable!("the guard only ever holds a map")
        };
        map.insert(key, value);
    }

    /// Whether the map already carries `key`; a duplicate-label refusal lets
    /// the caller wipe the would-be value inside its own guard.
    pub(crate) fn contains_key(&self, key: u64) -> bool {
        let CborValue::Map(map) = &self.0 else {
            unreachable!("the guard only ever holds a map")
        };
        map.contains_key(&key)
    }

    /// Pushes one element; a `?` that fails after it still wipes the tree.
    pub(crate) fn push(&mut self, value: CborValue) {
        let CborValue::Array(values) = &mut self.0 else {
            unreachable!("the guard only ever holds an array")
        };
        values.push(value);
    }

    /// Releases the tree to its caller, leaving an inert value behind.
    pub(crate) fn take(&mut self) -> CborValue {
        std::mem::replace(&mut self.0, CborValue::Null)
    }
}

impl Drop for WipedValue {
    fn drop(&mut self) {
        wipe_bytes(&mut self.0);
    }
}

fn wipe_bytes(value: &mut CborValue) {
    match value {
        CborValue::Bytes(bytes) => bytes.zeroize(),
        CborValue::Text(text) => text.zeroize(),
        CborValue::Array(items) => items.iter_mut().for_each(wipe_bytes),
        CborValue::Map(map) => map.values_mut().for_each(wipe_bytes),
        CborValue::Null | CborValue::Unsigned(_) | CborValue::Bool(_) => {}
    }
}

/// A flat byte buffer with the same contract: the canonical encodings the
/// codecs materialize are secret-bearing too, so they zeroize on drop.
pub(crate) struct WipedBytes(pub(crate) Vec<u8>);

impl WipedBytes {
    /// Hands the buffer to the caller, leaving an empty buffer behind.
    pub(crate) fn take(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.0)
    }
}

impl std::ops::Deref for WipedBytes {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for WipedBytes {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Drop for WipedBytes {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

pub fn encode(value: &CborValue) -> Result<Vec<u8>, Error> {
    encode_at(value, &DEFAULT_LIMITS)
}

pub(crate) fn encode_at(value: &CborValue, limits: &Limits) -> Result<Vec<u8>, Error> {
    let length = encoded_length(value, 0, limits)?;
    let mut output = Vec::with_capacity(length);
    encode_into(value, &mut output);
    Ok(output)
}

pub fn decode(bytes: &[u8]) -> Result<CborValue, Error> {
    decode_detailed(bytes, &DEFAULT_LIMITS).map_err(DecodeFailure::into_error)
}

pub(crate) fn decode_at(bytes: &[u8], limits: &Limits) -> Result<CborValue, Error> {
    decode_detailed(bytes, limits).map_err(DecodeFailure::into_error)
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

pub(crate) fn decode_detailed(bytes: &[u8], limits: &Limits) -> Result<CborValue, DecodeFailure> {
    if bytes.len() > limits.encoded_bytes {
        return Err(DecodeFailure::BoundExceeded);
    }
    let mut decoder = Decoder {
        bytes,
        offset: 0,
        limits: *limits,
    };
    let mut value = WipedValue(decoder.value(0)?);
    if decoder.offset != bytes.len() {
        return Err(DecodeFailure::TrailingBytes);
    }
    // The canonicality re-encode copies the whole tree; the buffer it lands
    // in wipes itself whether the comparison succeeds or not.
    if WipedBytes(encode_at(&value.0, limits).map_err(|_| DecodeFailure::BoundExceeded)?).as_slice()
        != bytes
    {
        return Err(DecodeFailure::NonCanonical);
    }
    Ok(value.take())
}

fn encoded_length(value: &CborValue, depth: usize, limits: &Limits) -> Result<usize, Error> {
    if depth > limits.depth {
        return Err(representation(ErrorCode::BoundExceeded));
    }
    let length = match value {
        CborValue::Null => 1,
        CborValue::Unsigned(value) if *value <= MAX_INTEGER => head_length(*value),
        CborValue::Unsigned(_) => return Err(representation(ErrorCode::BoundExceeded)),
        CborValue::Bytes(value) if value.len() <= limits.raw_bytes => {
            head_length(value.len() as u64)
                .checked_add(value.len())
                .ok_or_else(|| representation(ErrorCode::BoundExceeded))?
        }
        CborValue::Bytes(_) => return Err(representation(ErrorCode::BoundExceeded)),
        CborValue::Text(value) if value.len() <= limits.text_bytes => {
            head_length(value.len() as u64)
                .checked_add(value.len())
                .ok_or_else(|| representation(ErrorCode::BoundExceeded))?
        }
        CborValue::Text(_) => return Err(representation(ErrorCode::BoundExceeded)),
        CborValue::Bool(_) => 1,
        CborValue::Array(values) if values.len() <= limits.collection_items => {
            collection_encoded_length(values.iter(), values.len(), depth, limits)?
        }
        CborValue::Array(_) => return Err(representation(ErrorCode::BoundExceeded)),
        CborValue::Map(values) if values.len() <= limits.collection_items => {
            let mut length = head_length(values.len() as u64);
            for (key, value) in values {
                if *key > MAX_INTEGER {
                    return Err(representation(ErrorCode::BoundExceeded));
                }
                let value_length = encoded_length(value, depth + 1, limits)?;
                length = length
                    .checked_add(head_length(*key))
                    .and_then(|length| length.checked_add(value_length))
                    .ok_or_else(|| representation(ErrorCode::BoundExceeded))?;
            }
            length
        }
        CborValue::Map(_) => return Err(representation(ErrorCode::BoundExceeded)),
    };
    if length > limits.encoded_bytes {
        return Err(representation(ErrorCode::BoundExceeded));
    }
    Ok(length)
}

fn collection_encoded_length<'a>(
    values: impl Iterator<Item = &'a CborValue>,
    count: usize,
    depth: usize,
    limits: &Limits,
) -> Result<usize, Error> {
    let mut length = head_length(count as u64);
    for value in values {
        length = length
            .checked_add(encoded_length(value, depth + 1, limits)?)
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
    limits: Limits,
}

impl Decoder<'_> {
    fn value(&mut self, depth: usize) -> Result<CborValue, DecodeFailure> {
        if depth > self.limits.depth {
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
                if length > self.limits.raw_bytes {
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
                if length > self.limits.text_bytes {
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
                let mut values = WipedValue::array();
                for _ in 0..length {
                    values.push(self.value(depth + 1)?);
                }
                Ok(values.take())
            }
            5 => {
                let length = self.collection_length(additional)?;
                let mut values = WipedValue::map();
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
                    let mut child = WipedValue(self.value(depth + 1)?);
                    if values.contains_key(key) {
                        return Err(DecodeFailure::DuplicateLabel);
                    }
                    values.insert(key, child.take());
                }
                Ok(values.take())
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
        if length > self.limits.collection_items {
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

#[cfg(test)]
mod tests {
    use super::{CborValue, decode, encode};
    use crate::error::ErrorCode;

    // Every refusal below happens only after a secret-bearing child was
    // materialized: the guarded parser must wipe those children on its way
    // out, which these cases exercise at the public boundary.
    #[test]
    fn refusals_after_parsed_secret_children() {
        // Indefinite-length element after a byte-string sibling.
        let malformed = [0x82, 0x44, 1, 2, 3, 4, 0x9f];
        assert!(decode(&malformed).is_err());
        // Duplicate label after a byte-string value was already stored.
        let duplicate = [0xa2, 0x00, 0x41, 0xaa, 0x00, 0x41, 0xbb];
        let error = decode(&duplicate).unwrap_err();
        assert_eq!(error.code, ErrorCode::InvalidRepresentation);
        // Trailing bytes after a complete byte-string root.
        let trailing = [0x41, 0xaa, 0x00];
        assert!(decode(&trailing).is_err());
        // Noncanonical argument inside a map whose earlier entry is secret.
        let noncanonical = [0xa2, 0x00, 0x44, 1, 2, 3, 4, 0x01, 0x18, 0x17];
        let error = decode(&noncanonical).unwrap_err();
        assert_eq!(error.code, ErrorCode::NonCanonicalRepresentation);
    }

    #[test]
    fn guarded_parse_round_trip_is_unchanged() {
        let value = CborValue::Map(std::collections::BTreeMap::from([
            (0, CborValue::Bytes(vec![7; 32])),
            (1, CborValue::Array(vec![CborValue::Unsigned(9)])),
        ]));
        let bytes = encode(&value).unwrap();
        assert_eq!(decode(&bytes).unwrap(), value);
    }
}
