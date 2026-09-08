//! Stable-core hybrid key schedule and classic Double Ratchet transitions.

use core::fmt;
use std::collections::{BTreeMap, HashMap};
use zeroize::Zeroize;

use crate::{
    encoding::{self, CborValue},
    error::{Error, ErrorCode, Stage},
    provider::Provider,
    state::{CustodyRef, KeyCustody, SecretHandle, StagedSecretHandle, X25519Private},
};

pub const MAX_ACTIVE_PREKEY_PAIRS: usize = 256;
pub const MAX_ACTIVE_SESSIONS: usize = 256;
pub const MAX_SKIP_PER_RECORD: u32 = 256;
pub const MAX_SKIPPED_KEYS: usize = 1_024;
pub const MAX_PLAINTEXT_BYTES: usize = 524_224;
pub const MAX_PROTECTED_PACKET_BYTES: usize = 524_288;
pub const MAX_SESSION_ACCEPT_BYTES: usize = 221;
pub const MAX_FIRST_PACKET_BYTES: usize = 9_655;

pub fn validate_authority_session_binding(
    initiator_authority_digest: Option<[u8; 32]>,
    responder_authority_digest: Option<[u8; 32]>,
    protected_initiator_payload_digest: Option<[u8; 32]>,
    protected_responder_payload_digest: Option<[u8; 32]>,
) -> Result<(), Error> {
    let (Some(initiator), Some(responder), Some(protected_initiator), Some(protected_responder)) = (
        initiator_authority_digest,
        responder_authority_digest,
        protected_initiator_payload_digest,
        protected_responder_payload_digest,
    ) else {
        return Err(handshake_rejected());
    };
    if initiator != protected_initiator || responder != protected_responder {
        return Err(handshake_rejected());
    }
    Ok(())
}

const D_HYBRID_EXTRACT_SALT: &[u8] = b"LICOARC-V1/HYBRID/EXTRACT-SALT\0";
const D_HYBRID_ROOT: &[u8] = b"LICOARC-V1/HYBRID/ROOT\0";
const D_CLIENT_KEY: &[u8] = b"LICOARC-V1/HANDSHAKE/CLIENT-CONFIRM-KEY\0";
const D_CLIENT_NONCE: &[u8] = b"LICOARC-V1/HANDSHAKE/CLIENT-CONFIRM-NONCE\0";
const D_ACCEPT_KEY: &[u8] = b"LICOARC-V1/HANDSHAKE/SESSION-ACCEPT-KEY\0";
const D_INITIAL_ROOT: &[u8] = b"LICOARC-V1/RATCHET/ROOT/INITIAL\0";
const D_CHAIN_I2R: &[u8] = b"LICOARC-V1/RATCHET/CHAIN/I2R\0";
const D_CHAIN_R2I: &[u8] = b"LICOARC-V1/RATCHET/CHAIN/R2I\0";
const D_ROOT_I2R: &[u8] = b"LICOARC-V1/RATCHET/ROOT/I2R\0";
const D_ROOT_R2I: &[u8] = b"LICOARC-V1/RATCHET/ROOT/R2I\0";
const D_MESSAGE_KEY: &[u8] = b"LICOARC-V1/RATCHET/MESSAGE-KEY\0";
const D_NEXT_CHAIN: &[u8] = b"LICOARC-V1/RATCHET/NEXT-CHAIN\0";
const D_NONCE: &[u8] = b"LICOARC-V1/RATCHET/NONCE\0";
const D_RECORD_AAD: &[u8] = b"LICOARC-V1/RECORD/AAD\0";

#[derive(Clone, Eq, PartialEq)]
struct Secret([u8; 32]);

impl Secret {
    const fn new(value: [u8; 32]) -> Self {
        Self(value)
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Secret([REDACTED])")
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct HybridSecrets {
    hybrid_root: Secret,
    client_confirm_key: Secret,
    client_confirm_nonce: [u8; 12],
    session_accept_key: Secret,
}

impl Drop for HybridSecrets {
    fn drop(&mut self) {
        self.client_confirm_nonce.zeroize();
    }
}

impl HybridSecrets {
    pub(crate) fn derive<P: Provider>(
        provider: &P,
        x25519_shared: &[u8; 32],
        ml_kem_shared: &[u8; 32],
        prekey_transcript_digest: &[u8; 32],
        handshake_core_digest: &[u8; 32],
    ) -> Result<Self, Error> {
        let salt = provider.sha256(&[D_HYBRID_EXTRACT_SALT, prekey_transcript_digest].concat());
        let mut ikm = [0_u8; 64];
        ikm[..32].copy_from_slice(x25519_shared);
        ikm[32..].copy_from_slice(ml_kem_shared);
        let mut hybrid_root = [0; 32];
        expand(
            provider,
            &salt,
            &ikm,
            D_HYBRID_ROOT,
            handshake_core_digest,
            &mut hybrid_root,
        )?;
        let mut client_confirm_key = [0; 32];
        expand(
            provider,
            &salt,
            &ikm,
            D_CLIENT_KEY,
            handshake_core_digest,
            &mut client_confirm_key,
        )?;
        let mut client_confirm_nonce = [0; 12];
        expand(
            provider,
            &salt,
            &ikm,
            D_CLIENT_NONCE,
            handshake_core_digest,
            &mut client_confirm_nonce,
        )?;
        let mut session_accept_key = [0; 32];
        expand(
            provider,
            &salt,
            &ikm,
            D_ACCEPT_KEY,
            handshake_core_digest,
            &mut session_accept_key,
        )?;
        Ok(Self {
            hybrid_root: Secret::new(hybrid_root),
            client_confirm_key: Secret::new(client_confirm_key),
            client_confirm_nonce,
            session_accept_key: Secret::new(session_accept_key),
        })
    }

    pub(crate) fn client_confirmation<P: Provider>(
        &self,
        provider: &P,
        handshake_core_digest: &[u8; 32],
    ) -> Result<Vec<u8>, Error> {
        provider.seal(
            &self.client_confirm_key.0,
            &self.client_confirm_nonce,
            handshake_core_digest,
            b"LICOARC-V1/HANDSHAKE/CLIENT-CONFIRM\0",
        )
    }

    pub(crate) fn verify_client_confirmation<P: Provider>(
        &self,
        provider: &P,
        handshake_core_digest: &[u8; 32],
        confirmation: &[u8],
    ) -> Result<(), Error> {
        let plaintext = provider
            .open(
                &self.client_confirm_key.0,
                &self.client_confirm_nonce,
                handshake_core_digest,
                confirmation,
            )
            .map_err(|_| handshake_rejected())?;
        if plaintext != b"LICOARC-V1/HANDSHAKE/CLIENT-CONFIRM\0" {
            return Err(handshake_rejected());
        }
        Ok(())
    }

    pub(crate) fn session_accept_mac<P: Provider>(
        &self,
        provider: &P,
        unsigned_accept: &[u8],
    ) -> Result<[u8; 32], Error> {
        provider.hmac_sha256(
            &self.session_accept_key.0,
            &[
                b"LICOARC-V1/HANDSHAKE/SESSION-ACCEPT-MAC\0",
                unsigned_accept,
            ]
            .concat(),
        )
    }

    pub(crate) fn verify_session_accept_mac<P: Provider>(
        &self,
        provider: &P,
        unsigned_accept: &[u8],
        mac: &[u8; 32],
    ) -> Result<(), Error> {
        provider
            .hmac_sha256_verify(
                &self.session_accept_key.0,
                &[
                    b"LICOARC-V1/HANDSHAKE/SESSION-ACCEPT-MAC\0".as_slice(),
                    unsigned_accept,
                ]
                .concat(),
                mac,
            )
            .map_err(|_| handshake_rejected())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Direction {
    InitiatorToResponder,
    ResponderToInitiator,
}

impl Direction {
    const fn chain_domain(self) -> &'static [u8] {
        match self {
            Self::InitiatorToResponder => D_CHAIN_I2R,
            Self::ResponderToInitiator => D_CHAIN_R2I,
        }
    }
    const fn root_domain(self) -> &'static [u8] {
        match self {
            Self::InitiatorToResponder => D_ROOT_I2R,
            Self::ResponderToInitiator => D_ROOT_R2I,
        }
    }
    const fn opposite(self) -> Self {
        match self {
            Self::InitiatorToResponder => Self::ResponderToInitiator,
            Self::ResponderToInitiator => Self::InitiatorToResponder,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RatchetHeader {
    pub dh: [u8; 32],
    pub pn: u32,
    pub n: u32,
}

impl RatchetHeader {
    pub fn encode(self) -> Result<Vec<u8>, Error> {
        encoding::encode(&CborValue::Map(BTreeMap::from([
            (0, CborValue::Bytes(self.dh.to_vec())),
            (1, CborValue::Unsigned(u64::from(self.pn))),
            (2, CborValue::Unsigned(u64::from(self.n))),
        ])))
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let CborValue::Map(map) = encoding::decode(bytes)? else {
            return Err(record_error(ErrorCode::InvalidRepresentation));
        };
        if map.len() != 3 {
            return Err(record_error(ErrorCode::UnknownField));
        }
        Ok(Self {
            dh: exact_32(map.get(&0))?,
            pn: exact_u32(map.get(&1))?,
            n: exact_u32(map.get(&2))?,
        })
    }
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct RatchetState {
    session_context: [u8; 32],
    root: Secret,
    local_private: SecretHandle<X25519Private>,
    local_public: [u8; 32],
    peer_public: [u8; 32],
    sending: Option<Secret>,
    receiving: Option<Secret>,
    send_direction: Direction,
    pn: u32,
    ns: u32,
    nr: u32,
    skipped: HashMap<([u8; 32], u32), (Secret, [u8; 12])>,
}

struct RatchetInit {
    session_context: [u8; 32],
    root: [u8; 32],
    local_private: SecretHandle<X25519Private>,
    local_public: [u8; 32],
    peer_public: [u8; 32],
    sending: Option<[u8; 32]>,
    receiving: Option<[u8; 32]>,
    send_direction: Direction,
}

type MessageStep = ([u8; 32], [u8; 12], [u8; 32]);

impl fmt::Debug for RatchetState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RatchetState")
            .field("secrets", &"[REDACTED]")
            .field("pn", &self.pn)
            .field("ns", &self.ns)
            .field("nr", &self.nr)
            .field("skipped_count", &self.skipped.len())
            .finish()
    }
}

impl RatchetState {
    pub(crate) const fn local_private_handle(&self) -> &SecretHandle<X25519Private> {
        &self.local_private
    }

    pub(crate) fn initiator<P: Provider>(
        provider: &P,
        hybrid: &HybridSecrets,
        session_context: [u8; 32],
        local_private: SecretHandle<X25519Private>,
        local_public: [u8; 32],
        peer_public: [u8; 32],
    ) -> Result<Self, Error> {
        let (root, chain) = initial_keys(provider, hybrid, &session_context)?;
        Self::new(RatchetInit {
            session_context,
            root,
            local_private,
            local_public,
            peer_public,
            sending: Some(chain),
            receiving: None,
            send_direction: Direction::InitiatorToResponder,
        })
    }

    pub(crate) fn responder<P: Provider>(
        provider: &P,
        hybrid: &HybridSecrets,
        session_context: [u8; 32],
        local_private: SecretHandle<X25519Private>,
        local_public: [u8; 32],
        peer_public: [u8; 32],
    ) -> Result<Self, Error> {
        let (root, chain) = initial_keys(provider, hybrid, &session_context)?;
        Self::new(RatchetInit {
            session_context,
            root,
            local_private,
            local_public,
            peer_public,
            sending: None,
            receiving: Some(chain),
            send_direction: Direction::ResponderToInitiator,
        })
    }

    fn new(init: RatchetInit) -> Result<Self, Error> {
        Ok(Self {
            session_context: init.session_context,
            root: Secret::new(init.root),
            local_private: init.local_private,
            local_public: init.local_public,
            peer_public: init.peer_public,
            sending: init.sending.map(Secret::new),
            receiving: init.receiving.map(Secret::new),
            send_direction: init.send_direction,
            pn: 0,
            ns: 0,
            nr: 0,
            skipped: HashMap::new(),
        })
    }

    pub(crate) fn bootstrap_responder<P: Provider, C: KeyCustody>(
        &self,
        provider: &P,
        custody: &C,
        fresh_private: &StagedSecretHandle<X25519Private>,
    ) -> Result<Self, Error> {
        if self.sending.is_some() || self.send_direction != Direction::ResponderToInitiator {
            return Err(record_error(ErrorCode::InvalidTransition));
        }
        let fresh_public = custody
            .x25519_public(CustodyRef::Staged(fresh_private))
            .map_err(|_| record_error(ErrorCode::RecordAuthentication))?;
        let (root, chain) = dh_step(
            provider,
            custody,
            &self.root.0,
            CustodyRef::Staged(fresh_private),
            &self.peer_public,
            self.send_direction,
            &self.session_context,
        )?;
        let mut next = self.clone();
        next.root = Secret::new(root);
        next.local_private = fresh_private.adopted_handle();
        next.local_public = fresh_public;
        next.sending = Some(Secret::new(chain));
        Ok(next)
    }

    pub(crate) fn send<P: Provider>(
        &self,
        provider: &P,
        plaintext: &[u8],
    ) -> Result<(Self, Vec<u8>), Error> {
        if plaintext.len() > MAX_PLAINTEXT_BYTES {
            return Err(record_error(ErrorCode::BoundExceeded));
        }
        let chain = self
            .sending
            .as_ref()
            .ok_or_else(|| record_error(ErrorCode::InvalidTransition))?;
        let next_n = self
            .ns
            .checked_add(1)
            .ok_or_else(|| record_error(ErrorCode::CounterOverflow))?;
        let (message_key, nonce, next_chain) = message_step(provider, &chain.0, self.ns)?;
        let header = RatchetHeader {
            dh: self.local_public,
            pn: self.pn,
            n: self.ns,
        }
        .encode()?;
        let body = provider
            .seal(
                &message_key,
                &nonce,
                &record_aad(&self.session_context, &header),
                plaintext,
            )
            .map_err(|_| record_error(ErrorCode::RecordAuthentication))?;
        let mut packet = header;
        packet.extend_from_slice(&body);
        if packet.len() > MAX_PROTECTED_PACKET_BYTES {
            return Err(record_error(ErrorCode::BoundExceeded));
        }
        let mut next = self.clone();
        next.sending = Some(Secret::new(next_chain));
        next.ns = next_n;
        Ok((next, packet))
    }

    pub(crate) fn receive<P: Provider, C: KeyCustody>(
        &self,
        provider: &P,
        custody: &C,
        packet: &[u8],
        fresh_private: Option<&StagedSecretHandle<X25519Private>>,
    ) -> Result<(Self, Vec<u8>), Error> {
        if packet.len() > MAX_PROTECTED_PACKET_BYTES {
            return Err(record_error(ErrorCode::BoundExceeded));
        }
        let header_len = ratchet_header_length(packet)?;
        let header_bytes = &packet[..header_len];
        let header = RatchetHeader::decode(header_bytes)?;
        let coordinate = (header.dh, header.n);
        if let Some((key, nonce)) = self.skipped.get(&coordinate) {
            let plaintext = provider
                .open(
                    &key.0,
                    nonce,
                    &record_aad(&self.session_context, header_bytes),
                    &packet[header_len..],
                )
                .map_err(|_| record_error(ErrorCode::RecordAuthentication))?;
            let mut next = self.clone();
            next.skipped.remove(&coordinate);
            return Ok((next, plaintext));
        }
        let mut tentative = self.clone();
        if header.dh != tentative.peer_public {
            tentative =
                tentative.receive_dh_transition(provider, custody, header, fresh_private)?;
        }
        let (message_key, nonce, next_chain, next_nr, from_skipped) = if header.n < tentative.nr {
            let (key, nonce) = tentative
                .skipped
                .get(&coordinate)
                .ok_or_else(|| record_error(ErrorCode::Replay))?;
            (key.0, *nonce, None, tentative.nr, true)
        } else {
            let distance = header.n - tentative.nr;
            if distance > MAX_SKIP_PER_RECORD
                || tentative
                    .skipped
                    .len()
                    .checked_add(
                        usize::try_from(distance)
                            .map_err(|_| record_error(ErrorCode::BoundExceeded))?,
                    )
                    .is_none_or(|total| total > MAX_SKIPPED_KEYS)
            {
                return Err(record_error(ErrorCode::SkipBound));
            }
            let mut chain = tentative
                .receiving
                .as_ref()
                .ok_or_else(|| record_error(ErrorCode::StaleRatchet))?
                .0;
            for number in tentative.nr..header.n {
                let (key, nonce, next) = message_step(provider, &chain, number)?;
                tentative
                    .skipped
                    .insert((header.dh, number), (Secret::new(key), nonce));
                chain = next;
            }
            let (key, nonce, next) = message_step(provider, &chain, header.n)?;
            let next_nr = header
                .n
                .checked_add(1)
                .ok_or_else(|| record_error(ErrorCode::CounterOverflow))?;
            (key, nonce, Some(next), next_nr, false)
        };
        let plaintext = provider
            .open(
                &message_key,
                &nonce,
                &record_aad(&tentative.session_context, header_bytes),
                &packet[header_len..],
            )
            .map_err(|_| record_error(ErrorCode::RecordAuthentication))?;
        if from_skipped {
            tentative.skipped.remove(&coordinate);
        } else if let Some(next_chain) = next_chain {
            tentative.receiving = Some(Secret::new(next_chain));
            tentative.nr = next_nr;
        }
        Ok((tentative, plaintext))
    }

    fn receive_dh_transition<P: Provider, C: KeyCustody>(
        &self,
        provider: &P,
        custody: &C,
        header: RatchetHeader,
        fresh_private: Option<&StagedSecretHandle<X25519Private>>,
    ) -> Result<Self, Error> {
        if header.pn < self.nr || header.pn - self.nr > MAX_SKIP_PER_RECORD {
            return Err(record_error(ErrorCode::StaleRatchet));
        }
        let previous_distance = header.pn - self.nr;
        if self
            .skipped
            .len()
            .checked_add(
                usize::try_from(previous_distance)
                    .map_err(|_| record_error(ErrorCode::BoundExceeded))?,
            )
            .is_none_or(|total| total > MAX_SKIPPED_KEYS)
        {
            return Err(record_error(ErrorCode::SkipBound));
        }
        let fresh_private =
            fresh_private.ok_or_else(|| record_error(ErrorCode::InvalidTransition))?;
        let fresh_public = custody
            .x25519_public(CustodyRef::Staged(fresh_private))
            .map_err(|_| record_error(ErrorCode::RecordAuthentication))?;
        let mut next = self.clone();
        if previous_distance != 0 {
            let mut previous_chain = self
                .receiving
                .as_ref()
                .ok_or_else(|| record_error(ErrorCode::StaleRatchet))?
                .0;
            for number in self.nr..header.pn {
                let (key, nonce, following) = message_step(provider, &previous_chain, number)?;
                next.skipped
                    .insert((self.peer_public, number), (Secret::new(key), nonce));
                previous_chain = following;
            }
        }
        let incoming = self.send_direction.opposite();
        let (root_after_receive, receiving) = dh_step(
            provider,
            custody,
            &self.root.0,
            CustodyRef::Adopted(&self.local_private),
            &header.dh,
            incoming,
            &self.session_context,
        )?;
        let (root_after_send, sending) = dh_step(
            provider,
            custody,
            &root_after_receive,
            CustodyRef::Staged(fresh_private),
            &header.dh,
            self.send_direction,
            &self.session_context,
        )?;
        next.root = Secret::new(root_after_send);
        next.peer_public = header.dh;
        next.local_private = fresh_private.adopted_handle();
        next.local_public = fresh_public;
        next.receiving = Some(Secret::new(receiving));
        next.sending = Some(Secret::new(sending));
        next.pn = self.ns;
        next.ns = 0;
        next.nr = 0;
        Ok(next)
    }
}

fn initial_keys<P: Provider>(
    provider: &P,
    hybrid: &HybridSecrets,
    context: &[u8; 32],
) -> Result<([u8; 32], [u8; 32]), Error> {
    let mut root = [0; 32];
    provider.hkdf_expand_sha256(
        &hybrid.hybrid_root.0,
        &[D_INITIAL_ROOT, context].concat(),
        &mut root,
    )?;
    let mut chain = [0; 32];
    provider.hkdf_expand_sha256(
        &hybrid.hybrid_root.0,
        &[D_CHAIN_I2R, context].concat(),
        &mut chain,
    )?;
    Ok((root, chain))
}

fn dh_step<P: Provider, C: KeyCustody>(
    provider: &P,
    custody: &C,
    root: &[u8; 32],
    private: CustodyRef<'_, X25519Private>,
    public: &[u8; 32],
    direction: Direction,
    context: &[u8; 32],
) -> Result<([u8; 32], [u8; 32]), Error> {
    let shared = custody
        .x25519(private, public)
        .map_err(|_| record_error(ErrorCode::RecordAuthentication))?;
    let mut next_root = [0; 32];
    provider.hkdf_sha256(
        root,
        &shared,
        &[direction.root_domain(), context].concat(),
        &mut next_root,
    )?;
    let mut chain = [0; 32];
    provider.hkdf_sha256(
        root,
        &shared,
        &[direction.chain_domain(), context].concat(),
        &mut chain,
    )?;
    Ok((next_root, chain))
}

fn message_step<P: Provider>(
    provider: &P,
    chain: &[u8; 32],
    number: u32,
) -> Result<MessageStep, Error> {
    let counter = number.to_be_bytes();
    let mut message = [0; 32];
    provider.hkdf_expand_sha256(chain, &[D_MESSAGE_KEY, &counter].concat(), &mut message)?;
    let mut nonce = [0; 12];
    provider.hkdf_expand_sha256(chain, &[D_NONCE, &counter].concat(), &mut nonce)?;
    let mut next = [0; 32];
    provider.hkdf_expand_sha256(chain, &[D_NEXT_CHAIN, &counter].concat(), &mut next)?;
    Ok((message, nonce, next))
}

fn expand<P: Provider>(
    provider: &P,
    salt: &[u8],
    ikm: &[u8],
    domain: &[u8],
    digest: &[u8; 32],
    output: &mut [u8],
) -> Result<(), Error> {
    provider.hkdf_sha256(salt, ikm, &[domain, digest].concat(), output)
}

fn record_aad(context: &[u8; 32], header: &[u8]) -> Vec<u8> {
    [D_RECORD_AAD, context, header].concat()
}

fn ratchet_header_length(packet: &[u8]) -> Result<usize, Error> {
    for length in 38..=packet.len().min(48) {
        if RatchetHeader::decode(&packet[..length]).is_ok() {
            return Ok(length);
        }
    }
    Err(record_error(ErrorCode::InvalidRepresentation))
}

fn exact_32(value: Option<&CborValue>) -> Result<[u8; 32], Error> {
    let Some(CborValue::Bytes(bytes)) = value else {
        return Err(record_error(ErrorCode::InvalidRepresentation));
    };
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| record_error(ErrorCode::InvalidRepresentation))
}

fn exact_u32(value: Option<&CborValue>) -> Result<u32, Error> {
    let Some(CborValue::Unsigned(value)) = value else {
        return Err(record_error(ErrorCode::InvalidRepresentation));
    };
    u32::try_from(*value).map_err(|_| record_error(ErrorCode::BoundExceeded))
}

const fn handshake_rejected() -> Error {
    Error::terminal(ErrorCode::HandshakeRejected, Stage::Validation)
}

const fn record_error(code: ErrorCode) -> Error {
    Error::terminal(code, Stage::Validation)
}

#[cfg(test)]
mod tests {
    use super::{HybridSecrets, RatchetState};
    use crate::{
        error::{Error, ErrorCode, Stage},
        provider::{AgreementProvider, RustCryptoProvider},
        state::{
            CustodyRef, Ed25519Signing, KeyCustody, MlDsa65Signing, MlKem768Private,
            MlKemEncapsulationEntropy, SecretHandle, StagedSecretHandle, X25519Private,
        },
    };
    use std::collections::HashMap;

    struct TestCustody {
        keys: HashMap<u128, [u8; 32]>,
        fail_x25519_public: Option<u128>,
    }

    impl KeyCustody for TestCustody {
        fn ed25519_public(&self, _: &SecretHandle<Ed25519Signing>) -> Result<[u8; 32], Error> {
            Err(fail())
        }
        fn ed25519_sign(
            &self,
            _: &SecretHandle<Ed25519Signing>,
            _: &[u8],
        ) -> Result<[u8; 64], Error> {
            Err(fail())
        }
        fn ml_dsa_65_public(&self, _: &SecretHandle<MlDsa65Signing>) -> Result<Vec<u8>, Error> {
            Err(fail())
        }
        fn ml_dsa_65_sign(
            &self,
            _: &SecretHandle<MlDsa65Signing>,
            _: &[u8],
        ) -> Result<Vec<u8>, Error> {
            Err(fail())
        }
        fn x25519_public(&self, handle: CustodyRef<'_, X25519Private>) -> Result<[u8; 32], Error> {
            let token = handle.custody_token();
            if self.fail_x25519_public == Some(token) {
                return Err(Error::retryable(ErrorCode::Deleted, Stage::Commit));
            }
            self.keys
                .get(&token)
                .map(|value| RustCryptoProvider.x25519_public(value))
                .ok_or_else(fail)
        }
        fn x25519(
            &self,
            handle: CustodyRef<'_, X25519Private>,
            public: &[u8; 32],
        ) -> Result<[u8; 32], Error> {
            RustCryptoProvider.x25519(
                self.keys.get(&handle.custody_token()).ok_or_else(fail)?,
                public,
            )
        }
        fn ml_kem_768_public(&self, _: CustodyRef<'_, MlKem768Private>) -> Result<Vec<u8>, Error> {
            Err(fail())
        }
        fn ml_kem_768_encapsulate(
            &self,
            _: &[u8],
            _: &SecretHandle<MlKemEncapsulationEntropy>,
        ) -> Result<(Vec<u8>, [u8; 32]), Error> {
            Err(fail())
        }
        fn ml_kem_768_decapsulate(
            &self,
            _: &SecretHandle<MlKem768Private>,
            _: &[u8],
        ) -> Result<[u8; 32], Error> {
            Err(fail())
        }
        fn abort_x25519(&mut self, _: &StagedSecretHandle<X25519Private>) {}
        fn abort_ml_kem_768(&mut self, _: &StagedSecretHandle<MlKem768Private>) {}
    }

    const fn fail() -> Error {
        Error::terminal(ErrorCode::ProviderFailure, Stage::Provider)
    }

    fn pair() -> (TestCustody, RatchetState, RatchetState) {
        let provider = RustCryptoProvider;
        let initiator_private = [7; 32];
        let responder_private = [8; 32];
        let custody = TestCustody {
            keys: HashMap::from([
                (1, initiator_private),
                (2, responder_private),
                (3, [13; 32]),
                (4, [14; 32]),
                (5, [15; 32]),
            ]),
            fail_x25519_public: None,
        };
        let shared = provider
            .x25519(
                &initiator_private,
                &provider.x25519_public(&responder_private),
            )
            .unwrap();
        let hybrid =
            HybridSecrets::derive(&provider, &shared, &[9; 32], &[10; 32], &[11; 32]).unwrap();
        let initiator = RatchetState::initiator(
            &provider,
            &hybrid,
            [12; 32],
            SecretHandle::from_custody_token(1),
            provider.x25519_public(&initiator_private),
            provider.x25519_public(&responder_private),
        )
        .unwrap();
        let responder = RatchetState::responder(
            &provider,
            &hybrid,
            [12; 32],
            SecretHandle::from_custody_token(2),
            provider.x25519_public(&responder_private),
            provider.x25519_public(&initiator_private),
        )
        .unwrap();
        (custody, initiator, responder)
    }

    #[test]
    fn staged_public_failure_is_bounded_before_handle_adoption() {
        let provider = RustCryptoProvider;
        let (mut custody, _, responder) = pair();
        custody.fail_x25519_public = Some(3);

        let error = responder
            .bootstrap_responder(
                &provider,
                &custody,
                &StagedSecretHandle::from_custody_token(3),
            )
            .unwrap_err();
        assert_eq!(
            (error.code, error.stage, error.retryable),
            (ErrorCode::RecordAuthentication, Stage::Validation, false)
        );
        assert_eq!(responder.local_private_handle().custody_token(), 2);
    }

    #[test]
    fn out_of_order_and_replay_are_closed_inside_the_endpoint_boundary() {
        let provider = RustCryptoProvider;
        let (custody, initiator, responder) = pair();
        let (initiator, first) = initiator.send(&provider, b"first").unwrap();
        let (_, second) = initiator.send(&provider, b"second").unwrap();
        let (responder, plaintext) = responder
            .receive(&provider, &custody, &second, None)
            .unwrap();
        assert_eq!(plaintext, b"second");
        let (responder, plaintext) = responder
            .receive(&provider, &custody, &first, None)
            .unwrap();
        assert_eq!(plaintext, b"first");
        assert_eq!(
            responder
                .receive(&provider, &custody, &first, None)
                .unwrap_err()
                .code,
            ErrorCode::Replay
        );
    }

    #[test]
    fn dh_transition_retains_skipped_keys_from_the_previous_chain() {
        let provider = RustCryptoProvider;
        let (custody, initiator, responder) = pair();
        let (initiator, first) = initiator.send(&provider, b"old-zero").unwrap();
        let (initiator, delayed) = initiator.send(&provider, b"old-one").unwrap();
        let (responder, _) = responder
            .receive(&provider, &custody, &first, None)
            .unwrap();

        let responder = responder
            .bootstrap_responder(
                &provider,
                &custody,
                &StagedSecretHandle::from_custody_token(3),
            )
            .unwrap();
        let (responder, response) = responder.send(&provider, b"response").unwrap();
        let (initiator, _) = initiator
            .receive(
                &provider,
                &custody,
                &response,
                Some(&StagedSecretHandle::from_custody_token(4)),
            )
            .unwrap();
        let (_, new_chain) = initiator.send(&provider, b"new-chain").unwrap();

        let (responder, _) = responder
            .receive(
                &provider,
                &custody,
                &new_chain,
                Some(&StagedSecretHandle::from_custody_token(5)),
            )
            .unwrap();
        let (_, recovered) = responder
            .receive(&provider, &custody, &delayed, None)
            .unwrap();
        assert_eq!(recovered, b"old-one");
    }
}
