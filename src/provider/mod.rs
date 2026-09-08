//! Fixed cryptographic operation boundary.
//!
//! Protocol modules depend on these traits. Concrete RustCrypto types never
//! escape this adapter and no operation accepts an algorithm selector.

use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce, Tag,
    aead::{AeadInOut, KeyInit, inout::InOutBuf},
};
use ed25519_dalek::{Signature as Ed25519Signature, Signer as _, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use ml_dsa::{
    KeyExport as _, Keypair as _, MlDsa65, Signature as MlDsaSignature, SignatureEncoding as _,
    SigningKey as MlDsaSigningKey, Verifier as _, VerifyingKey as MlDsaVerifyingKey,
};
use ml_kem::{B32, Decapsulate as _, EncapsulationKey768, MlKem768, Seed, ml_kem_768::Ciphertext};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::error::{Error, ErrorCode, Stage};

pub const ML_KEM_768_PUBLIC_KEY_BYTES: usize = 1_184;
pub const ML_KEM_768_CIPHERTEXT_BYTES: usize = 1_088;
pub const ML_DSA_65_PUBLIC_KEY_BYTES: usize = 1_952;
pub const ML_DSA_65_SIGNATURE_BYTES: usize = 3_309;

pub trait DigestProvider {
    fn sha256(&self, input: &[u8]) -> [u8; 32];
}

pub trait KdfProvider {
    fn hkdf_sha256(
        &self,
        salt: &[u8],
        input_key_material: &[u8],
        info: &[u8],
        output: &mut [u8],
    ) -> Result<(), Error>;

    fn hkdf_expand_sha256(
        &self,
        pseudorandom_key: &[u8; 32],
        info: &[u8],
        output: &mut [u8],
    ) -> Result<(), Error>;

    fn hmac_sha256(&self, key: &[u8], input: &[u8]) -> Result<[u8; 32], Error>;

    /// Verifies a fixed-size HMAC without exposing a data-dependent equality
    /// comparison to protocol code.
    fn hmac_sha256_verify(
        &self,
        key: &[u8],
        input: &[u8],
        expected: &[u8; 32],
    ) -> Result<(), Error>;
}

pub trait AeadProvider {
    fn seal(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 12],
        associated_data: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, Error>;

    fn open(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 12],
        associated_data: &[u8],
        ciphertext_and_tag: &[u8],
    ) -> Result<Vec<u8>, Error>;
}

pub trait AgreementProvider {
    fn x25519_public(&self, private: &[u8; 32]) -> [u8; 32];
    fn x25519(&self, private: &[u8; 32], public: &[u8; 32]) -> Result<[u8; 32], Error>;
    fn ml_kem_768_public(&self, seed: &[u8; 64]) -> Vec<u8>;
    fn ml_kem_768_encapsulate(
        &self,
        public: &[u8],
        entropy: &[u8; 32],
    ) -> Result<(Vec<u8>, [u8; 32]), Error>;
    /// Correctly sized ciphertexts always produce key material. Invalid input
    /// is distinguished only by later uniform confirmation failure.
    fn ml_kem_768_decapsulate(&self, seed: &[u8; 64], ciphertext: &[u8])
    -> Result<[u8; 32], Error>;
}

pub trait SignatureProvider {
    fn ed25519_public(&self, seed: &[u8; 32]) -> [u8; 32];
    fn ed25519_sign(&self, seed: &[u8; 32], message: &[u8]) -> [u8; 64];
    fn ed25519_verify_strict(
        &self,
        public: &[u8; 32],
        message: &[u8],
        signature: &[u8; 64],
    ) -> Result<(), Error>;
    fn ml_dsa_65_public(&self, seed: &[u8; 32]) -> Vec<u8>;
    fn ml_dsa_65_sign(&self, seed: &[u8; 32], message: &[u8]) -> Vec<u8>;
    fn ml_dsa_65_verify(
        &self,
        public: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), Error>;
}

pub trait Provider:
    DigestProvider + KdfProvider + AeadProvider + AgreementProvider + SignatureProvider
{
}

impl<T> Provider for T where
    T: DigestProvider + KdfProvider + AeadProvider + AgreementProvider + SignatureProvider
{
}

#[derive(Clone, Copy, Debug, Default)]
pub struct RustCryptoProvider;

#[must_use]
pub fn fixed_provider() -> impl Provider {
    RustCryptoProvider
}

#[must_use]
pub fn fixed_sha256(input: &[u8]) -> [u8; 32] {
    RustCryptoProvider.sha256(input)
}

impl DigestProvider for RustCryptoProvider {
    fn sha256(&self, input: &[u8]) -> [u8; 32] {
        Sha256::digest(input).into()
    }
}

impl KdfProvider for RustCryptoProvider {
    fn hkdf_sha256(
        &self,
        salt: &[u8],
        input_key_material: &[u8],
        info: &[u8],
        output: &mut [u8],
    ) -> Result<(), Error> {
        Hkdf::<Sha256>::new(Some(salt), input_key_material)
            .expand(info, output)
            .map_err(|_| provider_error())
    }

    fn hmac_sha256(&self, key: &[u8], input: &[u8]) -> Result<[u8; 32], Error> {
        let mut mac = <Hmac<Sha256> as hmac::digest::KeyInit>::new_from_slice(key)
            .map_err(|_| provider_error())?;
        mac.update(input);
        Ok(mac.finalize().into_bytes().into())
    }

    fn hmac_sha256_verify(
        &self,
        key: &[u8],
        input: &[u8],
        expected: &[u8; 32],
    ) -> Result<(), Error> {
        let mut mac = <Hmac<Sha256> as hmac::digest::KeyInit>::new_from_slice(key)
            .map_err(|_| provider_error())?;
        mac.update(input);
        mac.verify_slice(expected)
            .map_err(|_| authentication_error())
    }

    fn hkdf_expand_sha256(
        &self,
        pseudorandom_key: &[u8; 32],
        info: &[u8],
        output: &mut [u8],
    ) -> Result<(), Error> {
        Hkdf::<Sha256>::from_prk(pseudorandom_key)
            .map_err(|_| provider_error())?
            .expand(info, output)
            .map_err(|_| provider_error())
    }
}

impl AeadProvider for RustCryptoProvider {
    fn seal(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 12],
        associated_data: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let cipher = ChaCha20Poly1305::new(&Key::from(*key));
        let mut output = plaintext.to_vec();
        let tag = cipher
            .encrypt_inout_detached(
                &Nonce::from(*nonce),
                associated_data,
                InOutBuf::from(output.as_mut_slice()),
            )
            .map_err(|_| authentication_error())?;
        output.extend_from_slice(&tag);
        Ok(output)
    }

    fn open(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 12],
        associated_data: &[u8],
        ciphertext_and_tag: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let split = ciphertext_and_tag
            .len()
            .checked_sub(16)
            .ok_or_else(authentication_error)?;
        let mut output = ciphertext_and_tag[..split].to_vec();
        let tag =
            Tag::try_from(&ciphertext_and_tag[split..]).map_err(|_| authentication_error())?;
        ChaCha20Poly1305::new(&Key::from(*key))
            .decrypt_inout_detached(
                &Nonce::from(*nonce),
                associated_data,
                InOutBuf::from(output.as_mut_slice()),
                &tag,
            )
            .map_err(|_| authentication_error())?;
        Ok(output)
    }
}

impl AgreementProvider for RustCryptoProvider {
    fn x25519_public(&self, private: &[u8; 32]) -> [u8; 32] {
        PublicKey::from(&StaticSecret::from(*private)).to_bytes()
    }

    fn x25519(&self, private: &[u8; 32], public: &[u8; 32]) -> Result<[u8; 32], Error> {
        let bytes = StaticSecret::from(*private)
            .diffie_hellman(&PublicKey::from(*public))
            .to_bytes();
        if bytes == [0; 32] {
            return Err(authentication_error());
        }
        Ok(bytes)
    }

    fn ml_kem_768_public(&self, seed: &[u8; 64]) -> Vec<u8> {
        let (_, encapsulation) = <MlKem768 as ml_kem::FromSeed>::from_seed(&Seed::from(*seed));
        encapsulation.to_bytes().to_vec()
    }

    fn ml_kem_768_encapsulate(
        &self,
        public: &[u8],
        entropy: &[u8; 32],
    ) -> Result<(Vec<u8>, [u8; 32]), Error> {
        let encoded = ml_kem::Key::<EncapsulationKey768>::try_from(public)
            .map_err(|_| authentication_error())?;
        let public = EncapsulationKey768::new(&encoded).map_err(|_| authentication_error())?;
        let (ciphertext, shared) = public.encapsulate_deterministic(&B32::from(*entropy));
        Ok((ciphertext.to_vec(), shared.into()))
    }

    fn ml_kem_768_decapsulate(
        &self,
        seed: &[u8; 64],
        ciphertext: &[u8],
    ) -> Result<[u8; 32], Error> {
        let ciphertext = Ciphertext::try_from(ciphertext).map_err(|_| authentication_error())?;
        let (decapsulation, _) = <MlKem768 as ml_kem::FromSeed>::from_seed(&Seed::from(*seed));
        Ok(decapsulation.decapsulate(&ciphertext).into())
    }
}

impl SignatureProvider for RustCryptoProvider {
    fn ed25519_public(&self, seed: &[u8; 32]) -> [u8; 32] {
        SigningKey::from_bytes(seed).verifying_key().to_bytes()
    }

    fn ed25519_sign(&self, seed: &[u8; 32], message: &[u8]) -> [u8; 64] {
        SigningKey::from_bytes(seed).sign(message).to_bytes()
    }

    fn ed25519_verify_strict(
        &self,
        public: &[u8; 32],
        message: &[u8],
        signature: &[u8; 64],
    ) -> Result<(), Error> {
        VerifyingKey::from_bytes(public)
            .map_err(|_| authentication_error())?
            .verify_strict(message, &Ed25519Signature::from_bytes(signature))
            .map_err(|_| authentication_error())
    }

    fn ml_dsa_65_public(&self, seed: &[u8; 32]) -> Vec<u8> {
        MlDsaSigningKey::<MlDsa65>::from_seed(&(*seed).into())
            .verifying_key()
            .to_bytes()
            .to_vec()
    }

    fn ml_dsa_65_sign(&self, seed: &[u8; 32], message: &[u8]) -> Vec<u8> {
        let signature: MlDsaSignature<MlDsa65> =
            MlDsaSigningKey::<MlDsa65>::from_seed(&(*seed).into()).sign(message);
        signature.to_bytes().to_vec()
    }

    fn ml_dsa_65_verify(
        &self,
        public: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), Error> {
        let public = ml_dsa::EncodedVerifyingKey::<MlDsa65>::try_from(public)
            .map_err(|_| authentication_error())?;
        let public = MlDsaVerifyingKey::<MlDsa65>::decode(&public);
        let signature =
            MlDsaSignature::<MlDsa65>::try_from(signature).map_err(|_| authentication_error())?;
        public
            .verify(message, &signature)
            .map_err(|_| authentication_error())
    }
}

const fn provider_error() -> Error {
    Error::terminal(ErrorCode::ProviderFailure, Stage::Provider)
}

const fn authentication_error() -> Error {
    Error::terminal(ErrorCode::AuthenticationFailed, Stage::Provider)
}
