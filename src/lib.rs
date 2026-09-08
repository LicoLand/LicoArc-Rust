//! Independent safe-Rust implementation of the exact current stable-core Line.
//!
//! LicoArc-owned bytes are supplied explicitly and remain the sole protocol
//! authority. Product policy, persistence, custody, transport, and effects stay
//! caller-owned.

#![forbid(unsafe_code)]

pub mod artifact;
pub mod conformance;
pub mod encoding;
pub mod endpoint;
pub mod error;
pub mod governance;
pub mod group;
pub mod identity;
pub mod messaging;
pub mod protection;
pub mod provider;
pub mod reliable;
pub mod security;
pub mod state;
pub mod transport;

pub use artifact::{AuthorityBundle, SnapshotDigest, VerifiedProtocolLine};
pub use error::{Error, ErrorCode, Stage};
