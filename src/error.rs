use core::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ErrorCode {
    InvalidAuthorityInput,
    DigestMismatch,
    SourceClosureMismatch,
    UnsupportedDefinition,
    LineNotEligible,
    ContentIdentityMismatch,
    UnknownProfile,
    AuthenticationFailed,
    AuthorizationFailed,
    ProviderFailure,
    HandshakeRejected,
    PrekeyConsumed,
    RecordAuthentication,
    Replay,
    StaleRatchet,
    SkipBound,
    CounterOverflow,
    StateRollback,
    Deleted,
    InvalidRepresentation,
    NonCanonicalRepresentation,
    UnknownField,
    BoundExceeded,
    InvalidTransition,
    Conflict,
    SecurityClaimUnproved,
    ConformanceMismatch,
    UnsupportedConformanceCase,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Stage {
    Admission,
    Representation,
    Validation,
    Commit,
    Provider,
    SecurityAccounting,
}

/// A bounded error which never includes input bytes, payloads, secrets, or paths.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Error {
    pub code: ErrorCode,
    pub stage: Stage,
    pub retryable: bool,
}

impl Error {
    #[must_use]
    pub const fn terminal(code: ErrorCode, stage: Stage) -> Self {
        Self {
            code,
            stage,
            retryable: false,
        }
    }

    #[must_use]
    pub const fn retryable(code: ErrorCode, stage: Stage) -> Self {
        Self {
            code,
            stage,
            retryable: true,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?} at {:?}", self.code, self.stage)
    }
}

impl std::error::Error for Error {}
