use thiserror::Error;

use crate::key_state::KeyState;

#[derive(Debug, Error)]
pub enum ForgeError {
    #[error("CA not found: {name}")]
    CaNotFound { name: String },

    #[error("CA already exists: {name}")]
    CaAlreadyExists { name: String },

    #[error("CA is disabled: {name}")]
    CaDisabled { name: String },

    #[error("no active key for CA '{ca}'")]
    NoActiveKey { ca: String },

    #[error("invalid state transition: {from:?} -> {to:?}")]
    InvalidStateTransition { from: KeyState, to: KeyState },

    #[error("certificate not found: CA '{ca}' serial '{serial}'")]
    CertNotFound { ca: String, serial: String },

    #[error("certificate already revoked: serial '{serial}'")]
    CertAlreadyRevoked { serial: String },

    #[error("profile not found: {name}")]
    ProfileNotFound { name: String },

    #[error("TTL {requested_days} days exceeds profile max of {max_days} days")]
    TtlExceedsMax { requested_days: u32, max_days: u32 },

    #[error("SAN DNS names not allowed by profile '{profile}'")]
    SanDnsNotAllowed { profile: String },

    #[error("SAN IP addresses not allowed by profile '{profile}'")]
    SanIpNotAllowed { profile: String },

    #[error("unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),

    #[error("X.509 generation failed: {0}")]
    X509Generation(String),

    #[error("CSR parsing failed: {0}")]
    CsrParsing(String),

    #[error("crypto error: {0}")]
    Crypto(String),

    #[error("OCSP request error: {0}")]
    OcspRequest(String),

    #[error("OCSP response error: {0}")]
    OcspResponse(String),

    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    #[error("store error: {0}")]
    Store(String),

    #[error("internal error: {0}")]
    Internal(String),
}
