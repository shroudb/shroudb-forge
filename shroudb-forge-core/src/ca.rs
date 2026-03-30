use serde::{Deserialize, Serialize};

use crate::error::ForgeError;
use crate::key_state::KeyState;

/// Supported CA signing algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CaAlgorithm {
    EcdsaP256,
    EcdsaP384,
    Ed25519,
}

impl CaAlgorithm {
    /// Parse from config/command string (case-insensitive).
    pub fn from_config(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "ecdsa-p256" | "ecdsap256" | "p256" | "ecdsa_p256" => Some(CaAlgorithm::EcdsaP256),
            "ecdsa-p384" | "ecdsap384" | "p384" | "ecdsa_p384" => Some(CaAlgorithm::EcdsaP384),
            "ed25519" | "eddsa" => Some(CaAlgorithm::Ed25519),
            _ => None,
        }
    }

    /// Canonical wire name.
    pub fn wire_name(&self) -> &'static str {
        match self {
            CaAlgorithm::EcdsaP256 => "ecdsa-p256",
            CaAlgorithm::EcdsaP384 => "ecdsa-p384",
            CaAlgorithm::Ed25519 => "ed25519",
        }
    }
}

impl std::fmt::Display for CaAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.wire_name())
    }
}

impl std::str::FromStr for CaAlgorithm {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        CaAlgorithm::from_config(s).ok_or_else(|| format!("unsupported algorithm: {s}"))
    }
}

/// A single version of a CA signing key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaKeyVersion {
    pub version: u32,
    pub state: KeyState,
    /// Hex-encoded DER private key (encrypted at rest by Store).
    pub key_material: Option<String>,
    /// Hex-encoded public key bytes.
    pub public_key: Option<String>,
    /// PEM-encoded CA certificate for this key version.
    pub certificate_pem: String,
    pub created_at: u64,
    pub activated_at: Option<u64>,
    pub draining_since: Option<u64>,
    pub retired_at: Option<u64>,
}

/// A Certificate Authority with versioned signing keys.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateAuthority {
    pub name: String,
    pub subject: String,
    pub algorithm: CaAlgorithm,
    /// CA certificate validity in days.
    pub ttl_days: u32,
    /// Parent CA name for intermediates (None = self-signed root).
    pub parent: Option<String>,
    /// Days between automatic key rotations.
    pub rotation_days: u32,
    /// Days a key stays in Draining before Retired.
    pub drain_days: u32,
    pub created_at: u64,
    pub disabled: bool,
    pub key_versions: Vec<CaKeyVersion>,
}

impl CertificateAuthority {
    /// Find the active key version.
    pub fn active_key(&self) -> Option<&CaKeyVersion> {
        self.key_versions
            .iter()
            .find(|kv| kv.state == KeyState::Active)
    }

    /// Find the active key version mutably.
    pub fn active_key_mut(&mut self) -> Option<&mut CaKeyVersion> {
        self.key_versions
            .iter_mut()
            .find(|kv| kv.state == KeyState::Active)
    }

    /// Find a key version by version number.
    pub fn key_version(&self, version: u32) -> Option<&CaKeyVersion> {
        self.key_versions.iter().find(|kv| kv.version == version)
    }

    /// Next version number (max existing + 1, or 1 if none).
    pub fn next_version(&self) -> u32 {
        self.key_versions
            .iter()
            .map(|kv| kv.version)
            .max()
            .unwrap_or(0)
            + 1
    }

    /// All key versions that can still verify signatures (Active + Draining).
    pub fn verifiable_keys(&self) -> Vec<&CaKeyVersion> {
        self.key_versions
            .iter()
            .filter(|kv| kv.state == KeyState::Active || kv.state == KeyState::Draining)
            .collect()
    }
}

/// Decode hex-encoded key material from a CaKeyVersion to zeroize-on-drop bytes.
pub fn decode_key_material(kv: &CaKeyVersion) -> Result<shroudb_crypto::SecretBytes, ForgeError> {
    kv.key_material
        .as_ref()
        .ok_or_else(|| ForgeError::NoActiveKey {
            ca: "unknown".into(),
        })
        .and_then(|hex_str| {
            hex::decode(hex_str)
                .map(shroudb_crypto::SecretBytes::new)
                .map_err(|e| ForgeError::Crypto(format!("invalid key material hex: {e}")))
        })
}
