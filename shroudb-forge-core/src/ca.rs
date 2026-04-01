use std::fmt;

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
#[derive(Clone, Serialize, Deserialize)]
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

impl fmt::Debug for CaKeyVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CaKeyVersion")
            .field("version", &self.version)
            .field("state", &self.state)
            .field(
                "key_material",
                &match &self.key_material {
                    Some(_) => "[REDACTED]",
                    None => "None",
                },
            )
            .field("public_key", &self.public_key)
            .field("certificate_pem", &self.certificate_pem)
            .field("created_at", &self.created_at)
            .field("activated_at", &self.activated_at)
            .field("draining_since", &self.draining_since)
            .field("retired_at", &self.retired_at)
            .finish()
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    // --- CaAlgorithm::from_config ---

    #[test]
    fn ca_algorithm_from_config_ecdsa_p256_variants() {
        assert_eq!(
            CaAlgorithm::from_config("ecdsa-p256"),
            Some(CaAlgorithm::EcdsaP256)
        );
        assert_eq!(
            CaAlgorithm::from_config("ecdsap256"),
            Some(CaAlgorithm::EcdsaP256)
        );
        assert_eq!(
            CaAlgorithm::from_config("p256"),
            Some(CaAlgorithm::EcdsaP256)
        );
        assert_eq!(
            CaAlgorithm::from_config("ecdsa_p256"),
            Some(CaAlgorithm::EcdsaP256)
        );
        assert_eq!(
            CaAlgorithm::from_config("ECDSA-P256"),
            Some(CaAlgorithm::EcdsaP256)
        );
    }

    #[test]
    fn ca_algorithm_from_config_ecdsa_p384_variants() {
        assert_eq!(
            CaAlgorithm::from_config("ecdsa-p384"),
            Some(CaAlgorithm::EcdsaP384)
        );
        assert_eq!(
            CaAlgorithm::from_config("ecdsap384"),
            Some(CaAlgorithm::EcdsaP384)
        );
        assert_eq!(
            CaAlgorithm::from_config("p384"),
            Some(CaAlgorithm::EcdsaP384)
        );
        assert_eq!(
            CaAlgorithm::from_config("ecdsa_p384"),
            Some(CaAlgorithm::EcdsaP384)
        );
    }

    #[test]
    fn ca_algorithm_from_config_ed25519_variants() {
        assert_eq!(
            CaAlgorithm::from_config("ed25519"),
            Some(CaAlgorithm::Ed25519)
        );
        assert_eq!(
            CaAlgorithm::from_config("eddsa"),
            Some(CaAlgorithm::Ed25519)
        );
        assert_eq!(
            CaAlgorithm::from_config("ED25519"),
            Some(CaAlgorithm::Ed25519)
        );
    }

    #[test]
    fn ca_algorithm_from_config_unknown() {
        assert_eq!(CaAlgorithm::from_config("rsa-2048"), None);
        assert_eq!(CaAlgorithm::from_config(""), None);
        assert_eq!(CaAlgorithm::from_config("bogus"), None);
    }

    #[test]
    fn ca_algorithm_from_str() {
        assert_eq!(
            "p256".parse::<CaAlgorithm>().unwrap(),
            CaAlgorithm::EcdsaP256
        );
        assert_eq!(
            "ed25519".parse::<CaAlgorithm>().unwrap(),
            CaAlgorithm::Ed25519
        );
        assert!("rsa-4096".parse::<CaAlgorithm>().is_err());
    }

    #[test]
    fn ca_algorithm_wire_name() {
        assert_eq!(CaAlgorithm::EcdsaP256.wire_name(), "ecdsa-p256");
        assert_eq!(CaAlgorithm::EcdsaP384.wire_name(), "ecdsa-p384");
        assert_eq!(CaAlgorithm::Ed25519.wire_name(), "ed25519");
    }

    #[test]
    fn ca_algorithm_display() {
        assert_eq!(format!("{}", CaAlgorithm::EcdsaP256), "ecdsa-p256");
        assert_eq!(format!("{}", CaAlgorithm::Ed25519), "ed25519");
    }

    // --- CertificateAuthority methods ---

    fn test_ca() -> CertificateAuthority {
        CertificateAuthority {
            name: "test-ca".into(),
            subject: "CN=Test CA".into(),
            algorithm: CaAlgorithm::EcdsaP256,
            ttl_days: 365,
            parent: None,
            rotation_days: 90,
            drain_days: 30,
            created_at: 1000,
            disabled: false,
            key_versions: vec![
                CaKeyVersion {
                    version: 1,
                    state: KeyState::Retired,
                    key_material: None,
                    public_key: None,
                    certificate_pem: String::new(),
                    created_at: 1000,
                    activated_at: Some(1000),
                    draining_since: Some(2000),
                    retired_at: Some(3000),
                },
                CaKeyVersion {
                    version: 2,
                    state: KeyState::Draining,
                    key_material: None,
                    public_key: None,
                    certificate_pem: String::new(),
                    created_at: 2000,
                    activated_at: Some(2000),
                    draining_since: Some(3000),
                    retired_at: None,
                },
                CaKeyVersion {
                    version: 3,
                    state: KeyState::Active,
                    key_material: Some("aabb".into()),
                    public_key: Some("ccdd".into()),
                    certificate_pem: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"
                        .into(),
                    created_at: 3000,
                    activated_at: Some(3000),
                    draining_since: None,
                    retired_at: None,
                },
            ],
        }
    }

    #[test]
    fn active_key_returns_active_version() {
        let ca = test_ca();
        let active = ca.active_key().unwrap();
        assert_eq!(active.version, 3);
        assert_eq!(active.state, KeyState::Active);
    }

    #[test]
    fn active_key_none_when_no_active() {
        let mut ca = test_ca();
        for kv in &mut ca.key_versions {
            kv.state = KeyState::Retired;
        }
        assert!(ca.active_key().is_none());
    }

    #[test]
    fn key_version_by_number() {
        let ca = test_ca();
        assert_eq!(ca.key_version(1).unwrap().state, KeyState::Retired);
        assert_eq!(ca.key_version(2).unwrap().state, KeyState::Draining);
        assert_eq!(ca.key_version(3).unwrap().state, KeyState::Active);
        assert!(ca.key_version(99).is_none());
    }

    #[test]
    fn next_version() {
        let ca = test_ca();
        assert_eq!(ca.next_version(), 4);
    }

    #[test]
    fn next_version_empty() {
        let mut ca = test_ca();
        ca.key_versions.clear();
        assert_eq!(ca.next_version(), 1);
    }

    #[test]
    fn verifiable_keys_includes_active_and_draining() {
        let ca = test_ca();
        let verifiable = ca.verifiable_keys();
        assert_eq!(verifiable.len(), 2);
        let versions: Vec<u32> = verifiable.iter().map(|kv| kv.version).collect();
        assert!(versions.contains(&2)); // Draining
        assert!(versions.contains(&3)); // Active
    }

    #[test]
    fn decode_key_material_missing() {
        let kv = CaKeyVersion {
            version: 1,
            state: KeyState::Active,
            key_material: None,
            public_key: None,
            certificate_pem: String::new(),
            created_at: 0,
            activated_at: None,
            draining_since: None,
            retired_at: None,
        };
        assert!(decode_key_material(&kv).is_err());
    }

    #[test]
    fn decode_key_material_invalid_hex() {
        let kv = CaKeyVersion {
            version: 1,
            state: KeyState::Active,
            key_material: Some("not-valid-hex!".into()),
            public_key: None,
            certificate_pem: String::new(),
            created_at: 0,
            activated_at: None,
            draining_since: None,
            retired_at: None,
        };
        assert!(decode_key_material(&kv).is_err());
    }

    #[test]
    fn decode_key_material_valid_hex() {
        let kv = CaKeyVersion {
            version: 1,
            state: KeyState::Active,
            key_material: Some("deadbeef".into()),
            public_key: None,
            certificate_pem: String::new(),
            created_at: 0,
            activated_at: None,
            draining_since: None,
            retired_at: None,
        };
        let result = decode_key_material(&kv).unwrap();
        assert_eq!(result.as_bytes(), &[0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn debug_redacts_key_material() {
        let kv = CaKeyVersion {
            version: 1,
            state: KeyState::Active,
            key_material: Some("secret".into()),
            public_key: Some("pub".into()),
            certificate_pem: "cert".into(),
            created_at: 100,
            activated_at: Some(100),
            draining_since: None,
            retired_at: None,
        };
        let debug = format!("{:?}", kv);
        assert!(
            debug.contains("[REDACTED]"),
            "expected [REDACTED] in: {debug}"
        );
        assert!(!debug.contains("secret"), "key material leaked in: {debug}");
    }
}
