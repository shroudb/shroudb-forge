use serde::{Deserialize, Serialize};

/// State of an issued certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CertState {
    Active,
    Revoked,
}

impl std::fmt::Display for CertState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CertState::Active => write!(f, "active"),
            CertState::Revoked => write!(f, "revoked"),
        }
    }
}

impl CertState {
    pub fn from_arg(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "active" => Some(CertState::Active),
            "revoked" => Some(CertState::Revoked),
            _ => None,
        }
    }
}

/// RFC 5280 revocation reason codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RevocationReason {
    Unspecified,
    KeyCompromise,
    CaCompromise,
    AffiliationChanged,
    Superseded,
    CessationOfOperation,
}

impl RevocationReason {
    pub fn from_arg(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "unspecified" => Some(RevocationReason::Unspecified),
            "key_compromise" | "keycompromise" => Some(RevocationReason::KeyCompromise),
            "ca_compromise" | "cacompromise" => Some(RevocationReason::CaCompromise),
            "affiliation_changed" | "affiliationchanged" => {
                Some(RevocationReason::AffiliationChanged)
            }
            "superseded" => Some(RevocationReason::Superseded),
            "cessation_of_operation" | "cessationofoperation" | "cessation" => {
                Some(RevocationReason::CessationOfOperation)
            }
            _ => None,
        }
    }
}

impl std::fmt::Display for RevocationReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RevocationReason::Unspecified => write!(f, "unspecified"),
            RevocationReason::KeyCompromise => write!(f, "key_compromise"),
            RevocationReason::CaCompromise => write!(f, "ca_compromise"),
            RevocationReason::AffiliationChanged => write!(f, "affiliation_changed"),
            RevocationReason::Superseded => write!(f, "superseded"),
            RevocationReason::CessationOfOperation => write!(f, "cessation_of_operation"),
        }
    }
}

/// Metadata for an issued certificate. The private key is NOT stored here —
/// it is returned at issuance time only.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssuedCertificate {
    pub serial: String,
    pub ca_name: String,
    pub ca_key_version: u32,
    pub subject: String,
    pub profile: String,
    pub state: CertState,
    pub not_before: u64,
    pub not_after: u64,
    pub san_dns: Vec<String>,
    pub san_ip: Vec<String>,
    pub issued_at: u64,
    pub revoked_at: Option<u64>,
    pub revocation_reason: Option<RevocationReason>,
    pub certificate_pem: String,
}

impl IssuedCertificate {
    pub fn is_expired(&self, now: u64) -> bool {
        now > self.not_after
    }

    pub fn effective_state(&self, now: u64) -> &'static str {
        match self.state {
            CertState::Revoked => "revoked",
            CertState::Active if self.is_expired(now) => "expired",
            CertState::Active => "active",
        }
    }
}

/// Generate a random serial number as a hex string (20 bytes = 160 bits).
pub fn generate_serial() -> String {
    let rng = ring::rand::SystemRandom::new();
    let mut buf = [0u8; 20];
    ring::rand::SecureRandom::fill(&rng, &mut buf).expect("CSPRNG failure");
    // Ensure the high bit is 0 (X.509 serials are positive integers).
    buf[0] &= 0x7F;
    hex::encode(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serial_generation_is_unique() {
        let a = generate_serial();
        let b = generate_serial();
        assert_ne!(a, b);
        assert_eq!(a.len(), 40);
    }

    #[test]
    fn serial_high_bit_cleared() {
        for _ in 0..100 {
            let serial = generate_serial();
            let first_byte = u8::from_str_radix(&serial[..2], 16).unwrap();
            assert!(first_byte & 0x80 == 0, "high bit must be 0");
        }
    }

    #[test]
    fn revocation_reason_parsing() {
        assert_eq!(
            RevocationReason::from_arg("key_compromise"),
            Some(RevocationReason::KeyCompromise)
        );
        assert_eq!(
            RevocationReason::from_arg("SUPERSEDED"),
            Some(RevocationReason::Superseded)
        );
        assert_eq!(RevocationReason::from_arg("bogus"), None);
    }

    #[test]
    fn effective_state() {
        let cert = IssuedCertificate {
            serial: "01".into(),
            ca_name: "test".into(),
            ca_key_version: 1,
            subject: "CN=test".into(),
            profile: "server".into(),
            state: CertState::Active,
            not_before: 1000,
            not_after: 2000,
            san_dns: vec![],
            san_ip: vec![],
            issued_at: 1000,
            revoked_at: None,
            revocation_reason: None,
            certificate_pem: String::new(),
        };
        assert_eq!(cert.effective_state(1500), "active");
        assert_eq!(cert.effective_state(2500), "expired");
    }
}
