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
pub fn generate_serial() -> Result<String, crate::error::ForgeError> {
    let rng = ring::rand::SystemRandom::new();
    let mut buf = [0u8; 20];
    ring::rand::SecureRandom::fill(&rng, &mut buf)
        .map_err(|_| crate::error::ForgeError::Internal("CSPRNG failure".into()))?;
    // Ensure the high bit is 0 (X.509 serials are positive integers).
    buf[0] &= 0x7F;
    Ok(hex::encode(buf))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serial_generation_is_unique() {
        let a = generate_serial().unwrap();
        let b = generate_serial().unwrap();
        assert_ne!(a, b);
        assert_eq!(a.len(), 40);
    }

    #[test]
    fn serial_high_bit_cleared() {
        for _ in 0..100 {
            let serial = generate_serial().unwrap();
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
    fn revocation_reason_all_variants() {
        assert_eq!(
            RevocationReason::from_arg("unspecified"),
            Some(RevocationReason::Unspecified)
        );
        assert_eq!(
            RevocationReason::from_arg("keycompromise"),
            Some(RevocationReason::KeyCompromise)
        );
        assert_eq!(
            RevocationReason::from_arg("ca_compromise"),
            Some(RevocationReason::CaCompromise)
        );
        assert_eq!(
            RevocationReason::from_arg("cacompromise"),
            Some(RevocationReason::CaCompromise)
        );
        assert_eq!(
            RevocationReason::from_arg("affiliation_changed"),
            Some(RevocationReason::AffiliationChanged)
        );
        assert_eq!(
            RevocationReason::from_arg("affiliationchanged"),
            Some(RevocationReason::AffiliationChanged)
        );
        assert_eq!(
            RevocationReason::from_arg("cessation_of_operation"),
            Some(RevocationReason::CessationOfOperation)
        );
        assert_eq!(
            RevocationReason::from_arg("cessation"),
            Some(RevocationReason::CessationOfOperation)
        );
    }

    #[test]
    fn revocation_reason_display() {
        assert_eq!(format!("{}", RevocationReason::Unspecified), "unspecified");
        assert_eq!(
            format!("{}", RevocationReason::KeyCompromise),
            "key_compromise"
        );
        assert_eq!(
            format!("{}", RevocationReason::CaCompromise),
            "ca_compromise"
        );
        assert_eq!(
            format!("{}", RevocationReason::AffiliationChanged),
            "affiliation_changed"
        );
        assert_eq!(format!("{}", RevocationReason::Superseded), "superseded");
        assert_eq!(
            format!("{}", RevocationReason::CessationOfOperation),
            "cessation_of_operation"
        );
    }

    #[test]
    fn cert_state_from_arg() {
        assert_eq!(CertState::from_arg("active"), Some(CertState::Active));
        assert_eq!(CertState::from_arg("ACTIVE"), Some(CertState::Active));
        assert_eq!(CertState::from_arg("revoked"), Some(CertState::Revoked));
        assert_eq!(CertState::from_arg("REVOKED"), Some(CertState::Revoked));
        assert_eq!(CertState::from_arg("unknown"), None);
        assert_eq!(CertState::from_arg(""), None);
    }

    #[test]
    fn cert_state_display() {
        assert_eq!(format!("{}", CertState::Active), "active");
        assert_eq!(format!("{}", CertState::Revoked), "revoked");
    }

    #[test]
    fn issued_cert_revoked_state() {
        let cert = IssuedCertificate {
            serial: "02".into(),
            ca_name: "test".into(),
            ca_key_version: 1,
            subject: "CN=test".into(),
            profile: "server".into(),
            state: CertState::Revoked,
            not_before: 1000,
            not_after: 2000,
            san_dns: vec![],
            san_ip: vec![],
            issued_at: 1000,
            revoked_at: Some(1500),
            revocation_reason: Some(RevocationReason::KeyCompromise),
            certificate_pem: String::new(),
        };
        // Revoked certs show "revoked" regardless of expiry
        assert_eq!(cert.effective_state(1500), "revoked");
        assert_eq!(cert.effective_state(3000), "revoked");
    }

    #[test]
    fn is_expired() {
        let cert = IssuedCertificate {
            serial: "03".into(),
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
        assert!(!cert.is_expired(1500));
        assert!(!cert.is_expired(2000)); // at boundary: not expired (now == not_after)
        assert!(cert.is_expired(2001));
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
