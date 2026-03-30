use serde::{Deserialize, Serialize};

/// X.509 Key Usage extension values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyUsage {
    DigitalSignature,
    KeyEncipherment,
    DataEncipherment,
    KeyAgreement,
}

impl KeyUsage {
    pub fn from_config(s: &str) -> Option<Self> {
        match s {
            "DigitalSignature" => Some(KeyUsage::DigitalSignature),
            "KeyEncipherment" => Some(KeyUsage::KeyEncipherment),
            "DataEncipherment" => Some(KeyUsage::DataEncipherment),
            "KeyAgreement" => Some(KeyUsage::KeyAgreement),
            _ => None,
        }
    }
}

/// X.509 Extended Key Usage extension values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExtendedKeyUsage {
    ServerAuth,
    ClientAuth,
    CodeSigning,
}

impl ExtendedKeyUsage {
    pub fn from_config(s: &str) -> Option<Self> {
        match s {
            "ServerAuth" => Some(ExtendedKeyUsage::ServerAuth),
            "ClientAuth" => Some(ExtendedKeyUsage::ClientAuth),
            "CodeSigning" => Some(ExtendedKeyUsage::CodeSigning),
            _ => None,
        }
    }
}

/// A certificate profile defining constraints on issued certificates.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateProfile {
    pub name: String,
    pub key_usage: Vec<KeyUsage>,
    pub extended_key_usage: Vec<ExtendedKeyUsage>,
    /// Maximum allowed TTL in days.
    pub max_ttl_days: u32,
    /// Default TTL as a duration string (e.g., "24h", "7d", "30d").
    pub default_ttl: String,
    pub allow_san_dns: bool,
    pub allow_san_ip: bool,
    /// Optional subject template. `{}` is replaced with the subject argument.
    pub subject_template: Option<String>,
}

impl CertificateProfile {
    /// Parse a TTL duration string into seconds.
    /// Supports: "30s", "15m", "24h", "7d", "90d".
    pub fn parse_ttl(s: &str) -> Option<u64> {
        let s = s.trim();
        if s.is_empty() {
            return None;
        }
        let (num_str, suffix) = s.split_at(s.len() - 1);
        let num: u64 = num_str.parse().ok()?;
        match suffix {
            "s" => Some(num),
            "m" => Some(num * 60),
            "h" => Some(num * 3600),
            "d" => Some(num * 86400),
            _ => None,
        }
    }

    /// Parse a TTL string into days (rounded up).
    pub fn parse_ttl_days(s: &str) -> Option<u32> {
        let secs = Self::parse_ttl(s)?;
        Some(secs.div_ceil(86400) as u32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ttl_variants() {
        assert_eq!(CertificateProfile::parse_ttl("30s"), Some(30));
        assert_eq!(CertificateProfile::parse_ttl("15m"), Some(900));
        assert_eq!(CertificateProfile::parse_ttl("24h"), Some(86400));
        assert_eq!(CertificateProfile::parse_ttl("7d"), Some(604800));
        assert_eq!(CertificateProfile::parse_ttl("90d"), Some(7776000));
        assert_eq!(CertificateProfile::parse_ttl(""), None);
        assert_eq!(CertificateProfile::parse_ttl("abc"), None);
    }

    #[test]
    fn parse_ttl_days_rounds_up() {
        assert_eq!(CertificateProfile::parse_ttl_days("24h"), Some(1));
        assert_eq!(CertificateProfile::parse_ttl_days("25h"), Some(2));
        assert_eq!(CertificateProfile::parse_ttl_days("7d"), Some(7));
    }
}
