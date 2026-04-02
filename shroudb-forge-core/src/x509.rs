//! X.509 certificate generation using `rcgen`.

use std::net::IpAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose, SanType,
};

use crate::ca::{CaAlgorithm, CaKeyVersion, decode_key_material};
use crate::cert::generate_serial;
use crate::error::ForgeError;
use crate::profile::{CertificateProfile, ExtendedKeyUsage, KeyUsage};

/// Result of generating a CA certificate and key pair.
pub struct GeneratedCa {
    /// PEM-encoded CA certificate.
    pub certificate_pem: String,
    /// Raw private key bytes (DER, to be hex-encoded before storing).
    pub private_key: shroudb_crypto::SecretBytes,
    /// Raw public key bytes (to be hex-encoded before storing).
    pub public_key: Vec<u8>,
}

/// Result of issuing an end-entity certificate.
pub struct IssuedCertResult {
    pub certificate_pem: String,
    /// PEM-encoded private key (returned to caller, never stored).
    pub private_key_pem: String,
    pub serial: String,
    pub not_before: u64,
    pub not_after: u64,
}

/// Generate a self-signed CA certificate.
pub fn generate_ca_certificate(
    subject: &str,
    algorithm: CaAlgorithm,
    ttl_days: u32,
) -> Result<GeneratedCa, ForgeError> {
    let key_pair = generate_key_pair(algorithm)?;

    let mut params = CertificateParams::default();
    params.distinguished_name = parse_subject(subject);
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];

    let serial = generate_serial()?;
    let serial_bytes =
        hex::decode(&serial).map_err(|e| ForgeError::X509Generation(e.to_string()))?;
    params.serial_number = Some(rcgen::SerialNumber::from_slice(&serial_bytes));

    let now = SystemTime::now();
    params.not_before = now.into();
    params.not_after = (now + Duration::from_secs(u64::from(ttl_days) * 86400)).into();

    let public_key = key_pair.public_key_raw().to_vec();

    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| ForgeError::X509Generation(e.to_string()))?;

    let private_key_der = key_pair.serialize_der();
    let private_key = shroudb_crypto::SecretBytes::new(private_key_der);

    Ok(GeneratedCa {
        certificate_pem: cert.pem(),
        private_key,
        public_key,
    })
}

/// Generate an intermediate CA certificate signed by a parent CA.
pub fn generate_intermediate_ca_certificate(
    subject: &str,
    algorithm: CaAlgorithm,
    ttl_days: u32,
    parent_key_version: &CaKeyVersion,
    parent_subject: &str,
    parent_algorithm: CaAlgorithm,
) -> Result<GeneratedCa, ForgeError> {
    let key_pair = generate_key_pair(algorithm)?;

    let mut params = CertificateParams::default();
    params.distinguished_name = parse_subject(subject);
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];

    let serial = generate_serial()?;
    let serial_bytes =
        hex::decode(&serial).map_err(|e| ForgeError::X509Generation(e.to_string()))?;
    params.serial_number = Some(rcgen::SerialNumber::from_slice(&serial_bytes));

    let now = SystemTime::now();
    params.not_before = now.into();
    params.not_after = (now + Duration::from_secs(u64::from(ttl_days) * 86400)).into();

    let public_key = key_pair.public_key_raw().to_vec();

    // Load parent's private key (hex-encoded) and reconstruct parent CA cert.
    let parent_key_der = decode_key_material(parent_key_version)?;

    let parent_sign_alg = sign_algorithm(parent_algorithm);
    let parent_private_key_der = rustls_pki_types::PrivateKeyDer::try_from(
        parent_key_der.as_bytes().to_vec(),
    )
    .map_err(|e| ForgeError::X509Generation(format!("invalid parent private key DER: {e}")))?;
    let parent_key_pair = KeyPair::from_der_and_sign_algo(&parent_private_key_der, parent_sign_alg)
        .map_err(|e| ForgeError::X509Generation(format!("failed to load parent key: {e}")))?;

    let parent_cert_params = reconstruct_ca_params(parent_subject)?;
    let parent_ca_cert = parent_cert_params
        .self_signed(&parent_key_pair)
        .map_err(|e| {
            ForgeError::X509Generation(format!("failed to reconstruct parent CA cert: {e}"))
        })?;

    let cert = params
        .signed_by(&key_pair, &parent_ca_cert, &parent_key_pair)
        .map_err(|e| ForgeError::X509Generation(e.to_string()))?;

    let private_key_der = key_pair.serialize_der();
    let private_key = shroudb_crypto::SecretBytes::new(private_key_der);

    Ok(GeneratedCa {
        certificate_pem: cert.pem(),
        private_key,
        public_key,
    })
}

/// Parameters for issuing an end-entity certificate.
pub struct IssueCertParams<'a> {
    pub ca_key_version: &'a CaKeyVersion,
    pub ca_subject: &'a str,
    pub ca_algorithm: CaAlgorithm,
    pub subject: &'a str,
    pub profile: &'a CertificateProfile,
    pub ttl_secs: u64,
    pub san_dns: &'a [String],
    pub san_ip: &'a [String],
}

/// Issue an end-entity certificate signed by the given CA key.
pub fn issue_certificate(params: &IssueCertParams<'_>) -> Result<IssuedCertResult, ForgeError> {
    let ca_key_der = decode_key_material(params.ca_key_version)?;

    let ca_sign_alg = sign_algorithm(params.ca_algorithm);
    let ca_private_key_der =
        rustls_pki_types::PrivateKeyDer::try_from(ca_key_der.as_bytes().to_vec())
            .map_err(|e| ForgeError::X509Generation(format!("invalid CA private key DER: {e}")))?;
    let ca_key_pair = KeyPair::from_der_and_sign_algo(&ca_private_key_der, ca_sign_alg)
        .map_err(|e| ForgeError::X509Generation(format!("failed to load CA key: {e}")))?;

    let ca_cert_params = reconstruct_ca_params(params.ca_subject)?;
    let ca_cert = ca_cert_params
        .self_signed(&ca_key_pair)
        .map_err(|e| ForgeError::X509Generation(format!("failed to reconstruct CA cert: {e}")))?;

    // Generate end-entity key pair (same algorithm as CA).
    let ee_key_pair = generate_key_pair(params.ca_algorithm)?;

    let mut cert_params = CertificateParams::default();

    // Apply subject (use template if configured).
    let effective_subject = if let Some(ref template) = params.profile.subject_template {
        template.replace("{}", params.subject)
    } else {
        params.subject.to_string()
    };
    cert_params.distinguished_name = parse_subject(&effective_subject);

    cert_params.is_ca = IsCa::NoCa;

    // Key usage
    cert_params.key_usages = params
        .profile
        .key_usage
        .iter()
        .map(|ku| match ku {
            KeyUsage::DigitalSignature => KeyUsagePurpose::DigitalSignature,
            KeyUsage::KeyEncipherment => KeyUsagePurpose::KeyEncipherment,
            KeyUsage::DataEncipherment => KeyUsagePurpose::DataEncipherment,
            KeyUsage::KeyAgreement => KeyUsagePurpose::KeyAgreement,
        })
        .collect();

    // Extended key usage
    cert_params.extended_key_usages = params
        .profile
        .extended_key_usage
        .iter()
        .map(|eku| match eku {
            ExtendedKeyUsage::ServerAuth => ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsage::ClientAuth => ExtendedKeyUsagePurpose::ClientAuth,
            ExtendedKeyUsage::CodeSigning => ExtendedKeyUsagePurpose::CodeSigning,
        })
        .collect();

    // SANs
    let mut sans = Vec::new();
    for dns in params.san_dns {
        sans.push(SanType::DnsName(dns.clone().try_into().map_err(|e| {
            ForgeError::X509Generation(format!("invalid DNS SAN '{dns}': {e}"))
        })?));
    }
    for ip in params.san_ip {
        let addr: IpAddr = ip
            .parse()
            .map_err(|e| ForgeError::X509Generation(format!("invalid IP SAN '{ip}': {e}")))?;
        sans.push(SanType::IpAddress(addr));
    }
    cert_params.subject_alt_names = sans;

    // Serial number
    let serial = generate_serial()?;
    let serial_bytes =
        hex::decode(&serial).map_err(|e| ForgeError::X509Generation(e.to_string()))?;
    cert_params.serial_number = Some(rcgen::SerialNumber::from_slice(&serial_bytes));

    // Validity
    let now = SystemTime::now();
    let now_unix = now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    cert_params.not_before = now.into();
    cert_params.not_after = (now + Duration::from_secs(params.ttl_secs)).into();

    let cert = cert_params
        .signed_by(&ee_key_pair, &ca_cert, &ca_key_pair)
        .map_err(|e| ForgeError::X509Generation(e.to_string()))?;

    Ok(IssuedCertResult {
        certificate_pem: cert.pem(),
        private_key_pem: ee_key_pair.serialize_pem(),
        serial,
        not_before: now_unix,
        not_after: now_unix + params.ttl_secs,
    })
}

/// Issue a certificate from a PEM-encoded CSR.
pub fn issue_from_csr(
    ca_key_version: &CaKeyVersion,
    ca_subject: &str,
    ca_algorithm: CaAlgorithm,
    csr_pem: &str,
    ttl_secs: u64,
) -> Result<IssuedCertResult, ForgeError> {
    let _csr_params = rcgen::CertificateSigningRequestParams::from_pem(csr_pem)
        .map_err(|e| ForgeError::CsrParsing(format!("CSR parse: {e}")))?;

    let ca_key_der = decode_key_material(ca_key_version)?;

    let ca_sign_alg = sign_algorithm(ca_algorithm);
    let ca_private_key_der =
        rustls_pki_types::PrivateKeyDer::try_from(ca_key_der.as_bytes().to_vec())
            .map_err(|e| ForgeError::X509Generation(format!("invalid CA private key DER: {e}")))?;
    let ca_key_pair = KeyPair::from_der_and_sign_algo(&ca_private_key_der, ca_sign_alg)
        .map_err(|e| ForgeError::X509Generation(format!("failed to load CA key: {e}")))?;

    let ca_cert_params = reconstruct_ca_params(ca_subject)?;
    let ca_cert = ca_cert_params
        .self_signed(&ca_key_pair)
        .map_err(|e| ForgeError::X509Generation(format!("failed to reconstruct CA cert: {e}")))?;

    let now = SystemTime::now();
    let now_unix = now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();

    let cert = _csr_params
        .signed_by(&ca_cert, &ca_key_pair)
        .map_err(|e| ForgeError::X509Generation(format!("CSR signing failed: {e}")))?;

    let serial = generate_serial()?;

    Ok(IssuedCertResult {
        certificate_pem: cert.pem(),
        private_key_pem: String::new(), // CSR: caller already has the private key
        serial,
        not_before: now_unix,
        not_after: now_unix + ttl_secs,
    })
}

fn sign_algorithm(algorithm: CaAlgorithm) -> &'static rcgen::SignatureAlgorithm {
    match algorithm {
        CaAlgorithm::EcdsaP256 => &rcgen::PKCS_ECDSA_P256_SHA256,
        CaAlgorithm::EcdsaP384 => &rcgen::PKCS_ECDSA_P384_SHA384,
        CaAlgorithm::Ed25519 => &rcgen::PKCS_ED25519,
    }
}

fn generate_key_pair(algorithm: CaAlgorithm) -> Result<KeyPair, ForgeError> {
    KeyPair::generate_for(sign_algorithm(algorithm))
        .map_err(|e| ForgeError::X509Generation(e.to_string()))
}

fn reconstruct_ca_params(subject: &str) -> Result<CertificateParams, ForgeError> {
    let mut params = CertificateParams::default();
    params.distinguished_name = parse_subject(subject);
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    Ok(params)
}

/// Parse a subject DN string like "CN=Test,O=ShrouDB" into rcgen's DistinguishedName.
pub fn parse_subject(subject: &str) -> DistinguishedName {
    let mut dn = DistinguishedName::new();
    for part in subject.split(',') {
        let part = part.trim();
        if let Some((key, value)) = part.split_once('=') {
            match key.trim().to_uppercase().as_str() {
                "CN" => dn.push(DnType::CommonName, value.trim()),
                "O" => dn.push(DnType::OrganizationName, value.trim()),
                "OU" => dn.push(DnType::OrganizationalUnitName, value.trim()),
                "C" => dn.push(DnType::CountryName, value.trim()),
                "ST" => dn.push(DnType::StateOrProvinceName, value.trim()),
                "L" => dn.push(DnType::LocalityName, value.trim()),
                _ => {
                    tracing::warn!(key = key, "ignoring unknown DN component");
                }
            }
        }
    }
    dn
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key_state::KeyState;

    #[test]
    fn generate_ca_ecdsa_p256() {
        let result = generate_ca_certificate("CN=Test CA,O=Test", CaAlgorithm::EcdsaP256, 365);
        assert!(result.is_ok());
        let ca = result.unwrap();
        assert!(
            ca.certificate_pem
                .starts_with("-----BEGIN CERTIFICATE-----")
        );
        assert!(!ca.private_key.as_bytes().is_empty());
        assert!(!ca.public_key.is_empty());
    }

    #[test]
    fn generate_ca_ed25519() {
        let result = generate_ca_certificate("CN=Ed25519 CA", CaAlgorithm::Ed25519, 365);
        assert!(result.is_ok());
    }

    #[test]
    fn issue_cert_with_sans() {
        let ca = generate_ca_certificate("CN=Test CA", CaAlgorithm::EcdsaP256, 365).unwrap();

        let ca_kv = CaKeyVersion {
            version: 1,
            state: KeyState::Active,
            key_material: Some(hex::encode(ca.private_key.as_bytes())),
            public_key: Some(hex::encode(&ca.public_key)),
            certificate_pem: ca.certificate_pem.clone(),
            created_at: 0,
            activated_at: Some(0),
            draining_since: None,
            retired_at: None,
        };

        let profile = CertificateProfile {
            name: "server".into(),
            key_usage: vec![KeyUsage::DigitalSignature, KeyUsage::KeyEncipherment],
            extended_key_usage: vec![ExtendedKeyUsage::ServerAuth],
            max_ttl_days: 90,
            default_ttl: "30d".into(),
            allow_san_dns: true,
            allow_san_ip: true,
            subject_template: None,
        };

        let result = issue_certificate(&IssueCertParams {
            ca_key_version: &ca_kv,
            ca_subject: "CN=Test CA",
            ca_algorithm: CaAlgorithm::EcdsaP256,
            subject: "CN=myservice",
            profile: &profile,
            ttl_secs: 86400,
            san_dns: &["myservice.local".into()],
            san_ip: &["127.0.0.1".into()],
        });
        assert!(result.is_ok());
        let issued = result.unwrap();
        assert!(
            issued
                .certificate_pem
                .starts_with("-----BEGIN CERTIFICATE-----")
        );
        assert!(
            issued
                .private_key_pem
                .starts_with("-----BEGIN PRIVATE KEY-----")
        );
        assert_eq!(issued.serial.len(), 40);
    }

    mod fuzz {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            // Arbitrary strings must never panic parse_subject.
            #[test]
            fn parse_subject_never_panics(s in "\\PC*") {
                let _ = parse_subject(&s);
            }

            // A well-formed "CN=<value>" input always produces a non-empty DistinguishedName.
            #[test]
            fn valid_dn_roundtrip(cn in "[a-zA-Z0-9 ]{1,64}") {
                let input = format!("CN={cn}");
                let dn = parse_subject(&input);
                // DistinguishedName doesn't expose a len/is_empty, but its Debug
                // output will contain the CN value if it was parsed correctly.
                let debug = format!("{dn:?}");
                assert!(debug.contains(&cn.trim().to_string()),
                    "DistinguishedName should contain the CN value");
            }
        }
    }

    #[test]
    fn generate_intermediate_ca() {
        let root =
            generate_ca_certificate("CN=Root CA,O=Test", CaAlgorithm::EcdsaP256, 3650).unwrap();

        let root_kv = CaKeyVersion {
            version: 1,
            state: KeyState::Active,
            key_material: Some(hex::encode(root.private_key.as_bytes())),
            public_key: Some(hex::encode(&root.public_key)),
            certificate_pem: root.certificate_pem.clone(),
            created_at: 0,
            activated_at: Some(0),
            draining_since: None,
            retired_at: None,
        };

        let intermediate = generate_intermediate_ca_certificate(
            "CN=Intermediate CA,O=Test",
            CaAlgorithm::EcdsaP256,
            365,
            &root_kv,
            "CN=Root CA,O=Test",
            CaAlgorithm::EcdsaP256,
        );
        assert!(intermediate.is_ok());
        let inter = intermediate.unwrap();
        assert!(
            inter
                .certificate_pem
                .starts_with("-----BEGIN CERTIFICATE-----")
        );
    }
}
