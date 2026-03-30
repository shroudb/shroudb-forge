//! CRL (Certificate Revocation List) generation using `rcgen`.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rcgen::{
    CertificateRevocationListParams, KeyPair, RevocationReason, RevokedCertParams, SerialNumber,
};

use crate::ca::CaAlgorithm;
use crate::error::ForgeError;

/// A revoked certificate entry for CRL generation.
pub struct CrlRevokedEntry {
    pub serial_hex: String,
    pub revoked_at: u64,
}

/// Generate a PEM-encoded CRL for the given CA.
pub fn generate_crl_pem(
    ca_key_der: &[u8],
    ca_subject: &str,
    ca_algorithm: CaAlgorithm,
    revoked_entries: &[CrlRevokedEntry],
) -> Result<String, ForgeError> {
    let sign_alg = match ca_algorithm {
        CaAlgorithm::EcdsaP256 => &rcgen::PKCS_ECDSA_P256_SHA256,
        CaAlgorithm::EcdsaP384 => &rcgen::PKCS_ECDSA_P384_SHA384,
        CaAlgorithm::Ed25519 => &rcgen::PKCS_ED25519,
    };

    let private_key_der = rustls_pki_types::PrivateKeyDer::try_from(ca_key_der.to_vec())
        .map_err(|e| ForgeError::X509Generation(format!("invalid CA key DER: {e}")))?;
    let ca_key_pair = KeyPair::from_der_and_sign_algo(&private_key_der, sign_alg)
        .map_err(|e| ForgeError::X509Generation(format!("failed to load CA key: {e}")))?;

    let mut ca_params = rcgen::CertificateParams::default();
    ca_params.distinguished_name = crate::x509::parse_subject(ca_subject);
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
        rcgen::KeyUsagePurpose::DigitalSignature,
    ];

    let ca_cert = ca_params
        .self_signed(&ca_key_pair)
        .map_err(|e| ForgeError::X509Generation(format!("CA cert reconstruction failed: {e}")))?;

    let mut revoked_params = Vec::with_capacity(revoked_entries.len());
    for entry in revoked_entries {
        let serial_bytes = hex::decode(&entry.serial_hex)
            .map_err(|e| ForgeError::X509Generation(format!("invalid serial hex: {e}")))?;

        let revocation_time = if entry.revoked_at == 0 {
            UNIX_EPOCH + Duration::from_secs(1)
        } else {
            UNIX_EPOCH + Duration::from_secs(entry.revoked_at)
        };

        revoked_params.push(RevokedCertParams {
            serial_number: SerialNumber::from_slice(&serial_bytes),
            revocation_time: revocation_time.into(),
            reason_code: Some(RevocationReason::Unspecified),
            invalidity_date: None,
        });
    }

    let now = SystemTime::now();
    let crl_params = CertificateRevocationListParams {
        this_update: now.into(),
        next_update: (now + Duration::from_secs(86400)).into(),
        crl_number: rcgen::SerialNumber::from_slice(&[1]),
        issuing_distribution_point: None,
        revoked_certs: revoked_params,
        key_identifier_method: rcgen::KeyIdMethod::Sha256,
    };

    let crl = crl_params
        .signed_by(&ca_cert, &ca_key_pair)
        .map_err(|e| ForgeError::X509Generation(format!("CRL signing failed: {e}")))?;

    crl.pem()
        .map_err(|e| ForgeError::X509Generation(format!("CRL PEM encoding failed: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_empty_crl() {
        let ca =
            crate::x509::generate_ca_certificate("CN=Test CA,O=Test", CaAlgorithm::EcdsaP256, 365)
                .unwrap();

        let crl_pem = generate_crl_pem(
            ca.private_key.as_bytes(),
            "CN=Test CA,O=Test",
            CaAlgorithm::EcdsaP256,
            &[],
        )
        .unwrap();

        assert!(crl_pem.contains("-----BEGIN X509 CRL-----"));
    }

    #[test]
    fn generate_crl_with_revoked() {
        let ca = crate::x509::generate_ca_certificate("CN=Test CA", CaAlgorithm::EcdsaP256, 365)
            .unwrap();

        let entries = vec![CrlRevokedEntry {
            serial_hex: "0102030405060708091011121314151617181920".into(),
            revoked_at: 1_700_000_000,
        }];

        let crl_pem = generate_crl_pem(
            ca.private_key.as_bytes(),
            "CN=Test CA",
            CaAlgorithm::EcdsaP256,
            &entries,
        )
        .unwrap();

        assert!(crl_pem.contains("-----BEGIN X509 CRL-----"));
    }
}
