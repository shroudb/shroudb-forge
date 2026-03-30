//! Minimal OCSP responder (RFC 6960).
//!
//! Parses DER-encoded `OCSPRequest` messages, looks up certificate status,
//! and builds DER-encoded `OCSPResponse` messages signed by the CA key.
//!
//! Rather than pulling in the full `x509-ocsp` / `der` 0.8 / `x509-cert`
//! dependency tree (which conflicts with the workspace's `der` 0.7), this
//! module hand-encodes the small subset of ASN.1 structures needed for OCSP.

use ring::digest::{self, SHA1_FOR_LEGACY_USE_ONLY, SHA256};
use ring::rand::SystemRandom;
use ring::signature::{self, EcdsaKeyPair, Ed25519KeyPair};

use crate::ca::CaAlgorithm;
use crate::error::ForgeError;

// ---------------------------------------------------------------------------
// ASN.1 DER encoding helpers
// ---------------------------------------------------------------------------

/// Encode a DER tag + length + value.
fn der_tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    der_encode_length(value.len(), &mut out);
    out.extend_from_slice(value);
    out
}

/// Encode ASN.1 length in DER format (short or long form).
fn der_encode_length(len: usize, out: &mut Vec<u8>) {
    if len < 0x80 {
        out.push(len as u8);
    } else if len <= 0xFF {
        out.push(0x81);
        out.push(len as u8);
    } else if len <= 0xFFFF {
        out.push(0x82);
        out.push((len >> 8) as u8);
        out.push(len as u8);
    } else if len <= 0xFF_FFFF {
        out.push(0x83);
        out.push((len >> 16) as u8);
        out.push((len >> 8) as u8);
        out.push(len as u8);
    } else {
        out.push(0x84);
        out.push((len >> 24) as u8);
        out.push((len >> 16) as u8);
        out.push((len >> 8) as u8);
        out.push(len as u8);
    }
}

/// SEQUENCE (constructed, tag 0x30).
fn der_sequence(contents: &[u8]) -> Vec<u8> {
    der_tlv(0x30, contents)
}

/// OCTET STRING (tag 0x04).
fn der_octet_string(value: &[u8]) -> Vec<u8> {
    der_tlv(0x04, value)
}

/// INTEGER (tag 0x02). Ensures a leading 0x00 if the high bit is set (positive).
fn der_integer(value: &[u8]) -> Vec<u8> {
    if value.is_empty() {
        return der_tlv(0x02, &[0x00]);
    }
    if value[0] & 0x80 != 0 {
        let mut padded = vec![0x00];
        padded.extend_from_slice(value);
        der_tlv(0x02, &padded)
    } else {
        // Strip leading zeros but keep at least one byte.
        let start = value
            .iter()
            .position(|&b| b != 0)
            .unwrap_or(value.len() - 1);
        let stripped = &value[start..];
        if stripped[0] & 0x80 != 0 {
            let mut padded = vec![0x00];
            padded.extend_from_slice(stripped);
            der_tlv(0x02, &padded)
        } else {
            der_tlv(0x02, stripped)
        }
    }
}

/// BIT STRING (tag 0x03). Wraps `value` with a leading 0x00 (no unused bits).
fn der_bit_string(value: &[u8]) -> Vec<u8> {
    let mut inner = vec![0x00]; // unused-bits byte
    inner.extend_from_slice(value);
    der_tlv(0x03, &inner)
}

/// NULL (tag 0x05).
fn der_null() -> Vec<u8> {
    vec![0x05, 0x00]
}

/// OID (tag 0x06).
fn der_oid(encoded: &[u8]) -> Vec<u8> {
    der_tlv(0x06, encoded)
}

/// ENUMERATED (tag 0x0A).
fn der_enumerated(value: u8) -> Vec<u8> {
    der_tlv(0x0A, &[value])
}

/// GeneralizedTime (tag 0x18).
fn der_generalized_time(unix_secs: u64) -> Vec<u8> {
    let secs = unix_secs;
    // Convert to calendar date (basic Gregorian — sufficient for OCSP).
    let (year, month, day, hour, min, sec) = unix_to_calendar(secs);
    let s = format!("{year:04}{month:02}{day:02}{hour:02}{min:02}{sec:02}Z");
    der_tlv(0x18, s.as_bytes())
}

/// Context-specific explicit tag [n] CONSTRUCTED.
fn der_explicit(tag_num: u8, inner: &[u8]) -> Vec<u8> {
    der_tlv(0xA0 | tag_num, inner)
}

// ---------------------------------------------------------------------------
// OID constants
// ---------------------------------------------------------------------------

// id-sha1 (1.3.14.3.2.26)
const OID_SHA1: &[u8] = &[0x2B, 0x0E, 0x03, 0x02, 0x1A];

// id-sha256 (2.16.840.1.101.3.4.2.1)
const OID_SHA256: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];

// id-pkix-ocsp-basic (1.3.6.1.5.5.7.48.1.1)
const OID_OCSP_BASIC: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01];

// ecdsa-with-SHA256 (1.2.840.10045.4.3.2)
const OID_ECDSA_SHA256: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02];

// ecdsa-with-SHA384 (1.2.840.10045.4.3.3)
const OID_ECDSA_SHA384: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03];

// id-EdDSA ed25519 (1.3.101.112)
const OID_ED25519: &[u8] = &[0x2B, 0x65, 0x70];

// ---------------------------------------------------------------------------
// OCSP request parsing
// ---------------------------------------------------------------------------

/// Parsed fields from an OCSP request that we need to generate a response.
#[derive(Debug, Clone)]
pub struct OcspRequestInfo {
    /// The hash algorithm OID used for issuerNameHash/issuerKeyHash.
    pub hash_algorithm_oid: Vec<u8>,
    /// Hash of the issuer's distinguished name.
    pub issuer_name_hash: Vec<u8>,
    /// Hash of the issuer's public key.
    pub issuer_key_hash: Vec<u8>,
    /// Serial number of the certificate being queried (raw bytes, not hex).
    pub serial_number: Vec<u8>,
}

/// Decoded DER tag-length-value.
struct Tlv<'a> {
    tag: u8,
    value: &'a [u8],
    total_len: usize,
}

/// Parse a single TLV from a DER byte slice.
fn parse_tlv(data: &[u8]) -> Result<Tlv<'_>, ForgeError> {
    if data.is_empty() {
        return Err(ForgeError::OcspRequest("empty TLV".into()));
    }
    let tag = data[0];
    if data.len() < 2 {
        return Err(ForgeError::OcspRequest("truncated TLV".into()));
    }
    let (length, hdr_len) = parse_der_length(&data[1..])?;
    let total_hdr = 1 + hdr_len;
    if data.len() < total_hdr + length {
        return Err(ForgeError::OcspRequest(format!(
            "TLV length {length} exceeds available data {}",
            data.len() - total_hdr
        )));
    }
    Ok(Tlv {
        tag,
        value: &data[total_hdr..total_hdr + length],
        total_len: total_hdr + length,
    })
}

/// Parse DER length encoding, returning (length, bytes consumed).
fn parse_der_length(data: &[u8]) -> Result<(usize, usize), ForgeError> {
    if data.is_empty() {
        return Err(ForgeError::OcspRequest("truncated length".into()));
    }
    let first = data[0];
    if first < 0x80 {
        Ok((first as usize, 1))
    } else {
        let num_bytes = (first & 0x7F) as usize;
        if num_bytes == 0 || num_bytes > 4 {
            return Err(ForgeError::OcspRequest(format!(
                "unsupported length encoding: {num_bytes} bytes"
            )));
        }
        if data.len() < 1 + num_bytes {
            return Err(ForgeError::OcspRequest("truncated length bytes".into()));
        }
        let mut length = 0usize;
        for i in 0..num_bytes {
            length = (length << 8) | data[1 + i] as usize;
        }
        Ok((length, 1 + num_bytes))
    }
}

/// Parse an OCSP request (DER-encoded) and extract the first CertID.
///
/// OCSPRequest ::= SEQUENCE {
///     tbsRequest  TBSRequest
/// }
/// TBSRequest ::= SEQUENCE {
///     version        [0] EXPLICIT Version DEFAULT v1,
///     requestorName  [1] EXPLICIT GeneralName OPTIONAL,
///     requestList    SEQUENCE OF Request
/// }
/// Request ::= SEQUENCE {
///     reqCert  CertID
/// }
/// CertID ::= SEQUENCE {
///     hashAlgorithm  AlgorithmIdentifier,
///     issuerNameHash OCTET STRING,
///     issuerKeyHash  OCTET STRING,
///     serialNumber   CertificateSerialNumber (INTEGER)
/// }
pub fn parse_ocsp_request(der: &[u8]) -> Result<OcspRequestInfo, ForgeError> {
    // OCSPRequest is a SEQUENCE.
    let outer = parse_tlv(der)?;
    if outer.tag != 0x30 {
        return Err(ForgeError::OcspRequest(format!(
            "expected SEQUENCE, got tag 0x{:02X}",
            outer.tag
        )));
    }

    // TBSRequest is a SEQUENCE.
    let tbs = parse_tlv(outer.value)?;
    if tbs.tag != 0x30 {
        return Err(ForgeError::OcspRequest(
            "expected TBSRequest SEQUENCE".into(),
        ));
    }

    // Skip optional version [0] and requestorName [1].
    let mut pos = 0;
    let tbs_data = tbs.value;
    while pos < tbs_data.len() {
        let t = parse_tlv(&tbs_data[pos..])?;
        if t.tag == 0x30 {
            // This should be requestList (SEQUENCE OF Request).
            return parse_request_list(t.value);
        }
        // Skip context-tagged optional fields.
        pos += t.total_len;
    }

    Err(ForgeError::OcspRequest(
        "requestList not found in TBSRequest".into(),
    ))
}

/// Parse the requestList and extract the first CertID.
fn parse_request_list(data: &[u8]) -> Result<OcspRequestInfo, ForgeError> {
    // First element is a Request SEQUENCE.
    let request = parse_tlv(data)?;
    if request.tag != 0x30 {
        return Err(ForgeError::OcspRequest(
            "expected Request SEQUENCE in requestList".into(),
        ));
    }

    // The Request contains reqCert (CertID SEQUENCE).
    let cert_id = parse_tlv(request.value)?;
    if cert_id.tag != 0x30 {
        return Err(ForgeError::OcspRequest("expected CertID SEQUENCE".into()));
    }

    parse_cert_id(cert_id.value)
}

/// Parse a CertID SEQUENCE.
fn parse_cert_id(data: &[u8]) -> Result<OcspRequestInfo, ForgeError> {
    let mut pos = 0;

    // 1. hashAlgorithm (AlgorithmIdentifier SEQUENCE)
    let alg_id = parse_tlv(&data[pos..])?;
    if alg_id.tag != 0x30 {
        return Err(ForgeError::OcspRequest(
            "expected AlgorithmIdentifier SEQUENCE".into(),
        ));
    }
    let oid_tlv = parse_tlv(alg_id.value)?;
    if oid_tlv.tag != 0x06 {
        return Err(ForgeError::OcspRequest(
            "expected OID in AlgorithmIdentifier".into(),
        ));
    }
    let hash_algorithm_oid = oid_tlv.value.to_vec();
    pos += alg_id.total_len;

    // 2. issuerNameHash (OCTET STRING)
    let name_hash = parse_tlv(&data[pos..])?;
    if name_hash.tag != 0x04 {
        return Err(ForgeError::OcspRequest(
            "expected OCTET STRING for issuerNameHash".into(),
        ));
    }
    pos += name_hash.total_len;

    // 3. issuerKeyHash (OCTET STRING)
    let key_hash = parse_tlv(&data[pos..])?;
    if key_hash.tag != 0x04 {
        return Err(ForgeError::OcspRequest(
            "expected OCTET STRING for issuerKeyHash".into(),
        ));
    }
    pos += key_hash.total_len;

    // 4. serialNumber (INTEGER)
    let serial = parse_tlv(&data[pos..])?;
    if serial.tag != 0x02 {
        return Err(ForgeError::OcspRequest(
            "expected INTEGER for serialNumber".into(),
        ));
    }

    Ok(OcspRequestInfo {
        hash_algorithm_oid,
        issuer_name_hash: name_hash.value.to_vec(),
        issuer_key_hash: key_hash.value.to_vec(),
        serial_number: serial.value.to_vec(),
    })
}

// ---------------------------------------------------------------------------
// OCSP response building
// ---------------------------------------------------------------------------

/// Certificate status for an OCSP response.
#[derive(Debug, Clone)]
pub enum OcspCertStatus {
    /// Certificate is good (not revoked).
    Good,
    /// Certificate has been revoked.
    Revoked {
        /// Unix timestamp of revocation.
        revoked_at: u64,
    },
    /// Certificate status is unknown (not issued by this CA).
    Unknown,
}

/// Parameters needed to build and sign an OCSP response.
pub struct OcspResponseParams<'a> {
    /// The original request info (CertID fields echoed back).
    pub request: &'a OcspRequestInfo,
    /// Certificate status.
    pub status: OcspCertStatus,
    /// CA signing algorithm.
    pub algorithm: CaAlgorithm,
    /// CA private key in PKCS#8 DER format.
    pub ca_key_der: &'a [u8],
    /// DER-encoded issuer Name (from CA certificate).
    pub responder_name_der: &'a [u8],
    /// Current time (Unix seconds) for thisUpdate / producedAt.
    pub now: u64,
}

/// Build a DER-encoded OCSPResponse.
///
/// OCSPResponse ::= SEQUENCE {
///     responseStatus  OCSPResponseStatus (ENUMERATED),
///     responseBytes   [0] EXPLICIT ResponseBytes OPTIONAL
/// }
/// ResponseBytes ::= SEQUENCE {
///     responseType  OID (id-pkix-ocsp-basic),
///     response      OCTET STRING (contains BasicOCSPResponse DER)
/// }
pub fn build_ocsp_response(params: &OcspResponseParams<'_>) -> Result<Vec<u8>, ForgeError> {
    let basic_response = build_basic_ocsp_response(params)?;

    // ResponseBytes
    let response_bytes_inner =
        [der_oid(OID_OCSP_BASIC), der_octet_string(&basic_response)].concat();
    let response_bytes = der_sequence(&response_bytes_inner);

    // OCSPResponse: successful(0) + [0] responseBytes
    let ocsp_response_inner = [
        der_enumerated(0), // successful
        der_explicit(0, &response_bytes),
    ]
    .concat();

    Ok(der_sequence(&ocsp_response_inner))
}

/// Build the internal unauthorized response (when we don't recognize the CA).
pub fn build_ocsp_unauthorized_response() -> Vec<u8> {
    // OCSPResponseStatus: unauthorized(6)
    der_sequence(&der_enumerated(6))
}

/// Build the internal error response (malformed request, etc.).
pub fn build_ocsp_malformed_request_response() -> Vec<u8> {
    // OCSPResponseStatus: malformedRequest(1)
    der_sequence(&der_enumerated(1))
}

/// Build a BasicOCSPResponse.
///
/// BasicOCSPResponse ::= SEQUENCE {
///     tbsResponseData   ResponseData,
///     signatureAlgorithm AlgorithmIdentifier,
///     signature          BIT STRING,
///     certs              [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL
/// }
fn build_basic_ocsp_response(params: &OcspResponseParams<'_>) -> Result<Vec<u8>, ForgeError> {
    let tbs_response_data = build_response_data(params);

    // Sign the tbsResponseData.
    let (signature_bytes, sig_alg_der) =
        sign_response_data(&tbs_response_data, params.algorithm, params.ca_key_der)?;

    let basic_inner = [
        tbs_response_data,
        sig_alg_der,
        der_bit_string(&signature_bytes),
    ]
    .concat();

    Ok(der_sequence(&basic_inner))
}

/// Build the ResponseData (the tbsResponseData that gets signed).
///
/// ResponseData ::= SEQUENCE {
///     version           [0] EXPLICIT Version DEFAULT v1,
///     responderID       ResponderID,
///     producedAt        GeneralizedTime,
///     responses         SEQUENCE OF SingleResponse
/// }
/// ResponderID ::= CHOICE {
///     byName   [1] Name,
///     byKey    [2] KeyHash
/// }
fn build_response_data(params: &OcspResponseParams<'_>) -> Vec<u8> {
    // responderID byName [1] EXPLICIT — use the CA's issuer Name DER.
    let responder_id = der_explicit(1, params.responder_name_der);

    // producedAt
    let produced_at = der_generalized_time(params.now);

    // Single response
    let single_response = build_single_response(params);
    let responses = der_sequence(&single_response);

    let inner = [responder_id, produced_at, responses].concat();
    der_sequence(&inner)
}

/// Build a SingleResponse.
///
/// SingleResponse ::= SEQUENCE {
///     certID      CertID,
///     certStatus  CertStatus,
///     thisUpdate  GeneralizedTime,
///     nextUpdate  [0] EXPLICIT GeneralizedTime OPTIONAL
/// }
/// CertStatus ::= CHOICE {
///     good    [0] IMPLICIT NULL,
///     revoked [1] IMPLICIT RevokedInfo,
///     unknown [2] IMPLICIT NULL
/// }
/// RevokedInfo ::= SEQUENCE {
///     revocationTime  GeneralizedTime,
///     revocationReason [0] EXPLICIT CRLReason OPTIONAL
/// }
fn build_single_response(params: &OcspResponseParams<'_>) -> Vec<u8> {
    let cert_id = build_cert_id(params.request);

    let cert_status = match &params.status {
        OcspCertStatus::Good => {
            // [0] IMPLICIT NULL — tag 0x80, length 0
            vec![0x80, 0x00]
        }
        OcspCertStatus::Revoked { revoked_at } => {
            // [1] IMPLICIT RevokedInfo (constructed)
            let revocation_time = der_generalized_time(*revoked_at);
            der_tlv(0xA1, &revocation_time)
        }
        OcspCertStatus::Unknown => {
            // [2] IMPLICIT NULL — tag 0x82, length 0
            vec![0x82, 0x00]
        }
    };

    let this_update = der_generalized_time(params.now);

    // nextUpdate: now + 1 hour
    let next_update_time = der_generalized_time(params.now + 3600);
    let next_update = der_explicit(0, &next_update_time);

    let inner = [cert_id, cert_status, this_update, next_update].concat();
    der_sequence(&inner)
}

/// Build a CertID that echoes the request's CertID fields.
fn build_cert_id(req: &OcspRequestInfo) -> Vec<u8> {
    // AlgorithmIdentifier
    let alg_inner = [der_oid(&req.hash_algorithm_oid), der_null()].concat();
    let alg_id = der_sequence(&alg_inner);

    let inner = [
        alg_id,
        der_octet_string(&req.issuer_name_hash),
        der_octet_string(&req.issuer_key_hash),
        der_integer(&req.serial_number),
    ]
    .concat();

    der_sequence(&inner)
}

/// Sign the tbsResponseData DER and return (signature_bytes, AlgorithmIdentifier DER).
fn sign_response_data(
    tbs_der: &[u8],
    algorithm: CaAlgorithm,
    ca_key_der: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), ForgeError> {
    let rng = SystemRandom::new();

    match algorithm {
        CaAlgorithm::EcdsaP256 => {
            let key = EcdsaKeyPair::from_pkcs8(
                &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
                ca_key_der,
                &rng,
            )
            .map_err(|e| ForgeError::OcspResponse(format!("P256 key load: {e}")))?;

            let sig = key
                .sign(&rng, tbs_der)
                .map_err(|e| ForgeError::OcspResponse(format!("P256 sign: {e}")))?;

            let alg_id = der_sequence(&der_oid(OID_ECDSA_SHA256));
            Ok((sig.as_ref().to_vec(), alg_id))
        }
        CaAlgorithm::EcdsaP384 => {
            let key = EcdsaKeyPair::from_pkcs8(
                &signature::ECDSA_P384_SHA384_ASN1_SIGNING,
                ca_key_der,
                &rng,
            )
            .map_err(|e| ForgeError::OcspResponse(format!("P384 key load: {e}")))?;

            let sig = key
                .sign(&rng, tbs_der)
                .map_err(|e| ForgeError::OcspResponse(format!("P384 sign: {e}")))?;

            let alg_id = der_sequence(&der_oid(OID_ECDSA_SHA384));
            Ok((sig.as_ref().to_vec(), alg_id))
        }
        CaAlgorithm::Ed25519 => {
            let key = Ed25519KeyPair::from_pkcs8(ca_key_der)
                .map_err(|e| ForgeError::OcspResponse(format!("Ed25519 key load: {e}")))?;

            let sig = key.sign(tbs_der);

            let alg_id = der_sequence(&der_oid(OID_ED25519));
            Ok((sig.as_ref().to_vec(), alg_id))
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers for matching issuer identity
// ---------------------------------------------------------------------------

/// Compute the issuerNameHash for a given DER-encoded issuer Name,
/// using the hash algorithm from the OCSP request.
pub fn compute_issuer_name_hash(hash_oid: &[u8], issuer_name_der: &[u8]) -> Vec<u8> {
    hash_with_oid(hash_oid, issuer_name_der)
}

/// Compute the issuerKeyHash for a given raw public key bytes,
/// using the hash algorithm from the OCSP request.
pub fn compute_issuer_key_hash(hash_oid: &[u8], public_key_raw: &[u8]) -> Vec<u8> {
    hash_with_oid(hash_oid, public_key_raw)
}

/// Hash data with the algorithm identified by the given OID.
fn hash_with_oid(hash_oid: &[u8], data: &[u8]) -> Vec<u8> {
    if hash_oid == OID_SHA1 {
        digest::digest(&SHA1_FOR_LEGACY_USE_ONLY, data)
            .as_ref()
            .to_vec()
    } else if hash_oid == OID_SHA256 {
        digest::digest(&SHA256, data).as_ref().to_vec()
    } else {
        // Default to SHA-256 for unknown algorithms — conservative fallback.
        digest::digest(&SHA256, data).as_ref().to_vec()
    }
}

/// Convert a hex-encoded serial string to raw bytes (stripping leading zeros
/// but preserving at least one byte).
pub fn serial_hex_to_bytes(hex_serial: &str) -> Result<Vec<u8>, ForgeError> {
    let bytes = hex::decode(hex_serial)
        .map_err(|e| ForgeError::OcspRequest(format!("bad serial hex: {e}")))?;
    Ok(bytes)
}

/// Convert raw serial bytes to hex string (for store lookup).
pub fn serial_bytes_to_hex(bytes: &[u8]) -> String {
    // Strip leading zero bytes that are just ASN.1 sign-padding.
    let stripped = match bytes.iter().position(|&b| b != 0) {
        Some(pos) => &bytes[pos..],
        None => &bytes[bytes.len().saturating_sub(1)..],
    };
    hex::encode(stripped)
}

/// Extract the DER-encoded issuer Name from a PEM-encoded CA certificate.
///
/// The issuer Name is the subject field of the CA certificate. We parse just
/// enough of the X.509 structure to pull it out.
pub fn extract_issuer_name_der(ca_cert_pem: &str) -> Result<Vec<u8>, ForgeError> {
    let pem_block = pem::parse(ca_cert_pem)
        .map_err(|e| ForgeError::OcspRequest(format!("CA cert PEM parse: {e}")))?;
    let cert_der = pem_block.contents();
    extract_subject_from_cert_der(cert_der)
}

/// Extract the subject Name DER from a DER-encoded X.509 certificate.
///
/// Certificate ::= SEQUENCE {
///     tbsCertificate  SEQUENCE {
///         version      [0] EXPLICIT INTEGER OPTIONAL,
///         serialNumber INTEGER,
///         signature    AlgorithmIdentifier,
///         issuer       Name,
///         validity     SEQUENCE,
///         subject      Name,            <-- we want this
///         ...
///     },
///     ...
/// }
fn extract_subject_from_cert_der(cert_der: &[u8]) -> Result<Vec<u8>, ForgeError> {
    let cert_seq = parse_tlv(cert_der)?;
    if cert_seq.tag != 0x30 {
        return Err(ForgeError::OcspRequest("cert: expected SEQUENCE".into()));
    }

    // tbsCertificate
    let tbs = parse_tlv(cert_seq.value)?;
    if tbs.tag != 0x30 {
        return Err(ForgeError::OcspRequest(
            "cert: expected tbsCertificate SEQUENCE".into(),
        ));
    }

    let mut pos = 0;
    let data = tbs.value;

    // version [0] EXPLICIT INTEGER (optional, skip if present)
    if pos < data.len() && data[pos] == 0xA0 {
        let v = parse_tlv(&data[pos..])?;
        pos += v.total_len;
    }

    // serialNumber INTEGER (skip)
    let serial = parse_tlv(&data[pos..])?;
    pos += serial.total_len;

    // signature AlgorithmIdentifier SEQUENCE (skip)
    let sig_alg = parse_tlv(&data[pos..])?;
    pos += sig_alg.total_len;

    // issuer Name (skip)
    let issuer = parse_tlv(&data[pos..])?;
    pos += issuer.total_len;

    // validity SEQUENCE (skip)
    let validity = parse_tlv(&data[pos..])?;
    pos += validity.total_len;

    // subject Name — this is what we want
    let subject = parse_tlv(&data[pos..])?;
    // Return the full TLV (tag + length + value) as the DER encoding.
    Ok(data[pos..pos + subject.total_len].to_vec())
}

// ---------------------------------------------------------------------------
// Calendar conversion (no chrono dependency)
// ---------------------------------------------------------------------------

fn unix_to_calendar(secs: u64) -> (u32, u32, u32, u32, u32, u32) {
    // Algorithm from https://howardhinnant.github.io/date_algorithms.html
    let s = secs;
    let z = (s / 86400) as i64 + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };

    let day_secs = secs % 86400;
    let hour = day_secs / 3600;
    let minute = (day_secs % 3600) / 60;
    let second = day_secs % 60;

    (
        y as u32,
        m as u32,
        d as u32,
        hour as u32,
        minute as u32,
        second as u32,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ca::CaAlgorithm;
    use crate::x509::generate_ca_certificate;

    #[test]
    fn der_integer_positive() {
        let i = der_integer(&[0x01, 0x02]);
        assert_eq!(i, vec![0x02, 0x02, 0x01, 0x02]);
    }

    #[test]
    fn der_integer_high_bit_padded() {
        let i = der_integer(&[0xFF]);
        assert_eq!(i, vec![0x02, 0x02, 0x00, 0xFF]);
    }

    #[test]
    fn der_integer_zero() {
        let i = der_integer(&[0x00]);
        assert_eq!(i, vec![0x02, 0x01, 0x00]);
    }

    #[test]
    fn unix_to_calendar_epoch() {
        let (y, m, d, h, min, s) = unix_to_calendar(0);
        assert_eq!((y, m, d, h, min, s), (1970, 1, 1, 0, 0, 0));
    }

    #[test]
    fn unix_to_calendar_known_date() {
        // 2024-01-15 12:30:45 UTC = 1705321845
        let (y, m, d, h, min, s) = unix_to_calendar(1_705_321_845);
        assert_eq!((y, m, d, h, min, s), (2024, 1, 15, 12, 30, 45));
    }

    #[test]
    fn generalized_time_format() {
        let gt = der_generalized_time(1_705_321_845);
        // Should be "20240115123045Z" in GeneralizedTime DER
        let expected_str = b"20240115123045Z";
        assert_eq!(gt[0], 0x18); // GeneralizedTime tag
        assert_eq!(gt[1], expected_str.len() as u8);
        assert_eq!(&gt[2..], expected_str);
    }

    #[test]
    fn serial_round_trip() {
        let hex = "0102030405060708091011121314151617181920";
        let bytes = serial_hex_to_bytes(hex).unwrap();
        let back = serial_bytes_to_hex(&bytes);
        assert_eq!(back, hex);
    }

    #[test]
    fn serial_bytes_to_hex_strips_leading_zero() {
        // ASN.1 INTEGER with leading 0x00 for sign
        let bytes = vec![0x00, 0x01, 0x02];
        assert_eq!(serial_bytes_to_hex(&bytes), "0102");
    }

    #[test]
    fn extract_subject_from_ca_cert() {
        let ca =
            generate_ca_certificate("CN=Test OCSP CA,O=Test", CaAlgorithm::EcdsaP256, 365).unwrap();
        let subject_der = extract_issuer_name_der(&ca.certificate_pem).unwrap();
        // Should be a SEQUENCE (0x30) containing the DN components.
        assert_eq!(subject_der[0], 0x30);
        assert!(!subject_der.is_empty());
    }

    #[test]
    fn build_good_response() {
        let ca =
            generate_ca_certificate("CN=Test OCSP CA,O=Test", CaAlgorithm::EcdsaP256, 365).unwrap();
        let subject_der = extract_issuer_name_der(&ca.certificate_pem).unwrap();

        let req = OcspRequestInfo {
            hash_algorithm_oid: OID_SHA1.to_vec(),
            issuer_name_hash: vec![0; 20],
            issuer_key_hash: vec![0; 20],
            serial_number: vec![0x01, 0x02, 0x03],
        };

        let params = OcspResponseParams {
            request: &req,
            status: OcspCertStatus::Good,
            algorithm: CaAlgorithm::EcdsaP256,
            ca_key_der: ca.private_key.as_bytes(),
            responder_name_der: &subject_der,
            now: 1_705_321_845,
        };

        let response = build_ocsp_response(&params).unwrap();
        // Should be a valid DER SEQUENCE.
        assert_eq!(response[0], 0x30);
        // Parse the outer SEQUENCE and check the first element is ENUMERATED 0.
        let outer = parse_tlv(&response).unwrap();
        let inner = parse_tlv(outer.value).unwrap();
        assert_eq!(inner.tag, 0x0A); // ENUMERATED
        assert_eq!(inner.value, &[0x00]); // successful
    }

    #[test]
    fn build_revoked_response() {
        let ca =
            generate_ca_certificate("CN=Test OCSP CA,O=Test", CaAlgorithm::EcdsaP256, 365).unwrap();
        let subject_der = extract_issuer_name_der(&ca.certificate_pem).unwrap();

        let req = OcspRequestInfo {
            hash_algorithm_oid: OID_SHA1.to_vec(),
            issuer_name_hash: vec![0; 20],
            issuer_key_hash: vec![0; 20],
            serial_number: vec![0x01],
        };

        let params = OcspResponseParams {
            request: &req,
            status: OcspCertStatus::Revoked {
                revoked_at: 1_700_000_000,
            },
            algorithm: CaAlgorithm::EcdsaP256,
            ca_key_der: ca.private_key.as_bytes(),
            responder_name_der: &subject_der,
            now: 1_705_321_845,
        };

        let response = build_ocsp_response(&params).unwrap();
        assert_eq!(response[0], 0x30);
    }

    #[test]
    fn build_unknown_response() {
        let ca =
            generate_ca_certificate("CN=Test OCSP CA,O=Test", CaAlgorithm::EcdsaP256, 365).unwrap();
        let subject_der = extract_issuer_name_der(&ca.certificate_pem).unwrap();

        let req = OcspRequestInfo {
            hash_algorithm_oid: OID_SHA256.to_vec(),
            issuer_name_hash: vec![0; 32],
            issuer_key_hash: vec![0; 32],
            serial_number: vec![0xFF],
        };

        let params = OcspResponseParams {
            request: &req,
            status: OcspCertStatus::Unknown,
            algorithm: CaAlgorithm::EcdsaP256,
            ca_key_der: ca.private_key.as_bytes(),
            responder_name_der: &subject_der,
            now: 1_705_321_845,
        };

        let response = build_ocsp_response(&params).unwrap();
        assert_eq!(response[0], 0x30);
    }

    #[test]
    fn malformed_request_response() {
        let response = build_ocsp_malformed_request_response();
        let outer = parse_tlv(&response).unwrap();
        assert_eq!(outer.tag, 0x30);
        let inner = parse_tlv(outer.value).unwrap();
        assert_eq!(inner.tag, 0x0A); // ENUMERATED
        assert_eq!(inner.value, &[0x01]); // malformedRequest
    }

    #[test]
    fn unauthorized_response() {
        let response = build_ocsp_unauthorized_response();
        let outer = parse_tlv(&response).unwrap();
        assert_eq!(outer.tag, 0x30);
        let inner = parse_tlv(outer.value).unwrap();
        assert_eq!(inner.tag, 0x0A); // ENUMERATED
        assert_eq!(inner.value, &[0x06]); // unauthorized
    }

    #[test]
    fn build_response_ed25519() {
        let ca = generate_ca_certificate("CN=Ed25519 OCSP CA", CaAlgorithm::Ed25519, 365).unwrap();
        let subject_der = extract_issuer_name_der(&ca.certificate_pem).unwrap();

        let req = OcspRequestInfo {
            hash_algorithm_oid: OID_SHA256.to_vec(),
            issuer_name_hash: vec![0; 32],
            issuer_key_hash: vec![0; 32],
            serial_number: vec![0x42],
        };

        let params = OcspResponseParams {
            request: &req,
            status: OcspCertStatus::Good,
            algorithm: CaAlgorithm::Ed25519,
            ca_key_der: ca.private_key.as_bytes(),
            responder_name_der: &subject_der,
            now: 1_705_321_845,
        };

        let response = build_ocsp_response(&params).unwrap();
        assert_eq!(response[0], 0x30);
    }

    #[test]
    fn build_response_p384() {
        let ca = generate_ca_certificate("CN=P384 OCSP CA", CaAlgorithm::EcdsaP384, 365).unwrap();
        let subject_der = extract_issuer_name_der(&ca.certificate_pem).unwrap();

        let req = OcspRequestInfo {
            hash_algorithm_oid: OID_SHA1.to_vec(),
            issuer_name_hash: vec![0; 20],
            issuer_key_hash: vec![0; 20],
            serial_number: vec![0x10, 0x20],
        };

        let params = OcspResponseParams {
            request: &req,
            status: OcspCertStatus::Good,
            algorithm: CaAlgorithm::EcdsaP384,
            ca_key_der: ca.private_key.as_bytes(),
            responder_name_der: &subject_der,
            now: 1_705_321_845,
        };

        let response = build_ocsp_response(&params).unwrap();
        assert_eq!(response[0], 0x30);
    }

    /// Build a real OCSP request DER and verify we can round-trip it.
    #[test]
    fn parse_synthetic_ocsp_request() {
        // Build a minimal OCSPRequest DER by hand.
        let hash_alg = der_sequence(&[der_oid(OID_SHA1), der_null()].concat());
        let name_hash = der_octet_string(&[0xAA; 20]);
        let key_hash = der_octet_string(&[0xBB; 20]);
        let serial = der_integer(&[0x01, 0x02, 0x03]);
        let cert_id = der_sequence(&[hash_alg, name_hash, key_hash, serial].concat());
        let request = der_sequence(&cert_id);
        let request_list = der_sequence(&request);
        let tbs_request = der_sequence(&request_list);
        let ocsp_request = der_sequence(&tbs_request);

        let info = parse_ocsp_request(&ocsp_request).unwrap();
        assert_eq!(info.hash_algorithm_oid, OID_SHA1);
        assert_eq!(info.issuer_name_hash, vec![0xAA; 20]);
        assert_eq!(info.issuer_key_hash, vec![0xBB; 20]);
        assert_eq!(info.serial_number, vec![0x01, 0x02, 0x03]);
    }

    /// End-to-end: build a request, parse it, build a response.
    #[test]
    fn end_to_end_ocsp() {
        let ca =
            generate_ca_certificate("CN=E2E OCSP CA,O=Test", CaAlgorithm::EcdsaP256, 365).unwrap();

        let subject_der = extract_issuer_name_der(&ca.certificate_pem).unwrap();
        let name_hash = compute_issuer_name_hash(OID_SHA1, &subject_der);
        let key_hash = compute_issuer_key_hash(OID_SHA1, &ca.public_key);

        // Build request DER
        let hash_alg = der_sequence(&[der_oid(OID_SHA1), der_null()].concat());
        let serial_bytes = vec![0x01, 0x02, 0x03];
        let cert_id = der_sequence(
            &[
                hash_alg,
                der_octet_string(&name_hash),
                der_octet_string(&key_hash),
                der_integer(&serial_bytes),
            ]
            .concat(),
        );
        let request = der_sequence(&cert_id);
        let request_list = der_sequence(&request);
        let tbs_request = der_sequence(&request_list);
        let ocsp_request = der_sequence(&tbs_request);

        // Parse request
        let info = parse_ocsp_request(&ocsp_request).unwrap();
        assert_eq!(info.serial_number, serial_bytes);

        // Verify issuer match
        let expected_name_hash = compute_issuer_name_hash(&info.hash_algorithm_oid, &subject_der);
        assert_eq!(info.issuer_name_hash, expected_name_hash);

        let expected_key_hash = compute_issuer_key_hash(&info.hash_algorithm_oid, &ca.public_key);
        assert_eq!(info.issuer_key_hash, expected_key_hash);

        // Build response
        let params = OcspResponseParams {
            request: &info,
            status: OcspCertStatus::Good,
            algorithm: CaAlgorithm::EcdsaP256,
            ca_key_der: ca.private_key.as_bytes(),
            responder_name_der: &subject_der,
            now: 1_705_321_845,
        };

        let response = build_ocsp_response(&params).unwrap();
        assert!(!response.is_empty());
        assert_eq!(response[0], 0x30);
    }
}
