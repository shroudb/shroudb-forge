//! HTTP sidecar for CRL distribution, OCSP responder, and health checks.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{StatusCode, header};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use shroudb_forge_core::ca::decode_key_material;
use shroudb_forge_core::cert::CertState;
use shroudb_forge_core::ocsp::{
    self, OcspCertStatus, OcspResponseParams, build_ocsp_malformed_request_response,
    build_ocsp_response, build_ocsp_unauthorized_response, compute_issuer_key_hash,
    compute_issuer_name_hash, extract_issuer_name_der, parse_ocsp_request, serial_bytes_to_hex,
};
use shroudb_forge_engine::engine::ForgeEngine;
use shroudb_store::Store;

const OCSP_RESPONSE_CT: &str = "application/ocsp-response";

struct HttpState<S: Store> {
    engine: Arc<ForgeEngine<S>>,
}

impl<S: Store> Clone for HttpState<S> {
    fn clone(&self) -> Self {
        Self {
            engine: self.engine.clone(),
        }
    }
}

pub async fn run_http_sidecar<S: Store + 'static>(
    bind: SocketAddr,
    engine: Arc<ForgeEngine<S>>,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let state = HttpState { engine };

    let app = Router::new()
        .route("/crl/{ca}", get(get_crl::<S>))
        .route("/ocsp/{ca}", post(post_ocsp::<S>))
        .route("/ocsp/{ca}/{encoded_request}", get(get_ocsp::<S>))
        .route("/health", get(get_health))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(bind).await?;
    tracing::info!(addr = %bind, "HTTP sidecar listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            let _ = shutdown_rx.changed().await;
        })
        .await?;

    Ok(())
}

async fn get_crl<S: Store>(
    State(state): State<HttpState<S>>,
    Path(ca): Path<String>,
) -> impl IntoResponse {
    match state.engine.cert_manager().crl_pem(&ca) {
        Some(pem) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/x-pem-file")],
            pem,
        )
            .into_response(),
        None => (StatusCode::NOT_FOUND, "CRL not found").into_response(),
    }
}

async fn post_ocsp<S: Store>(
    State(state): State<HttpState<S>>,
    Path(ca_name): Path<String>,
    body: Bytes,
) -> impl IntoResponse {
    handle_ocsp_request(&state, &ca_name, &body)
}

async fn get_ocsp<S: Store>(
    State(state): State<HttpState<S>>,
    Path((ca_name, encoded_request)): Path<(String, String)>,
) -> impl IntoResponse {
    use base64::Engine;
    let engine = base64::engine::general_purpose::STANDARD;
    match engine.decode(&encoded_request) {
        Ok(der) => handle_ocsp_request(&state, &ca_name, &der),
        Err(_) => {
            let engine_urlsafe = base64::engine::general_purpose::URL_SAFE;
            match engine_urlsafe.decode(&encoded_request) {
                Ok(der) => handle_ocsp_request(&state, &ca_name, &der),
                Err(_) => ocsp_error_response(build_ocsp_malformed_request_response()),
            }
        }
    }
}

fn handle_ocsp_request<S: Store>(
    state: &HttpState<S>,
    ca_name: &str,
    request_der: &[u8],
) -> axum::response::Response {
    let ocsp_req = match parse_ocsp_request(request_der) {
        Ok(req) => req,
        Err(e) => {
            tracing::warn!(ca = ca_name, error = %e, "malformed OCSP request");
            return ocsp_error_response(build_ocsp_malformed_request_response());
        }
    };

    let ca = match state.engine.ca_manager().get(ca_name) {
        Ok(ca) => ca,
        Err(_) => {
            tracing::warn!(ca = ca_name, "OCSP request for unknown CA");
            return ocsp_error_response(build_ocsp_unauthorized_response());
        }
    };

    let active_key = match ca.active_key() {
        Some(k) => k,
        None => {
            tracing::warn!(ca = ca_name, "OCSP: CA has no active key");
            return ocsp_error_response(build_ocsp_unauthorized_response());
        }
    };

    let ca_key_der = match decode_key_material(active_key) {
        Ok(der) => der,
        Err(_) => {
            tracing::warn!(ca = ca_name, "OCSP: CA key material unavailable");
            return ocsp_error_response(build_ocsp_unauthorized_response());
        }
    };

    let responder_name_der = match extract_issuer_name_der(&active_key.certificate_pem) {
        Ok(der) => der,
        Err(e) => {
            tracing::error!(ca = ca_name, error = %e, "OCSP: failed to extract CA subject");
            return ocsp_error_response(build_ocsp_unauthorized_response());
        }
    };

    let public_key_bytes = active_key
        .public_key
        .as_ref()
        .and_then(|hex_str| hex::decode(hex_str).ok())
        .unwrap_or_default();

    let expected_name_hash =
        compute_issuer_name_hash(&ocsp_req.hash_algorithm_oid, &responder_name_der);
    let expected_key_hash =
        compute_issuer_key_hash(&ocsp_req.hash_algorithm_oid, &public_key_bytes);

    let issuer_matches = if ocsp_req.issuer_name_hash == expected_name_hash
        && ocsp_req.issuer_key_hash == expected_key_hash
    {
        true
    } else {
        ca.verifiable_keys().iter().any(|kv| {
            let pk = kv
                .public_key
                .as_ref()
                .and_then(|hex_str| hex::decode(hex_str).ok())
                .unwrap_or_default();
            let kh = compute_issuer_key_hash(&ocsp_req.hash_algorithm_oid, &pk);
            ocsp_req.issuer_name_hash == expected_name_hash && ocsp_req.issuer_key_hash == kh
        })
    };

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    if !issuer_matches {
        tracing::debug!(
            ca = ca_name,
            "OCSP: issuer hash mismatch, returning unknown"
        );
        let params = OcspResponseParams {
            request: &ocsp_req,
            status: OcspCertStatus::Unknown,
            algorithm: ca.algorithm,
            ca_key_der: ca_key_der.as_bytes(),
            responder_name_der: &responder_name_der,
            now,
        };

        return match build_ocsp_response(&params) {
            Ok(der) => ocsp_success_response(der),
            Err(e) => {
                tracing::error!(ca = ca_name, error = %e, "OCSP: failed to build response");
                ocsp_error_response(ocsp::build_ocsp_malformed_request_response())
            }
        };
    }

    let serial_hex = serial_bytes_to_hex(&ocsp_req.serial_number);

    let status = match state.engine.cert_manager().get(ca_name, &serial_hex) {
        Some(cert) => match cert.state {
            CertState::Revoked => OcspCertStatus::Revoked {
                revoked_at: cert.revoked_at.unwrap_or(now),
            },
            CertState::Active => OcspCertStatus::Good,
        },
        None => OcspCertStatus::Unknown,
    };

    let params = OcspResponseParams {
        request: &ocsp_req,
        status,
        algorithm: ca.algorithm,
        ca_key_der: ca_key_der.as_bytes(),
        responder_name_der: &responder_name_der,
        now,
    };

    match build_ocsp_response(&params) {
        Ok(der) => {
            tracing::debug!(ca = ca_name, serial = serial_hex, "OCSP response generated");
            ocsp_success_response(der)
        }
        Err(e) => {
            tracing::error!(ca = ca_name, error = %e, "OCSP: failed to build response");
            ocsp_error_response(ocsp::build_ocsp_malformed_request_response())
        }
    }
}

fn ocsp_success_response(der: Vec<u8>) -> axum::response::Response {
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, OCSP_RESPONSE_CT),
            (header::CACHE_CONTROL, "public, max-age=3600, no-transform"),
        ],
        der,
    )
        .into_response()
}

fn ocsp_error_response(der: Vec<u8>) -> axum::response::Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, OCSP_RESPONSE_CT)],
        der,
    )
        .into_response()
}

async fn get_health() -> impl IntoResponse {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        r#"{"status":"ok"}"#,
    )
}
