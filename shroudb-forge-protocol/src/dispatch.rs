use shroudb_acl::AuthContext;
use shroudb_forge_core::ca::CaAlgorithm;
use shroudb_forge_core::cert::{CertState, RevocationReason};
use shroudb_forge_engine::ca_manager::CaCreateOpts;
use shroudb_forge_engine::engine::ForgeEngine;
use shroudb_store::Store;

use crate::commands::ForgeCommand;
use crate::response::ForgeResponse;

const SUPPORTED_COMMANDS: &[&str] = &[
    "AUTH",
    "CA CREATE",
    "CA INFO",
    "CA LIST",
    "CA ROTATE",
    "CA EXPORT",
    "ISSUE",
    "ISSUE_FROM_CSR",
    "REVOKE",
    "INSPECT",
    "LIST_CERTS",
    "RENEW",
    "HEALTH",
    "PING",
    "COMMAND LIST",
];

/// Dispatch a parsed command to the ForgeEngine and produce a response.
///
/// `auth_context` is the authenticated identity for this connection/request.
/// `None` means auth is disabled (dev mode / no auth config).
/// AUTH commands are handled externally by the TCP layer — dispatch never sees them.
pub async fn dispatch<S: Store>(
    engine: &ForgeEngine<S>,
    cmd: ForgeCommand,
    auth_context: Option<&AuthContext>,
) -> ForgeResponse {
    // Check ACL requirement before dispatch
    let requirement = cmd.acl_requirement();
    if let Some(ctx) = auth_context
        && let Err(e) = ctx.check(&requirement)
    {
        return ForgeResponse::error(format!("access denied: {e}"));
    }

    match cmd {
        ForgeCommand::Auth { .. } => ForgeResponse::error("AUTH handled at connection layer"),

        // ── CA management ─────────────────────────────────────────
        ForgeCommand::CaCreate {
            name,
            algorithm,
            subject,
            ttl_days,
            parent,
        } => {
            let algo: CaAlgorithm = match algorithm.parse() {
                Ok(a) => a,
                Err(e) => return ForgeResponse::error(e),
            };
            let mut opts = CaCreateOpts {
                subject,
                parent,
                ..Default::default()
            };
            if let Some(days) = ttl_days {
                opts.ttl_days = days;
            }
            match engine.ca_create(&name, algo, opts).await {
                Ok(info) => ForgeResponse::ok(serde_json::json!({
                    "status": "ok",
                    "ca": info.name,
                    "algorithm": info.algorithm,
                    "subject": info.subject,
                    "active_version": info.active_version,
                    "ttl_days": info.ttl_days,
                    "parent": info.parent,
                })),
                Err(e) => ForgeResponse::error(e.to_string()),
            }
        }

        ForgeCommand::CaInfo { ca } => match engine.ca_info(&ca) {
            Ok(info) => ForgeResponse::ok(serde_json::json!({
                "status": "ok",
                "ca": info.name,
                "algorithm": info.algorithm,
                "subject": info.subject,
                "ttl_days": info.ttl_days,
                "parent": info.parent,
                "rotation_days": info.rotation_days,
                "drain_days": info.drain_days,
                "disabled": info.disabled,
                "active_version": info.active_version,
                "key_versions": info.key_versions.iter().map(|kv| serde_json::json!({
                    "version": kv.version,
                    "state": kv.state,
                    "created_at": kv.created_at,
                    "activated_at": kv.activated_at,
                    "draining_since": kv.draining_since,
                    "retired_at": kv.retired_at,
                })).collect::<Vec<_>>(),
            })),
            Err(e) => ForgeResponse::error(e.to_string()),
        },

        ForgeCommand::CaList => {
            let names = engine.ca_list();
            ForgeResponse::ok(serde_json::json!(names))
        }

        ForgeCommand::CaRotate { ca, force, dryrun } => {
            match engine.ca_rotate(&ca, force, dryrun).await {
                Ok(result) => ForgeResponse::ok(serde_json::json!({
                    "status": "ok",
                    "rotated": result.rotated,
                    "key_version": result.key_version,
                    "previous_version": result.previous_version,
                })),
                Err(e) => ForgeResponse::error(e.to_string()),
            }
        }

        ForgeCommand::CaExport { ca } => match engine.ca_export(&ca) {
            Ok(pem) => ForgeResponse::ok(serde_json::json!({
                "status": "ok",
                "certificate_pem": pem,
            })),
            Err(e) => ForgeResponse::error(e.to_string()),
        },

        // ── Certificate operations ────────────────────────────────
        ForgeCommand::Issue {
            ca,
            subject,
            profile,
            ttl,
            san_dns,
            san_ip,
        } => {
            match engine
                .issue(&ca, &subject, &profile, ttl.as_deref(), &san_dns, &san_ip)
                .await
            {
                Ok(result) => ForgeResponse::ok(serde_json::json!({
                    "status": "ok",
                    "certificate_pem": result.certificate_pem,
                    "private_key_pem": result.private_key_pem,
                    "serial": result.serial,
                    "not_before": result.not_before,
                    "not_after": result.not_after,
                    "ca_key_version": result.ca_key_version,
                })),
                Err(e) => ForgeResponse::error(e.to_string()),
            }
        }

        ForgeCommand::IssueFromCsr {
            ca,
            csr_pem,
            profile,
            ttl,
        } => match engine
            .issue_from_csr(&ca, &csr_pem, &profile, ttl.as_deref())
            .await
        {
            Ok(result) => ForgeResponse::ok(serde_json::json!({
                "status": "ok",
                "certificate_pem": result.certificate_pem,
                "private_key_pem": result.private_key_pem,
                "serial": result.serial,
                "not_before": result.not_before,
                "not_after": result.not_after,
                "ca_key_version": result.ca_key_version,
            })),
            Err(e) => ForgeResponse::error(e.to_string()),
        },

        ForgeCommand::Revoke { ca, serial, reason } => {
            let revocation_reason = if let Some(ref r) = reason {
                match RevocationReason::from_arg(r) {
                    Some(rr) => Some(rr),
                    None => return ForgeResponse::error(format!("unknown revocation reason: {r}")),
                }
            } else {
                None
            };

            match engine.revoke(&ca, &serial, revocation_reason).await {
                Ok(()) => ForgeResponse::ok(serde_json::json!({
                    "status": "ok",
                    "ca": ca,
                    "serial": serial,
                })),
                Err(e) => ForgeResponse::error(e.to_string()),
            }
        }

        ForgeCommand::Inspect { ca, serial } => match engine.inspect(&ca, &serial) {
            Ok(info) => ForgeResponse::ok(serde_json::json!({
                "status": "ok",
                "serial": info.serial,
                "ca": info.ca_name,
                "ca_key_version": info.ca_key_version,
                "subject": info.subject,
                "profile": info.profile,
                "state": info.state,
                "not_before": info.not_before,
                "not_after": info.not_after,
                "san_dns": info.san_dns,
                "san_ip": info.san_ip,
                "certificate_pem": info.certificate_pem,
            })),
            Err(e) => ForgeResponse::error(e.to_string()),
        },

        ForgeCommand::ListCerts {
            ca,
            state,
            limit,
            offset,
        } => {
            let state_filter = if let Some(ref s) = state {
                match CertState::from_arg(s) {
                    Some(st) => Some(st),
                    None => return ForgeResponse::error(format!("unknown cert state: {s}")),
                }
            } else {
                None
            };

            let certs = engine.list_certs(&ca, state_filter, limit, offset);
            let entries: Vec<serde_json::Value> = certs
                .iter()
                .map(|c| {
                    serde_json::json!({
                        "serial": c.serial,
                        "subject": c.subject,
                        "profile": c.profile,
                        "state": c.state,
                        "not_before": c.not_before,
                        "not_after": c.not_after,
                        "ca_key_version": c.ca_key_version,
                    })
                })
                .collect();

            ForgeResponse::ok(serde_json::json!({
                "status": "ok",
                "ca": ca,
                "count": entries.len(),
                "certificates": entries,
            }))
        }

        ForgeCommand::Renew { ca, serial, ttl } => {
            match engine.renew(&ca, &serial, ttl.as_deref()).await {
                Ok(result) => ForgeResponse::ok(serde_json::json!({
                    "status": "ok",
                    "certificate_pem": result.certificate_pem,
                    "private_key_pem": result.private_key_pem,
                    "serial": result.serial,
                    "not_before": result.not_before,
                    "not_after": result.not_after,
                    "ca_key_version": result.ca_key_version,
                })),
                Err(e) => ForgeResponse::error(e.to_string()),
            }
        }

        // ── Operational ───────────────────────────────────────────
        ForgeCommand::Health => ForgeResponse::ok(serde_json::json!({
            "status": "ok",
        })),

        ForgeCommand::Ping => ForgeResponse::ok(serde_json::json!("PONG")),

        ForgeCommand::CommandList => ForgeResponse::ok(serde_json::json!({
            "count": SUPPORTED_COMMANDS.len(),
            "commands": SUPPORTED_COMMANDS,
        })),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::commands::parse_command;
    use shroudb_forge_engine::engine::ForgeConfig;

    async fn setup() -> ForgeEngine<shroudb_storage::EmbeddedStore> {
        let store = create_test_store().await;
        ForgeEngine::new(store, test_profiles(), ForgeConfig::default())
            .await
            .unwrap()
    }

    async fn create_test_store() -> Arc<shroudb_storage::EmbeddedStore> {
        let dir = tempfile::tempdir().unwrap().keep();
        let config = shroudb_storage::StorageEngineConfig {
            data_dir: dir,
            ..Default::default()
        };
        let engine = shroudb_storage::StorageEngine::open(config, &EphemeralKey)
            .await
            .unwrap();
        Arc::new(shroudb_storage::EmbeddedStore::new(
            Arc::new(engine),
            "forge-test",
        ))
    }

    struct EphemeralKey;
    impl shroudb_storage::MasterKeySource for EphemeralKey {
        fn source_name(&self) -> &str {
            "ephemeral-test"
        }
        fn load<'a>(
            &'a self,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<shroudb_crypto::SecretBytes, shroudb_storage::StorageError>,
                    > + Send
                    + 'a,
            >,
        > {
            Box::pin(async { Ok(shroudb_crypto::SecretBytes::new(vec![0x42u8; 32])) })
        }
    }

    fn test_profiles() -> Vec<shroudb_forge_core::profile::CertificateProfile> {
        vec![
            shroudb_forge_core::profile::CertificateProfile {
                name: "server".into(),
                key_usage: vec![
                    shroudb_forge_core::profile::KeyUsage::DigitalSignature,
                    shroudb_forge_core::profile::KeyUsage::KeyEncipherment,
                ],
                extended_key_usage: vec![shroudb_forge_core::profile::ExtendedKeyUsage::ServerAuth],
                max_ttl_days: 90,
                default_ttl: "30d".into(),
                allow_san_dns: true,
                allow_san_ip: true,
                subject_template: None,
            },
            shroudb_forge_core::profile::CertificateProfile {
                name: "client".into(),
                key_usage: vec![shroudb_forge_core::profile::KeyUsage::DigitalSignature],
                extended_key_usage: vec![shroudb_forge_core::profile::ExtendedKeyUsage::ClientAuth],
                max_ttl_days: 30,
                default_ttl: "1h".into(),
                allow_san_dns: false,
                allow_san_ip: false,
                subject_template: None,
            },
        ]
    }

    async fn setup_with_ca(engine: &ForgeEngine<shroudb_storage::EmbeddedStore>) {
        let cmd = parse_command(&[
            "CA",
            "CREATE",
            "internal",
            "ecdsa-p256",
            "SUBJECT",
            "CN=Internal CA,O=Test",
        ])
        .unwrap();
        let resp = dispatch(engine, cmd, None).await;
        assert!(resp.is_ok(), "CA CREATE failed: {resp:?}");
    }

    #[tokio::test]
    async fn ca_create_and_info_flow() {
        let engine = setup().await;

        let cmd = parse_command(&[
            "CA",
            "CREATE",
            "internal",
            "ecdsa-p256",
            "SUBJECT",
            "CN=Internal CA,O=Test",
        ])
        .unwrap();
        let resp = dispatch(&engine, cmd, None).await;
        assert!(resp.is_ok(), "CA CREATE failed: {resp:?}");

        match &resp {
            ForgeResponse::Ok(v) => {
                assert_eq!(v["ca"], "internal");
                assert_eq!(v["algorithm"], "ecdsa-p256");
            }
            _ => panic!("expected ok"),
        }

        let cmd = parse_command(&["CA", "INFO", "internal"]).unwrap();
        let resp = dispatch(&engine, cmd, None).await;
        assert!(resp.is_ok(), "CA INFO failed: {resp:?}");

        match &resp {
            ForgeResponse::Ok(v) => {
                assert_eq!(v["ca"], "internal");
                assert_eq!(v["subject"], "CN=Internal CA,O=Test");
            }
            _ => panic!("expected ok"),
        }
    }

    #[tokio::test]
    async fn issue_and_inspect_flow() {
        let engine = setup().await;
        setup_with_ca(&engine).await;

        let cmd = parse_command(&[
            "ISSUE",
            "internal",
            "CN=myservice",
            "server",
            "TTL",
            "24h",
            "SAN_DNS",
            "myservice.local",
        ])
        .unwrap();
        let resp = dispatch(&engine, cmd, None).await;
        assert!(resp.is_ok(), "ISSUE failed: {resp:?}");

        let serial = match &resp {
            ForgeResponse::Ok(v) => {
                assert!(
                    v["certificate_pem"]
                        .as_str()
                        .unwrap()
                        .starts_with("-----BEGIN CERTIFICATE-----")
                );
                assert!(
                    v["private_key_pem"]
                        .as_str()
                        .unwrap()
                        .starts_with("-----BEGIN PRIVATE KEY-----")
                );
                v["serial"].as_str().unwrap().to_string()
            }
            _ => panic!("expected ok"),
        };

        let cmd = parse_command(&["INSPECT", "internal", &serial]).unwrap();
        let resp = dispatch(&engine, cmd, None).await;
        assert!(resp.is_ok(), "INSPECT failed: {resp:?}");

        match &resp {
            ForgeResponse::Ok(v) => {
                assert_eq!(v["subject"], "CN=myservice");
                assert_eq!(v["profile"], "server");
                assert_eq!(v["state"], "active");
            }
            _ => panic!("expected ok"),
        }
    }

    #[tokio::test]
    async fn revoke_flow() {
        let engine = setup().await;
        setup_with_ca(&engine).await;

        let cmd = parse_command(&["ISSUE", "internal", "CN=svc", "server"]).unwrap();
        let resp = dispatch(&engine, cmd, None).await;
        let serial = match &resp {
            ForgeResponse::Ok(v) => v["serial"].as_str().unwrap().to_string(),
            _ => panic!("expected ok"),
        };

        let cmd = parse_command(&["REVOKE", "internal", &serial, "REASON", "superseded"]).unwrap();
        let resp = dispatch(&engine, cmd, None).await;
        assert!(resp.is_ok(), "REVOKE failed: {resp:?}");

        let cmd = parse_command(&["INSPECT", "internal", &serial]).unwrap();
        let resp = dispatch(&engine, cmd, None).await;
        match &resp {
            ForgeResponse::Ok(v) => assert_eq!(v["state"], "revoked"),
            _ => panic!("expected ok"),
        }
    }

    #[tokio::test]
    async fn health_and_ping() {
        let engine = setup().await;

        let cmd = parse_command(&["HEALTH"]).unwrap();
        let resp = dispatch(&engine, cmd, None).await;
        assert!(resp.is_ok());

        let cmd = parse_command(&["PING"]).unwrap();
        let resp = dispatch(&engine, cmd, None).await;
        assert!(resp.is_ok());
        match &resp {
            ForgeResponse::Ok(v) => assert_eq!(v, "PONG"),
            _ => panic!("expected ok"),
        }

        let cmd = parse_command(&["COMMAND"]).unwrap();
        let resp = dispatch(&engine, cmd, None).await;
        assert!(resp.is_ok());
        match &resp {
            ForgeResponse::Ok(v) => {
                assert_eq!(v["count"], SUPPORTED_COMMANDS.len());
            }
            _ => panic!("expected ok"),
        }
    }

    #[tokio::test]
    async fn list_certs_flow() {
        let engine = setup().await;
        setup_with_ca(&engine).await;

        let cmd = parse_command(&["ISSUE", "internal", "CN=svc1", "server"]).unwrap();
        let resp = dispatch(&engine, cmd, None).await;
        assert!(resp.is_ok());

        let cmd = parse_command(&["ISSUE", "internal", "CN=svc2", "server"]).unwrap();
        let resp = dispatch(&engine, cmd, None).await;
        assert!(resp.is_ok());

        let cmd = parse_command(&["LIST_CERTS", "internal"]).unwrap();
        let resp = dispatch(&engine, cmd, None).await;
        assert!(resp.is_ok(), "LIST_CERTS failed: {resp:?}");

        match &resp {
            ForgeResponse::Ok(v) => {
                assert_eq!(v["count"], 2);
                assert_eq!(v["certificates"].as_array().unwrap().len(), 2);
            }
            _ => panic!("expected ok"),
        }

        // With state filter
        let cmd = parse_command(&["LIST_CERTS", "internal", "STATE", "active"]).unwrap();
        let resp = dispatch(&engine, cmd, None).await;
        assert!(resp.is_ok());
        match &resp {
            ForgeResponse::Ok(v) => {
                assert_eq!(v["count"], 2);
            }
            _ => panic!("expected ok"),
        }
    }
}
