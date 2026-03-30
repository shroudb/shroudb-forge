mod common;

use common::*;

// ═══════════════════════════════════════════════════════════════════════
// TCP: CA lifecycle
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn tcp_ca_lifecycle() {
    let server = TestServer::start().await.expect("server failed to start");
    let mut client = shroudb_forge_client::ForgeClient::connect(&server.tcp_addr)
        .await
        .expect("connect failed");

    // Health
    client.health().await.expect("health check failed");

    // Create CA
    let ca = client
        .ca_create(
            "internal",
            "ecdsa-p256",
            "CN=Internal CA,O=Test",
            None,
            None,
        )
        .await
        .expect("ca create failed");
    assert_eq!(ca["ca"], "internal");
    assert_eq!(ca["algorithm"], "ecdsa-p256");

    // CA Info
    let info = client.ca_info("internal").await.expect("ca info failed");
    assert_eq!(info["ca"], "internal");
    assert_eq!(info["active_version"], 1);

    // CA List
    let list = client.ca_list().await.expect("ca list failed");
    assert!(list.contains(&"internal".to_string()));

    // CA Export
    let pem = client
        .ca_export("internal")
        .await
        .expect("ca export failed");
    assert!(pem.starts_with("-----BEGIN CERTIFICATE-----"));
}

// ═══════════════════════════════════════════════════════════════════════
// TCP: Certificate issuance
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn tcp_issue_and_inspect() {
    let server = TestServer::start().await.expect("server failed to start");
    let mut client = shroudb_forge_client::ForgeClient::connect(&server.tcp_addr)
        .await
        .expect("connect failed");

    client
        .ca_create("internal", "ecdsa-p256", "CN=Internal CA", None, None)
        .await
        .unwrap();

    let issued = client
        .issue(
            "internal",
            "CN=myservice",
            "server",
            Some("24h"),
            &["myservice.local"],
            &[],
        )
        .await
        .expect("issue failed");

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

    // Inspect
    let info = client
        .inspect("internal", &issued.serial)
        .await
        .expect("inspect failed");
    assert_eq!(info["state"], "active");
    assert_eq!(info["profile"], "server");
}

// ═══════════════════════════════════════════════════════════════════════
// TCP: Revocation
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn tcp_revoke() {
    let server = TestServer::start().await.expect("server failed to start");
    let mut client = shroudb_forge_client::ForgeClient::connect(&server.tcp_addr)
        .await
        .expect("connect failed");

    client
        .ca_create("internal", "ecdsa-p256", "CN=Internal CA", None, None)
        .await
        .unwrap();

    let issued = client
        .issue("internal", "CN=svc", "server", None, &[], &[])
        .await
        .unwrap();

    client
        .revoke("internal", &issued.serial, Some("superseded"))
        .await
        .expect("revoke failed");

    let info = client
        .inspect("internal", &issued.serial)
        .await
        .expect("inspect failed");
    assert_eq!(info["state"], "revoked");
}

// ═══════════════════════════════════════════════════════════════════════
// TCP: Multiple SANs
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn tcp_issue_with_multiple_sans() {
    let server = TestServer::start().await.expect("server failed to start");
    let mut client = shroudb_forge_client::ForgeClient::connect(&server.tcp_addr)
        .await
        .expect("connect failed");

    client
        .ca_create("internal", "ecdsa-p256", "CN=Internal CA", None, None)
        .await
        .unwrap();

    let issued = client
        .issue(
            "internal",
            "CN=myservice",
            "server",
            Some("24h"),
            &["svc1.local", "svc2.local", "svc3.local"],
            &["10.0.0.1"],
        )
        .await
        .expect("issue with multiple SANs failed");

    assert!(
        issued
            .certificate_pem
            .starts_with("-----BEGIN CERTIFICATE-----")
    );

    let info = client
        .inspect("internal", &issued.serial)
        .await
        .expect("inspect failed");
    assert_eq!(info["san_dns"].as_array().unwrap().len(), 3);
    assert_eq!(info["san_ip"].as_array().unwrap().len(), 1);
}

// ═══════════════════════════════════════════════════════════════════════
// TCP: Renew
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn tcp_renew() {
    let server = TestServer::start().await.expect("server failed to start");
    let mut client = shroudb_forge_client::ForgeClient::connect(&server.tcp_addr)
        .await
        .expect("connect failed");

    client
        .ca_create("internal", "ecdsa-p256", "CN=Internal CA", None, None)
        .await
        .unwrap();

    let issued = client
        .issue("internal", "CN=svc", "server", None, &[], &[])
        .await
        .unwrap();

    let renewed = client
        .renew("internal", &issued.serial, Some("7d"))
        .await
        .expect("renew failed");

    // Renewed cert has a different serial
    assert_ne!(renewed.serial, issued.serial);
    assert!(
        renewed
            .certificate_pem
            .starts_with("-----BEGIN CERTIFICATE-----")
    );
}

// ═══════════════════════════════════════════════════════════════════════
// TCP: List certs
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn tcp_list_certs() {
    let server = TestServer::start().await.expect("server failed to start");
    let mut client = shroudb_forge_client::ForgeClient::connect(&server.tcp_addr)
        .await
        .expect("connect failed");

    client
        .ca_create("internal", "ecdsa-p256", "CN=Internal CA", None, None)
        .await
        .unwrap();

    client
        .issue("internal", "CN=svc1", "server", None, &[], &[])
        .await
        .unwrap();
    let issued2 = client
        .issue("internal", "CN=svc2", "server", None, &[], &[])
        .await
        .unwrap();

    // List all
    let resp = client
        .list_certs("internal", None, None, None)
        .await
        .expect("list certs failed");
    assert_eq!(resp["count"], 2);

    // Revoke one and filter by state
    client
        .revoke("internal", &issued2.serial, None)
        .await
        .unwrap();

    let active = client
        .list_certs("internal", Some("active"), None, None)
        .await
        .unwrap();
    assert_eq!(active["count"], 1);

    let revoked = client
        .list_certs("internal", Some("revoked"), None, None)
        .await
        .unwrap();
    assert_eq!(revoked["count"], 1);
}

// ═══════════════════════════════════════════════════════════════════════
// TCP: Key rotation
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn tcp_ca_rotate() {
    let server = TestServer::start().await.expect("server failed to start");
    let mut client = shroudb_forge_client::ForgeClient::connect(&server.tcp_addr)
        .await
        .expect("connect failed");

    client
        .ca_create("internal", "ecdsa-p256", "CN=Internal CA", None, None)
        .await
        .unwrap();

    let result = client
        .ca_rotate("internal", true)
        .await
        .expect("rotate failed");
    assert_eq!(result["rotated"], true);
    assert_eq!(result["key_version"], 2);
}

// ═══════════════════════════════════════════════════════════════════════
// ACL: Token-based auth
// ═══════════════════════════════════════════════════════════════════════

fn auth_server_config() -> TestServerConfig {
    TestServerConfig {
        profiles: vec![(
            "server",
            TestProfile {
                key_usage: vec!["DigitalSignature", "KeyEncipherment"],
                extended_key_usage: vec!["ServerAuth"],
                max_ttl_days: 90,
                default_ttl: "30d",
                allow_san_dns: true,
                allow_san_ip: true,
            },
        )],
        tokens: vec![
            TestToken {
                raw: "admin-token".to_string(),
                tenant: "tenant-a".to_string(),
                actor: "admin".to_string(),
                platform: true,
                grants: vec![],
            },
            TestToken {
                raw: "app-token".to_string(),
                tenant: "tenant-a".to_string(),
                actor: "my-app".to_string(),
                platform: false,
                grants: vec![TestGrant {
                    namespace: "forge.internal.*".to_string(),
                    scopes: vec!["read".to_string(), "write".to_string()],
                }],
            },
            TestToken {
                raw: "readonly-token".to_string(),
                tenant: "tenant-a".to_string(),
                actor: "reader".to_string(),
                platform: false,
                grants: vec![TestGrant {
                    namespace: "forge.internal.*".to_string(),
                    scopes: vec!["read".to_string()],
                }],
            },
        ],
        ..Default::default()
    }
}

#[tokio::test]
async fn acl_unauthenticated_rejected() {
    let server = TestServer::start_with_config(auth_server_config())
        .await
        .expect("server failed to start");
    let mut client = shroudb_forge_client::ForgeClient::connect(&server.tcp_addr)
        .await
        .expect("connect failed");

    // Health is public
    client.health().await.expect("health should be public");

    // CA CREATE requires Admin → rejected
    let err = client
        .ca_create("internal", "ecdsa-p256", "CN=Test", None, None)
        .await;
    assert!(err.is_err(), "unauthenticated ca create should fail");
}

#[tokio::test]
async fn acl_admin_token_full_access() {
    let server = TestServer::start_with_config(auth_server_config())
        .await
        .expect("server failed to start");
    let mut client = shroudb_forge_client::ForgeClient::connect(&server.tcp_addr)
        .await
        .expect("connect failed");

    client.auth("admin-token").await.expect("admin auth failed");

    client
        .ca_create("internal", "ecdsa-p256", "CN=Internal CA", None, None)
        .await
        .expect("admin should create CA");

    client
        .issue("internal", "CN=svc", "server", None, &[], &[])
        .await
        .expect("admin should issue");
}

#[tokio::test]
async fn acl_wrong_token_rejected() {
    let server = TestServer::start_with_config(auth_server_config())
        .await
        .expect("server failed to start");
    let mut client = shroudb_forge_client::ForgeClient::connect(&server.tcp_addr)
        .await
        .expect("connect failed");

    let err = client.auth("totally-wrong-token").await;
    assert!(err.is_err(), "wrong token should be rejected");
}

#[tokio::test]
async fn acl_readonly_token_cannot_issue() {
    let server = TestServer::start_with_config(auth_server_config())
        .await
        .expect("server failed to start");

    // Admin creates CA first
    let mut admin = shroudb_forge_client::ForgeClient::connect(&server.tcp_addr)
        .await
        .unwrap();
    admin.auth("admin-token").await.unwrap();
    admin
        .ca_create("internal", "ecdsa-p256", "CN=Internal CA", None, None)
        .await
        .unwrap();
    admin
        .issue("internal", "CN=svc", "server", None, &[], &[])
        .await
        .unwrap();

    // Readonly can read
    let mut reader = shroudb_forge_client::ForgeClient::connect(&server.tcp_addr)
        .await
        .unwrap();
    reader.auth("readonly-token").await.unwrap();
    reader
        .ca_info("internal")
        .await
        .expect("readonly should get ca info");

    // Readonly cannot issue (Write scope)
    let err = reader
        .issue("internal", "CN=other", "server", None, &[], &[])
        .await;
    assert!(err.is_err(), "readonly should not issue");
}
