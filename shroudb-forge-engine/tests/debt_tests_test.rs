//! Debt tests (AUDIT_2026-04-17) — hard-ratchet FAILING tests that encode
//! the correct behavior Forge must exhibit.
//!
//! These tests currently fail. They are not to be marked `#[ignore]`.
//! Each test corresponds to a finding documented in the audit.

use std::sync::{Arc, Mutex};

use shroudb_chronicle_core::event::Event;
use shroudb_chronicle_core::ops::ChronicleOps;
use shroudb_forge_core::ca::CaAlgorithm;
use shroudb_forge_core::error::ForgeError;
use shroudb_forge_core::profile::{CertificateProfile, ExtendedKeyUsage, KeyUsage};
use shroudb_forge_engine::ca_manager::CaCreateOpts;
use shroudb_forge_engine::capabilities::ForgeKeepOps;
use shroudb_forge_engine::engine::{ForgeConfig, ForgeEngine, PolicyMode};
use shroudb_server_bootstrap::Capability;

// ── Test doubles ─────────────────────────────────────────────────────

struct RecordingKeep {
    stored: Mutex<Vec<(String, Vec<u8>)>>,
}

fn recording_keep() -> (Box<dyn ForgeKeepOps>, Arc<RecordingKeep>) {
    let inner = Arc::new(RecordingKeep {
        stored: Mutex::new(Vec::new()),
    });
    struct Forward(Arc<RecordingKeep>);
    impl ForgeKeepOps for Forward {
        fn store_key(
            &self,
            path: &str,
            key_material: &[u8],
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<u64, ForgeError>> + Send + '_>>
        {
            self.0
                .stored
                .lock()
                .unwrap()
                .push((path.to_string(), key_material.to_vec()));
            Box::pin(async { Ok(1) })
        }
        fn get_key(
            &self,
            _path: &str,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<Vec<u8>, ForgeError>> + Send + '_>,
        > {
            Box::pin(async { Ok(vec![]) })
        }
    }
    (Box::new(Forward(inner.clone())), inner)
}

struct FailingKeep;
fn failing_keep() -> Box<dyn ForgeKeepOps> {
    Box::new(FailingKeep)
}
impl ForgeKeepOps for FailingKeep {
    fn store_key(
        &self,
        _path: &str,
        _key_material: &[u8],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<u64, ForgeError>> + Send + '_>>
    {
        Box::pin(async { Err(ForgeError::Internal("simulated keep failure".into())) })
    }
    fn get_key(
        &self,
        _path: &str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<u8>, ForgeError>> + Send + '_>>
    {
        Box::pin(async { Err(ForgeError::Internal("simulated keep failure".into())) })
    }
}

struct FailingChronicle;
fn failing_chronicle() -> Arc<dyn ChronicleOps> {
    Arc::new(FailingChronicle)
}
impl ChronicleOps for FailingChronicle {
    fn record(
        &self,
        _event: Event,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + '_>> {
        Box::pin(async { Err("simulated chronicle failure".to_string()) })
    }
    fn record_batch(
        &self,
        _events: Vec<Event>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + '_>> {
        Box::pin(async { Err("simulated chronicle failure".to_string()) })
    }
}

fn test_profiles() -> Vec<CertificateProfile> {
    vec![CertificateProfile {
        name: "server".into(),
        key_usage: vec![KeyUsage::DigitalSignature, KeyUsage::KeyEncipherment],
        extended_key_usage: vec![ExtendedKeyUsage::ServerAuth],
        max_ttl_days: 90,
        default_ttl: "30d".into(),
        allow_san_dns: true,
        allow_san_ip: true,
        subject_template: None,
    }]
}

fn open_config() -> ForgeConfig {
    ForgeConfig {
        policy_mode: PolicyMode::Open,
        ..Default::default()
    }
}

// ── Debt tests ───────────────────────────────────────────────────────

// F-forge-1: server/main.rs hard-codes `None, None, None` for policy
// evaluator, chronicle, and keep when constructing ForgeEngine. Every
// production Forge runs WITHOUT audit, WITHOUT policy enforcement
// (PolicyMode::Closed will then deny everything — actually worse: it
// falls back to "no evaluator configured" deny in closed mode, making
// the server unusable; in open mode it silently permits), and WITHOUT
// Keep defense-in-depth for CA private keys.
#[test]
fn debt_1_server_main_must_not_hardcode_capabilities_none() {
    let src = include_str!("../../shroudb-forge-server/src/main.rs");
    let stripped: String = src
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !stripped.contains("ForgeEngine::new(store, profiles, forge_config, None, None, None)"),
        "shroudb-forge-server/src/main.rs hard-codes `None, None, None` \
         for (PolicyEvaluator, ChronicleOps, ForgeKeepOps) when building \
         ForgeEngine. The server MUST wire these capabilities from \
         config (at least ChronicleOps and ForgeKeepOps), or the CA runs \
         unaudited with private keys held only in the Store."
    );
}

// F-forge-2: when Keep is configured, `ca_create` stores the key in
// Keep AFTER the CA has already been persisted to the Store (which
// includes `key_material` as a hex string). The Store entry is never
// updated to null out the plaintext hex — so the private key lives in
// BOTH places forever. Keep integration is defense-in-depth only on
// paper; the Store copy defeats it entirely.
//
// Expected: after ca_create with Keep configured, the persisted CA's
// `key_material` must be None (so only Keep holds it).
#[tokio::test]
async fn debt_2_ca_create_with_keep_must_clear_store_key_material() {
    let store = shroudb_storage::test_util::create_test_store("forge-debt-2").await;
    let (keep, _rec) = recording_keep();

    let engine = ForgeEngine::new(
        store,
        test_profiles(),
        open_config(),
        Capability::DisabledForTests,
        Capability::DisabledForTests,
        Capability::Enabled(keep),
    )
    .await
    .unwrap();

    engine
        .ca_create(
            "internal",
            CaAlgorithm::EcdsaP256,
            CaCreateOpts {
                subject: "CN=Internal CA".into(),
                ..Default::default()
            },
            Some("admin"),
        )
        .await
        .unwrap();

    // Directly inspect the persisted CA state.
    let ca = engine.ca_manager().get("internal").unwrap();
    let active = ca.active_key().unwrap();
    assert!(
        active.key_material.is_none(),
        "when Keep is configured, CA private key material MUST be \
         removed from the Store after storing in Keep — defense-in-depth \
         is meaningless if the plaintext hex is still in the Store"
    );
}

// F-forge-3: ca_create persists the CA to the Store BEFORE attempting
// the Keep store. If Keep fails, the CA is already in the Store with
// plaintext key_material. The caller gets an error but the state is
// half-committed: a CA exists, but the caller thinks the operation
// failed. Idempotent retry won't help because the CA already exists.
#[tokio::test]
async fn debt_3_ca_create_must_rollback_when_keep_store_fails() {
    let store = shroudb_storage::test_util::create_test_store("forge-debt-3").await;

    let engine = ForgeEngine::new(
        store,
        test_profiles(),
        open_config(),
        Capability::DisabledForTests,
        Capability::DisabledForTests,
        Capability::Enabled(failing_keep()),
    )
    .await
    .unwrap();

    let result = engine
        .ca_create(
            "half-created",
            CaAlgorithm::EcdsaP256,
            CaCreateOpts {
                subject: "CN=Half Created CA".into(),
                ..Default::default()
            },
            Some("admin"),
        )
        .await;
    assert!(
        result.is_err(),
        "ca_create must surface Keep failure as Err"
    );

    assert!(
        engine.ca_manager().get("half-created").is_err(),
        "CA must NOT exist in the Store when Keep.store_key failed — \
         ca_create is half-committed, violating atomicity and leaving \
         plaintext CA private key in the Store despite the error"
    );
}

// F-forge-4: ca_create with chronicle configured-but-failing persists
// the CA AND (if keep is configured) stores the key in Keep, then emits
// the audit event. If the audit event fails, the caller gets an error
// but the CA exists and the Keep write already happened. Unaudited CA
// creation is a severe security regression.
#[tokio::test]
async fn debt_4_ca_create_must_rollback_when_audit_fails() {
    let store = shroudb_storage::test_util::create_test_store("forge-debt-4").await;

    let engine = ForgeEngine::new(
        store,
        test_profiles(),
        open_config(),
        Capability::DisabledForTests,
        Capability::Enabled(failing_chronicle()),
        Capability::DisabledForTests,
    )
    .await
    .unwrap();

    let result = engine
        .ca_create(
            "unaudited",
            CaAlgorithm::EcdsaP256,
            CaCreateOpts {
                subject: "CN=Unaudited CA".into(),
                ..Default::default()
            },
            Some("attacker"),
        )
        .await;
    assert!(
        result.is_err(),
        "ca_create must surface audit failure as Err"
    );

    assert!(
        engine.ca_manager().get("unaudited").is_err(),
        "CA must NOT persist when audit failed — unaudited CA creation \
         is a security regression; audit is a gate not a hint"
    );
}

// F-forge-5: revoke commits the revocation (changes cert state to
// Revoked + updates CRL cache) THEN emits the audit. If audit fails,
// the cert is revoked with no audit record. Worse: CRL has been
// regenerated to include the revoked serial. Asymmetric partial
// commit.
#[tokio::test]
async fn debt_5_revoke_must_rollback_when_audit_fails() {
    let store = shroudb_storage::test_util::create_test_store("forge-debt-5").await;

    // First create a CA and issue a cert with a working chronicle. Forge's
    // new() takes Option<Arc<dyn ChronicleOps>> — we simulate pre-existing
    // healthy state by using None during setup, then build a second engine
    // on the same store with a failing chronicle for the revoke call.
    let store_ref = store.clone();
    let setup_engine = ForgeEngine::new(
        store_ref,
        test_profiles(),
        open_config(),
        Capability::DisabledForTests,
        Capability::DisabledForTests,
        Capability::DisabledForTests,
    )
    .await
    .unwrap();
    setup_engine
        .ca_create(
            "ca1",
            CaAlgorithm::EcdsaP256,
            CaCreateOpts {
                subject: "CN=CA1".into(),
                ..Default::default()
            },
            Some("admin"),
        )
        .await
        .unwrap();
    let issued = setup_engine
        .issue(
            "ca1",
            "CN=svc",
            "server",
            Some("1h"),
            &[],
            &[],
            Some("admin"),
        )
        .await
        .unwrap();
    let serial = issued.serial.clone();
    drop(setup_engine);

    // New engine on the same store with a failing chronicle.
    let engine = ForgeEngine::new(
        store,
        test_profiles(),
        open_config(),
        Capability::DisabledForTests,
        Capability::Enabled(failing_chronicle()),
        Capability::DisabledForTests,
    )
    .await
    .unwrap();

    let result = engine
        .revoke(
            "ca1",
            &serial,
            Some(shroudb_forge_core::cert::RevocationReason::Superseded),
            Some("attacker"),
        )
        .await;
    assert!(result.is_err(), "revoke must surface audit failure as Err");

    let info = engine.inspect("ca1", &serial).unwrap();
    assert_eq!(
        info.state, "active",
        "certificate must remain Active when audit failed — a revocation \
         that isn't audited is a secret revocation"
    );
}

// F-forge-6: ca_create default flow: when NO Keep is configured, the
// private key lives only in the Store. That's documented and accepted,
// but the engine must make it IMPOSSIBLE to accidentally run without
// Keep in production. ForgeConfig should carry an explicit "require_keep"
// flag (defaulting to true for fail-closed) that rejects engine
// construction without a Keep capability. Today a Forge with no Keep
// silently holds CA private keys in the Store.
#[test]
fn debt_6_forge_config_must_have_require_keep_defaulting_true() {
    // This test encodes the missing field. Today ForgeConfig has no
    // `require_keep` field; the test fails to compile unless added.
    // We use a runtime reflection hack via Debug to keep the test a
    // clean failure rather than a build break.
    let cfg = ForgeConfig::default();
    let debug_str = format!("{:?}", ShowConfig(&cfg));
    assert!(
        debug_str.contains("require_keep: true"),
        "ForgeConfig::default() must include `require_keep: true` so \
         production deployments fail-closed when Keep is absent. Today \
         a misconfigured deployment silently holds CA private keys in \
         the Store with no defense-in-depth."
    );
}

// Helper to stringify ForgeConfig via its fields without requiring Debug
// on the real type (which isn't derived).
struct ShowConfig<'a>(&'a ForgeConfig);
impl std::fmt::Debug for ShowConfig<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Render only the fields the test cares about, including
        // `require_keep` so the DEBT-6 ratchet remains honest against
        // future changes to the default.
        write!(
            f,
            "ForgeConfig {{ default_rotation_days: {}, default_drain_days: {}, default_ca_ttl_days: {}, scheduler_interval_secs: {}, policy_mode: {:?}, require_keep: {} }}",
            self.0.default_rotation_days,
            self.0.default_drain_days,
            self.0.default_ca_ttl_days,
            self.0.scheduler_interval_secs,
            self.0.policy_mode,
            self.0.require_keep,
        )
    }
}

// F-forge-7: the scheduler background task calls `engine.ca_rotate(..)`
// with `actor: None`, which then reaches `emit_audit_event` and records
// the actor as literal "anonymous". Auto-rotation events must be
// distinguishable from user-driven rotations — a shared "anonymous"
// string conflates automated security events with unknown users. The
// scheduler must pass a distinct system actor (e.g. "system:scheduler")
// so audit logs can differentiate.
#[tokio::test]
async fn debt_7_scheduler_auto_rotation_audit_must_not_use_anonymous() {
    // This test proves the scheduler path uses a non-anonymous actor by
    // reading the scheduler.rs source. The alternative — driving the
    // scheduler end-to-end — requires 24+ hours of wall time for
    // rotation eligibility.
    let src = include_str!("../src/scheduler.rs");
    let stripped: String = src
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    // The current code passes `None` for actor to ca_rotate/regenerate_crl.
    let has_anonymous_rotate = stripped.contains("engine.ca_rotate(&name, true, false, None)");
    let has_anonymous_crl = stripped.contains("engine.regenerate_crl(&name, None)");
    assert!(
        !has_anonymous_rotate && !has_anonymous_crl,
        "scheduler must pass a distinct system actor (e.g. \
         Some(\"system:scheduler\")) to audited operations. Passing \
         None renders as the string \"anonymous\" in audit events, \
         conflating automated security events with unauthenticated \
         user traffic."
    );
}
