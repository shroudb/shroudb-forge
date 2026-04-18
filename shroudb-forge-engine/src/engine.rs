use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use shroudb_acl::{PolicyEffect, PolicyEvaluator, PolicyPrincipal, PolicyRequest, PolicyResource};
use shroudb_chronicle_core::event::{Engine as AuditEngine, Event, EventResult};
use shroudb_chronicle_core::ops::ChronicleOps;
use shroudb_courier_core::ops::CourierOps;
use shroudb_forge_core::ca::{CaAlgorithm, CertificateAuthority, decode_key_material};
use shroudb_forge_core::cert::{CertState, IssuedCertificate, RevocationReason};
use shroudb_forge_core::crl;
use shroudb_forge_core::error::ForgeError;
use shroudb_forge_core::key_state::KeyState;
use shroudb_forge_core::profile::CertificateProfile;
use shroudb_forge_core::x509;
use shroudb_server_bootstrap::Capability;
use shroudb_store::Store;

use crate::ca_manager::{CaCreateOpts, CaManager};
use crate::capabilities::ForgeKeepOps;
use crate::cert_manager::{CertManager, CertSummary};

/// Configuration for the Forge engine.
pub struct ForgeConfig {
    pub default_rotation_days: u32,
    pub default_drain_days: u32,
    pub default_ca_ttl_days: u32,
    pub scheduler_interval_secs: u64,
    /// Policy enforcement mode. Default: fail-closed.
    pub policy_mode: PolicyMode,
}

impl Default for ForgeConfig {
    fn default() -> Self {
        Self {
            default_rotation_days: 365,
            default_drain_days: 90,
            default_ca_ttl_days: 3650,
            scheduler_interval_secs: 3600,
            policy_mode: PolicyMode::default(),
        }
    }
}

/// Result from a CA create or info operation.
#[derive(Debug)]
pub struct CaInfoResult {
    pub name: String,
    pub subject: String,
    pub algorithm: String,
    pub ttl_days: u32,
    pub parent: Option<String>,
    pub rotation_days: u32,
    pub drain_days: u32,
    pub disabled: bool,
    pub active_version: Option<u32>,
    pub key_versions: Vec<KeyVersionInfo>,
}

#[derive(Debug)]
pub struct KeyVersionInfo {
    pub version: u32,
    pub state: String,
    pub created_at: u64,
    pub activated_at: Option<u64>,
    pub draining_since: Option<u64>,
    pub retired_at: Option<u64>,
}

/// Result from a rotate operation.
#[derive(Debug)]
pub struct RotateResult {
    pub key_version: u32,
    pub previous_version: Option<u32>,
    pub rotated: bool,
}

/// Result from an issue operation.
#[derive(Debug)]
pub struct IssueResult {
    pub certificate_pem: String,
    pub private_key_pem: String,
    pub serial: String,
    pub not_before: u64,
    pub not_after: u64,
    pub ca_key_version: u32,
}

/// Result from an inspect operation.
#[derive(Debug)]
pub struct CertInfoResult {
    pub serial: String,
    pub ca_name: String,
    pub ca_key_version: u32,
    pub subject: String,
    pub profile: String,
    pub state: String,
    pub not_before: u64,
    pub not_after: u64,
    pub san_dns: Vec<String>,
    pub san_ip: Vec<String>,
    pub certificate_pem: String,
}

/// Policy enforcement mode for engine-level ABAC checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PolicyMode {
    /// Fail-closed: if no PolicyEvaluator is configured, deny all operations.
    #[default]
    Closed,
    /// Explicit opt-in to permissive mode: if no PolicyEvaluator is configured,
    /// allow all operations. Only appropriate for development/testing.
    Open,
}

/// The Forge certificate authority engine.
pub struct ForgeEngine<S: Store> {
    pub(crate) cas: CaManager<S>,
    pub(crate) certs: CertManager<S>,
    pub(crate) profiles: Vec<CertificateProfile>,
    pub(crate) config: ForgeConfig,
    policy_evaluator: Capability<Arc<dyn PolicyEvaluator>>,
    chronicle: Capability<Arc<dyn ChronicleOps>>,
    keep: Capability<Box<dyn ForgeKeepOps>>,
    courier: Capability<Arc<dyn CourierOps>>,
    /// Runtime-configurable scheduler interval (seconds). Updated via CONFIG SET.
    scheduler_interval: AtomicU64,
}

impl<S: Store> ForgeEngine<S> {
    /// Create a new Forge engine.
    ///
    /// Every capability slot is explicit: `Capability::Enabled(...)`,
    /// `Capability::DisabledForTests`, or
    /// `Capability::DisabledWithJustification("<reason>")`. Absence is
    /// never silent — operators must name why they're opting out.
    pub async fn new(
        store: Arc<S>,
        profiles: Vec<CertificateProfile>,
        config: ForgeConfig,
        policy_evaluator: Capability<Arc<dyn PolicyEvaluator>>,
        chronicle: Capability<Arc<dyn ChronicleOps>>,
        keep: Capability<Box<dyn ForgeKeepOps>>,
    ) -> Result<Self, ForgeError> {
        Self::new_with_capabilities(
            store,
            profiles,
            config,
            policy_evaluator,
            chronicle,
            keep,
            Capability::disabled(
                "courier rotation-notify not configured — use new_with_capabilities to wire it",
            ),
        )
        .await
    }

    /// Create a new Forge engine with all capability traits.
    pub async fn new_with_capabilities(
        store: Arc<S>,
        profiles: Vec<CertificateProfile>,
        config: ForgeConfig,
        policy_evaluator: Capability<Arc<dyn PolicyEvaluator>>,
        chronicle: Capability<Arc<dyn ChronicleOps>>,
        keep: Capability<Box<dyn ForgeKeepOps>>,
        courier: Capability<Arc<dyn CourierOps>>,
    ) -> Result<Self, ForgeError> {
        let cas = CaManager::new(store.clone());
        cas.init().await?;

        let certs = CertManager::new(store);

        for name in cas.list() {
            certs.init_for_ca(&name).await?;
        }

        let scheduler_interval = AtomicU64::new(config.scheduler_interval_secs);

        Ok(Self {
            cas,
            certs,
            profiles,
            config,
            policy_evaluator,
            chronicle,
            keep,
            courier,
            scheduler_interval,
        })
    }

    /// Access the courier capability (if configured).
    pub fn courier(&self) -> Option<&Arc<dyn CourierOps>> {
        self.courier.as_ref()
    }

    /// Current scheduler interval in seconds. Read by the scheduler each cycle.
    pub fn scheduler_interval_secs(&self) -> u64 {
        self.scheduler_interval.load(Ordering::Relaxed)
    }

    /// Get a configuration value by key.
    pub fn config_get(&self, key: &str) -> Result<serde_json::Value, ForgeError> {
        match key {
            "scheduler_interval_secs" => Ok(serde_json::json!(self.scheduler_interval_secs())),
            "default_rotation_days" => Ok(serde_json::json!(self.config.default_rotation_days)),
            "default_drain_days" => Ok(serde_json::json!(self.config.default_drain_days)),
            "default_ca_ttl_days" => Ok(serde_json::json!(self.config.default_ca_ttl_days)),
            _ => Err(ForgeError::InvalidArgument(format!(
                "unknown config key: {key}"
            ))),
        }
    }

    /// Set a configuration value by key. Only `scheduler_interval_secs` is
    /// runtime-configurable; other keys are read-only.
    pub fn config_set(&self, key: &str, value: &str) -> Result<(), ForgeError> {
        match key {
            "scheduler_interval_secs" => {
                let secs: u64 = value.parse().map_err(|_| {
                    ForgeError::InvalidArgument(format!(
                        "scheduler_interval_secs must be a positive integer, got: {value}"
                    ))
                })?;
                if secs == 0 {
                    return Err(ForgeError::InvalidArgument(
                        "scheduler_interval_secs must be > 0".into(),
                    ));
                }
                self.scheduler_interval.store(secs, Ordering::Relaxed);
                tracing::info!(key, value, "config updated");
                Ok(())
            }
            "default_rotation_days" | "default_drain_days" | "default_ca_ttl_days" => Err(
                ForgeError::InvalidArgument(format!("{key} is read-only at runtime")),
            ),
            _ => Err(ForgeError::InvalidArgument(format!(
                "unknown config key: {key}"
            ))),
        }
    }

    /// Emit an audit event to Chronicle. Fail-closed for security-critical
    /// operations — cert issuance and key rotation must not proceed unaudited.
    async fn emit_audit_event(
        &self,
        operation: &str,
        resource: &str,
        result: EventResult,
        actor: Option<&str>,
        start: Instant,
    ) -> Result<(), ForgeError> {
        let Some(chronicle) = self.chronicle.as_ref() else {
            return Ok(());
        };
        let mut event = Event::new(
            AuditEngine::Forge,
            operation.to_string(),
            "ca".to_string(),
            resource.to_string(),
            result,
            actor.unwrap_or("anonymous").to_string(),
        );
        event.duration_ms = start.elapsed().as_millis() as u64;
        chronicle
            .record(event)
            .await
            .map_err(|e| ForgeError::Internal(format!("audit failed: {e}")))
    }

    async fn check_policy(
        &self,
        resource_id: &str,
        action: &str,
        actor: Option<&str>,
    ) -> Result<(), ForgeError> {
        let Some(evaluator) = self.policy_evaluator.as_ref() else {
            if self.config.policy_mode == PolicyMode::Open {
                return Ok(());
            }
            return Err(ForgeError::PolicyDenied {
                action: action.to_string(),
                resource: resource_id.to_string(),
                policy: "no policy evaluator configured (fail-closed)".to_string(),
            });
        };
        let request = PolicyRequest {
            principal: PolicyPrincipal {
                id: actor.unwrap_or("").to_string(),
                roles: vec![],
                claims: Default::default(),
            },
            resource: PolicyResource {
                id: resource_id.to_string(),
                resource_type: "ca".to_string(),
                attributes: Default::default(),
            },
            action: action.to_string(),
        };
        let decision = evaluator
            .evaluate(&request)
            .await
            .map_err(|e| ForgeError::Internal(format!("policy evaluation: {e}")))?;
        if decision.effect == PolicyEffect::Deny {
            return Err(ForgeError::PolicyDenied {
                action: action.to_string(),
                resource: resource_id.to_string(),
                policy: decision.matched_policy.unwrap_or_default(),
            });
        }
        Ok(())
    }

    pub fn ca_manager(&self) -> &CaManager<S> {
        &self.cas
    }

    pub fn cert_manager(&self) -> &CertManager<S> {
        &self.certs
    }

    // ── CA management ───────────────────────────────────────────────

    pub async fn ca_create(
        &self,
        name: &str,
        algorithm: CaAlgorithm,
        mut opts: CaCreateOpts,
        actor: Option<&str>,
    ) -> Result<CaInfoResult, ForgeError> {
        let start = Instant::now();
        self.check_policy(name, "ca_create", actor).await?;
        // Apply config defaults for fields still at their default values
        let defaults = CaCreateOpts::default();
        if opts.ttl_days == defaults.ttl_days {
            opts.ttl_days = self.config.default_ca_ttl_days;
        }
        if opts.rotation_days == defaults.rotation_days {
            opts.rotation_days = self.config.default_rotation_days;
        }
        if opts.drain_days == defaults.drain_days {
            opts.drain_days = self.config.default_drain_days;
        }
        let ca = self.cas.create(name, algorithm, opts).await?;
        // Initialize cert namespace for the new CA
        self.certs.init_for_ca(name).await?;

        // Store key material in Keep for defense-in-depth encryption
        if let Some(keep) = self.keep.as_ref() {
            let active = ca.active_key().ok_or_else(|| ForgeError::NoActiveKey {
                ca: name.to_string(),
            })?;
            if let Some(ref km) = active.key_material {
                let path = format!("forge/{name}/v{}", active.version);
                keep.store_key(&path, km.as_bytes()).await?;
                tracing::info!(ca = name, version = active.version, "CA key stored in Keep");
            }
        }

        self.emit_audit_event("CA_CREATE", name, EventResult::Ok, actor, start)
            .await?;
        Ok(ca_to_info(&ca))
    }

    pub fn ca_info(&self, name: &str) -> Result<CaInfoResult, ForgeError> {
        let ca = self.cas.get(name)?;
        Ok(ca_to_info(&ca))
    }

    pub fn ca_list(&self) -> Vec<String> {
        self.cas.list()
    }

    pub async fn ca_rotate(
        &self,
        name: &str,
        force: bool,
        dryrun: bool,
        actor: Option<&str>,
    ) -> Result<RotateResult, ForgeError> {
        let start = Instant::now();
        self.check_policy(name, "ca_rotate", actor).await?;
        let ca = self.cas.get(name)?;

        if ca.disabled {
            return Err(ForgeError::CaDisabled {
                name: name.to_string(),
            });
        }

        let active = ca.active_key().ok_or_else(|| ForgeError::NoActiveKey {
            ca: name.to_string(),
        })?;

        // Check if rotation is due
        let now = unix_now();
        let age_days = active
            .activated_at
            .map(|at| now.saturating_sub(at) / 86400)
            .unwrap_or(0);

        if !force && age_days < ca.rotation_days as u64 {
            return Ok(RotateResult {
                key_version: active.version,
                previous_version: None,
                rotated: false,
            });
        }

        if dryrun {
            return Ok(RotateResult {
                key_version: ca.next_version(),
                previous_version: Some(active.version),
                rotated: true,
            });
        }

        // Generate new key
        let generated = x509::generate_ca_certificate(&ca.subject, ca.algorithm, ca.ttl_days)?;
        let new_version = ca.next_version();
        let previous_version = active.version;

        self.cas
            .update(name, |ca| {
                // Demote current active to draining
                if let Some(active_key) = ca.active_key_mut() {
                    active_key.state = KeyState::Draining;
                    active_key.draining_since = Some(now);
                }

                // Add new active key
                ca.key_versions.push(shroudb_forge_core::ca::CaKeyVersion {
                    version: new_version,
                    state: KeyState::Active,
                    key_material: Some(hex::encode(generated.private_key.as_bytes())),
                    public_key: Some(hex::encode(&generated.public_key)),
                    certificate_pem: generated.certificate_pem.clone(),
                    created_at: now,
                    activated_at: Some(now),
                    draining_since: None,
                    retired_at: None,
                });

                Ok(())
            })
            .await?;

        tracing::info!(ca = name, new_version, previous_version, "CA key rotated");

        // Store new key material in Keep for defense-in-depth encryption
        if let Some(keep) = self.keep.as_ref() {
            let path = format!("forge/{name}/v{new_version}");
            keep.store_key(&path, generated.private_key.as_bytes())
                .await?;
            tracing::info!(
                ca = name,
                version = new_version,
                "rotated CA key stored in Keep"
            );
        }

        self.emit_audit_event("CA_ROTATE", name, EventResult::Ok, actor, start)
            .await?;
        Ok(RotateResult {
            key_version: new_version,
            previous_version: Some(previous_version),
            rotated: true,
        })
    }

    pub fn ca_export(&self, name: &str) -> Result<String, ForgeError> {
        let ca = self.cas.get(name)?;
        let active = ca.active_key().ok_or_else(|| ForgeError::NoActiveKey {
            ca: name.to_string(),
        })?;
        Ok(active.certificate_pem.clone())
    }

    // ── Certificate operations ──────────────────────────────────────

    #[allow(clippy::too_many_arguments)]
    pub async fn issue(
        &self,
        ca_name: &str,
        subject: &str,
        profile_name: &str,
        ttl: Option<&str>,
        san_dns: &[String],
        san_ip: &[String],
        actor: Option<&str>,
    ) -> Result<IssueResult, ForgeError> {
        let start = Instant::now();
        self.check_policy(ca_name, "issue", actor).await?;
        let ca = self.cas.get(ca_name)?;
        if ca.disabled {
            return Err(ForgeError::CaDisabled {
                name: ca_name.to_string(),
            });
        }

        let active = ca.active_key().ok_or_else(|| ForgeError::NoActiveKey {
            ca: ca_name.to_string(),
        })?;

        let profile = self
            .profiles
            .iter()
            .find(|p| p.name == profile_name)
            .ok_or_else(|| ForgeError::ProfileNotFound {
                name: profile_name.to_string(),
            })?;

        // Validate SANs against profile
        if !san_dns.is_empty() && !profile.allow_san_dns {
            return Err(ForgeError::SanDnsNotAllowed {
                profile: profile_name.to_string(),
            });
        }
        if !san_ip.is_empty() && !profile.allow_san_ip {
            return Err(ForgeError::SanIpNotAllowed {
                profile: profile_name.to_string(),
            });
        }

        // Determine TTL
        let ttl_str = ttl.unwrap_or(&profile.default_ttl);
        let ttl_secs = CertificateProfile::parse_ttl(ttl_str)
            .ok_or_else(|| ForgeError::InvalidArgument(format!("invalid TTL: {ttl_str}")))?;

        // Validate TTL against profile max
        let ttl_days = ttl_secs.div_ceil(86400);
        if ttl_days > profile.max_ttl_days as u64 {
            return Err(ForgeError::TtlExceedsMax {
                requested_days: ttl_days as u32,
                max_days: profile.max_ttl_days,
            });
        }

        let issued = x509::issue_certificate(&x509::IssueCertParams {
            ca_key_version: active,
            ca_subject: &ca.subject,
            ca_algorithm: ca.algorithm,
            subject,
            profile,
            ttl_secs,
            san_dns,
            san_ip,
        })?;

        let now = unix_now();
        let cert_meta = IssuedCertificate {
            serial: issued.serial.clone(),
            ca_name: ca_name.to_string(),
            ca_key_version: active.version,
            subject: subject.to_string(),
            profile: profile_name.to_string(),
            state: CertState::Active,
            not_before: issued.not_before,
            not_after: issued.not_after,
            san_dns: san_dns.to_vec(),
            san_ip: san_ip.to_vec(),
            issued_at: now,
            revoked_at: None,
            revocation_reason: None,
            certificate_pem: issued.certificate_pem.clone(),
        };

        self.certs.store_cert(cert_meta).await?;

        let resource = format!("{ca_name}/{}", issued.serial);
        self.emit_audit_event("ISSUE", &resource, EventResult::Ok, actor, start)
            .await?;
        Ok(IssueResult {
            certificate_pem: issued.certificate_pem,
            private_key_pem: issued.private_key_pem,
            serial: issued.serial,
            not_before: issued.not_before,
            not_after: issued.not_after,
            ca_key_version: active.version,
        })
    }

    pub async fn issue_from_csr(
        &self,
        ca_name: &str,
        csr_pem: &str,
        profile_name: &str,
        ttl: Option<&str>,
        actor: Option<&str>,
    ) -> Result<IssueResult, ForgeError> {
        let start = Instant::now();
        self.check_policy(ca_name, "issue", actor).await?;
        let ca = self.cas.get(ca_name)?;
        if ca.disabled {
            return Err(ForgeError::CaDisabled {
                name: ca_name.to_string(),
            });
        }

        let active = ca.active_key().ok_or_else(|| ForgeError::NoActiveKey {
            ca: ca_name.to_string(),
        })?;

        let profile = self
            .profiles
            .iter()
            .find(|p| p.name == profile_name)
            .ok_or_else(|| ForgeError::ProfileNotFound {
                name: profile_name.to_string(),
            })?;

        let ttl_str = ttl.unwrap_or(&profile.default_ttl);
        let ttl_secs = CertificateProfile::parse_ttl(ttl_str)
            .ok_or_else(|| ForgeError::InvalidArgument(format!("invalid TTL: {ttl_str}")))?;

        // Validate TTL against profile max
        let ttl_days = ttl_secs.div_ceil(86400);
        if ttl_days > profile.max_ttl_days as u64 {
            return Err(ForgeError::TtlExceedsMax {
                requested_days: ttl_days as u32,
                max_days: profile.max_ttl_days,
            });
        }

        // Extract subject from CSR for metadata (best-effort, fallback to "CSR")
        let csr_subject = rcgen::CertificateSigningRequestParams::from_pem(csr_pem)
            .ok()
            .and_then(|p| {
                let dn = &p.params.distinguished_name;
                let cn = dn.iter().find_map(|(dt, s)| {
                    if *dt == rcgen::DnType::CommonName {
                        match s {
                            rcgen::DnValue::Utf8String(v) => Some(v.clone()),
                            rcgen::DnValue::PrintableString(v) => Some(v.to_string()),
                            _ => None,
                        }
                    } else {
                        None
                    }
                });
                cn.map(|cn| format!("CN={cn}"))
            })
            .unwrap_or_else(|| "CSR".to_string());

        let issued = x509::issue_from_csr(active, &ca.subject, ca.algorithm, csr_pem, ttl_secs)?;

        let now = unix_now();
        let cert_meta = IssuedCertificate {
            serial: issued.serial.clone(),
            ca_name: ca_name.to_string(),
            ca_key_version: active.version,
            subject: csr_subject,
            profile: profile_name.to_string(),
            state: CertState::Active,
            not_before: issued.not_before,
            not_after: issued.not_after,
            san_dns: vec![],
            san_ip: vec![],
            issued_at: now,
            revoked_at: None,
            revocation_reason: None,
            certificate_pem: issued.certificate_pem.clone(),
        };

        self.certs.store_cert(cert_meta).await?;

        let resource = format!("{ca_name}/{}", issued.serial);
        self.emit_audit_event("ISSUE_FROM_CSR", &resource, EventResult::Ok, actor, start)
            .await?;
        Ok(IssueResult {
            certificate_pem: issued.certificate_pem,
            private_key_pem: issued.private_key_pem,
            serial: issued.serial,
            not_before: issued.not_before,
            not_after: issued.not_after,
            ca_key_version: active.version,
        })
    }

    pub async fn revoke(
        &self,
        ca_name: &str,
        serial: &str,
        reason: Option<RevocationReason>,
        actor: Option<&str>,
    ) -> Result<(), ForgeError> {
        let start = Instant::now();
        self.check_policy(ca_name, "revoke", actor).await?;
        let cert = self
            .certs
            .get(ca_name, serial)
            .ok_or_else(|| ForgeError::CertNotFound {
                ca: ca_name.to_string(),
                serial: serial.to_string(),
            })?;

        if cert.state == CertState::Revoked {
            return Err(ForgeError::CertAlreadyRevoked {
                serial: serial.to_string(),
            });
        }

        let now = unix_now();

        // Generate CRL *before* committing the revocation. Build the revoked
        // entry list from the store, then append this cert as a pending
        // revocation. If CRL generation fails the cert stays Active and the
        // caller gets an error they can retry.
        let ca = self.cas.get(ca_name)?;
        let active = ca.active_key().ok_or_else(|| ForgeError::NoActiveKey {
            ca: ca_name.to_string(),
        })?;
        let key_der = decode_key_material(active)?;
        let mut revoked = self.certs.revoked_for_crl(ca_name);
        revoked.push(crl::CrlRevokedEntry {
            serial_hex: serial.to_string(),
            revoked_at: now,
        });
        let crl_pem =
            crl::generate_crl_pem(key_der.as_bytes(), &ca.subject, ca.algorithm, &revoked)?;

        // CRL succeeded — now commit the revocation to the Store.
        self.certs
            .update(ca_name, serial, |cert| {
                cert.state = CertState::Revoked;
                cert.revoked_at = Some(now);
                cert.revocation_reason = reason;
            })
            .await?;

        self.certs.set_crl_pem(ca_name, crl_pem);

        let resource = format!("{ca_name}/{serial}");
        self.emit_audit_event("REVOKE", &resource, EventResult::Ok, actor, start)
            .await?;
        tracing::info!(ca = ca_name, serial, "certificate revoked");
        Ok(())
    }

    pub fn inspect(&self, ca_name: &str, serial: &str) -> Result<CertInfoResult, ForgeError> {
        let cert = self
            .certs
            .get(ca_name, serial)
            .ok_or_else(|| ForgeError::CertNotFound {
                ca: ca_name.to_string(),
                serial: serial.to_string(),
            })?;

        let now = unix_now();
        let state = cert.effective_state(now).to_string();
        Ok(CertInfoResult {
            serial: cert.serial,
            ca_name: cert.ca_name,
            ca_key_version: cert.ca_key_version,
            subject: cert.subject,
            profile: cert.profile,
            state,
            not_before: cert.not_before,
            not_after: cert.not_after,
            san_dns: cert.san_dns,
            san_ip: cert.san_ip,
            certificate_pem: cert.certificate_pem,
        })
    }

    pub fn list_certs(
        &self,
        ca_name: &str,
        state_filter: Option<CertState>,
        limit: Option<usize>,
        offset: Option<usize>,
    ) -> Vec<CertSummary> {
        let now = unix_now();
        self.certs.list_certs(
            ca_name,
            state_filter,
            now,
            limit.unwrap_or(100),
            offset.unwrap_or(0),
        )
    }

    pub async fn renew(
        &self,
        ca_name: &str,
        serial: &str,
        ttl: Option<&str>,
        actor: Option<&str>,
    ) -> Result<IssueResult, ForgeError> {
        self.check_policy(ca_name, "renew", actor).await?;
        let cert = self
            .certs
            .get(ca_name, serial)
            .ok_or_else(|| ForgeError::CertNotFound {
                ca: ca_name.to_string(),
                serial: serial.to_string(),
            })?;

        if cert.state == CertState::Revoked {
            return Err(ForgeError::CertAlreadyRevoked {
                serial: serial.to_string(),
            });
        }

        self.issue(
            ca_name,
            &cert.subject,
            &cert.profile,
            ttl,
            &cert.san_dns,
            &cert.san_ip,
            actor,
        )
        .await
    }

    /// Regenerate the CRL for a CA.
    pub async fn regenerate_crl(
        &self,
        ca_name: &str,
        actor: Option<&str>,
    ) -> Result<(), ForgeError> {
        let start = Instant::now();
        self.check_policy(ca_name, "regenerate_crl", actor).await?;
        let ca = self.cas.get(ca_name)?;
        let active = ca.active_key().ok_or_else(|| ForgeError::NoActiveKey {
            ca: ca_name.to_string(),
        })?;

        let key_der = decode_key_material(active)?;
        let revoked = self.certs.revoked_for_crl(ca_name);

        let crl_pem =
            crl::generate_crl_pem(key_der.as_bytes(), &ca.subject, ca.algorithm, &revoked)?;

        self.certs.set_crl_pem(ca_name, crl_pem);
        self.emit_audit_event("REGENERATE_CRL", ca_name, EventResult::Ok, actor, start)
            .await?;
        Ok(())
    }
}

fn ca_to_info(ca: &CertificateAuthority) -> CaInfoResult {
    let active_version = ca.active_key().map(|k| k.version);
    let key_versions = ca
        .key_versions
        .iter()
        .map(|kv| KeyVersionInfo {
            version: kv.version,
            state: kv.state.to_string(),
            created_at: kv.created_at,
            activated_at: kv.activated_at,
            draining_since: kv.draining_since,
            retired_at: kv.retired_at,
        })
        .collect();

    CaInfoResult {
        name: ca.name.clone(),
        subject: ca.subject.clone(),
        algorithm: ca.algorithm.wire_name().to_string(),
        ttl_days: ca.ttl_days,
        parent: ca.parent.clone(),
        rotation_days: ca.rotation_days,
        drain_days: ca.drain_days,
        disabled: ca.disabled,
        active_version,
        key_versions,
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_profiles() -> Vec<CertificateProfile> {
        vec![
            CertificateProfile {
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
            CertificateProfile {
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

    async fn setup() -> ForgeEngine<shroudb_storage::EmbeddedStore> {
        let store = shroudb_storage::test_util::create_test_store("forge-test").await;
        let config = ForgeConfig {
            policy_mode: PolicyMode::Open,
            ..Default::default()
        };
        ForgeEngine::new(
            store,
            test_profiles(),
            config,
            Capability::DisabledForTests,
            Capability::DisabledForTests,
            Capability::DisabledForTests,
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn ca_create_and_info() {
        let engine = setup().await;

        let info = engine
            .ca_create(
                "internal",
                CaAlgorithm::EcdsaP256,
                CaCreateOpts {
                    subject: "CN=Internal CA,O=Test".into(),
                    ..Default::default()
                },
                None,
            )
            .await
            .unwrap();

        assert_eq!(info.name, "internal");
        assert_eq!(info.algorithm, "ecdsa-p256");
        assert_eq!(info.active_version, Some(1));

        let fetched = engine.ca_info("internal").unwrap();
        assert_eq!(fetched.name, "internal");
    }

    #[tokio::test]
    async fn ca_list() {
        let engine = setup().await;

        engine
            .ca_create(
                "a",
                CaAlgorithm::EcdsaP256,
                CaCreateOpts {
                    subject: "CN=A".into(),
                    ..Default::default()
                },
                None,
            )
            .await
            .unwrap();
        engine
            .ca_create(
                "b",
                CaAlgorithm::Ed25519,
                CaCreateOpts {
                    subject: "CN=B".into(),
                    ..Default::default()
                },
                None,
            )
            .await
            .unwrap();

        let mut names = engine.ca_list();
        names.sort();
        assert_eq!(names, vec!["a", "b"]);
    }

    #[tokio::test]
    async fn issue_and_inspect() {
        let engine = setup().await;

        engine
            .ca_create(
                "internal",
                CaAlgorithm::EcdsaP256,
                CaCreateOpts {
                    subject: "CN=Internal CA".into(),
                    ..Default::default()
                },
                None,
            )
            .await
            .unwrap();

        let issued = engine
            .issue(
                "internal",
                "CN=myservice",
                "server",
                Some("24h"),
                &["myservice.local".into()],
                &[],
                None,
            )
            .await
            .unwrap();

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

        let info = engine.inspect("internal", &issued.serial).unwrap();
        assert_eq!(info.subject, "CN=myservice");
        assert_eq!(info.profile, "server");
        assert_eq!(info.state, "active");
    }

    #[tokio::test]
    async fn revoke_certificate() {
        let engine = setup().await;

        engine
            .ca_create(
                "internal",
                CaAlgorithm::EcdsaP256,
                CaCreateOpts {
                    subject: "CN=Internal CA".into(),
                    ..Default::default()
                },
                None,
            )
            .await
            .unwrap();

        let issued = engine
            .issue("internal", "CN=svc", "server", None, &[], &[], None)
            .await
            .unwrap();

        engine
            .revoke(
                "internal",
                &issued.serial,
                Some(RevocationReason::Superseded),
                None,
            )
            .await
            .unwrap();

        let info = engine.inspect("internal", &issued.serial).unwrap();
        assert_eq!(info.state, "revoked");
    }

    #[tokio::test]
    async fn revoke_fails_if_crl_generation_fails() {
        let engine = setup().await;

        engine
            .ca_create(
                "internal",
                CaAlgorithm::EcdsaP256,
                CaCreateOpts {
                    subject: "CN=Internal CA".into(),
                    ..Default::default()
                },
                None,
            )
            .await
            .unwrap();

        let issued = engine
            .issue("internal", "CN=svc", "server", None, &[], &[], None)
            .await
            .unwrap();

        // Force all keys to Retired state so active_key() returns None,
        // which makes CRL generation fail with NoActiveKey.
        engine
            .cas
            .update("internal", |ca| {
                for kv in &mut ca.key_versions {
                    kv.state = KeyState::Retired;
                    kv.retired_at = Some(1);
                    kv.key_material = None;
                }
                Ok(())
            })
            .await
            .unwrap();

        // Revoke should fail because CRL generation requires an active key.
        let err = engine
            .revoke(
                "internal",
                &issued.serial,
                Some(RevocationReason::Superseded),
                None,
            )
            .await
            .unwrap_err();

        assert!(
            matches!(err, ForgeError::NoActiveKey { .. }),
            "expected NoActiveKey error, got: {err}"
        );

        // The cert must still be Active — revocation was not committed.
        let info = engine.inspect("internal", &issued.serial).unwrap();
        assert_eq!(
            info.state, "active",
            "cert should remain active when CRL generation fails"
        );
    }

    #[tokio::test]
    async fn ca_rotate() {
        let engine = setup().await;

        engine
            .ca_create(
                "internal",
                CaAlgorithm::EcdsaP256,
                CaCreateOpts {
                    subject: "CN=Internal CA".into(),
                    ..Default::default()
                },
                None,
            )
            .await
            .unwrap();

        let result = engine
            .ca_rotate("internal", true, false, None)
            .await
            .unwrap();
        assert!(result.rotated);
        assert_eq!(result.key_version, 2);
        assert_eq!(result.previous_version, Some(1));

        let info = engine.ca_info("internal").unwrap();
        assert_eq!(info.active_version, Some(2));
        assert_eq!(info.key_versions.len(), 2);
        assert_eq!(info.key_versions[0].state, "Draining");
        assert_eq!(info.key_versions[1].state, "Active");
    }

    #[tokio::test]
    async fn ca_export() {
        let engine = setup().await;

        engine
            .ca_create(
                "internal",
                CaAlgorithm::EcdsaP256,
                CaCreateOpts {
                    subject: "CN=Internal CA".into(),
                    ..Default::default()
                },
                None,
            )
            .await
            .unwrap();

        let pem = engine.ca_export("internal").unwrap();
        assert!(pem.starts_with("-----BEGIN CERTIFICATE-----"));
    }

    #[tokio::test]
    async fn list_certs() {
        let engine = setup().await;

        engine
            .ca_create(
                "internal",
                CaAlgorithm::EcdsaP256,
                CaCreateOpts {
                    subject: "CN=Internal CA".into(),
                    ..Default::default()
                },
                None,
            )
            .await
            .unwrap();

        engine
            .issue("internal", "CN=svc1", "server", None, &[], &[], None)
            .await
            .unwrap();
        engine
            .issue("internal", "CN=svc2", "server", None, &[], &[], None)
            .await
            .unwrap();

        let certs = engine.list_certs("internal", None, None, None);
        assert_eq!(certs.len(), 2);
    }

    #[tokio::test]
    async fn profile_validation() {
        let engine = setup().await;

        engine
            .ca_create(
                "internal",
                CaAlgorithm::EcdsaP256,
                CaCreateOpts {
                    subject: "CN=Internal CA".into(),
                    ..Default::default()
                },
                None,
            )
            .await
            .unwrap();

        // client profile doesn't allow SAN DNS
        let err = engine
            .issue(
                "internal",
                "CN=svc",
                "client",
                None,
                &["svc.local".into()],
                &[],
                None,
            )
            .await
            .unwrap_err();
        assert!(matches!(err, ForgeError::SanDnsNotAllowed { .. }));

        // Unknown profile
        let err = engine
            .issue("internal", "CN=svc", "nonexistent", None, &[], &[], None)
            .await
            .unwrap_err();
        assert!(matches!(err, ForgeError::ProfileNotFound { .. }));
    }

    // ── KeepOps tests ──────────────────────────────────────────────

    use std::sync::Mutex;

    use crate::capabilities::ForgeKeepOps;

    /// Mock implementation of ForgeKeepOps that records calls.
    struct MockKeepOps {
        stored: Mutex<Vec<(String, Vec<u8>)>>,
    }

    impl MockKeepOps {
        fn new() -> Self {
            Self {
                stored: Mutex::new(Vec::new()),
            }
        }

        fn stored_keys(&self) -> Vec<(String, Vec<u8>)> {
            self.stored.lock().unwrap().clone()
        }
    }

    impl ForgeKeepOps for MockKeepOps {
        fn store_key(
            &self,
            path: &str,
            key_material: &[u8],
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<u64, ForgeError>> + Send + '_>>
        {
            self.stored
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

    async fn setup_with_keep(
        keep: Box<dyn ForgeKeepOps>,
    ) -> ForgeEngine<shroudb_storage::EmbeddedStore> {
        let store = shroudb_storage::test_util::create_test_store("forge-test").await;
        let config = ForgeConfig {
            policy_mode: PolicyMode::Open,
            ..Default::default()
        };
        ForgeEngine::new_with_capabilities(
            store,
            test_profiles(),
            config,
            Capability::DisabledForTests,
            Capability::DisabledForTests,
            Capability::Enabled(keep),
            Capability::DisabledForTests,
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn test_ca_create_stores_key_in_keep() {
        let mock = Arc::new(MockKeepOps::new());
        // Wrap in a forwarding adapter so we can inspect mock after engine takes ownership
        struct ForwardKeep(Arc<MockKeepOps>);
        impl ForgeKeepOps for ForwardKeep {
            fn store_key(
                &self,
                path: &str,
                key_material: &[u8],
            ) -> std::pin::Pin<
                Box<dyn std::future::Future<Output = Result<u64, ForgeError>> + Send + '_>,
            > {
                self.0.store_key(path, key_material)
            }
            fn get_key(
                &self,
                path: &str,
            ) -> std::pin::Pin<
                Box<dyn std::future::Future<Output = Result<Vec<u8>, ForgeError>> + Send + '_>,
            > {
                self.0.get_key(path)
            }
        }

        let engine = setup_with_keep(Box::new(ForwardKeep(mock.clone()))).await;

        engine
            .ca_create(
                "internal",
                CaAlgorithm::EcdsaP256,
                CaCreateOpts {
                    subject: "CN=Internal CA".into(),
                    ..Default::default()
                },
                None,
            )
            .await
            .unwrap();

        let stored = mock.stored_keys();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].0, "forge/internal/v1");
        assert!(!stored[0].1.is_empty(), "key material must not be empty");
    }

    #[tokio::test]
    async fn test_ca_rotate_stores_new_key_in_keep() {
        let mock = Arc::new(MockKeepOps::new());
        struct ForwardKeep(Arc<MockKeepOps>);
        impl ForgeKeepOps for ForwardKeep {
            fn store_key(
                &self,
                path: &str,
                key_material: &[u8],
            ) -> std::pin::Pin<
                Box<dyn std::future::Future<Output = Result<u64, ForgeError>> + Send + '_>,
            > {
                self.0.store_key(path, key_material)
            }
            fn get_key(
                &self,
                path: &str,
            ) -> std::pin::Pin<
                Box<dyn std::future::Future<Output = Result<Vec<u8>, ForgeError>> + Send + '_>,
            > {
                self.0.get_key(path)
            }
        }

        let engine = setup_with_keep(Box::new(ForwardKeep(mock.clone()))).await;

        engine
            .ca_create(
                "internal",
                CaAlgorithm::EcdsaP256,
                CaCreateOpts {
                    subject: "CN=Internal CA".into(),
                    ..Default::default()
                },
                None,
            )
            .await
            .unwrap();

        // Force rotation
        engine
            .ca_rotate("internal", true, false, None)
            .await
            .unwrap();

        let stored = mock.stored_keys();
        assert_eq!(stored.len(), 2);
        assert_eq!(stored[0].0, "forge/internal/v1");
        assert_eq!(stored[1].0, "forge/internal/v2");
        assert!(
            !stored[1].1.is_empty(),
            "rotated key material must not be empty"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_concurrent_issue_from_same_ca() {
        let engine = Arc::new(setup().await);

        engine
            .ca_create(
                "concurrent-ca",
                CaAlgorithm::EcdsaP256,
                CaCreateOpts {
                    subject: "CN=Concurrent CA".into(),
                    ..Default::default()
                },
                None,
            )
            .await
            .unwrap();

        let mut handles = Vec::new();
        for i in 0..5 {
            let eng = engine.clone();
            handles.push(tokio::spawn(async move {
                eng.issue(
                    "concurrent-ca",
                    &format!("CN=svc-{i}"),
                    "server",
                    Some("1h"),
                    &[],
                    &[],
                    None,
                )
                .await
            }));
        }

        let mut serials = std::collections::HashSet::new();
        for handle in handles {
            let result = handle.await.unwrap().unwrap();
            assert!(
                result
                    .certificate_pem
                    .starts_with("-----BEGIN CERTIFICATE-----"),
                "cert PEM must be valid"
            );
            assert!(
                serials.insert(result.serial.clone()),
                "duplicate serial detected: {}",
                result.serial
            );
        }
        assert_eq!(serials.len(), 5, "all 5 certs must have unique serials");

        // Verify CA state is consistent — all certs are listed.
        let certs = engine.list_certs("concurrent-ca", None, None, None);
        assert_eq!(certs.len(), 5, "CA must list all 5 issued certs");
    }

    // ── Policy mode tests (MED-19) ──────────────────────────────────

    #[tokio::test]
    async fn no_evaluator_default_closed_denies() {
        let store = shroudb_storage::test_util::create_test_store("forge-closed-test").await;
        // Default PolicyMode::Closed, no evaluator
        let engine = ForgeEngine::new(
            store,
            test_profiles(),
            ForgeConfig::default(),
            Capability::DisabledForTests,
            Capability::DisabledForTests,
            Capability::DisabledForTests,
        )
        .await
        .unwrap();

        let err = engine
            .ca_create(
                "test-ca",
                CaAlgorithm::EcdsaP256,
                CaCreateOpts {
                    subject: "CN=Test".into(),
                    ..Default::default()
                },
                None,
            )
            .await;
        assert!(err.is_err(), "fail-closed should deny without evaluator");
        let msg = err.unwrap_err().to_string();
        assert!(
            msg.contains("no policy evaluator configured"),
            "expected fail-closed message, got: {msg}"
        );
    }

    #[tokio::test]
    async fn explicit_open_mode_permits() {
        let store = shroudb_storage::test_util::create_test_store("forge-open-test").await;
        let config = ForgeConfig {
            policy_mode: PolicyMode::Open,
            ..Default::default()
        };
        let engine = ForgeEngine::new(
            store,
            test_profiles(),
            config,
            Capability::DisabledForTests,
            Capability::DisabledForTests,
            Capability::DisabledForTests,
        )
        .await
        .unwrap();

        let result = engine
            .ca_create(
                "open-ca",
                CaAlgorithm::EcdsaP256,
                CaCreateOpts {
                    subject: "CN=Open".into(),
                    ..Default::default()
                },
                None,
            )
            .await;
        assert!(
            result.is_ok(),
            "open mode should allow: {}",
            result.unwrap_err()
        );
    }
}
