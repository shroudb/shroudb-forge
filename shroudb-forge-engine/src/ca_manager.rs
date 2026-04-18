//! Store-backed CA management with in-memory cache.
//!
//! All read operations serve from the in-memory DashMap cache.
//! Mutations write-through to the Store, then update the cache.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use dashmap::DashMap;
use shroudb_forge_core::ca::{CaAlgorithm, CaKeyVersion, CertificateAuthority};
use shroudb_forge_core::error::ForgeError;
use shroudb_forge_core::key_state::KeyState;
use shroudb_forge_core::name::validate_name;
use shroudb_forge_core::x509;
use shroudb_store::Store;
use zeroize::Zeroize;

const CAS_NAMESPACE: &str = "forge.cas";

/// Options for creating a new CA.
pub struct CaCreateOpts {
    pub subject: String,
    pub ttl_days: u32,
    pub parent: Option<String>,
    pub rotation_days: u32,
    pub drain_days: u32,
}

impl Default for CaCreateOpts {
    fn default() -> Self {
        Self {
            subject: String::new(),
            ttl_days: 3650,
            parent: None,
            rotation_days: 365,
            drain_days: 90,
        }
    }
}

/// Manages Certificate Authorities with Store-backed persistence and in-memory cache.
pub struct CaManager<S: Store> {
    store: Arc<S>,
    cache: DashMap<String, Arc<CertificateAuthority>>,
}

impl<S: Store> CaManager<S> {
    pub fn new(store: Arc<S>) -> Self {
        Self {
            store,
            cache: DashMap::new(),
        }
    }

    /// Initialize: create namespace and load all CAs into cache.
    pub async fn init(&self) -> Result<(), ForgeError> {
        match self
            .store
            .namespace_create(CAS_NAMESPACE, shroudb_store::NamespaceConfig::default())
            .await
        {
            Ok(()) => {}
            Err(shroudb_store::StoreError::NamespaceExists(_)) => {}
            Err(e) => return Err(ForgeError::Store(e.to_string())),
        }

        let mut cursor = None;
        loop {
            let page = self
                .store
                .list(CAS_NAMESPACE, None, cursor.as_deref(), 100)
                .await
                .map_err(|e| ForgeError::Store(e.to_string()))?;

            for key in &page.keys {
                let entry = self
                    .store
                    .get(CAS_NAMESPACE, key, None)
                    .await
                    .map_err(|e| ForgeError::Store(e.to_string()))?;
                let ca: CertificateAuthority = serde_json::from_slice(&entry.value)
                    .map_err(|e| ForgeError::Internal(format!("corrupt CA data: {e}")))?;
                self.cache.insert(ca.name.clone(), Arc::new(ca));
            }

            if page.cursor.is_none() {
                break;
            }
            cursor = page.cursor;
        }

        let count = self.cache.len();
        if count > 0 {
            tracing::info!(count, "loaded CAs from store");
        }

        Ok(())
    }

    /// Create a new root CA with the first Active key version.
    pub async fn create(
        &self,
        name: &str,
        algorithm: CaAlgorithm,
        opts: CaCreateOpts,
    ) -> Result<Arc<CertificateAuthority>, ForgeError> {
        validate_name(name)?;

        if self.cache.contains_key(name) {
            return Err(ForgeError::CaAlreadyExists {
                name: name.to_string(),
            });
        }

        let now = unix_now();

        let ca = if let Some(ref parent_name) = opts.parent {
            // Intermediate CA: signed by parent
            let parent = self.get(parent_name)?;
            let parent_active = parent.active_key().ok_or_else(|| ForgeError::NoActiveKey {
                ca: parent_name.clone(),
            })?;

            let generated = x509::generate_intermediate_ca_certificate(
                &opts.subject,
                algorithm,
                opts.ttl_days,
                parent_active,
                &parent.subject,
                parent.algorithm,
            )?;

            let key_version = CaKeyVersion {
                version: 1,
                state: KeyState::Active,
                key_material: Some(hex::encode(generated.private_key.as_bytes())),
                public_key: Some(hex::encode(&generated.public_key)),
                certificate_pem: generated.certificate_pem,
                created_at: now,
                activated_at: Some(now),
                draining_since: None,
                retired_at: None,
            };

            CertificateAuthority {
                name: name.to_string(),
                subject: opts.subject,
                algorithm,
                ttl_days: opts.ttl_days,
                parent: Some(parent_name.clone()),
                rotation_days: opts.rotation_days,
                drain_days: opts.drain_days,
                created_at: now,
                disabled: false,
                key_versions: vec![key_version],
            }
        } else {
            // Self-signed root CA
            let generated = x509::generate_ca_certificate(&opts.subject, algorithm, opts.ttl_days)?;

            let key_version = CaKeyVersion {
                version: 1,
                state: KeyState::Active,
                key_material: Some(hex::encode(generated.private_key.as_bytes())),
                public_key: Some(hex::encode(&generated.public_key)),
                certificate_pem: generated.certificate_pem,
                created_at: now,
                activated_at: Some(now),
                draining_since: None,
                retired_at: None,
            };

            CertificateAuthority {
                name: name.to_string(),
                subject: opts.subject,
                algorithm,
                ttl_days: opts.ttl_days,
                parent: None,
                rotation_days: opts.rotation_days,
                drain_days: opts.drain_days,
                created_at: now,
                disabled: false,
                key_versions: vec![key_version],
            }
        };

        self.save(&ca).await?;
        let ca = Arc::new(ca);
        self.cache.insert(name.to_string(), Arc::clone(&ca));

        tracing::info!(
            ca = name,
            algorithm = algorithm.wire_name(),
            parent = ?opts.parent,
            "CA created"
        );

        Ok(ca)
    }

    /// Get a CA by name from cache.
    pub fn get(&self, name: &str) -> Result<Arc<CertificateAuthority>, ForgeError> {
        self.cache
            .get(name)
            .map(|r| Arc::clone(r.value()))
            .ok_or_else(|| ForgeError::CaNotFound {
                name: name.to_string(),
            })
    }

    /// List all CA names from cache.
    pub fn list(&self) -> Vec<String> {
        self.cache.iter().map(|r| r.key().clone()).collect()
    }

    /// Update a CA: applies a mutation function, saves to Store, updates cache.
    pub async fn update(
        &self,
        name: &str,
        f: impl FnOnce(&mut CertificateAuthority) -> Result<(), ForgeError>,
    ) -> Result<Arc<CertificateAuthority>, ForgeError> {
        let arc = self.get(name)?;
        let mut ca = Arc::unwrap_or_clone(arc);
        f(&mut ca)?;
        self.save(&ca).await?;
        let ca = Arc::new(ca);
        self.cache.insert(name.to_string(), Arc::clone(&ca));
        Ok(ca)
    }

    /// Delete a CA: tombstones it in the Store and evicts from the cache.
    /// Used by the engine's `ca_create` rollback path when a downstream
    /// capability (Keep, Chronicle) fails after the CA was persisted. The
    /// Store copy must not survive a half-committed create — it contains
    /// plaintext CA private key material.
    pub async fn delete(&self, name: &str) -> Result<(), ForgeError> {
        match self.store.delete(CAS_NAMESPACE, name.as_bytes()).await {
            Ok(_) => {}
            Err(shroudb_store::StoreError::NotFound) => {}
            Err(e) => return Err(ForgeError::Store(e.to_string())),
        }
        self.cache.remove(name);
        Ok(())
    }

    /// Clear the active key version's plaintext key material in the Store
    /// (and cache). Used after Keep has accepted the material so the
    /// private key lives in exactly one place. Zeroizes the hex string
    /// before dropping.
    pub async fn clear_active_key_material(&self, name: &str) -> Result<(), ForgeError> {
        self.update(name, |ca| {
            if let Some(active_key) = ca.active_key_mut()
                && let Some(ref mut km) = active_key.key_material
            {
                km.zeroize();
                active_key.key_material = None;
            }
            Ok(())
        })
        .await?;
        Ok(())
    }

    /// Retire draining keys that have exceeded the drain period.
    /// Zeroizes private key material before clearing it.
    pub async fn retire_draining_keys(&self, name: &str) -> Result<Vec<u32>, ForgeError> {
        let ca = self.get(name)?;
        let now = unix_now();
        let drain_secs = ca.drain_days as u64 * 86400;

        let to_retire: Vec<u32> = ca
            .key_versions
            .iter()
            .filter(|kv| kv.state == KeyState::Draining)
            .filter(|kv| {
                kv.draining_since
                    .is_some_and(|ds| now.saturating_sub(ds) >= drain_secs)
            })
            .map(|kv| kv.version)
            .collect();

        if to_retire.is_empty() {
            return Ok(Vec::new());
        }

        self.update(name, |ca| {
            for kv in &mut ca.key_versions {
                if to_retire.contains(&kv.version) && kv.state.can_transition_to(KeyState::Retired)
                {
                    kv.state = KeyState::Retired;
                    kv.retired_at = Some(now);
                    // Zeroize private key material before clearing
                    if let Some(ref mut km) = kv.key_material {
                        km.zeroize();
                    }
                    kv.key_material = None;
                }
            }
            Ok(())
        })
        .await?;

        for v in &to_retire {
            tracing::info!(ca = name, version = v, "CA key retired");
        }

        Ok(to_retire)
    }

    /// Persist a CA to the Store.
    async fn save(&self, ca: &CertificateAuthority) -> Result<(), ForgeError> {
        let value = serde_json::to_vec(ca)
            .map_err(|e| ForgeError::Internal(format!("serialization failed: {e}")))?;
        self.store
            .put(CAS_NAMESPACE, ca.name.as_bytes(), &value, None)
            .await
            .map_err(|e| ForgeError::Store(e.to_string()))?;
        Ok(())
    }

    /// Seed a CA from config if it doesn't already exist.
    pub async fn seed_if_absent(
        &self,
        name: &str,
        algorithm: CaAlgorithm,
        opts: CaCreateOpts,
    ) -> Result<(), ForgeError> {
        if self.cache.contains_key(name) {
            tracing::debug!(ca = name, "CA already exists, skipping seed");
            return Ok(());
        }
        self.create(name, algorithm, opts).await?;
        Ok(())
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

    #[tokio::test]
    async fn create_and_get_ca() {
        let store = shroudb_storage::test_util::create_test_store("forge-test").await;
        let mgr = CaManager::new(store);
        mgr.init().await.unwrap();

        let ca = mgr
            .create(
                "internal",
                CaAlgorithm::EcdsaP256,
                CaCreateOpts {
                    subject: "CN=Internal CA,O=Test".into(),
                    ..Default::default()
                },
            )
            .await
            .unwrap();

        assert_eq!(ca.name, "internal");
        assert_eq!(ca.algorithm, CaAlgorithm::EcdsaP256);
        assert_eq!(ca.key_versions.len(), 1);
        assert_eq!(ca.key_versions[0].state, KeyState::Active);

        let fetched = mgr.get("internal").unwrap();
        assert_eq!(fetched.name, "internal");
    }

    #[tokio::test]
    async fn create_duplicate_fails() {
        let store = shroudb_storage::test_util::create_test_store("forge-test").await;
        let mgr = CaManager::new(store);
        mgr.init().await.unwrap();

        mgr.create(
            "internal",
            CaAlgorithm::EcdsaP256,
            CaCreateOpts {
                subject: "CN=Internal CA".into(),
                ..Default::default()
            },
        )
        .await
        .unwrap();

        let err = mgr
            .create(
                "internal",
                CaAlgorithm::EcdsaP256,
                CaCreateOpts {
                    subject: "CN=Internal CA".into(),
                    ..Default::default()
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(err, ForgeError::CaAlreadyExists { .. }));
    }

    #[tokio::test]
    async fn list_cas() {
        let store = shroudb_storage::test_util::create_test_store("forge-test").await;
        let mgr = CaManager::new(store);
        mgr.init().await.unwrap();

        mgr.create(
            "a",
            CaAlgorithm::EcdsaP256,
            CaCreateOpts {
                subject: "CN=A".into(),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        mgr.create(
            "b",
            CaAlgorithm::Ed25519,
            CaCreateOpts {
                subject: "CN=B".into(),
                ..Default::default()
            },
        )
        .await
        .unwrap();

        let mut names = mgr.list();
        names.sort();
        assert_eq!(names, vec!["a", "b"]);
    }

    #[tokio::test]
    async fn persistence_survives_reload() {
        let store = shroudb_storage::test_util::create_test_store("forge-test").await;

        let mgr1 = CaManager::new(store.clone());
        mgr1.init().await.unwrap();
        mgr1.create(
            "internal",
            CaAlgorithm::EcdsaP256,
            CaCreateOpts {
                subject: "CN=Internal CA".into(),
                ..Default::default()
            },
        )
        .await
        .unwrap();

        let mgr2 = CaManager::new(store);
        mgr2.init().await.unwrap();
        let ca = mgr2.get("internal").unwrap();
        assert_eq!(ca.name, "internal");
        assert_eq!(ca.algorithm, CaAlgorithm::EcdsaP256);
    }

    #[tokio::test]
    async fn seed_if_absent() {
        let store = shroudb_storage::test_util::create_test_store("forge-test").await;
        let mgr = CaManager::new(store);
        mgr.init().await.unwrap();

        mgr.seed_if_absent(
            "internal",
            CaAlgorithm::EcdsaP256,
            CaCreateOpts {
                subject: "CN=Internal CA".into(),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert!(mgr.get("internal").is_ok());

        // Second call is a no-op
        mgr.seed_if_absent(
            "internal",
            CaAlgorithm::EcdsaP256,
            CaCreateOpts {
                subject: "CN=Internal CA".into(),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn test_corrupt_ca_data_handled() {
        let store = shroudb_storage::test_util::create_test_store("forge-test").await;

        // Create the namespace manually and write invalid JSON bytes
        store
            .namespace_create("forge.cas", shroudb_store::NamespaceConfig::default())
            .await
            .unwrap();
        store
            .put("forge.cas", b"corrupt-ca", b"not valid json {{{", None)
            .await
            .unwrap();

        // init() should return an error for the corrupt entry, not panic
        let mgr = CaManager::new(store);
        let result = mgr.init().await;
        assert!(
            result.is_err(),
            "init should return an error for corrupt data"
        );
        let err = result.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("corrupt") || msg.contains("invalid") || msg.contains("expected"),
            "error should mention corruption: {msg}"
        );
    }

    #[tokio::test]
    async fn create_intermediate_ca() {
        let store = shroudb_storage::test_util::create_test_store("forge-test").await;
        let mgr = CaManager::new(store);
        mgr.init().await.unwrap();

        // Create root first
        mgr.create(
            "root",
            CaAlgorithm::EcdsaP256,
            CaCreateOpts {
                subject: "CN=Root CA,O=Test".into(),
                ttl_days: 3650,
                ..Default::default()
            },
        )
        .await
        .unwrap();

        // Create intermediate
        let inter = mgr
            .create(
                "intermediate",
                CaAlgorithm::EcdsaP256,
                CaCreateOpts {
                    subject: "CN=Intermediate CA,O=Test".into(),
                    ttl_days: 365,
                    parent: Some("root".into()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();

        assert_eq!(inter.parent, Some("root".into()));
        assert_eq!(inter.key_versions.len(), 1);
        assert!(
            inter.key_versions[0]
                .certificate_pem
                .starts_with("-----BEGIN CERTIFICATE-----")
        );
    }

    #[tokio::test]
    async fn retire_zeroizes_key_material() {
        let store = shroudb_storage::test_util::create_test_store("forge-test").await;
        let mgr = CaManager::new(store);
        mgr.init().await.unwrap();

        // Create a CA (version 1 = Active)
        mgr.create(
            "test-retire",
            CaAlgorithm::EcdsaP256,
            CaCreateOpts {
                subject: "CN=Retire Test CA".into(),
                drain_days: 0, // immediate retirement eligibility
                ..Default::default()
            },
        )
        .await
        .unwrap();

        // Verify version 1 has key material
        let ca = mgr.get("test-retire").unwrap();
        assert!(ca.key_versions[0].key_material.is_some());

        // Rotate: version 1 becomes Draining, version 2 becomes Active
        let now = unix_now();
        mgr.update("test-retire", |ca| {
            if let Some(active_key) = ca.active_key_mut() {
                active_key.state = KeyState::Draining;
                active_key.draining_since = Some(now);
            }
            ca.key_versions.push(CaKeyVersion {
                version: 2,
                state: KeyState::Active,
                key_material: Some("newkey".into()),
                public_key: Some("newpub".into()),
                certificate_pem: ca.key_versions[0].certificate_pem.clone(),
                created_at: now,
                activated_at: Some(now),
                draining_since: None,
                retired_at: None,
            });
            Ok(())
        })
        .await
        .unwrap();

        // Verify version 1 is Draining with key material still present
        let ca = mgr.get("test-retire").unwrap();
        assert_eq!(ca.key_versions[0].state, KeyState::Draining);
        assert!(ca.key_versions[0].key_material.is_some());

        // Retire draining keys (drain_days=0 so they're immediately eligible)
        let retired = mgr.retire_draining_keys("test-retire").await.unwrap();
        assert_eq!(retired, vec![1]);

        // Verify version 1 is Retired with key material zeroized/cleared
        let ca = mgr.get("test-retire").unwrap();
        assert_eq!(ca.key_versions[0].state, KeyState::Retired);
        assert!(ca.key_versions[0].key_material.is_none());
        assert!(ca.key_versions[0].retired_at.is_some());

        // Verify version 2 is still Active with key material intact
        assert_eq!(ca.key_versions[1].state, KeyState::Active);
        assert!(ca.key_versions[1].key_material.is_some());
    }
}
