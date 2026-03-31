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
    cache: DashMap<String, CertificateAuthority>,
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
                self.cache.insert(ca.name.clone(), ca);
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
    ) -> Result<CertificateAuthority, ForgeError> {
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
        self.cache.insert(name.to_string(), ca.clone());

        tracing::info!(
            ca = name,
            algorithm = algorithm.wire_name(),
            parent = ?opts.parent,
            "CA created"
        );

        Ok(ca)
    }

    /// Get a CA by name from cache.
    pub fn get(&self, name: &str) -> Result<CertificateAuthority, ForgeError> {
        self.cache
            .get(name)
            .map(|r| r.value().clone())
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
    ) -> Result<CertificateAuthority, ForgeError> {
        let mut ca = self.get(name)?;
        f(&mut ca)?;
        self.save(&ca).await?;
        self.cache.insert(name.to_string(), ca.clone());
        Ok(ca)
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
}
