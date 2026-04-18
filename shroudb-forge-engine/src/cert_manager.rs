//! Store-backed certificate management with in-memory cache.

use std::sync::Arc;

use dashmap::DashMap;
use shroudb_forge_core::cert::{CertState, IssuedCertificate};
use shroudb_forge_core::error::ForgeError;
use shroudb_store::Store;

/// Manages issued certificates with Store-backed persistence and in-memory cache.
pub struct CertManager<S: Store> {
    store: Arc<S>,
    /// Cache keyed by (ca_name, serial).
    cache: DashMap<(String, String), IssuedCertificate>,
    /// CRL PEM cache per CA.
    crl_cache: DashMap<String, String>,
}

fn cert_namespace(ca_name: &str) -> String {
    format!("forge.{ca_name}.certs")
}

impl<S: Store> CertManager<S> {
    pub fn new(store: Arc<S>) -> Self {
        Self {
            store,
            cache: DashMap::new(),
            crl_cache: DashMap::new(),
        }
    }

    /// Initialize namespace and load certificates for a CA.
    pub async fn init_for_ca(&self, ca_name: &str) -> Result<(), ForgeError> {
        let ns = cert_namespace(ca_name);
        match self
            .store
            .namespace_create(&ns, shroudb_store::NamespaceConfig::default())
            .await
        {
            Ok(()) => {}
            Err(shroudb_store::StoreError::NamespaceExists(_)) => {}
            Err(e) => return Err(ForgeError::Store(e.to_string())),
        }

        let mut cursor = None;
        let mut count = 0u64;
        loop {
            let page = self
                .store
                .list(&ns, None, cursor.as_deref(), 100)
                .await
                .map_err(|e| ForgeError::Store(e.to_string()))?;

            for key in &page.keys {
                let entry = self
                    .store
                    .get(&ns, key, None)
                    .await
                    .map_err(|e| ForgeError::Store(e.to_string()))?;
                let cert: IssuedCertificate = serde_json::from_slice(&entry.value)
                    .map_err(|e| ForgeError::Internal(format!("corrupt cert data: {e}")))?;
                self.cache
                    .insert((ca_name.to_string(), cert.serial.clone()), cert);
                count += 1;
            }

            if page.cursor.is_none() {
                break;
            }
            cursor = page.cursor;
        }

        if count > 0 {
            tracing::info!(ca = ca_name, count, "loaded certificates from store");
        }

        Ok(())
    }

    /// Store a newly issued certificate.
    pub async fn store_cert(&self, cert: IssuedCertificate) -> Result<(), ForgeError> {
        let ns = cert_namespace(&cert.ca_name);

        // Ensure namespace exists
        match self
            .store
            .namespace_create(&ns, shroudb_store::NamespaceConfig::default())
            .await
        {
            Ok(()) => {}
            Err(shroudb_store::StoreError::NamespaceExists(_)) => {}
            Err(e) => return Err(ForgeError::Store(e.to_string())),
        }

        let value = serde_json::to_vec(&cert)
            .map_err(|e| ForgeError::Internal(format!("serialization failed: {e}")))?;
        self.store
            .put(&ns, cert.serial.as_bytes(), &value, None)
            .await
            .map_err(|e| ForgeError::Store(e.to_string()))?;
        self.cache
            .insert((cert.ca_name.clone(), cert.serial.clone()), cert);
        Ok(())
    }

    /// Get a certificate by CA name and serial.
    pub fn get(&self, ca_name: &str, serial: &str) -> Option<IssuedCertificate> {
        self.cache
            .get(&(ca_name.to_string(), serial.to_string()))
            .map(|r| r.value().clone())
    }

    /// Update a certificate.
    pub async fn update(
        &self,
        ca_name: &str,
        serial: &str,
        f: impl FnOnce(&mut IssuedCertificate),
    ) -> Result<IssuedCertificate, ForgeError> {
        let key = (ca_name.to_string(), serial.to_string());
        let mut cert = self
            .cache
            .get(&key)
            .map(|r| r.value().clone())
            .ok_or_else(|| ForgeError::CertNotFound {
                ca: ca_name.to_string(),
                serial: serial.to_string(),
            })?;

        f(&mut cert);

        let ns = cert_namespace(ca_name);
        let value = serde_json::to_vec(&cert)
            .map_err(|e| ForgeError::Internal(format!("serialization failed: {e}")))?;
        self.store
            .put(&ns, serial.as_bytes(), &value, None)
            .await
            .map_err(|e| ForgeError::Store(e.to_string()))?;
        self.cache.insert(key, cert.clone());
        Ok(cert)
    }

    /// List certificates for a CA, with optional state filter.
    pub fn list_certs(
        &self,
        ca_name: &str,
        state_filter: Option<CertState>,
        now: u64,
        limit: usize,
        offset: usize,
    ) -> Vec<CertSummary> {
        let mut results: Vec<CertSummary> = self
            .cache
            .iter()
            .filter(|r| r.key().0 == ca_name)
            .filter(|r| {
                state_filter
                    .map(|s| match s {
                        CertState::Active => r.value().state == CertState::Active,
                        CertState::Revoked => r.value().state == CertState::Revoked,
                    })
                    .unwrap_or(true)
            })
            .map(|r| {
                let cert = r.value();
                CertSummary {
                    serial: cert.serial.clone(),
                    subject: cert.subject.clone(),
                    profile: cert.profile.clone(),
                    state: cert.effective_state(now).to_string(),
                    not_before: cert.not_before,
                    not_after: cert.not_after,
                    ca_key_version: cert.ca_key_version,
                }
            })
            .collect();

        results.sort_by(|a, b| a.serial.cmp(&b.serial));
        results.into_iter().skip(offset).take(limit).collect()
    }

    /// Get all revoked entries for CRL generation.
    pub fn revoked_for_crl(&self, ca_name: &str) -> Vec<shroudb_forge_core::crl::CrlRevokedEntry> {
        self.cache
            .iter()
            .filter(|r| r.key().0 == ca_name && r.value().state == CertState::Revoked)
            .map(|r| {
                let cert = r.value();
                shroudb_forge_core::crl::CrlRevokedEntry {
                    serial_hex: cert.serial.clone(),
                    revoked_at: cert.revoked_at.unwrap_or(0),
                }
            })
            .collect()
    }

    /// Get cached CRL PEM for a CA.
    pub fn crl_pem(&self, ca_name: &str) -> Option<String> {
        self.crl_cache.get(ca_name).map(|r| r.value().clone())
    }

    /// Set cached CRL PEM for a CA.
    pub fn set_crl_pem(&self, ca_name: &str, pem: String) {
        self.crl_cache.insert(ca_name.to_string(), pem);
    }

    /// Remove the cached CRL PEM for a CA, if any. Used to restore the
    /// pre-revocation state when `revoke` rolls back after audit failure
    /// and no CRL existed before the revocation.
    pub fn clear_crl_pem(&self, ca_name: &str) {
        self.crl_cache.remove(ca_name);
    }
}

/// Summary of a certificate for list operations.
#[derive(Debug, Clone)]
pub struct CertSummary {
    pub serial: String,
    pub subject: String,
    pub profile: String,
    pub state: String,
    pub not_before: u64,
    pub not_after: u64,
    pub ca_key_version: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn clear_crl_pem_removes_cached_entry() {
        let store = shroudb_storage::test_util::create_test_store("forge-cert-mgr-test").await;
        let mgr = CertManager::new(store);
        mgr.set_crl_pem(
            "ca1",
            "-----BEGIN X509 CRL-----\n...\n-----END X509 CRL-----".into(),
        );
        assert!(mgr.crl_pem("ca1").is_some());
        mgr.clear_crl_pem("ca1");
        assert!(
            mgr.crl_pem("ca1").is_none(),
            "clear_crl_pem must remove the cached CRL so revoke rollback \
             restores the prior state when no CRL existed before"
        );
    }

    #[tokio::test]
    async fn clear_crl_pem_absent_is_noop() {
        let store =
            shroudb_storage::test_util::create_test_store("forge-cert-mgr-absent-test").await;
        let mgr = CertManager::new(store);
        mgr.clear_crl_pem("never-set");
        assert!(mgr.crl_pem("never-set").is_none());
    }
}
