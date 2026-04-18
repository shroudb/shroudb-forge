//! Embedded Keep capability adapter for the standalone Forge server.
//!
//! When `[keep] mode = "embedded"` is set, Forge runs an in-process
//! `KeepEngine` on the same `StorageEngine` (distinct namespace) and
//! persists issued CA private keys through Keep's per-path HKDF +
//! AES-256-GCM double encryption.
//!
//! Mirrors the `EmbeddedForgeKeepOps` adapter that Moat uses when Keep
//! is co-located — the wiring pattern is identical so operators get
//! the same security posture whether they deploy via Moat or as a
//! standalone Forge process.

use std::sync::Arc;

use shroudb_forge_core::error::ForgeError;
use shroudb_forge_engine::capabilities::ForgeKeepOps;
use shroudb_keep_engine::engine::KeepEngine;
use shroudb_store::Store;

type BoxFut<'a, T> =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<T, ForgeError>> + Send + 'a>>;

pub struct EmbeddedForgeKeepOps<S: Store> {
    engine: Arc<KeepEngine<S>>,
}

impl<S: Store> EmbeddedForgeKeepOps<S> {
    pub fn new(engine: Arc<KeepEngine<S>>) -> Self {
        Self { engine }
    }
}

impl<S: Store + 'static> ForgeKeepOps for EmbeddedForgeKeepOps<S> {
    fn store_key(&self, path: &str, key_material: &[u8]) -> BoxFut<'_, u64> {
        use base64::Engine as _;
        let p = path.to_string();
        let b64 = base64::engine::general_purpose::STANDARD.encode(key_material);
        Box::pin(async move {
            let result = self
                .engine
                .put(&p, &b64, None)
                .await
                .map_err(|e| ForgeError::Internal(format!("keep put: {e}")))?;
            Ok(result.version as u64)
        })
    }

    fn get_key(&self, path: &str) -> BoxFut<'_, Vec<u8>> {
        use base64::Engine as _;
        let p = path.to_string();
        Box::pin(async move {
            let result = self
                .engine
                .get(&p, None, None)
                .await
                .map_err(|e| ForgeError::Internal(format!("keep get: {e}")))?;
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(&result.value)
                .map_err(|e| ForgeError::Internal(format!("keep decode: {e}")))?;
            Ok(bytes)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shroudb_crypto::SecretBytes;
    use shroudb_keep_engine::engine::KeepConfig;
    use shroudb_server_bootstrap::Capability;

    fn test_master_key() -> SecretBytes {
        SecretBytes::new(vec![0x42u8; 32])
    }

    async fn build_ops() -> EmbeddedForgeKeepOps<shroudb_storage::EmbeddedStore> {
        let store = shroudb_storage::test_util::create_test_store("forge-keep-embed-test").await;
        let engine = KeepEngine::new(
            store,
            KeepConfig::default(),
            test_master_key(),
            Capability::DisabledForTests,
            Capability::DisabledForTests,
        )
        .await
        .expect("keep engine init");
        EmbeddedForgeKeepOps::new(Arc::new(engine))
    }

    #[tokio::test]
    async fn store_and_get_round_trips_key_material() {
        let ops = build_ops().await;
        let path = "forge/ca-root/v1";
        let key = vec![0xAB; 64];

        let version = ops.store_key(path, &key).await.expect("store_key");
        assert_eq!(version, 1, "first put yields version 1");

        let fetched = ops.get_key(path).await.expect("get_key");
        assert_eq!(fetched, key, "round-trip preserves key material");
    }

    #[tokio::test]
    async fn store_key_bumps_version_on_rewrite() {
        let ops = build_ops().await;
        let path = "forge/ca-root/v1";

        let v1 = ops.store_key(path, &[0x01; 32]).await.unwrap();
        let v2 = ops.store_key(path, &[0x02; 32]).await.unwrap();

        assert_eq!(v1, 1);
        assert_eq!(v2, 2, "second put increments version");

        let fetched = ops.get_key(path).await.unwrap();
        assert_eq!(fetched, vec![0x02; 32], "get returns latest version");
    }
}
