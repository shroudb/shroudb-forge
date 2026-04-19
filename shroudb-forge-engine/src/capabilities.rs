use shroudb_forge_core::error::ForgeError;

/// Shorthand for a pinned boxed future.
type BoxFut<'a, T> =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<T, ForgeError>> + Send + 'a>>;

/// Trait for Keep operations on CA private key material.
///
/// When configured, Forge stores CA private keys through Keep for
/// defense-in-depth: per-path HKDF key derivation, double encryption
/// with path-as-AAD, and versioned access.
///
/// Keys are stored at path `forge/{ca_name}/v{version}`.
///
/// `actor` identifies the caller responsible for the operation.
/// End-user-driven calls (ca_create from an authenticated request)
/// pass the authenticated actor; scheduler-driven calls (ca_rotate
/// from the rotation scheduler) pass a stable sentinel like
/// `"system:scheduler"`. Never pass an empty string — downstream
/// Keep audit paths reject that as a missing-identity violation.
pub trait ForgeKeepOps: Send + Sync {
    /// Store key material in Keep. Returns the Keep version number.
    fn store_key(&self, path: &str, key_material: &[u8], actor: &str) -> BoxFut<'_, u64>;

    /// Retrieve key material from Keep.
    fn get_key(&self, path: &str, actor: &str) -> BoxFut<'_, Vec<u8>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Pins the trait signature: both methods carry an actor. A mock
    /// records args and exercises the trait object. If someone drops
    /// the `actor` parameter, this test fails to compile.
    struct MockKeep {
        last_store: Mutex<Option<(String, Vec<u8>, String)>>,
        last_get: Mutex<Option<(String, String)>>,
    }

    impl ForgeKeepOps for MockKeep {
        fn store_key(&self, path: &str, key_material: &[u8], actor: &str) -> BoxFut<'_, u64> {
            let path = path.to_string();
            let km = key_material.to_vec();
            let actor = actor.to_string();
            Box::pin(async move {
                *self.last_store.lock().unwrap() = Some((path, km, actor));
                Ok(1)
            })
        }
        fn get_key(&self, path: &str, actor: &str) -> BoxFut<'_, Vec<u8>> {
            let path = path.to_string();
            let actor = actor.to_string();
            Box::pin(async move {
                *self.last_get.lock().unwrap() = Some((path, actor));
                Ok(vec![1, 2, 3])
            })
        }
    }

    #[tokio::test]
    async fn store_key_and_get_key_carry_actor() {
        let mock = MockKeep {
            last_store: Mutex::new(None),
            last_get: Mutex::new(None),
        };
        let obj: &dyn ForgeKeepOps = &mock;
        obj.store_key("forge/ca/v1", &[0x1u8, 0x2, 0x3], "admin")
            .await
            .expect("store ok");
        let (path, km, actor) = mock.last_store.lock().unwrap().clone().unwrap();
        assert_eq!(path, "forge/ca/v1");
        assert_eq!(km, vec![0x1, 0x2, 0x3]);
        assert_eq!(actor, "admin");

        obj.get_key("forge/ca/v1", "system:scheduler")
            .await
            .expect("get ok");
        let (path, actor) = mock.last_get.lock().unwrap().clone().unwrap();
        assert_eq!(path, "forge/ca/v1");
        assert_eq!(actor, "system:scheduler");
    }
}
