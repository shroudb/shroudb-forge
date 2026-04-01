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
pub trait ForgeKeepOps: Send + Sync {
    /// Store key material in Keep. Returns the Keep version number.
    fn store_key(&self, path: &str, key_material: &[u8]) -> BoxFut<'_, u64>;

    /// Retrieve key material from Keep.
    fn get_key(&self, path: &str) -> BoxFut<'_, Vec<u8>>;
}
