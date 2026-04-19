mod config;
mod http;
mod keep_embedded;
mod tcp;

use std::sync::Arc;

use anyhow::Context;
use clap::Parser;
use shroudb_crypto::SecretBytes;
use shroudb_forge_core::ca::CaAlgorithm;
use shroudb_forge_engine::ca_manager::CaCreateOpts;
use shroudb_forge_engine::engine::{ForgeConfig, ForgeEngine};
use shroudb_forge_engine::scheduler;
use shroudb_keep_engine::engine::{KeepConfig as KeepEngineConfig, KeepEngine};
use shroudb_store::Store;

use crate::config::{ForgeServerConfig, load_config};

#[derive(Parser)]
#[command(name = "shroudb-forge", about = "Forge internal certificate authority")]
struct Cli {
    /// Path to config file.
    #[arg(short, long, env = "FORGE_CONFIG")]
    config: Option<String>,

    /// Data directory (overrides config).
    #[arg(long, env = "FORGE_DATA_DIR")]
    data_dir: Option<String>,

    /// TCP bind address (overrides config).
    #[arg(long, env = "FORGE_TCP_BIND")]
    tcp_bind: Option<String>,

    /// Log level.
    #[arg(long, env = "FORGE_LOG_LEVEL", default_value = "info")]
    log_level: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Load config
    let mut cfg = load_config(cli.config.as_deref())?;

    // Resolve log level
    let log_level = if cli.log_level != "info" {
        cli.log_level.clone()
    } else {
        cfg.server
            .log_level
            .take()
            .unwrap_or_else(|| "info".to_string())
    };

    // Bootstrap: logging + core dumps + key source
    let key_source = shroudb_server_bootstrap::bootstrap(&log_level);

    // CLI overrides
    if let Some(ref dir) = cli.data_dir {
        cfg.store.data_dir = dir.into();
    }
    if let Some(ref bind) = cli.tcp_bind {
        cfg.server.tcp_bind = bind.parse().context("invalid TCP bind address")?;
    }

    // Embedded Keep (if configured) needs the same master key that Forge's
    // storage is opened with — load it up front so both consumers share it.
    let master_key = key_source
        .load()
        .await
        .context("failed to load master key")?;

    // Store: embedded or remote
    match cfg.store.mode.as_str() {
        "embedded" => {
            let storage =
                shroudb_server_bootstrap::open_storage(&cfg.store.data_dir, key_source.as_ref())
                    .await
                    .context("failed to open storage engine")?;
            let store = Arc::new(shroudb_storage::EmbeddedStore::new(
                storage.clone(),
                "forge",
            ));
            let keep_handle = build_keep_embedded(&cfg, storage.clone(), master_key).await?;
            run_server(cfg, store, Some(storage), keep_handle).await
        }
        "remote" => {
            let uri = cfg
                .store
                .uri
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("remote mode requires store.uri"))?;
            tracing::info!(uri, "connecting to remote store");
            let store = Arc::new(
                shroudb_client::RemoteStore::connect(uri)
                    .await
                    .context("failed to connect to remote store")?,
            );
            if let Some(ref keep_cfg) = cfg.keep
                && keep_cfg.is_embedded()
            {
                anyhow::bail!(
                    "keep.mode = \"embedded\" requires store.mode = \"embedded\" \
                     (embedded Keep needs a co-located StorageEngine)"
                );
            }
            run_server(cfg, store, None, None).await
        }
        other => anyhow::bail!("unknown store mode: {other}"),
    }
}

/// Build an embedded `KeepEngine` on a dedicated namespace of the same
/// storage engine Forge uses. Returns `None` when `[keep]` is absent or
/// not in embedded mode.
async fn build_keep_embedded(
    cfg: &ForgeServerConfig,
    storage: Arc<shroudb_storage::StorageEngine>,
    master_key: SecretBytes,
) -> anyhow::Result<Option<KeepEmbeddedHandle>> {
    let keep_cfg = match cfg.keep.as_ref() {
        Some(k) => k,
        None => return Ok(None),
    };
    keep_cfg
        .validate(&cfg.store.mode)
        .context("invalid [keep] config")?;
    if !keep_cfg.is_embedded() {
        return Ok(None);
    }

    let store = Arc::new(shroudb_storage::EmbeddedStore::new(storage, "keep"));
    let engine_cfg = KeepEngineConfig {
        max_versions: keep_cfg.max_versions,
    };
    let engine = KeepEngine::new(
        store,
        engine_cfg,
        master_key,
        shroudb_server_bootstrap::Capability::disabled(
            "forge-server embedded Keep: policy evaluation flows through Forge's own sentry slot",
        ),
        shroudb_server_bootstrap::Capability::disabled(
            "forge-server embedded Keep: audit events flow through Forge's own chronicle slot",
        ),
    )
    .await
    .context("failed to initialize embedded Keep engine")?;

    tracing::info!(
        max_versions = keep_cfg.max_versions,
        "embedded Keep engine initialized on 'keep' namespace"
    );
    Ok(Some(KeepEmbeddedHandle {
        engine: Arc::new(engine),
    }))
}

struct KeepEmbeddedHandle {
    engine: Arc<KeepEngine<shroudb_storage::EmbeddedStore>>,
}

async fn run_server<S: Store + 'static>(
    cfg: ForgeServerConfig,
    store: Arc<S>,
    storage: Option<Arc<shroudb_storage::StorageEngine>>,
    keep_embedded: Option<KeepEmbeddedHandle>,
) -> anyhow::Result<()> {
    use shroudb_server_bootstrap::Capability;

    // Resolve [audit] and [policy] capabilities. Both default to embedded
    // (per shroudb-engine-bootstrap 0.3.0) when the section is absent — the
    // server wires an in-process Chronicle / Sentry on the shared storage
    // engine. Init failures surface as Err; they are not silently swallowed.
    let audit_cfg = cfg.audit.clone().unwrap_or_default();
    let audit_cap = audit_cfg
        .resolve(storage.clone())
        .await
        .context("failed to resolve [audit] capability")?;
    let policy_cfg = cfg.policy.clone().unwrap_or_default();
    let policy_cap = policy_cfg
        .resolve(storage.clone(), audit_cap.as_ref().cloned())
        .await
        .context("failed to resolve [policy] capability")?;

    // Build profiles from config
    let profiles: Vec<_> = cfg
        .profiles
        .iter()
        .map(|(name, pcfg)| config::to_profile(name, pcfg))
        .collect();

    // Forge engine
    let mut forge_config = ForgeConfig {
        default_rotation_days: cfg.engine.default_rotation_days,
        default_drain_days: cfg.engine.default_drain_days,
        default_ca_ttl_days: cfg.engine.default_ca_ttl_days,
        scheduler_interval_secs: cfg.engine.scheduler_interval_secs,
        ..Default::default()
    };
    forge_config.policy_mode = match cfg.policy_mode.as_str() {
        "open" => shroudb_forge_engine::engine::PolicyMode::Open,
        _ => shroudb_forge_engine::engine::PolicyMode::Closed,
    };

    // Keep capability: embedded (co-located KeepEngine), remote (follow-up),
    // or explicit DisabledWithJustification when [keep] is absent.
    let keep_cap: Capability<Box<dyn shroudb_forge_engine::capabilities::ForgeKeepOps>> =
        match (cfg.keep.as_ref(), keep_embedded) {
            (Some(keep_cfg), Some(handle)) if keep_cfg.is_embedded() => {
                tracing::info!("forge: using embedded Keep for CA private-key persistence");
                Capability::Enabled(Box::new(keep_embedded::EmbeddedForgeKeepOps::new(
                    handle.engine,
                )))
            }
            (Some(keep_cfg), _) if keep_cfg.is_remote() => {
                anyhow::bail!(
                    "keep.mode = \"remote\" is reserved — standalone remote Keep wiring \
                     is follow-up scope. Use [keep] mode = \"embedded\", deploy via Moat, \
                     or omit the [keep] section to run Forge without Keep."
                );
            }
            _ => Capability::<Box<dyn shroudb_forge_engine::capabilities::ForgeKeepOps>>::disabled(
                "forge: no [keep] config — issued CA private keys are not persisted through Keep",
            ),
        };

    let engine = Arc::new(
        ForgeEngine::new(
            store,
            profiles,
            forge_config,
            policy_cap,
            audit_cap,
            keep_cap,
        )
        .await
        .context("failed to initialize forge engine")?,
    );

    // Seed CAs from config
    for (name, ca_cfg) in &cfg.cas {
        let algorithm: CaAlgorithm = ca_cfg
            .algorithm
            .parse()
            .map_err(|e: String| anyhow::anyhow!("CA '{name}': {e}"))?;
        engine
            .ca_manager()
            .seed_if_absent(
                name,
                algorithm,
                CaCreateOpts {
                    subject: ca_cfg.subject.clone(),
                    ttl_days: ca_cfg.ttl_days.unwrap_or(cfg.engine.default_ca_ttl_days),
                    parent: ca_cfg.parent.clone(),
                    rotation_days: ca_cfg
                        .rotation_days
                        .unwrap_or(cfg.engine.default_rotation_days),
                    drain_days: ca_cfg.drain_days.unwrap_or(cfg.engine.default_drain_days),
                },
            )
            .await
            .with_context(|| format!("failed to seed CA '{name}'"))?;

        // Initialize cert namespace for seeded CAs
        engine
            .cert_manager()
            .init_for_ca(name)
            .await
            .with_context(|| format!("failed to init certs for CA '{name}'"))?;
    }

    // Shutdown signal
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    // Start scheduler
    let _scheduler_handle = scheduler::start_scheduler(
        engine.clone(),
        cfg.engine.scheduler_interval_secs,
        shutdown_rx.clone(),
    );

    // Auth
    let token_validator = cfg.auth.build_validator();
    if token_validator.is_some() {
        tracing::info!(tokens = cfg.auth.tokens.len(), "token-based auth enabled");
    }

    // TCP server
    let tcp_listener = tokio::net::TcpListener::bind(cfg.server.tcp_bind)
        .await
        .context("failed to bind TCP")?;

    let tls_acceptor = cfg
        .server
        .tls
        .as_ref()
        .map(shroudb_server_tcp::build_tls_acceptor)
        .transpose()
        .context("failed to build TLS acceptor")?;

    let tcp_engine = engine.clone();
    let tcp_validator = token_validator.clone();
    let tcp_shutdown = shutdown_rx.clone();
    let tcp_handle = tokio::spawn(async move {
        tcp::run_tcp(
            tcp_listener,
            tcp_engine,
            tcp_validator,
            tcp_shutdown,
            tls_acceptor,
        )
        .await;
    });

    // HTTP sidecar
    let http_engine = engine.clone();
    let http_shutdown = shutdown_rx.clone();
    let http_bind = cfg.server.http_bind;
    let http_handle = tokio::spawn(async move {
        if let Err(e) = http::run_http_sidecar(http_bind, http_engine, http_shutdown).await {
            tracing::error!(error = %e, "HTTP sidecar failed");
        }
    });

    // Banner (Forge has extra http line)
    eprintln!();
    eprintln!("Forge v{}", env!("CARGO_PKG_VERSION"));
    eprintln!("├─ tcp:     {}", cfg.server.tcp_bind);
    eprintln!("├─ http:    {}", cfg.server.http_bind);
    eprintln!("├─ data:    {}", cfg.store.data_dir.display());
    eprintln!(
        "└─ key:     {}",
        if std::env::var("SHROUDB_MASTER_KEY").is_ok()
            || std::env::var("SHROUDB_MASTER_KEY_FILE").is_ok()
        {
            "configured"
        } else {
            "ephemeral (dev mode)"
        }
    );
    eprintln!();
    eprintln!("Ready.");

    // Wait for shutdown
    shroudb_server_bootstrap::wait_for_shutdown(shutdown_tx).await?;
    let _ = tcp_handle.await;
    let _ = http_handle.await;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_debug_asserts() {
        Cli::command().debug_assert();
    }

    #[test]
    fn cli_accepts_config_flag() {
        let parsed = Cli::try_parse_from(["shroudb-forge", "--config", "forge.toml"]).unwrap();
        assert_eq!(parsed.config.as_deref(), Some("forge.toml"));
    }
}
