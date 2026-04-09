mod config;
mod http;
mod tcp;

use std::sync::Arc;

use anyhow::Context;
use clap::Parser;
use shroudb_forge_core::ca::CaAlgorithm;
use shroudb_forge_engine::ca_manager::CaCreateOpts;
use shroudb_forge_engine::engine::{ForgeConfig, ForgeEngine};
use shroudb_forge_engine::scheduler;

use crate::config::load_config;

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

    // Store mode validation
    if cfg.store.mode == "remote" {
        anyhow::bail!(
            "remote store mode not yet implemented (uri: {:?})",
            cfg.store.uri
        );
    }

    // Storage engine
    let storage = shroudb_server_bootstrap::open_storage(&cfg.store.data_dir, key_source.as_ref())
        .await
        .context("failed to open storage engine")?;
    let store = Arc::new(shroudb_storage::EmbeddedStore::new(storage, "forge"));

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
    let engine = Arc::new(
        ForgeEngine::new(store, profiles, forge_config, None, None, None)
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

    let tcp_engine = engine.clone();
    let tcp_validator = token_validator.clone();
    let tcp_shutdown = shutdown_rx.clone();
    let tcp_handle = tokio::spawn(async move {
        tcp::run_tcp(tcp_listener, tcp_engine, tcp_validator, tcp_shutdown).await;
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
