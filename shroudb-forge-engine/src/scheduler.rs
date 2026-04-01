//! Background scheduler for automatic key rotation, retirement, and CRL regeneration.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use shroudb_forge_core::ca::decode_key_material;
use shroudb_store::Store;
use tokio::sync::watch;

use crate::engine::ForgeEngine;

/// Start the background scheduler.
pub fn start_scheduler<S: Store + 'static>(
    engine: Arc<ForgeEngine<S>>,
    interval_secs: u64,
    mut shutdown: watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(interval_secs)) => {
                    if let Err(e) = run_cycle(&engine).await {
                        tracing::warn!(error = %e, "scheduler cycle failed");
                    }
                }
                _ = shutdown.changed() => {
                    tracing::info!("forge scheduler shutting down");
                    break;
                }
            }
        }
    })
}

async fn run_cycle<S: Store>(engine: &ForgeEngine<S>) -> Result<(), String> {
    let names = engine.ca_list();
    let now = unix_now();

    for name in names {
        let ca = match engine.ca_manager().get(&name) {
            Ok(ca) => ca,
            Err(e) => {
                tracing::warn!(ca = name, error = %e, "failed to load CA in scheduler");
                continue;
            }
        };

        if ca.disabled {
            continue;
        }

        // Auto-rotate: if active key exceeds rotation_days
        if let Some(active) = ca.active_key() {
            let age_days = active
                .activated_at
                .map(|at| now.saturating_sub(at) / 86400)
                .unwrap_or(0);

            if age_days >= ca.rotation_days as u64 {
                match engine.ca_rotate(&name, true, false, None).await {
                    Ok(result) => {
                        tracing::info!(
                            ca = name,
                            new_version = result.key_version,
                            "auto-rotated CA key"
                        );
                    }
                    Err(e) => {
                        tracing::warn!(ca = name, error = %e, "auto-rotation failed");
                    }
                }
            }
        }

        // Auto-retire: draining keys past drain_days (with zeroization)
        match engine.ca_manager().retire_draining_keys(&name).await {
            Ok(retired) => {
                for v in &retired {
                    tracing::info!(ca = name, version = v, "auto-retired key version");
                }
            }
            Err(e) => {
                tracing::warn!(ca = name, error = %e, "auto-retirement failed");
            }
        }

        // Regenerate CRL for CAs with active keys
        if let Some(active) = ca.active_key()
            && decode_key_material(active).is_ok()
            && let Err(e) = engine.regenerate_crl(&name, None).await
        {
            tracing::warn!(ca = name, error = %e, "CRL regeneration failed");
        }
    }

    Ok(())
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
