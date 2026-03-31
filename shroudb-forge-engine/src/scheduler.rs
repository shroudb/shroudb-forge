//! Background scheduler for automatic key rotation, retirement, and CRL regeneration.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use shroudb_forge_core::ca::decode_key_material;
use shroudb_forge_core::key_state::KeyState;
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

        // Auto-retire: draining keys past drain_days
        let should_retire: Vec<u32> = ca
            .key_versions
            .iter()
            .filter(|kv| kv.state == KeyState::Draining)
            .filter(|kv| {
                kv.draining_since
                    .map(|ds| (now.saturating_sub(ds)) / 86400 >= ca.drain_days as u64)
                    .unwrap_or(false)
            })
            .map(|kv| kv.version)
            .collect();

        if !should_retire.is_empty() {
            let result = engine
                .ca_manager()
                .update(&name, |ca| {
                    for kv in &mut ca.key_versions {
                        if should_retire.contains(&kv.version) && kv.state == KeyState::Draining {
                            kv.state = KeyState::Retired;
                            kv.retired_at = Some(now);
                            kv.key_material = None;
                            tracing::info!(
                                ca = ca.name,
                                version = kv.version,
                                "auto-retired key version"
                            );
                        }
                    }
                    Ok(())
                })
                .await;

            if let Err(e) = result {
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
