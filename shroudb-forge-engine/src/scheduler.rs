//! Background scheduler for automatic key rotation, retirement, and CRL regeneration.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use shroudb_forge_core::ca::decode_key_material;
use shroudb_store::Store;
use tokio::sync::watch;

use crate::engine::ForgeEngine;

/// Actor string recorded on audit events emitted by the background
/// scheduler. Uses the `system:<role>` namespace so automated security
/// events are distinguishable from unauthenticated user traffic (which
/// surfaces as the literal string `"anonymous"`).
const SCHEDULER_ACTOR: &str = "system:scheduler";

/// Start the background scheduler.
///
/// If a `CourierOps` capability is configured on the engine, the scheduler
/// sends notifications on CA rotation events.
pub fn start_scheduler<S: Store + 'static>(
    engine: Arc<ForgeEngine<S>>,
    interval_secs: u64,
    mut shutdown: watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    // Use the initial value; each subsequent cycle reads from the engine
    // so CONFIG SET scheduler_interval_secs takes effect on the next sleep.
    let _ = interval_secs;
    tokio::spawn(async move {
        loop {
            let secs = engine.scheduler_interval_secs();
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(secs)) => {
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
                match engine
                    .ca_rotate(&name, true, false, Some(SCHEDULER_ACTOR))
                    .await
                {
                    Ok(result) => {
                        tracing::info!(
                            ca = name,
                            new_version = result.key_version,
                            "auto-rotated CA key"
                        );
                        if let Some(c) = engine.courier()
                            && let Err(e) = c
                                .notify(
                                    "ops",
                                    "CA key rotated",
                                    &format!("CA '{}' rotated to v{}", name, result.key_version),
                                )
                                .await
                        {
                            tracing::warn!(
                                ca = name,
                                error = %e,
                                "failed to send rotation notification"
                            );
                        }
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
            && let Err(e) = engine.regenerate_crl(&name, Some(SCHEDULER_ACTOR)).await
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scheduler_actor_is_namespaced_system_not_anonymous() {
        assert_ne!(
            SCHEDULER_ACTOR, "anonymous",
            "scheduler actor must be distinguishable from unauthenticated \
             user traffic in audit events"
        );
        assert!(
            SCHEDULER_ACTOR.starts_with("system:"),
            "scheduler actor must use the `system:<role>` namespace so \
             audit consumers can filter automated events; got {SCHEDULER_ACTOR:?}"
        );
    }
}
