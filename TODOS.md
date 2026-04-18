# TODOS

## Debt

Each item below is captured as a FAILING test in this repo. The test is the forcing function — this file only indexes them. When a test goes green, check its item off or delete the entry.

Rules:
- Do NOT `#[ignore]` a debt test to make CI pass.
- A visible ratchet (`#[ignore = "DEBT-X: <reason>"]`) requires a matching line in this file AND a clear reason on the attribute. Use sparingly.
- `cargo test -p shroudb-forge-engine --test debt_tests_test` is the live punch list.

### Cross-cutting root causes

1. **Server binary hardcodes `None` for all three capabilities.** `main.rs:117` calls `ForgeEngine::new(store, profiles, forge_config, None, None, None)` — no Sentry, no Chronicle, no Keep. CA private keys live only in Store.
2. **When Keep IS configured, plaintext key material stays in Store anyway.** `ca_create`/`ca_rotate` write to Keep AFTER persisting CA with `key_material` hex. The Store copy is never cleared. Defense-in-depth defeated.
3. **Audit emitted AFTER commit.** Every write op (create, rotate, issue, revoke, regenerate_crl) commits state then audits. Audit failure surfaces as Err but the state change is already durable. Worst case: `revoke` publishes a CRL before audit — audit failure = silent revocation with a published CRL.

### Open

- [x] **DEBT-1** — `main.rs` must not hardcode all three capabilities as None. Test: `debt_1_server_main_must_not_hardcode_capabilities_none` @ `shroudb-forge-engine/tests/debt_tests_test.rs`.
- [x] **DEBT-2** — `ca_create` with Keep configured must clear Store's key_material (Keep becomes sole source). Test: `debt_2_ca_create_with_keep_must_clear_store_key_material` @ same file.
- [x] **DEBT-3** — `ca_create` must rollback when Keep store fails (currently half-committed with plaintext in Store). Test: `debt_3_ca_create_must_rollback_when_keep_store_fails` @ same file.
- [x] **DEBT-4** — `ca_create` must rollback when audit fails. Test: `debt_4_ca_create_must_rollback_when_audit_fails` @ same file.
- [x] **DEBT-5** — `revoke` must rollback when audit fails (currently: CRL already published, revocation done, audit missing). Test: `debt_5_revoke_must_rollback_when_audit_fails` @ same file.
- [x] **DEBT-6** — `ForgeConfig` must have `require_keep` defaulting to `true`. Test: `debt_6_forge_config_must_have_require_keep_defaulting_true` @ same file.
- [x] **DEBT-7** — scheduler auto-rotation audit must not use `"anonymous"` actor (conflates with unauth traffic). Test: `debt_7_scheduler_auto_rotation_audit_must_not_use_anonymous` @ same file.
