# Forge

Internal certificate authority engine for ShrouDB.

## Identity

Forge is a **lightweight internal Certificate Authority** — it issues short-lived TLS certificates for mTLS bootstrapping in service-to-service communication. It manages CA lifecycle (creation, key rotation, draining, retirement), enforces profile-based constraints on certificate issuance, and provides CRL/OCSP endpoints for revocation checking.

ShrouDB is **not Redis**. It uses RESP3 as a wire protocol because RESP3 is efficient binary framing — not because ShrouDB is related to Redis in any way.

## Security posture

ShrouDB is security infrastructure. Every change must be evaluated through a security lens:

- **Fail closed, not open.** When in doubt, deny access, reject the request, or return an error. Never default to permissive behavior for convenience.
- **No plaintext at rest.** Secrets, keys, and sensitive data must be encrypted before touching disk. If a value could be sensitive, treat it as sensitive.
- **Minimize exposure windows.** Plaintext in memory must be zeroized after use. Connections holding decrypted data must be short-lived. Audit every code path where sensitive data is held in the clear.
- **Cryptographic choices are not negotiable.** Do not downgrade algorithms, skip integrity checks, weaken key derivation, or reduce key sizes to simplify implementation. If the secure path is harder, take the harder path.
- **Every shortcut is a vulnerability.** Skipping validation, hardcoding credentials, disabling TLS for testing, using `unsafe` without justification, suppressing security-relevant warnings — these are not acceptable trade-offs regardless of time pressure. The correct implementation is the only implementation.
- **Audit surface changes require scrutiny.** Any change that modifies authentication, authorization, key management, certificate operations, or network-facing code must be reviewed with the assumption that an attacker will examine it.

## Pre-push checklist (mandatory — no exceptions)

Every check below **must** pass locally before pushing to any branch. Do not rely on GitHub Actions to catch these — CI is a safety net, not the first line of defense.

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo deny check
```

### Rules

1. **Run all checks before every push.** No shortcuts, no "I'll fix it in the next commit."
2. **Pre-existing issues must be fixed.** If any check reveals warnings, formatting drift, deny failures, or any other issue — even if you didn't introduce it — fix it in the same changeset. Do not skip it as "not in scope", "pre-existing", or "unrelated." If the tool flags it, it gets fixed.
3. **Never suppress or bypass checks.** Do not add `#[allow(...)]` to silence clippy, do not skip `cargo deny`, do not push with known failures. Do not use `--no-verify` on git push.
4. **Warnings are errors.** `RUSTFLAGS="-D warnings"` is set in CI. Clippy runs with `-D warnings`. Both compiler warnings and clippy warnings fail the build.
5. **Dependency issues require resolution.** If `cargo deny` flags a new advisory or license issue, investigate and resolve it (update the dep, or add a justified exemption to `deny.toml`). Do not ignore it.
6. **Documentation must stay in sync.** Any change that affects CLI commands, config keys, public API, or user-facing behavior **must** include corresponding updates to docs in the same changeset.
7. **`protocol.toml` must stay in sync.** Any change to commands, parameters, response fields, error codes, or API endpoints **must** include a corresponding update to `protocol.toml` in the same changeset.
8. **Cross-repo impact must be addressed.** If a change affects shared types, protocols, or APIs consumed by other ShrouDB repos, update those downstream repos in the same effort. Do not leave other repos broken or out of sync.

## Architecture

```
shroudb-forge-core/        — domain types (CA, cert, profile, X.509, CRL, OCSP)
shroudb-forge-engine/      — Store-backed logic (ForgeEngine, CaManager, CertManager)
shroudb-forge-protocol/    — RESP3 command parsing + dispatch (Moat integration path)
shroudb-forge-server/      — TCP + HTTP binary (standalone deployment)
shroudb-forge-client/      — Rust client SDK
shroudb-forge-cli/         — CLI tool
```

## Dependencies

- **Upstream:** commons (shroudb-store, shroudb-storage, shroudb-crypto, shroudb-acl, shroudb-protocol-wire)
- **Downstream:** shroudb-moat (embeds engine + protocol), shroudb-codegen (reads `protocol.toml`)
