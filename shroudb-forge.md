# Forge — ShrouDB Repository Analysis

**Component:** shroudb-forge  
**Type:** Engine (CA engine — 4 library crates, 1 server binary, 1 CLI binary)  
**Language:** Rust (edition 2024, MSRV 1.92)  
**License:** MIT OR Apache-2.0  
**Published:** Private "shroudb" registry (not crates.io)  
**Analyzed:** /Users/nlucas/dev/shroudb/shroudb-forge

---

## Role in Platform

Forge is ShrouDB's internal Certificate Authority engine. It issues short-lived X.509 certificates for mTLS bootstrapping between ShrouDB services, manages CA key lifecycle (creation, rotation, draining, retirement), enforces profile-based issuance constraints, and serves CRL/OCSP endpoints for revocation checking. Without Forge, ShrouDB cannot bootstrap mutual TLS between its components — all inter-service authentication degrades or becomes impossible.

---

## Behavioral Surface

### Public API

**RESP3 Commands (TCP port 6699, 17 commands):**

| Command | ACL | Purpose |
|---------|-----|---------|
| `CA CREATE` | Admin | Create CA with algorithm and subject |
| `CA INFO` | Namespace Read | CA metadata and key versions |
| `CA LIST` | None | List all CA names |
| `CA ROTATE` | Admin | Rotate CA signing key (supports FORCE, DRYRUN) |
| `CA EXPORT` | Namespace Read | Export active CA certificate PEM |
| `REGENERATE_CRL` | Admin | Force CRL regeneration |
| `ISSUE` | Namespace Write | Issue certificate from subject + profile |
| `ISSUE_FROM_CSR` | Namespace Write | Issue from CSR PEM |
| `REVOKE` | Namespace Write | Revoke certificate by serial |
| `INSPECT` | Namespace Read | Certificate details by serial |
| `LIST_CERTS` | Namespace Read | List certificates with state/limit/offset |
| `RENEW` | Namespace Write | Re-issue with same subject/profile, new serial |
| `AUTH` | None | Token-based authentication |
| `HEALTH` | None | Health check |
| `PING` | None | Ping |
| `COMMAND LIST` | None | List supported commands |

**HTTP Endpoints (port 6700):**

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/crl/{ca}` | GET | CRL distribution point (PEM) |
| `/ocsp/{ca}` | POST | OCSP responder (DER body) |
| `/ocsp/{ca}/{encoded}` | GET | OCSP GET method (base64/URL-safe) |
| `/health` | GET | Health check (JSON) |

**Rust Client SDK (`shroudb-forge-client`):** Typed async client with methods mirroring all RESP3 commands.

**CLI (`shroudb-forge-cli`):** Interactive REPL and single-command modes for all operations.

### Core operations traced

**1. Certificate Issuance (`ISSUE`):**
`dispatch.rs` → ACL check via `check_dispatch_acl()` → `engine.rs::issue()` → policy evaluation (optional) → profile lookup and TTL validation → `x509.rs::issue_certificate()` (generates keypair via `rcgen::KeyPair::generate_for()`, builds cert with profile constraints, signs with CA's active key) → persist to Store at `forge.{ca_name}.certs` → emit Chronicle audit event → return PEM cert + key + serial.

**2. CA Key Rotation (`CA ROTATE`):**
`engine.rs::ca_rotate()` → ACL + policy check → generate new keypair with same algorithm and TTL → store key material in Keep (defense-in-depth, if configured) → transition current active key to Draining → activate new key → persist CA state to Store → emit audit event → optionally notify via Courier.

**3. OCSP Request Handling:**
HTTP POST to `/ocsp/{ca}` → `http.rs::handle_ocsp_request()` → `ocsp.rs::parse_ocsp_request()` (hand-coded ASN.1 DER parser) → validate issuer name hash + key hash against active and draining keys → look up certificate status → `ocsp.rs::build_ocsp_response()` → sign with CA key → return DER response.

### Capability gating

Four optional capability traits gate extended behavior:

| Trait | Purpose | Fail behavior |
|-------|---------|---------------|
| `ForgeKeepOps` | Defense-in-depth key encryption via Keep | Degrades to Store-only encryption |
| `ChronicleOps` | Audit event logging | Fail-closed: blocks security operations |
| `CourierOps` | Notifications on auto-rotation | Logs warning, continues |
| `PolicyEvaluator` | Fine-grained ABAC policy checks | Fail-open if unconfigured |

No feature flags gate compilation. All capabilities are runtime-optional via `Option<Box<dyn Trait>>`.

---

## Cryptographic Constructs

**Signing Algorithms:**
- ECDSA P-256 with SHA-256 (`PKCS_ECDSA_P256_SHA256`)
- ECDSA P-384 with SHA-384 (`PKCS_ECDSA_P384_SHA384`)
- Ed25519 (`PKCS_ED25519`)

**Libraries:** `ring` 0.17 (RNG, digest, signing), `rcgen` 0.13 (X.509 generation).

**Key Generation:** `rcgen::KeyPair::generate_for()` with algorithm-specific parameters. Serials are 160-bit cryptographically random via `ring::rand::SystemRandom`.

**Key Storage (dual-layer):**
1. Primary: Store trait — key material stored as hex-encoded DER (PKCS#8), encrypted at rest by Store's envelope encryption.
2. Optional: Keep integration — per-path HKDF-derived envelope encryption at `forge/{ca_name}/v{version}` with path as AAD.

**Key Material Protection:**
- `shroudb_crypto::SecretBytes` wrapper — zeroize-on-drop for DER-encoded private keys.
- Explicit `zeroize()` call on hex strings before setting to `None` during key retirement.
- Custom `Debug` impl redacts `key_material` as `[REDACTED]`.

**CRL:** `crl.rs::generate_crl_pem()` — loads CA private key, builds revoked entries with serial + revocation time, signs with CA algorithm, returns PEM.

**OCSP:** Hand-coded ASN.1 DER parser and response builder (~300 lines). Supports SHA-1 (legacy) and SHA-256 hash algorithms. Validates issuer name hash + key hash against active and draining keys (backward compat during rotation). Conservative SHA-256 default for unknown OIDs.

**Key Derivation:** HKDF via Keep integration for defense-in-depth encryption. No PBKDF2 usage.

---

## Engine Relationships

### Calls out to

| Component | How | Purpose |
|-----------|-----|---------|
| `shroudb-store` | Generic `S: Store` | Persistence for CAs and certificates |
| `shroudb-storage` | `EmbeddedStore` in server | Concrete storage backend |
| `shroudb-crypto` | `SecretBytes` | Zeroize-on-drop key wrapping |
| `shroudb-acl` | `check_dispatch_acl()`, `ServerAuthConfig`, `PolicyEvaluator` | Authentication and authorization |
| `shroudb-chronicle-core` | `ChronicleOps` trait | Audit event logging |
| `shroudb-courier-core` | `CourierOps` trait | Rotation notifications |
| `shroudb-protocol-wire` | RESP3 framing | Wire protocol encoding |
| `shroudb-server-tcp` | `ServerProtocol` trait | TCP server framework |
| `shroudb-server-bootstrap` | Bootstrap utilities | Logging, storage init, master key |

### Called by

| Component | How |
|-----------|-----|
| `shroudb-moat` | Embeds `shroudb-forge-engine` + `shroudb-forge-protocol` |
| `shroudb-codegen` | Reads `protocol.toml` for code generation |
| Any ShrouDB service | Via client SDK or direct RESP3 commands for mTLS cert provisioning |

### Sentry / ACL integration

**No Sentry integration.** Forge does not call Sentry.

**ACL is fully wired:**
- Dispatch layer: `shroudb_acl::check_dispatch_acl()` enforces per-command ACL requirements (None / Admin / Namespace Read / Namespace Write).
- Namespace pattern: `forge.{ca_name}.*` scopes read/write operations per CA.
- Engine layer: Optional `PolicyEvaluator` for fine-grained ABAC policy checks per CA operation.
- Auth: `ServerAuthConfig` from shroudb-acl provides token-based authentication with configurable validator.
- Actor identity propagated to all engine methods and audit events.

---

## Store Trait

Forge does **not** implement Store. It is generic over `S: Store` — the engine accepts any Store implementation.

**Concrete backend in standalone mode:** `shroudb_storage::EmbeddedStore` with "forge" namespace.

**Remote mode:** Declared in config schema but `anyhow::bail!("remote store mode not yet implemented")`.

**Storage layout:**
- `forge.cas` — CA metadata and key versions (JSON-serialized)
- `forge.{ca_name}.certs` — Issued certificate metadata per CA

Operations: `store.put()`, `store.get()`, `store.list()`, `store.namespace_create()`.

---

## Licensing Tier

**Tier:** Open core (MIT OR Apache-2.0)

All six crates are dual-licensed MIT/Apache-2.0. No capability traits, feature flags, or compile-time gates fence commercial behavior. The commercial boundary is at the platform level (Moat assembly, Keep integration, Chronicle/Sentry/Courier engines) — not within Forge itself. Forge is fully functional standalone under the open license.

---

## Standalone Extractability

**Extractable as independent product:** Yes, with modest work.

Forge already runs as a standalone binary (`shroudb-forge`) with its own TCP and HTTP servers. Dependencies on ShrouDB commons (store, acl, crypto, protocol-wire, server-tcp, server-bootstrap) would need to be vendored or published, but Forge's core logic (x509, crl, ocsp, profiles, key rotation) has no circular dependencies on other engines. The Keep, Chronicle, and Courier integrations are all optional.

**Value lost without sibling engines:** Defense-in-depth key encryption (Keep), audit trail (Chronicle), rotation notifications (Courier), and fine-grained ABAC (Sentry/PolicyEvaluator). Core CA functionality is unaffected.

### Target persona if standalone

DevOps/platform teams needing an internal CA for service mesh mTLS, Kubernetes sidecar cert provisioning, or zero-trust networking. Competes with Vault PKI secrets engine, step-ca, and CFSSL — but lighter weight and purpose-built for short-lived certs with automatic rotation.

### Pricing model fit if standalone

Open core + support/enterprise tier. Free tier: standalone CA with profiles, CRL, OCSP. Enterprise tier: Keep integration (HSM-backed key storage), Chronicle audit, Courier alerts, PolicyEvaluator ABAC, multi-CA hierarchies, Moat embedding.

---

## Deployment Profile

**Modes:**
- **Standalone binary** (`shroudb-forge`): TCP (RESP3, port 6699) + HTTP sidecar (CRL/OCSP, port 6700). Embedded storage only — remote store not yet implemented.
- **Library crate**: `shroudb-forge-engine` + `shroudb-forge-protocol` embedded in Moat for unified deployment.
- **Docker**: Multi-stage build, multi-arch (amd64/arm64), Alpine 3.21 runtime, non-root user (uid 65532), `/data` volume. Entrypoint script handles volume permission fixup for both Docker and Kubernetes.

**Infrastructure dependencies:** Filesystem (embedded storage). Optional: master key (env var or file) for encryption at rest.

**Self-hostable:** Yes, single binary + data directory. No external services required.

---

## Monetization Signals

**Absent.** No quota enforcement, no usage counters, no API key billing validation, no tenant metering. Certificate issuance is unlimited. CA count is unlimited.

**Tenant-like scoping exists** via CA namespaces (`forge.{ca_name}.*`) and ACL, but this is access control, not billing.

**Profile constraints** (max TTL, SAN restrictions) are operational guardrails, not commercial gates.

---

## Architectural Moat (Component-Level)

**Non-trivial to reproduce:**
1. **Hand-coded OCSP responder** (~300 lines of ASN.1 DER parsing/building). Most internal CAs skip OCSP or delegate to external tooling. Having a built-in OCSP responder that handles key rotation (checking active + draining keys) is operationally valuable and subtle to get right.
2. **Key version state machine** (Staged → Active → Draining → Retired) with automatic scheduler-driven transitions, zeroization on retirement, and backward-compatible verification during drain period. This is the kind of operational correctness that takes incidents to learn.
3. **Profile-based issuance constraints** with subject templates, SAN restrictions, and TTL capping — enforced at the engine level, not just documentation.
4. **Defense-in-depth key storage** — dual-layer encryption (Store + Keep/HKDF) with path-as-AAD is architecturally sound and non-obvious.

**Honest assessment:** The primary moat is platform-level (Moat integration, multi-engine orchestration). Forge alone is a well-built internal CA but competes with mature alternatives (step-ca, Vault PKI). The differentiator is tight integration with ShrouDB's encrypted storage, ACL, and audit infrastructure.

---

## Gaps and Liabilities

1. **Remote store mode unimplemented.** `main.rs` bails on `mode == "remote"`. Limits deployment flexibility.
2. **No LICENSE file in repository.** License is declared only in Cargo.toml. Missing `LICENSE-MIT` and `LICENSE-APACHE` files would block some compliance reviews.
3. **No CHANGELOG.md.** Version is 1.5.6 with no documented release history.
4. **OCSP responder is hand-rolled ASN.1.** Functional but maintenance burden — no upstream library handles updates to RFC 6960. Any parsing bug is a security issue.
5. **PolicyEvaluator is fail-open when unconfigured.** If no evaluator is provided, all operations are allowed. This is documented behavior but a footgun for standalone deployments without ACL.
6. **Scheduler interval is not configurable at runtime.** Set via `ForgeConfig::scheduler_interval_secs` at engine construction time.
7. **`cargo deny` ignores two advisories** (RUSTSEC-2023-0071 RSA Marvin Attack, RUSTSEC-2023-0089 atomic-polyfill unmaintained). Both have documented justifications in `deny.toml`.
8. **No integration tests in server crate** exercising the full TCP+HTTP path (dev-deps include forge-client and tempfile, suggesting they exist or are planned).

---

## Raw Signals for Evaluator

- **Workspace version 1.5.6** with internal crate versions at 1.5.1 — version skew suggests workspace version bumps don't always propagate to member crates.
- **10 ShrouDB commons dependencies** — deep coupling to the platform. Extracting Forge standalone means vendoring or publishing these crates.
- **Edition 2024, MSRV 1.92** — bleeding-edge Rust. Signals active development and willingness to adopt latest language features.
- **`protocol.toml`** is a machine-readable protocol spec consumed by `shroudb-codegen`. This is a code-generation-driven protocol pattern — changes to commands require protocol.toml updates that propagate to client code across repos.
- **Chronicle integration is fail-closed** ("must not proceed unaudited") — security-critical operations block if audit logging fails. This is a strong security posture signal.
- **Courier integration** for rotation notifications suggests operational maturity — teams want to know when CAs auto-rotate.
- **Subject validation** has proptest fuzz tests (commit 2099f4d) — property-based testing for security-sensitive input parsing.
- **No RSA support.** Algorithms are limited to ECDSA P-256, ECDSA P-384, and Ed25519. This is a deliberate choice (modern curves only) but may limit adoption in environments requiring RSA compatibility.
- **CA hierarchies supported** — `PARENT` parameter on `CA CREATE` enables intermediate CAs signed by parent CAs, enabling proper PKI hierarchy.
