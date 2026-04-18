# Forge Engine DAG

## Overview

Forge is ShrouDB's internal Certificate Authority engine. It creates and
rotates CA key material, issues short-lived X.509 certificates (directly or
from a CSR), enforces profile-scoped constraints (server / client / peer),
revokes with RFC 5280 reasons, and publishes revocation state over CRL and
OCSP HTTP endpoints. CA private keys are persisted via the `shroudb-store`
`Store` trait (embedded or remote ShrouDB); issued certificate private keys
are returned once at issuance and never stored. Policy (ABAC), Chronicle
(audit), Keep (defense-in-depth key encryption), and Courier (notifications)
are wired as explicit `Capability<T>` slots — `Enabled(...)`,
`DisabledForTests`, or `DisabledWithJustification("<reason>")`. Absence is
never silent: operators must name why they're opting out.

## Crate dependency DAG

Internal workspace crates (all under `shroudb-forge/`):

```
                       shroudb-forge-core
                       (domain types: CA, cert,
                        profile, x509, CRL, OCSP)
                              ^
                              |
                   +----------+----------+
                   |                     |
           shroudb-forge-engine   shroudb-forge-protocol
           (ForgeEngine,                 ^
            CaManager,                   | (also depends on
            CertManager,                 |  shroudb-forge-engine)
            scheduler,                   |
            capabilities)                |
                   ^                     |
                   |                     |
                   +----------+----------+
                              |
                     shroudb-forge-server
                     (TCP + HTTP binary,
                      config, main)

           shroudb-forge-client  (uses shroudb-client-common only;
                  ^              no dependency on core/engine/protocol)
                  |
           shroudb-forge-cli
```

Notes:

- `shroudb-forge-client` does not depend on `shroudb-forge-core`,
  `-engine`, or `-protocol`. It talks to a running server via
  `shroudb-client-common` over the RESP3 wire protocol.
- `shroudb-forge-engine` pulls in `shroudb-store`, `shroudb-crypto`,
  `shroudb-acl`, `shroudb-audit`, `shroudb-chronicle-core`,
  `shroudb-courier-core`, and `shroudb-server-bootstrap` (for the
  `Capability<T>` wrapper).
- `shroudb-forge-server` is the only crate that pulls in the full stack
  plus `shroudb-storage`, `shroudb-client` (for remote-store mode),
  `shroudb-protocol-wire`, `shroudb-server-tcp`,
  `shroudb-server-bootstrap`, `shroudb-engine-bootstrap` (for
  `[audit]` and `[policy]` capability resolution),
  `shroudb-keep-engine` and `shroudb-keep-core` (for the optional
  embedded Keep sidecar), `axum`, and `tokio-rustls`.

## Capabilities

- CA lifecycle: create, list, info, export active CA certificate (PEM),
  rotate signing keys, auto-retire draining keys, optional parent CA for
  intermediate hierarchies.
- Multiple signing algorithms: `ecdsa-p256`, `ecdsa-p384`, `ed25519`,
  `rsa-2048`, `rsa-3072`, `rsa-4096`.
- Key-version state machine (`Active` -> `Draining` -> `Retired`) with
  configurable `rotation_days` and `drain_days` per CA.
- Certificate issuance: `ISSUE` (Forge generates the key pair and returns
  cert + private key PEM) and `ISSUE_FROM_CSR` (caller submits a PEM CSR;
  Forge signs without seeing the private key).
- Profile-enforced constraints: key usage, extended key usage, max TTL,
  default TTL, SAN DNS / IP allow-list. TTL and SAN violations are
  rejected at issuance.
- Revocation: `REVOKE` with RFC 5280 reasons (`unspecified`,
  `key_compromise`, `ca_compromise`, `affiliation_changed`, `superseded`,
  `cessation_of_operation`). CRL is regenerated before the revocation is
  committed to the Store; if CRL signing fails the revocation is not
  persisted.
- Renewal: `RENEW` re-issues a certificate with the same profile and SANs
  and a new serial / expiry.
- Inspection and listing: `INSPECT <ca> <serial>`, `LIST_CERTS` with
  state / limit / offset filters.
- CRL and OCSP endpoints: `GET /crl/{ca}` returns PEM-encoded CRL;
  `POST /ocsp/{ca}` and `GET /ocsp/{ca}/{encoded_request}` implement
  RFC 6960 OCSP. Served from an axum HTTP sidecar on `default_http_port`
  6700 alongside the RESP3 TCP port 6699.
- ABAC policy enforcement via `shroudb-acl::PolicyEvaluator` wrapped in
  `Capability<Arc<dyn PolicyEvaluator>>`. Default `PolicyMode::Closed` —
  if the policy slot resolves to disabled, every mutating operation is
  denied; `PolicyMode::Open` is an explicit dev-only opt-in.
- Background scheduler: auto-rotates CAs past `rotation_days`,
  auto-retires draining keys past `drain_days` (zeroizing key material),
  and periodically regenerates CRLs. Runtime interval is mutable via
  `CONFIG SET scheduler_interval_secs`.
- Optional Keep-backed defense-in-depth: when `ForgeKeepOps` is wired
  via `Capability::Enabled`, CA private keys are additionally stored
  through Keep at path `forge/{ca_name}/v{version}`.

## Engine dependencies

Forge's runtime depends on two other ShrouDB engines through capability
traits, plus the ShrouDB core `Store` for primary persistence. All
engine dependencies are explicit `Capability<T>` slots at construction
time (`ForgeEngine::new(... policy_evaluator, chronicle, keep)` and
`ForgeEngine::new_with_capabilities(... policy_evaluator, chronicle,
keep, courier)`).

### Dependency: chronicle

Pinned via `shroudb-chronicle-core` (workspace dep `1.11.0`), used
through the `shroudb_chronicle_core::ops::ChronicleOps` trait in
`shroudb-forge-engine/src/engine.rs`, wrapped in
`Capability<Arc<dyn ChronicleOps>>`.

**What breaks without it.** Nothing on the hot path. When chronicle
resolves to disabled, `emit_audit_event` short-circuits and returns
`Ok(())` — `CA_CREATE`, `CA_ROTATE`, `ISSUE`, `ISSUE_FROM_CSR`,
`REVOKE`, and `REGENERATE_CRL` all still succeed and return normal
results. The cost is operational: security-critical certificate
operations proceed unaudited. There is no local fallback log of audit
records — the event is simply dropped.

**What works with it.** Every successful CA and certificate mutation
emits a structured `Event` (engine=`Forge`, resource=`ca`, actor,
duration_ms) to Chronicle. Chronicle errors are propagated as
`ForgeError::Internal("audit failed: ...")` and fail the originating
request, preserving a fail-closed audit posture when Chronicle is
configured.

### Dependency: courier

Pinned via `shroudb-courier-core` (workspace dep `1.3.4`), used
through the `shroudb_courier_core::ops::CourierOps` trait in
`shroudb-forge-engine/src/scheduler.rs`, wrapped in
`Capability<Arc<dyn CourierOps>>`.

**What breaks without it.** Nothing on the hot path. `ISSUE`, `REVOKE`,
`CA_CREATE`, and `CA_ROTATE` never call Courier directly — courier is
consulted only by the background scheduler, and only on
auto-rotation. When disabled the scheduler still rotates keys, retires
draining keys, and regenerates CRLs; operators simply do not receive a
push notification when an auto-rotation occurs.

**What works with it.** When the scheduler auto-rotates a CA it calls
`courier.notify("ops", "CA key rotated", "CA '<name>' rotated to
v<N>")`. Courier send failures are logged as warnings and do not fail
the rotation.

### Dependency: shroudb-store (not a peer engine)

Not a sibling engine but load-bearing: `CaManager` and `CertManager`
persist CA metadata, key material, issued certificate records, and CRL
PEM through the `shroudb_store::Store` trait. The `shroudb-forge`
binary selects between `EmbeddedStore` (backed by `shroudb-storage`)
and `shroudb_client::RemoteStore` (remote ShrouDB) via
`store.mode = "embedded" | "remote"` in config. Without a Store there
is no Forge — the engine cannot construct.

## Reverse dependencies

Two consumer surfaces inside this tree:

- `shroudb-forge-cli` depends on `shroudb-forge-client`. The CLI is a
  thin RESP3 client that talks to a running `shroudb-forge` server.
- `shroudb-forge-server` dev-depends on `shroudb-forge-client` for
  integration tests (`tests/integration.rs`, `tests/common/mod.rs`).

Outside this repo (as confirmed by a workspace-wide scan of ShrouDB
repos):

- `shroudb-moat` depends on `shroudb-forge-core`,
  `shroudb-forge-engine`, and `shroudb-forge-protocol` (behind the
  `forge` cargo feature). It constructs `ForgeEngine` directly via
  `new_with_capabilities` and does not use `shroudb-forge-client`.
- No other ShrouDB repo currently consumes `shroudb-forge-client`. Its
  only callers are `shroudb-forge-cli` and this crate's own tests.

## Deployment modes

Forge runs in two deployment shapes, both driven by the same
`ForgeEngine` type.

### Standalone (`shroudb-forge-server`)

The `shroudb-forge` binary (`shroudb-forge-server/src/main.rs`) is the
default workspace member. It:

- Listens on RESP3 TCP (default `6699`, optional TLS via
  `shroudb-server-tcp`) for protocol commands.
- Runs an axum HTTP sidecar (default `6700`) serving `/crl/{ca}`,
  `/ocsp/{ca}` (POST and GET), and `/health`.
- Opens a `Store`: `embedded` (local `shroudb-storage` +
  `EmbeddedStore` namespaced `"forge"`) or `remote` (connects to a
  ShrouDB server via `shroudb_client::RemoteStore`).
- Resolves `[audit]` and `[policy]` capability sections via
  `shroudb-engine-bootstrap` — both are **required** in config, with
  modes `remote` / `embedded` / `disabled` (the last requiring a
  `justification = "<reason>"`). There is no silent fallback.
- Builds the Keep slot from the optional `[keep]` config section. When
  `keep.mode = "embedded"` and `store.mode = "embedded"`, the server
  spins up an in-process `KeepEngine` on a dedicated `"keep"`
  namespace of the same `StorageEngine` Forge uses (sharing the same
  master key), and wires it as `Capability::Enabled` via
  `EmbeddedForgeKeepOps`. `keep.mode = "remote"` is reserved and
  currently errors — standalone remote Keep wiring is follow-up
  scope. Omitting `[keep]` resolves the slot to
  `Capability::disabled("forge: no [keep] config …")`.
- Constructs `ForgeEngine::new(store, profiles, forge_config,
  policy_cap, audit_cap, keep_cap)` — which internally sets the
  courier slot to `Capability::disabled("courier rotation-notify not
  configured — use new_with_capabilities to wire it")`.
- Seeds CAs listed in the config file on boot
  (`CaManager::seed_if_absent`).
- Starts the background scheduler and waits for shutdown.

With `[audit] mode = "remote"` or `"embedded"` the standalone server
wires Chronicle end-to-end, and with `[keep] mode = "embedded"` it
wires an in-process Keep sidecar for CA private-key defense-in-depth.
Courier remains unwired in the standalone binary — the scheduler's
rotation notifications are only exercised in the Moat-embedded
deployment, which is the shape that currently constructs Forge with
`new_with_capabilities`.

### Embedded (via `shroudb-moat`)

`shroudb-moat` embeds `shroudb-forge-engine` and
`shroudb-forge-protocol` as optional cargo features (`forge`,
enabled by default). Moat constructs `ForgeEngine` with
`new_with_capabilities`, wiring Chronicle (`chronicle` feature),
Courier (`courier` feature), and optionally Keep when those features
are enabled, and dispatches RESP3 commands through the shared moat
listener. This is the deployment shape where the Courier integration
described above is actually exercised.
