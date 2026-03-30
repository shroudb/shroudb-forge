# Forge

An internal certificate authority engine for [ShrouDB](https://github.com/shroudb/shroudb).

## What It Does

Forge is a lightweight internal CA — it issues short-lived TLS certificates for mTLS bootstrapping in service-to-service communication. It manages CA lifecycle (creation, key rotation, draining, retirement), enforces profile-based constraints on certificate issuance, and provides CRL/OCSP endpoints for revocation checking.

## Quick Start

```sh
export SHROUDB_MASTER_KEY="$(openssl rand -hex 32)"
cargo run
```

Forge listens on TCP port 6699 (RESP3) and HTTP port 6700 (CRL/OCSP).

```sh
# Create a CA
shroudb-forge-cli CA CREATE internal-ca ecdsa-p256 SUBJECT "CN=Internal CA,O=Acme"

# Issue a certificate
shroudb-forge-cli ISSUE internal-ca "CN=api.internal" server SAN_DNS api.internal TTL 24h

# List certificates
shroudb-forge-cli LIST_CERTS internal-ca

# Revoke
shroudb-forge-cli REVOKE internal-ca <serial>

# CRL endpoint
curl http://localhost:6700/crl/internal-ca
```

## Wire Protocol (RESP3)

```
CA CREATE <name> <algo> SUBJECT <subject> [TTL_DAYS <n>] [PARENT <ca>]
CA INFO <name>
CA LIST
CA ROTATE <name> [FORCE] [DRYRUN]
CA EXPORT <name>
ISSUE <ca> <subject> <profile> [TTL <dur>] [SAN_DNS <n>...] [SAN_IP <ip>...]
ISSUE_FROM_CSR <ca> <csr_pem> <profile> [TTL <dur>]
REVOKE <ca> <serial> [REASON <reason>]
INSPECT <ca> <serial>
LIST_CERTS <ca> [STATE <state>] [LIMIT <n>] [OFFSET <n>]
RENEW <ca> <serial> [TTL <dur>]
AUTH <token>
HEALTH
PING
```

## HTTP Endpoints

CRL and OCSP are standard HTTP (RFC 5280 / RFC 6960):

```
GET  /crl/{ca}                    — PEM-encoded CRL
POST /ocsp/{ca}                   — OCSP via POST (DER body)
GET  /ocsp/{ca}/{encoded_request} — OCSP via GET (base64 URL-encoded)
GET  /health                      — health check
```

## Configuration

| Setting | CLI flag | Env var | Default |
|---------|----------|---------|---------|
| Config file | `--config` | `FORGE_CONFIG` | — |
| Master key | — | `SHROUDB_MASTER_KEY` | ephemeral (dev) |
| Data directory | `--data-dir` | `FORGE_DATA_DIR` | `./forge-data` |
| TCP bind | `--tcp-bind` | `FORGE_TCP_BIND` | `0.0.0.0:6699` |
| HTTP bind | `--http-bind` | `FORGE_HTTP_BIND` | `0.0.0.0:6700` |
| Log level | `--log-level` | `FORGE_LOG_LEVEL` | `info` |

## Algorithms

| Algorithm | Use Case |
|-----------|----------|
| `ecdsa-p256` | Default. Fast, widely supported. |
| `ecdsa-p384` | Higher security margin. |
| `ed25519` | Small keys, fast signing. Limited TLS stack support. |

## Certificate Profiles

Profiles constrain what a certificate can be used for:

- **server** — TLS server authentication (Extended Key Usage: serverAuth)
- **client** — TLS client authentication (Extended Key Usage: clientAuth)
- **peer** — Both server and client auth (mTLS peers)

## Security

- CA private keys encrypted at rest, zeroed from memory after use
- Short-lived certificates (default TTL configurable per CA and per issuance)
- Private keys returned at issuance only, never stored
- Revocation via CRL and OCSP
- Token-based ACL with namespace-scoped grants
- Core dumps disabled (Linux + macOS)

## Architecture

```
shroudb-forge-core/        — domain types (CA, Certificate, Profile, CRL)
shroudb-forge-engine/      — Store-backed logic (ForgeEngine, CA lifecycle)
shroudb-forge-protocol/    — RESP3 command parsing + dispatch
shroudb-forge-server/      — TCP + HTTP binary (CRL/OCSP)
shroudb-forge-client/      — Rust client SDK
shroudb-forge-cli/         — CLI tool
```

See [`protocol.toml`](protocol.toml) for the full protocol specification.

## License

MIT OR Apache-2.0
