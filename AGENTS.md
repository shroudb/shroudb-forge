# Forge (formerly Mint) — Agent Instructions

> Lightweight internal CA: issues short-lived X.509 certificates for service-to-service mTLS with profile-based constraints, key rotation, and CRL/OCSP endpoints.

## Quick Context

- **Role in ecosystem**: Certificate authority for mTLS bootstrapping across ShrouDB services
- **Deployment modes**: embedded | remote (TCP port 6699, HTTP port 6700)
- **Wire protocol**: RESP3 (TCP) + HTTP (CRL/OCSP)
- **Backing store**: ShrouDB Store trait (encrypted at rest)

## Workspace Layout

```
shroudb-forge-core/      # CA, certificate, profile, X.509, CRL, OCSP types
shroudb-forge-engine/    # ForgeEngine, CaManager, CertManager, scheduler
shroudb-forge-protocol/  # RESP3 command parsing + dispatch
shroudb-forge-server/    # TCP + HTTP binary
shroudb-forge-client/    # Typed Rust SDK
shroudb-forge-cli/       # CLI tool
```

## RESP3 Commands

### CA Management

| Command | Args | Returns | Description |
|---------|------|---------|-------------|
| `CA CREATE` | `<name> <algorithm> SUBJECT <dn> [TTL_DAYS <n>] [PARENT <ca>]` | `{status, ca, algorithm, subject, active_version, ttl_days, parent?}` | Create CA (Admin) |
| `CA INFO` | `<name>` | `{status, ca, algorithm, subject, ttl_days, key_versions, ...}` | CA metadata |
| `CA LIST` | — | `[names]` | List all CAs |
| `CA ROTATE` | `<name> [FORCE] [DRYRUN]` | `{status, rotated, key_version, previous_version?}` | Rotate CA signing key (Admin) |
| `CA EXPORT` | `<name>` | `{status, certificate_pem}` | Export active CA certificate (PEM) |

### Certificate Operations

| Command | Args | Returns | Description |
|---------|------|---------|-------------|
| `ISSUE` | `<ca> <subject> <profile> [TTL <dur>] [SAN_DNS <name>...] [SAN_IP <ip>...]` | `{status, certificate_pem, private_key_pem, serial, not_before, not_after, ca_key_version}` | Issue certificate |
| `ISSUE_FROM_CSR` | `<ca> <csr_pem> <profile> [TTL <dur>]` | Same (no private_key_pem) | Issue from CSR |
| `REVOKE` | `<ca> <serial> [REASON <reason>]` | `{status, ca, serial}` | Revoke certificate + regen CRL |
| `INSPECT` | `<ca> <serial>` | `{status, serial, ca, subject, profile, state, san_dns, san_ip, certificate_pem, ...}` | Certificate details |
| `LIST_CERTS` | `<ca> [STATE <active\|revoked>] [LIMIT <n>] [OFFSET <n>]` | `{status, ca, count, certificates}` | List certificates |
| `RENEW` | `<ca> <serial> [TTL <dur>]` | Same as ISSUE | Re-issue with same subject/profile/SANs, new serial |

### Command Examples

```
> CA CREATE internal ecdsa-p256 SUBJECT "CN=Internal CA,O=ShrouDB"
{"status":"ok","ca":"internal","algorithm":"ecdsa-p256","subject":"CN=Internal CA,O=ShrouDB","active_version":1,"ttl_days":3650}

> ISSUE internal "CN=myservice" server TTL 30d SAN_DNS myservice.local
{"status":"ok","certificate_pem":"-----BEGIN CERTIFICATE-----\n...","private_key_pem":"-----BEGIN PRIVATE KEY-----\n...","serial":"a1b2c3...","not_before":1711843200,"not_after":1714435200,"ca_key_version":1}
```

## HTTP Endpoints

```
GET  /crl/{ca}                     → PEM CRL
POST /ocsp/{ca}                    → DER OCSP request → DER response
GET  /ocsp/{ca}/{base64_request}   → URL-encoded OCSP
GET  /health                       → {"status":"ok"}
```

## Configuration

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `server.tcp_bind` | `SocketAddr` | `"0.0.0.0:6699"` | RESP3 TCP endpoint |
| `server.http_bind` | `SocketAddr` | `"0.0.0.0:6700"` | HTTP CRL/OCSP endpoint |
| `engine.default_rotation_days` | `u32` | `365` | CA key auto-rotation |
| `engine.default_drain_days` | `u32` | `90` | Grace period before retirement |
| `engine.default_ca_ttl_days` | `u32` | `3650` | Default CA certificate validity |
| `engine.scheduler_interval_secs` | `u64` | `3600` | Key lifecycle check interval |

### Certificate Profiles (config)

```toml
[profiles.server]
key_usage = ["DigitalSignature", "KeyEncipherment"]
extended_key_usage = ["ServerAuth"]
max_ttl_days = 90
default_ttl = "30d"
allow_san_dns = true
allow_san_ip = true

[profiles.client]
key_usage = ["DigitalSignature"]
extended_key_usage = ["ClientAuth"]
max_ttl_days = 30
default_ttl = "1h"
```

## Data Model

| Namespace | Key | Value | Purpose |
|-----------|-----|-------|---------|
| `forge.cas` | CA name | JSON `CertificateAuthority` | CA metadata + key versions |
| `forge.{ca_name}.certs` | Serial (hex) | JSON `IssuedCertificate` | Certificate metadata + PEM |

### Key State Machine

```
Staged → Active → Draining → Retired

Active:   signs certificates
Draining: verifies only (grace period)
Retired:  private key zeroized
```

### Algorithms

| Algorithm | Wire Name | Signature |
|-----------|-----------|-----------|
| ECDSA P-256 | `ecdsa-p256` | `PKCS_ECDSA_P256_SHA256` |
| ECDSA P-384 | `ecdsa-p384` | `PKCS_ECDSA_P384_SHA384` |
| Ed25519 | `ed25519` | `PKCS_ED25519` |

### Private Key Handling

- **Certificates**: Private key returned in `ISSUE` response only, **never stored**. Caller must secure it.
- **CA keys**: Stored hex-encoded in `CaKeyVersion.key_material`, encrypted at rest via Store. Zeroized on retirement.
- **CSR**: No private key returned (caller already has it).

## Common Mistakes

- `ISSUE` returns the private key exactly once — it is never stored. If lost, issue a new certificate.
- TTL is clamped to `profile.max_ttl_days` — requesting a longer TTL silently caps it
- `REVOKE` regenerates the CRL automatically. The CRL is cached in memory and served via HTTP.
- `RENEW` creates a new certificate with a new serial. The caller is responsible for revoking the old one if needed.
- Revocation reasons follow RFC 5280: `unspecified`, `key_compromise`, `ca_compromise`, `affiliation_changed`, `superseded`, `cessation_of_operation`

## Related Crates

| Crate | Relationship |
|-------|-------------|
| `shroudb-store` | Provides Store trait for CA/certificate persistence |
| `shroudb-crypto` | Key generation for ECDSA/Ed25519 |
| `rcgen` | X.509 certificate generation and CSR parsing |
| `shroudb-moat` | Embeds Forge; issued certs integrate with ShrouDB's own TLS config |
