# Forge Documentation

## Configuration

### Config file

```toml
[server]
tcp_bind = "0.0.0.0:6699"
http_bind = "0.0.0.0:6700"

[store]
mode = "embedded"
data_dir = "./forge-data"

[auth]
method = "token"

[auth.tokens.infra-token]
tenant = "platform"
actor = "infra"
platform = true

[auth.tokens.api-service]
tenant = "tenant-a"
actor = "api-svc"
grants = [
    { namespace = "forge.internal-ca.*", scopes = ["read", "write"] },
]
```

### Master key

```sh
openssl rand -hex 32
export SHROUDB_MASTER_KEY="<64-hex-chars>"
```

Without a master key, Forge starts in dev mode with an ephemeral key — CA keys won't survive restarts.

## Certificate Authorities

### Create a CA

```sh
# ECDSA P-256 (default, recommended)
shroudb-forge-cli CA CREATE internal-ca ecdsa-p256 SUBJECT "CN=Internal CA,O=Acme"

# With custom CA certificate TTL
shroudb-forge-cli CA CREATE internal-ca ecdsa-p256 SUBJECT "CN=Internal CA" TTL_DAYS 365

# Intermediate CA (signed by parent)
shroudb-forge-cli CA CREATE leaf-ca ecdsa-p256 SUBJECT "CN=Leaf CA" PARENT internal-ca
```

### CA info

```sh
shroudb-forge-cli CA INFO internal-ca
```

Returns CA metadata including subject, algorithm, and key version history (active, draining, retired).

### List CAs

```sh
shroudb-forge-cli CA LIST
```

### Rotate CA key

```sh
# Only if rotation period elapsed
shroudb-forge-cli CA ROTATE internal-ca

# Force rotation regardless of age
shroudb-forge-cli CA ROTATE internal-ca FORCE

# Preview without applying
shroudb-forge-cli CA ROTATE internal-ca DRYRUN
```

Active key → draining (still verifies, doesn't sign new certs). New key becomes active.

### Export CA certificate

```sh
shroudb-forge-cli CA EXPORT internal-ca
```

Returns the active CA certificate in PEM format. Use this to configure trust anchors in services.

## Certificate Issuance

### Issue a certificate

```sh
# Server certificate
shroudb-forge-cli ISSUE internal-ca "CN=api.internal" server \
  SAN_DNS api.internal SAN_DNS api.internal.svc.cluster.local \
  TTL 24h

# Client certificate
shroudb-forge-cli ISSUE internal-ca "CN=worker" client TTL 7d

# Peer certificate (mTLS both sides)
shroudb-forge-cli ISSUE internal-ca "CN=mesh-node" peer \
  SAN_IP 10.0.1.5 SAN_DNS mesh-node.internal \
  TTL 48h
```

Returns: PEM certificate + PEM private key. **The private key is returned once and never stored.** If the service loses it, issue a new certificate.

### Issue from CSR

```sh
shroudb-forge-cli ISSUE_FROM_CSR internal-ca "$(cat service.csr)" server TTL 24h
```

The service generates its own key pair, submits a CSR. Forge signs without seeing the private key.

### Inspect a certificate

```sh
shroudb-forge-cli INSPECT internal-ca <serial>
```

Returns subject, state (active/revoked/expired), issuance date, expiry, SANs, profile.

### List certificates

```sh
# All certificates for a CA
shroudb-forge-cli LIST_CERTS internal-ca

# Only active
shroudb-forge-cli LIST_CERTS internal-ca STATE active

# With pagination
shroudb-forge-cli LIST_CERTS internal-ca LIMIT 50 OFFSET 100
```

### Renew a certificate

```sh
shroudb-forge-cli RENEW internal-ca <serial> TTL 24h
```

Re-issues with the same profile and SANs, new serial and expiry. Returns new cert + private key.

## Revocation

### Revoke a certificate

```sh
# Default reason (unspecified)
shroudb-forge-cli REVOKE internal-ca <serial>

# With reason
shroudb-forge-cli REVOKE internal-ca <serial> REASON key_compromise
```

RFC 5280 revocation reasons: `unspecified`, `key_compromise`, `ca_compromise`, `affiliation_changed`, `superseded`, `cessation_of_operation`.

### CRL endpoint

```sh
curl http://localhost:6700/crl/internal-ca
```

Returns the PEM-encoded Certificate Revocation List. Services poll this periodically.

### OCSP endpoints

```sh
# POST (DER body)
curl -X POST http://localhost:6700/ocsp/internal-ca \
  -H "Content-Type: application/ocsp-request" \
  --data-binary @request.der

# GET (base64 URL-encoded)
curl http://localhost:6700/ocsp/internal-ca/<base64url-encoded-request>
```

Real-time revocation status per RFC 6960.

## Profiles

| Profile | Extended Key Usage | Use Case |
|---------|-------------------|----------|
| `server` | serverAuth | TLS server certificates |
| `client` | clientAuth | TLS client certificates |
| `peer` | serverAuth + clientAuth | mTLS peer certificates |

## Algorithms

| Algorithm | Key Size | Notes |
|-----------|----------|-------|
| `ecdsa-p256` | 256-bit | Default. Fast, widely supported by TLS stacks. |
| `ecdsa-p384` | 384-bit | Higher security margin. |
| `ed25519` | 256-bit | Smallest keys, fastest signing. Limited TLS stack support. |

## Rust Client SDK

```rust
use shroudb_forge_client::ForgeClient;

let mut client = ForgeClient::connect("127.0.0.1:6699").await?;

// CA management
client.ca_create("internal", "ecdsa-p256", "CN=Internal CA,O=Acme", None, None).await?;
let info = client.ca_info("internal").await?;
let cas = client.ca_list().await?;
client.ca_rotate_opts("internal", false, false).await?;
let ca_pem = client.ca_export("internal").await?;

// Certificate issuance
let cert = client.issue("internal", "CN=api.svc", "server",
    Some("24h"), &["api.svc"], &["10.0.1.5"]).await?;
println!("cert: {}", cert.certificate_pem);
println!("key: {}", cert.private_key_pem);

// CSR-based issuance
let cert = client.issue_from_csr("internal", &csr_pem, "client", Some("7d")).await?;

// Revocation
client.revoke("internal", &serial, Some("superseded")).await?;

// Inspection
let details = client.inspect("internal", &serial).await?;
let certs = client.list_certs("internal", Some("active"), Some(50), None).await?;

// Renewal
let renewed = client.renew("internal", &serial, Some("24h")).await?;
```

## Security

- **CA private keys:** encrypted at rest, zeroed from memory after signing
- **Issued private keys:** returned once, never stored by Forge
- **Short-lived certificates:** default TTLs encourage frequent rotation
- **Profile enforcement:** prevents certificate misuse across roles
- **Core dumps disabled:** Linux (prctl) and macOS (setrlimit)
- **Token-based ACL:** CA-scoped namespace grants
