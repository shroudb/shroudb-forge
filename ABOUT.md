# Understanding Forge

## For Everyone: What Forge Does

Services that communicate internally need to verify each other's identity. The standard approach is mTLS — each service has a TLS certificate, and both sides verify the other's certificate during the handshake. But someone needs to issue those certificates.

**Forge is an internal Certificate Authority.** It generates CA key pairs, issues short-lived certificates for services, enforces profile-based constraints (server vs. client vs. peer), and handles revocation via CRL and OCSP endpoints. Services request certificates from Forge, and Forge signs them with the CA's private key.

**Why it matters:**

- Short-lived certificates reduce the blast radius of a compromised key
- Profile enforcement prevents a server certificate from being used for client auth
- CRL and OCSP endpoints let services check revocation in real time
- CA key rotation follows the same active → draining → retired lifecycle as other ShrouDB engines
- Private keys are returned at issuance and never stored — only the certificate is retained

## For Technical Leaders: Architecture and Trade-offs

### The Problem

Internal mTLS bootstrapping requires a CA. External CAs are expensive and slow for internal services. Self-signed certificates break the chain of trust. Teams either run a complex CA stack (step-ca, Vault PKI) or skip mTLS entirely.

### What Forge Is

Forge is an **internal certificate authority** — not a public CA, not a PKI framework. It issues certificates for internal service-to-service mTLS. It's designed for short-lived certificates and automated issuance, not long-lived human-facing certificates.

### Key Architectural Decisions

| Decision | Rationale |
|----------|-----------|
| **Short-lived certificates** | Default TTLs measured in hours/days, not years. Reduces the need for complex revocation infrastructure. |
| **Profile constraints** | Certificates are typed (server, client, peer). A server cert can't be used for client auth. Prevents lateral movement. |
| **Private key not stored** | The private key is returned once at issuance and never persisted. If the service loses it, it issues a new certificate. |
| **CRL + OCSP over HTTP** | Standards-compliant revocation checking. HTTP sidecar runs alongside the TCP wire protocol. |
| **CSR support** | Services can generate their own key pairs and submit CSRs. Forge signs without ever seeing the private key. |
| **CA hierarchy** | Optional PARENT parameter allows intermediate CAs. Root CA signs intermediates, intermediates sign leaf certificates. |

### Operational Model

- **CA lifecycle:** Create → rotate keys → drain old keys → retire. Same state machine as Cipher keyrings.
- **Issuance:** ISSUE or ISSUE_FROM_CSR. Returns PEM certificate + private key (or just certificate for CSR).
- **Revocation:** REVOKE with RFC 5280 reasons. Revoked certificates appear in CRL and OCSP responses.
- **Renewal:** RENEW re-issues with same profile and SANs, new serial and expiry.
- **ACL:** CA-scoped namespace grants. `forge.internal-ca.*` controls who can issue/revoke.
- **Durability:** ShrouDB v1 Store trait for persistence. Embedded or remote mode.

### Ecosystem

Forge is one engine in the ShrouDB ecosystem:

- **ShrouDB** — encrypted versioned KV store (the foundation)
- **Sigil** — credential envelope engine
- **Cipher** — encryption-as-a-service
- **Veil** — encrypted search
- **Keep** — secrets manager
- **Forge** — certificate authority (this engine)
- **Sentry** — authorization policy
- **Courier** — secure notifications
- **Chronicle** — audit events
- **Moat** — unified binary embedding all engines
