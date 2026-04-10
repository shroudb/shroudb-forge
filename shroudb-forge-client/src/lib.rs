//! Typed Rust client library for Forge.
//!
//! Provides a high-level async API for interacting with a Forge server
//! over TCP (RESP3 wire protocol).

mod connection;
mod error;

pub use error::ClientError;

use connection::Connection;

/// Result from an issue or renew operation.
#[derive(Debug, Clone)]
pub struct IssueResult {
    pub certificate_pem: String,
    pub private_key_pem: String,
    pub serial: String,
}

/// A Forge client connected via TCP.
pub struct ForgeClient {
    conn: Connection,
}

impl ForgeClient {
    /// Connect directly to a standalone Forge server.
    pub async fn connect(addr: &str) -> Result<Self, ClientError> {
        let conn = Connection::connect(addr).await?;
        Ok(Self { conn })
    }

    /// Connect to a Forge engine through a Moat gateway.
    ///
    /// Commands are automatically prefixed with `FORGE` for Moat routing.
    /// Meta-commands (AUTH, HEALTH, PING) are sent without prefix.
    pub async fn connect_moat(addr: &str) -> Result<Self, ClientError> {
        let conn = Connection::connect_moat(addr).await?;
        Ok(Self { conn })
    }

    /// Authenticate this connection.
    pub async fn auth(&mut self, token: &str) -> Result<(), ClientError> {
        let resp = self.meta_command(&["AUTH", token]).await?;
        check_status(&resp)
    }

    /// Health check.
    pub async fn health(&mut self) -> Result<(), ClientError> {
        let resp = self.meta_command(&["HEALTH"]).await?;
        check_status(&resp)
    }

    // ── CA management ─────────────────────────────────────────────

    /// Create a certificate authority.
    pub async fn ca_create(
        &mut self,
        name: &str,
        algorithm: &str,
        subject: &str,
        ttl_days: Option<u32>,
        parent: Option<&str>,
    ) -> Result<serde_json::Value, ClientError> {
        let mut args = vec!["CA", "CREATE", name, algorithm, "SUBJECT", subject];
        let ttl_str;
        if let Some(days) = ttl_days {
            ttl_str = days.to_string();
            args.push("TTL_DAYS");
            args.push(&ttl_str);
        }
        if let Some(p) = parent {
            args.push("PARENT");
            args.push(p);
        }
        let resp = self.command(&args).await?;
        check_status(&resp)?;
        Ok(resp)
    }

    /// Get CA info.
    pub async fn ca_info(&mut self, name: &str) -> Result<serde_json::Value, ClientError> {
        let resp = self.command(&["CA", "INFO", name]).await?;
        check_status(&resp)?;
        Ok(resp)
    }

    /// List all CA names.
    pub async fn ca_list(&mut self) -> Result<Vec<String>, ClientError> {
        let resp = self.command(&["CA", "LIST"]).await?;
        resp.as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .ok_or_else(|| ClientError::ResponseFormat("expected array".into()))
    }

    /// Rotate a CA's signing key.
    pub async fn ca_rotate(
        &mut self,
        name: &str,
        force: bool,
    ) -> Result<serde_json::Value, ClientError> {
        self.ca_rotate_opts(name, force, false).await
    }

    /// Rotate a CA's signing key with dry-run option.
    pub async fn ca_rotate_opts(
        &mut self,
        name: &str,
        force: bool,
        dryrun: bool,
    ) -> Result<serde_json::Value, ClientError> {
        let mut args = vec!["CA", "ROTATE", name];
        if force {
            args.push("FORCE");
        }
        if dryrun {
            args.push("DRYRUN");
        }
        let resp = self.command(&args).await?;
        check_status(&resp)?;
        Ok(resp)
    }

    /// Export a CA's certificate PEM.
    pub async fn ca_export(&mut self, name: &str) -> Result<String, ClientError> {
        let resp = self.command(&["CA", "EXPORT", name]).await?;
        check_status(&resp)?;
        resp["certificate_pem"]
            .as_str()
            .map(String::from)
            .ok_or_else(|| ClientError::ResponseFormat("missing certificate_pem".into()))
    }

    // ── Certificate operations ────────────────────────────────────

    /// Issue a certificate.
    pub async fn issue(
        &mut self,
        ca: &str,
        subject: &str,
        profile: &str,
        ttl: Option<&str>,
        san_dns: &[&str],
        san_ip: &[&str],
    ) -> Result<IssueResult, ClientError> {
        let mut args = vec!["ISSUE", ca, subject, profile];
        if let Some(t) = ttl {
            args.push("TTL");
            args.push(t);
        }
        if !san_dns.is_empty() {
            args.push("SAN_DNS");
            for dns in san_dns {
                args.push(dns);
            }
        }
        if !san_ip.is_empty() {
            args.push("SAN_IP");
            for ip in san_ip {
                args.push(ip);
            }
        }
        let resp = self.command(&args).await?;
        check_status(&resp)?;
        Ok(IssueResult {
            certificate_pem: resp["certificate_pem"]
                .as_str()
                .ok_or_else(|| ClientError::ResponseFormat("missing certificate_pem".into()))?
                .to_string(),
            private_key_pem: resp["private_key_pem"]
                .as_str()
                .ok_or_else(|| ClientError::ResponseFormat("missing private_key_pem".into()))?
                .to_string(),
            serial: resp["serial"]
                .as_str()
                .ok_or_else(|| ClientError::ResponseFormat("missing serial".into()))?
                .to_string(),
        })
    }

    /// Issue a certificate from a PEM-encoded CSR.
    pub async fn issue_from_csr(
        &mut self,
        ca: &str,
        csr_pem: &str,
        profile: &str,
        ttl: Option<&str>,
    ) -> Result<IssueResult, ClientError> {
        let mut args = vec!["ISSUE_FROM_CSR", ca, csr_pem, profile];
        if let Some(t) = ttl {
            args.push("TTL");
            args.push(t);
        }
        let resp = self.command(&args).await?;
        check_status(&resp)?;
        Ok(IssueResult {
            certificate_pem: resp["certificate_pem"]
                .as_str()
                .ok_or_else(|| ClientError::ResponseFormat("missing certificate_pem".into()))?
                .to_string(),
            private_key_pem: resp["private_key_pem"].as_str().unwrap_or("").to_string(),
            serial: resp["serial"]
                .as_str()
                .ok_or_else(|| ClientError::ResponseFormat("missing serial".into()))?
                .to_string(),
        })
    }

    /// Revoke a certificate.
    pub async fn revoke(
        &mut self,
        ca: &str,
        serial: &str,
        reason: Option<&str>,
    ) -> Result<(), ClientError> {
        let mut args = vec!["REVOKE", ca, serial];
        if let Some(r) = reason {
            args.push("REASON");
            args.push(r);
        }
        let resp = self.command(&args).await?;
        check_status(&resp)
    }

    /// Inspect a certificate.
    pub async fn inspect(
        &mut self,
        ca: &str,
        serial: &str,
    ) -> Result<serde_json::Value, ClientError> {
        let resp = self.command(&["INSPECT", ca, serial]).await?;
        check_status(&resp)?;
        Ok(resp)
    }

    /// List certificates for a CA.
    pub async fn list_certs(
        &mut self,
        ca: &str,
        state: Option<&str>,
        limit: Option<usize>,
        offset: Option<usize>,
    ) -> Result<serde_json::Value, ClientError> {
        let mut args = vec!["LIST_CERTS", ca];
        if let Some(s) = state {
            args.push("STATE");
            args.push(s);
        }
        let limit_str;
        if let Some(l) = limit {
            limit_str = l.to_string();
            args.push("LIMIT");
            args.push(&limit_str);
        }
        let offset_str;
        if let Some(o) = offset {
            offset_str = o.to_string();
            args.push("OFFSET");
            args.push(&offset_str);
        }
        let resp = self.command(&args).await?;
        check_status(&resp)?;
        Ok(resp)
    }

    /// Renew a certificate.
    pub async fn renew(
        &mut self,
        ca: &str,
        serial: &str,
        ttl: Option<&str>,
    ) -> Result<IssueResult, ClientError> {
        let mut args = vec!["RENEW", ca, serial];
        if let Some(t) = ttl {
            args.push("TTL");
            args.push(t);
        }
        let resp = self.command(&args).await?;
        check_status(&resp)?;
        Ok(IssueResult {
            certificate_pem: resp["certificate_pem"]
                .as_str()
                .ok_or_else(|| ClientError::ResponseFormat("missing certificate_pem".into()))?
                .to_string(),
            private_key_pem: resp["private_key_pem"]
                .as_str()
                .ok_or_else(|| ClientError::ResponseFormat("missing private_key_pem".into()))?
                .to_string(),
            serial: resp["serial"]
                .as_str()
                .ok_or_else(|| ClientError::ResponseFormat("missing serial".into()))?
                .to_string(),
        })
    }

    // ── Internal ────────────────────────────────────────────────────

    async fn command(&mut self, args: &[&str]) -> Result<serde_json::Value, ClientError> {
        self.conn.send_command(args).await
    }

    async fn meta_command(&mut self, args: &[&str]) -> Result<serde_json::Value, ClientError> {
        self.conn.send_meta_command(args).await
    }
}

fn check_status(resp: &serde_json::Value) -> Result<(), ClientError> {
    if let Some(status) = resp.get("status").and_then(|s| s.as_str())
        && status == "ok"
    {
        return Ok(());
    }
    if resp.is_array() || resp.is_object() {
        return Ok(());
    }
    Err(ClientError::ResponseFormat("unexpected response".into()))
}
