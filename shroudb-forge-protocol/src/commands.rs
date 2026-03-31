use shroudb_acl::{AclRequirement, Scope};

/// Parsed Forge wire protocol command.
#[derive(Debug)]
pub enum ForgeCommand {
    /// Authenticate this connection with a token.
    Auth {
        token: String,
    },

    // CA management
    CaCreate {
        name: String,
        algorithm: String,
        subject: String,
        ttl_days: Option<u32>,
        parent: Option<String>,
    },
    CaInfo {
        ca: String,
    },
    CaList,
    CaRotate {
        ca: String,
        force: bool,
        dryrun: bool,
    },
    CaExport {
        ca: String,
    },
    RegenerateCrl {
        ca: String,
    },

    // Certificate operations
    Issue {
        ca: String,
        subject: String,
        profile: String,
        ttl: Option<String>,
        san_dns: Vec<String>,
        san_ip: Vec<String>,
    },
    IssueFromCsr {
        ca: String,
        csr_pem: String,
        profile: String,
        ttl: Option<String>,
    },
    Revoke {
        ca: String,
        serial: String,
        reason: Option<String>,
    },
    Inspect {
        ca: String,
        serial: String,
    },
    ListCerts {
        ca: String,
        state: Option<String>,
        limit: Option<usize>,
        offset: Option<usize>,
    },
    Renew {
        ca: String,
        serial: String,
        ttl: Option<String>,
    },

    // Operational
    Health,
    Ping,
    CommandList,
}

impl ForgeCommand {
    /// The ACL requirement for this command.
    pub fn acl_requirement(&self) -> AclRequirement {
        match self {
            // Pre-auth / public
            ForgeCommand::Auth { .. }
            | ForgeCommand::Health
            | ForgeCommand::Ping
            | ForgeCommand::CommandList
            | ForgeCommand::CaList => AclRequirement::None,

            // Structural changes → admin
            ForgeCommand::CaCreate { .. }
            | ForgeCommand::CaRotate { .. }
            | ForgeCommand::RegenerateCrl { .. } => AclRequirement::Admin,

            // Read operations
            ForgeCommand::CaInfo { ca, .. }
            | ForgeCommand::CaExport { ca, .. }
            | ForgeCommand::Inspect { ca, .. }
            | ForgeCommand::ListCerts { ca, .. } => AclRequirement::Namespace {
                ns: format!("forge.{ca}.*"),
                scope: Scope::Read,
                tenant_override: None,
            },

            // Write operations
            ForgeCommand::Issue { ca, .. }
            | ForgeCommand::IssueFromCsr { ca, .. }
            | ForgeCommand::Revoke { ca, .. }
            | ForgeCommand::Renew { ca, .. } => AclRequirement::Namespace {
                ns: format!("forge.{ca}.*"),
                scope: Scope::Write,
                tenant_override: None,
            },
        }
    }
}

/// Known keywords for SAN_DNS/SAN_IP multi-value collection.
const KNOWN_KEYWORDS: &[&str] = &[
    "TTL", "SAN_DNS", "SAN_IP", "STATE", "LIMIT", "OFFSET", "REASON", "TTL_DAYS", "PARENT",
    "SUBJECT", "FORCE", "DRYRUN",
];

/// Parse raw RESP3 command arguments into a ForgeCommand.
pub fn parse_command(args: &[&str]) -> Result<ForgeCommand, String> {
    if args.is_empty() {
        return Err("empty command".into());
    }

    let cmd = args[0].to_uppercase();
    match cmd.as_str() {
        "AUTH" => {
            if args.len() < 2 {
                return Err("AUTH <token>".into());
            }
            Ok(ForgeCommand::Auth {
                token: args[1].to_string(),
            })
        }
        "CA" => parse_ca(args),
        "ISSUE" => parse_issue(args),
        "ISSUE_FROM_CSR" => parse_issue_from_csr(args),
        "REVOKE" => parse_revoke(args),
        "INSPECT" => parse_inspect(args),
        "LIST_CERTS" => parse_list_certs(args),
        "RENEW" => parse_renew(args),
        "REGENERATE_CRL" => {
            if args.len() < 2 {
                return Err("REGENERATE_CRL <ca>".into());
            }
            Ok(ForgeCommand::RegenerateCrl {
                ca: args[1].to_string(),
            })
        }
        "HEALTH" => Ok(ForgeCommand::Health),
        "PING" => Ok(ForgeCommand::Ping),
        "COMMAND" => Ok(ForgeCommand::CommandList),
        _ => Err(format!("unknown command: {}", args[0])),
    }
}

fn parse_ca(args: &[&str]) -> Result<ForgeCommand, String> {
    if args.len() < 2 {
        return Err("CA requires a subcommand".into());
    }
    match args[1].to_uppercase().as_str() {
        "CREATE" => {
            if args.len() < 4 {
                return Err(
                    "CA CREATE <name> <algorithm> SUBJECT <subject> [TTL_DAYS <n>] [PARENT <ca>]"
                        .into(),
                );
            }
            let subject = find_option(args, "SUBJECT")
                .ok_or("CA CREATE requires SUBJECT <subject>")?
                .to_string();
            let ttl_days = find_option(args, "TTL_DAYS")
                .map(|v| v.parse::<u32>())
                .transpose()
                .map_err(|e| format!("invalid TTL_DAYS: {e}"))?;
            let parent = find_option(args, "PARENT").map(String::from);

            Ok(ForgeCommand::CaCreate {
                name: args[2].to_string(),
                algorithm: args[3].to_string(),
                subject,
                ttl_days,
                parent,
            })
        }
        "INFO" => {
            if args.len() < 3 {
                return Err("CA INFO <name>".into());
            }
            Ok(ForgeCommand::CaInfo {
                ca: args[2].to_string(),
            })
        }
        "LIST" => Ok(ForgeCommand::CaList),
        "ROTATE" => {
            if args.len() < 3 {
                return Err("CA ROTATE <name> [FORCE] [DRYRUN]".into());
            }
            let force = has_flag(args, "FORCE");
            let dryrun = has_flag(args, "DRYRUN");
            Ok(ForgeCommand::CaRotate {
                ca: args[2].to_string(),
                force,
                dryrun,
            })
        }
        "EXPORT" => {
            if args.len() < 3 {
                return Err("CA EXPORT <name>".into());
            }
            Ok(ForgeCommand::CaExport {
                ca: args[2].to_string(),
            })
        }
        "REGENERATE_CRL" => {
            if args.len() < 3 {
                return Err("CA REGENERATE_CRL <name>".into());
            }
            Ok(ForgeCommand::RegenerateCrl {
                ca: args[2].to_string(),
            })
        }
        sub => Err(format!("unknown CA subcommand: {sub}")),
    }
}

fn parse_issue(args: &[&str]) -> Result<ForgeCommand, String> {
    if args.len() < 4 {
        return Err(
            "ISSUE <ca> <subject> <profile> [TTL <dur>] [SAN_DNS <name>...] [SAN_IP <ip>...]"
                .into(),
        );
    }
    let ttl = find_option(args, "TTL").map(String::from);
    let san_dns = collect_multi_values(args, "SAN_DNS");
    let san_ip = collect_multi_values(args, "SAN_IP");

    Ok(ForgeCommand::Issue {
        ca: args[1].to_string(),
        subject: args[2].to_string(),
        profile: args[3].to_string(),
        ttl,
        san_dns,
        san_ip,
    })
}

fn parse_issue_from_csr(args: &[&str]) -> Result<ForgeCommand, String> {
    if args.len() < 4 {
        return Err("ISSUE_FROM_CSR <ca> <csr_pem> <profile> [TTL <dur>]".into());
    }
    let ttl = find_option(args, "TTL").map(String::from);

    Ok(ForgeCommand::IssueFromCsr {
        ca: args[1].to_string(),
        csr_pem: args[2].to_string(),
        profile: args[3].to_string(),
        ttl,
    })
}

fn parse_revoke(args: &[&str]) -> Result<ForgeCommand, String> {
    if args.len() < 3 {
        return Err("REVOKE <ca> <serial> [REASON <reason>]".into());
    }
    let reason = find_option(args, "REASON").map(String::from);

    Ok(ForgeCommand::Revoke {
        ca: args[1].to_string(),
        serial: args[2].to_string(),
        reason,
    })
}

fn parse_inspect(args: &[&str]) -> Result<ForgeCommand, String> {
    if args.len() < 3 {
        return Err("INSPECT <ca> <serial>".into());
    }
    Ok(ForgeCommand::Inspect {
        ca: args[1].to_string(),
        serial: args[2].to_string(),
    })
}

fn parse_list_certs(args: &[&str]) -> Result<ForgeCommand, String> {
    if args.len() < 2 {
        return Err("LIST_CERTS <ca> [STATE <s>] [LIMIT <n>] [OFFSET <n>]".into());
    }
    let state = find_option(args, "STATE").map(String::from);
    let limit = find_option(args, "LIMIT")
        .map(|v| v.parse::<usize>())
        .transpose()
        .map_err(|e| format!("invalid LIMIT: {e}"))?;
    let offset = find_option(args, "OFFSET")
        .map(|v| v.parse::<usize>())
        .transpose()
        .map_err(|e| format!("invalid OFFSET: {e}"))?;

    Ok(ForgeCommand::ListCerts {
        ca: args[1].to_string(),
        state,
        limit,
        offset,
    })
}

fn parse_renew(args: &[&str]) -> Result<ForgeCommand, String> {
    if args.len() < 3 {
        return Err("RENEW <ca> <serial> [TTL <dur>]".into());
    }
    let ttl = find_option(args, "TTL").map(String::from);

    Ok(ForgeCommand::Renew {
        ca: args[1].to_string(),
        serial: args[2].to_string(),
        ttl,
    })
}

/// Find an optional keyword argument: `KEY value` in the args list.
fn find_option<'a>(args: &[&'a str], key: &str) -> Option<&'a str> {
    let upper = key.to_uppercase();
    args.windows(2)
        .find(|w| w[0].to_uppercase() == upper)
        .map(|w| w[1])
}

/// Check if a flag is present in the args.
fn has_flag(args: &[&str], flag: &str) -> bool {
    let upper = flag.to_uppercase();
    args.iter().any(|a| a.to_uppercase() == upper)
}

/// Collect all values between a keyword and the next known keyword or end of args.
fn collect_multi_values(args: &[&str], key: &str) -> Vec<String> {
    let upper = key.to_uppercase();
    let pos = args.iter().position(|a| a.to_uppercase() == upper);

    let start = match pos {
        Some(p) => p + 1,
        None => return vec![],
    };

    let mut values = Vec::new();
    for &arg in &args[start..] {
        if KNOWN_KEYWORDS.contains(&arg.to_uppercase().as_str()) {
            break;
        }
        values.push(arg.to_string());
    }
    values
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_auth() {
        let cmd = parse_command(&["AUTH", "my-token"]).unwrap();
        assert!(matches!(
            cmd,
            ForgeCommand::Auth { token } if token == "my-token"
        ));
    }

    #[test]
    fn parse_ca_create() {
        let cmd = parse_command(&[
            "CA",
            "CREATE",
            "internal",
            "ecdsa-p256",
            "SUBJECT",
            "CN=Internal CA,O=Test",
        ])
        .unwrap();
        assert!(matches!(
            cmd,
            ForgeCommand::CaCreate {
                name,
                algorithm,
                subject,
                ttl_days: None,
                parent: None,
            } if name == "internal" && algorithm == "ecdsa-p256" && subject == "CN=Internal CA,O=Test"
        ));
    }

    #[test]
    fn parse_ca_create_with_options() {
        let cmd = parse_command(&[
            "CA",
            "CREATE",
            "intermediate",
            "ecdsa-p256",
            "SUBJECT",
            "CN=Intermediate CA",
            "TTL_DAYS",
            "365",
            "PARENT",
            "root",
        ])
        .unwrap();
        assert!(matches!(
            cmd,
            ForgeCommand::CaCreate {
                ttl_days: Some(365),
                parent: Some(_),
                ..
            }
        ));
    }

    #[test]
    fn parse_ca_info() {
        let cmd = parse_command(&["CA", "INFO", "internal"]).unwrap();
        assert!(matches!(
            cmd,
            ForgeCommand::CaInfo { ca } if ca == "internal"
        ));
    }

    #[test]
    fn parse_ca_list() {
        let cmd = parse_command(&["CA", "LIST"]).unwrap();
        assert!(matches!(cmd, ForgeCommand::CaList));
    }

    #[test]
    fn parse_ca_rotate_with_flags() {
        let cmd = parse_command(&["CA", "ROTATE", "internal", "FORCE", "DRYRUN"]).unwrap();
        assert!(matches!(
            cmd,
            ForgeCommand::CaRotate {
                ca,
                force: true,
                dryrun: true,
            } if ca == "internal"
        ));
    }

    #[test]
    fn parse_ca_export() {
        let cmd = parse_command(&["CA", "EXPORT", "internal"]).unwrap();
        assert!(matches!(
            cmd,
            ForgeCommand::CaExport { ca } if ca == "internal"
        ));
    }

    #[test]
    fn parse_issue_basic() {
        let cmd = parse_command(&["ISSUE", "internal", "CN=myservice", "server"]).unwrap();
        assert!(matches!(
            cmd,
            ForgeCommand::Issue {
                ca,
                subject,
                profile,
                ttl: None,
                ref san_dns,
                ref san_ip,
            } if ca == "internal"
                && subject == "CN=myservice"
                && profile == "server"
                && san_dns.is_empty()
                && san_ip.is_empty()
        ));
    }

    #[test]
    fn parse_issue_with_sans() {
        let cmd = parse_command(&[
            "ISSUE",
            "internal",
            "CN=myservice",
            "server",
            "TTL",
            "24h",
            "SAN_DNS",
            "myservice.local",
            "myservice.internal",
            "SAN_IP",
            "10.0.0.1",
        ])
        .unwrap();
        match cmd {
            ForgeCommand::Issue {
                ttl,
                san_dns,
                san_ip,
                ..
            } => {
                assert_eq!(ttl.as_deref(), Some("24h"));
                assert_eq!(san_dns, vec!["myservice.local", "myservice.internal"]);
                assert_eq!(san_ip, vec!["10.0.0.1"]);
            }
            _ => panic!("expected Issue"),
        }
    }

    #[test]
    fn parse_issue_from_csr() {
        let cmd = parse_command(&[
            "ISSUE_FROM_CSR",
            "internal",
            "PEM_DATA",
            "server",
            "TTL",
            "7d",
        ])
        .unwrap();
        assert!(matches!(
            cmd,
            ForgeCommand::IssueFromCsr {
                ca,
                csr_pem,
                profile,
                ttl: Some(_),
            } if ca == "internal" && csr_pem == "PEM_DATA" && profile == "server"
        ));
    }

    #[test]
    fn parse_revoke() {
        let cmd =
            parse_command(&["REVOKE", "internal", "abc123", "REASON", "key_compromise"]).unwrap();
        assert!(matches!(
            cmd,
            ForgeCommand::Revoke {
                ca,
                serial,
                reason: Some(_),
            } if ca == "internal" && serial == "abc123"
        ));
    }

    #[test]
    fn parse_inspect() {
        let cmd = parse_command(&["INSPECT", "internal", "abc123"]).unwrap();
        assert!(matches!(
            cmd,
            ForgeCommand::Inspect { ca, serial }
            if ca == "internal" && serial == "abc123"
        ));
    }

    #[test]
    fn parse_list_certs() {
        let cmd = parse_command(&[
            "LIST_CERTS",
            "internal",
            "STATE",
            "active",
            "LIMIT",
            "10",
            "OFFSET",
            "5",
        ])
        .unwrap();
        assert!(matches!(
            cmd,
            ForgeCommand::ListCerts {
                ca,
                state: Some(_),
                limit: Some(10),
                offset: Some(5),
            } if ca == "internal"
        ));
    }

    #[test]
    fn parse_renew() {
        let cmd = parse_command(&["RENEW", "internal", "abc123", "TTL", "30d"]).unwrap();
        assert!(matches!(
            cmd,
            ForgeCommand::Renew {
                ca,
                serial,
                ttl: Some(_),
            } if ca == "internal" && serial == "abc123"
        ));
    }

    #[test]
    fn parse_health() {
        let cmd = parse_command(&["HEALTH"]).unwrap();
        assert!(matches!(cmd, ForgeCommand::Health));
    }

    #[test]
    fn parse_ping() {
        let cmd = parse_command(&["PING"]).unwrap();
        assert!(matches!(cmd, ForgeCommand::Ping));
    }

    #[test]
    fn parse_command_list() {
        let cmd = parse_command(&["COMMAND"]).unwrap();
        assert!(matches!(cmd, ForgeCommand::CommandList));
    }

    #[test]
    fn unknown_command_errors() {
        assert!(parse_command(&["NOPE"]).is_err());
    }

    #[test]
    fn empty_command_errors() {
        assert!(parse_command(&[]).is_err());
    }

    #[test]
    fn ca_create_missing_subject_errors() {
        assert!(parse_command(&["CA", "CREATE", "internal", "ecdsa-p256"]).is_err());
    }

    #[test]
    fn unknown_ca_subcommand_errors() {
        assert!(parse_command(&["CA", "DESTROY", "internal"]).is_err());
    }

    #[test]
    fn parse_regenerate_crl_via_ca_subcommand() {
        let cmd = parse_command(&["CA", "REGENERATE_CRL", "internal"]).unwrap();
        assert!(matches!(
            cmd,
            ForgeCommand::RegenerateCrl { ca } if ca == "internal"
        ));
    }

    #[test]
    fn parse_regenerate_crl_top_level() {
        let cmd = parse_command(&["REGENERATE_CRL", "internal"]).unwrap();
        assert!(matches!(
            cmd,
            ForgeCommand::RegenerateCrl { ca } if ca == "internal"
        ));
    }

    #[test]
    fn regenerate_crl_missing_ca_errors() {
        assert!(parse_command(&["REGENERATE_CRL"]).is_err());
    }
}
