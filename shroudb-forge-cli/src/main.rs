use anyhow::Context;
use clap::Parser;
use shroudb_forge_client::ForgeClient;

#[derive(Parser)]
#[command(name = "shroudb-forge-cli", about = "Forge CLI")]
struct Cli {
    /// Server address.
    #[arg(long, default_value = "127.0.0.1:6699", env = "FORGE_ADDR")]
    addr: String,

    /// Command to execute. If omitted, starts interactive mode.
    #[arg(trailing_var_arg = true)]
    command: Vec<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let mut client = ForgeClient::connect(&cli.addr)
        .await
        .with_context(|| format!("failed to connect to {}", cli.addr))?;

    if cli.command.is_empty() {
        interactive(&mut client).await
    } else {
        let args: Vec<&str> = cli.command.iter().map(|s| s.as_str()).collect();
        execute(&mut client, &args).await
    }
}

async fn execute(client: &mut ForgeClient, args: &[&str]) -> anyhow::Result<()> {
    if args.is_empty() {
        anyhow::bail!("empty command");
    }

    match args[0].to_uppercase().as_str() {
        "HEALTH" => {
            client.health().await.context("health check failed")?;
            println!("OK");
        }
        "PING" => {
            println!("PONG");
        }
        "AUTH" if args.len() >= 2 => {
            client.auth(args[1]).await.context("auth failed")?;
            println!("OK");
        }
        "CA" if args.len() >= 2 => match args[1].to_uppercase().as_str() {
            "CREATE" if args.len() >= 5 => {
                let ttl_days = find_option(args, "TTL_DAYS")
                    .map(|v| v.parse::<u32>())
                    .transpose()?;
                let parent = find_option(args, "PARENT");
                let resp = client
                    .ca_create(args[2], args[3], args[4], ttl_days, parent)
                    .await
                    .context("ca create failed")?;
                println!("{}", serde_json::to_string_pretty(&resp)?);
            }
            "INFO" if args.len() >= 3 => {
                let resp = client.ca_info(args[2]).await.context("ca info failed")?;
                println!("{}", serde_json::to_string_pretty(&resp)?);
            }
            "LIST" => {
                let names = client.ca_list().await.context("ca list failed")?;
                for name in names {
                    println!("{name}");
                }
            }
            "ROTATE" if args.len() >= 3 => {
                let force = has_flag(args, "FORCE");
                let resp = client
                    .ca_rotate(args[2], force)
                    .await
                    .context("ca rotate failed")?;
                println!("{}", serde_json::to_string_pretty(&resp)?);
            }
            "EXPORT" if args.len() >= 3 => {
                let pem = client
                    .ca_export(args[2])
                    .await
                    .context("ca export failed")?;
                println!("{pem}");
            }
            _ => anyhow::bail!("usage: CA CREATE|INFO|LIST|ROTATE|EXPORT ..."),
        },
        "ISSUE" if args.len() >= 4 => {
            let ttl = find_option(args, "TTL");
            let san_dns = find_all_options(args, "SAN_DNS");
            let san_ip = find_all_options(args, "SAN_IP");
            let result = client
                .issue(args[1], args[2], args[3], ttl, &san_dns, &san_ip)
                .await
                .context("issue failed")?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "certificate_pem": result.certificate_pem,
                    "private_key_pem": result.private_key_pem,
                    "serial": result.serial,
                }))?
            );
        }
        "REVOKE" if args.len() >= 3 => {
            let reason = find_option(args, "REASON");
            client
                .revoke(args[1], args[2], reason)
                .await
                .context("revoke failed")?;
            println!("OK");
        }
        "ISSUE_FROM_CSR" if args.len() >= 4 => {
            let ttl = find_option(args, "TTL");
            let result = client
                .issue_from_csr(args[1], args[2], args[3], ttl)
                .await
                .context("issue from csr failed")?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "certificate_pem": result.certificate_pem,
                    "serial": result.serial,
                }))?
            );
        }
        "INSPECT" if args.len() >= 3 => {
            let resp = client
                .inspect(args[1], args[2])
                .await
                .context("inspect failed")?;
            println!("{}", serde_json::to_string_pretty(&resp)?);
        }
        "LIST_CERTS" if args.len() >= 2 => {
            let state = find_option(args, "STATE");
            let limit = find_option(args, "LIMIT")
                .map(|v| v.parse::<usize>())
                .transpose()?;
            let offset = find_option(args, "OFFSET")
                .map(|v| v.parse::<usize>())
                .transpose()?;
            let resp = client
                .list_certs(args[1], state, limit, offset)
                .await
                .context("list certs failed")?;
            println!("{}", serde_json::to_string_pretty(&resp)?);
        }
        "RENEW" if args.len() >= 3 => {
            let ttl = find_option(args, "TTL");
            let result = client
                .renew(args[1], args[2], ttl)
                .await
                .context("renew failed")?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "certificate_pem": result.certificate_pem,
                    "private_key_pem": result.private_key_pem,
                    "serial": result.serial,
                }))?
            );
        }
        _ => anyhow::bail!("unknown command: {}", args.join(" ")),
    }

    Ok(())
}

async fn interactive(client: &mut ForgeClient) -> anyhow::Result<()> {
    use std::io::BufRead;

    let stdin = std::io::stdin();
    eprint!("forge> ");
    for line in stdin.lock().lines() {
        let line = line?;
        let line = line.trim();
        if line.is_empty() {
            eprint!("forge> ");
            continue;
        }
        if line == "quit" || line == "exit" {
            break;
        }

        let args = shell_split(line);
        let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

        match execute(client, &arg_refs).await {
            Ok(()) => {}
            Err(e) => eprintln!("error: {e}"),
        }
        eprint!("forge> ");
    }
    Ok(())
}

/// Split a command line by whitespace, preserving JSON objects in braces.
fn shell_split(input: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut current = String::new();
    let mut brace_depth = 0;

    for ch in input.chars() {
        match ch {
            '{' | '[' => {
                brace_depth += 1;
                current.push(ch);
            }
            '}' | ']' => {
                brace_depth -= 1;
                current.push(ch);
            }
            ' ' | '\t' if brace_depth == 0 => {
                if !current.is_empty() {
                    args.push(std::mem::take(&mut current));
                }
            }
            _ => current.push(ch),
        }
    }
    if !current.is_empty() {
        args.push(current);
    }
    args
}

fn find_option<'a>(args: &[&'a str], key: &str) -> Option<&'a str> {
    let upper = key.to_uppercase();
    args.windows(2)
        .find(|w| w[0].to_uppercase() == upper)
        .map(|w| w[1])
}

fn find_all_options<'a>(args: &[&'a str], key: &str) -> Vec<&'a str> {
    let upper = key.to_uppercase();
    args.windows(2)
        .filter(|w| w[0].to_uppercase() == upper)
        .map(|w| w[1])
        .collect()
}

fn has_flag(args: &[&str], flag: &str) -> bool {
    let upper = flag.to_uppercase();
    args.iter().any(|a| a.to_uppercase() == upper)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_split_simple() {
        let args = shell_split("ISSUE my-ca example.com server");
        assert_eq!(args, vec!["ISSUE", "my-ca", "example.com", "server"]);
    }

    #[test]
    fn shell_split_with_options() {
        let args = shell_split("ISSUE my-ca example.com server TTL 90d SAN_DNS www.example.com");
        assert_eq!(
            args,
            vec![
                "ISSUE",
                "my-ca",
                "example.com",
                "server",
                "TTL",
                "90d",
                "SAN_DNS",
                "www.example.com"
            ]
        );
    }

    #[test]
    fn shell_split_preserves_json() {
        let args = shell_split(r#"CA CREATE my-ca ed25519 {"CN":"Test CA"}"#);
        assert_eq!(
            args,
            vec!["CA", "CREATE", "my-ca", "ed25519", r#"{"CN":"Test CA"}"#]
        );
    }

    #[test]
    fn find_option_works() {
        let args = vec!["ISSUE", "my-ca", "example.com", "server", "TTL", "90d"];
        assert_eq!(find_option(&args, "TTL"), Some("90d"));
        assert_eq!(find_option(&args, "MISSING"), None);
    }

    #[test]
    fn find_all_options_works() {
        let args = vec![
            "ISSUE",
            "my-ca",
            "example.com",
            "server",
            "SAN_DNS",
            "a.example.com",
            "SAN_DNS",
            "b.example.com",
        ];
        assert_eq!(
            find_all_options(&args, "SAN_DNS"),
            vec!["a.example.com", "b.example.com"]
        );
    }

    #[test]
    fn has_flag_works() {
        let args = vec!["CA", "ROTATE", "my-ca", "FORCE"];
        assert!(has_flag(&args, "FORCE"));
        assert!(!has_flag(&args, "MISSING"));
    }
}
