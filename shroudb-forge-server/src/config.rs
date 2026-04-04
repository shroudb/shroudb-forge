use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;

use serde::Deserialize;
use shroudb_acl::ServerAuthConfig;

#[derive(Debug, Deserialize, Default)]
pub struct ForgeServerConfig {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub store: StoreConfig,
    #[serde(default)]
    pub engine: EngineConfig,
    #[serde(default)]
    pub auth: ServerAuthConfig,
    #[serde(default)]
    pub cas: HashMap<String, CaConfig>,
    #[serde(default)]
    pub profiles: HashMap<String, ProfileConfig>,
}

#[derive(Debug, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_tcp_bind")]
    pub tcp_bind: SocketAddr,
    #[serde(default = "default_http_bind")]
    pub http_bind: SocketAddr,
    #[serde(default)]
    pub log_level: Option<String>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            tcp_bind: default_tcp_bind(),
            http_bind: default_http_bind(),
            log_level: None,
        }
    }
}

fn default_tcp_bind() -> SocketAddr {
    "0.0.0.0:6699".parse().expect("valid hardcoded address")
}

fn default_http_bind() -> SocketAddr {
    "0.0.0.0:6700".parse().expect("valid hardcoded address")
}

#[derive(Debug, Deserialize)]
pub struct StoreConfig {
    #[serde(default = "default_mode")]
    pub mode: String,
    #[serde(default = "default_data_dir")]
    pub data_dir: PathBuf,
    #[serde(default)]
    pub uri: Option<String>,
}

impl Default for StoreConfig {
    fn default() -> Self {
        Self {
            mode: default_mode(),
            data_dir: default_data_dir(),
            uri: None,
        }
    }
}

fn default_mode() -> String {
    "embedded".to_string()
}

fn default_data_dir() -> PathBuf {
    PathBuf::from("./forge-data")
}

#[derive(Debug, Deserialize)]
pub struct EngineConfig {
    #[serde(default = "default_rotation_days")]
    pub default_rotation_days: u32,
    #[serde(default = "default_drain_days")]
    pub default_drain_days: u32,
    #[serde(default = "default_ca_ttl_days")]
    pub default_ca_ttl_days: u32,
    #[serde(default = "default_scheduler_interval")]
    pub scheduler_interval_secs: u64,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            default_rotation_days: default_rotation_days(),
            default_drain_days: default_drain_days(),
            default_ca_ttl_days: default_ca_ttl_days(),
            scheduler_interval_secs: default_scheduler_interval(),
        }
    }
}

fn default_rotation_days() -> u32 {
    365
}

fn default_drain_days() -> u32 {
    90
}

fn default_ca_ttl_days() -> u32 {
    3650
}

fn default_scheduler_interval() -> u64 {
    3600
}

/// Config-defined CA to seed on startup.
#[derive(Debug, Clone, Deserialize)]
pub struct CaConfig {
    pub algorithm: String,
    pub subject: String,
    #[serde(default)]
    pub ttl_days: Option<u32>,
    #[serde(default)]
    pub parent: Option<String>,
    #[serde(default)]
    pub rotation_days: Option<u32>,
    #[serde(default)]
    pub drain_days: Option<u32>,
}

/// Config-defined certificate profile.
#[derive(Debug, Clone, Deserialize)]
pub struct ProfileConfig {
    #[serde(default)]
    pub key_usage: Vec<String>,
    #[serde(default)]
    pub extended_key_usage: Vec<String>,
    #[serde(default = "default_max_ttl_days")]
    pub max_ttl_days: u32,
    #[serde(default = "default_default_ttl")]
    pub default_ttl: String,
    #[serde(default = "default_allow_san")]
    pub allow_san_dns: bool,
    #[serde(default)]
    pub allow_san_ip: bool,
    #[serde(default)]
    pub subject_template: Option<String>,
}

fn default_max_ttl_days() -> u32 {
    90
}

fn default_default_ttl() -> String {
    "24h".to_string()
}

fn default_allow_san() -> bool {
    true
}

/// Convert a profile config to a CertificateProfile.
pub fn to_profile(
    name: &str,
    cfg: &ProfileConfig,
) -> shroudb_forge_core::profile::CertificateProfile {
    use shroudb_forge_core::profile::{CertificateProfile, ExtendedKeyUsage, KeyUsage};

    let key_usage = cfg
        .key_usage
        .iter()
        .filter_map(|s| KeyUsage::from_config(s))
        .collect();
    let extended_key_usage = cfg
        .extended_key_usage
        .iter()
        .filter_map(|s| ExtendedKeyUsage::from_config(s))
        .collect();

    CertificateProfile {
        name: name.to_string(),
        key_usage,
        extended_key_usage,
        max_ttl_days: cfg.max_ttl_days,
        default_ttl: cfg.default_ttl.clone(),
        allow_san_dns: cfg.allow_san_dns,
        allow_san_ip: cfg.allow_san_ip,
        subject_template: cfg.subject_template.clone(),
    }
}

/// Load config from a TOML file, or return defaults.
pub fn load_config(path: Option<&str>) -> anyhow::Result<ForgeServerConfig> {
    match path {
        Some(p) => {
            let raw = std::fs::read_to_string(p)
                .map_err(|e| anyhow::anyhow!("failed to read config: {e}"))?;
            let config: ForgeServerConfig =
                toml::from_str(&raw).map_err(|e| anyhow::anyhow!("failed to parse config: {e}"))?;
            Ok(config)
        }
        None => Ok(ForgeServerConfig::default()),
    }
}
