//! Load, validate and own B.U.D.U's configuration (`config/budu.toml`).
//!
//! Phase 1 needs the `[server]` and `[limits]` blocks to stand up the
//! pass-through proxy; the rest is parsed and kept so later layers can read it
//! without a schema change. Hot-reload (`ArcSwap<Config>`, §9) layers on top of
//! [`Config::load`] later.

use std::net::SocketAddr;
use std::path::Path;

use http::Uri;
use ipnet::IpNet;
use serde::Deserialize;

mod size;
use size::ByteSize;

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("reading {path}: {source}")]
    Read {
        path: String,
        source: std::io::Error,
    },
    #[error("parsing config: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("invalid config: {0}")]
    Invalid(String),
}

/// `on_error = "closed" | "open"` — fail-closed (deny) or fail-open (allow)
/// when an inspection layer errors out. Default is closed for a security gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum OnError {
    #[default]
    Closed,
    Open,
}

/// `enforcement = "block" | "detect"` — in `detect` mode the WAF evaluates every
/// layer and logs/meters what it *would* block, but forwards the request anyway
/// (CRS "DetectionOnly" / AWS WAF "Count"). Resource limits (rate-limit 429,
/// body-size 413) stay enforced in both modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Enforcement {
    #[default]
    Block,
    Detect,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub listen: SocketAddr,
    #[serde(deserialize_with = "de_uri")]
    pub upstream: Uri,
    pub client_ip_header: String,
    pub trusted_peer: IpNet,
    #[serde(default)]
    pub on_error: OnError,
    #[serde(default)]
    pub enforcement: Enforcement,
    /// Max time to wait for the upstream backend before giving up (504).
    /// Guards against a slow/hung backend tying up connections indefinitely.
    #[serde(default = "default_upstream_timeout")]
    pub upstream_timeout_secs: u64,
    /// Default timezone for `time_between` rules that don't set their own `tz`,
    /// e.g. `"+08:00"`. Empty = UTC. A per-rule `tz` always overrides this.
    #[serde(default)]
    pub timezone: String,
    /// Optional path where `budu run` writes its PID (and removes on exit). Lets
    /// `budu ban --reload` signal the running proxy with `SIGHUP`. Empty = off.
    #[serde(default)]
    pub pidfile: String,
    /// Header carrying the per-request correlation id: reused inbound (if valid),
    /// else generated, and echoed on the response + forwarded upstream. Empty
    /// disables reading/writing the header (an id is still generated for logs).
    #[serde(default = "default_request_id_header")]
    pub request_id_header: String,
}

fn default_request_id_header() -> String {
    "X-Request-Id".to_string()
}

fn default_upstream_timeout() -> u64 {
    30
}

#[derive(Debug, Clone, Deserialize)]
pub struct LimitsConfig {
    pub max_uri_len: usize,
    pub max_header_count: usize,
    pub max_inspect_body: ByteSize,
}

#[derive(Debug, Clone, Deserialize)]
pub struct InspectConfig {
    /// Request Content-Types whose bodies are buffered + inspected. Empty =
    /// inspect no request bodies (they stream straight through).
    #[serde(default)]
    pub content_types: Vec<String>,
    /// Response Content-Types whose bodies are buffered + inspected by
    /// `phase = "response"` rules that reference `resp_body`. Defaults to the
    /// common text/markup types so large binary downloads are never buffered.
    /// Only consulted when at least one response rule needs the body.
    #[serde(default = "default_response_content_types")]
    pub response_content_types: Vec<String>,
}

impl Default for InspectConfig {
    fn default() -> Self {
        Self {
            content_types: Vec::new(),
            response_content_types: default_response_content_types(),
        }
    }
}

fn default_response_content_types() -> Vec<String> {
    [
        "text/html",
        "application/json",
        "application/xml",
        "text/xml",
        "text/plain",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

#[derive(Debug, Clone, Deserialize)]
pub struct RateLimitConfig {
    pub requests_per_sec: u32,
    pub burst: u32,
    pub ttl_secs: u64,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct PathsConfig {
    #[serde(default)]
    pub rules: String,
    #[serde(default)]
    pub signatures: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LogConfig {
    #[serde(default = "default_log_format")]
    pub format: String,
    #[serde(default)]
    pub audit_file: String,
}

fn default_log_format() -> String {
    "json".to_string()
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct MetricsConfig {
    /// Admin bind address for `/metrics` + `/healthz`. Disabled when unset.
    /// Keep this on localhost / a management interface — never client-facing.
    #[serde(default)]
    pub listen: Option<SocketAddr>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ReputationConfig {
    /// Inline CIDR blocklist, e.g. `["1.2.3.0/24", "10.0.0.5/32"]`.
    #[serde(default)]
    pub blocklist: Vec<IpNet>,
    /// Optional file of one CIDR per line (`#` comments allowed), merged with
    /// `blocklist`.
    #[serde(default)]
    pub blocklist_file: String,
    /// Optional external HTTP(S) feeds (one CIDR/IP per line) merged in and
    /// auto-refreshed. Requires the `remote-blocklist` build feature.
    #[serde(default)]
    pub blocklist_urls: Vec<String>,
    /// How often to re-fetch `blocklist_urls`, in seconds. `0` = fetch once at
    /// startup only.
    #[serde(default = "default_blocklist_refresh")]
    pub refresh_secs: u64,
    /// Trusted-IP **allowlist** (CIDRs): a matching client fully bypasses
    /// inspection — no blocklist/geoip/rate-limit/rules/signatures, request *and*
    /// response phases — and is forwarded straight upstream. Use sparingly, for
    /// IPs you fully trust (health checkers, internal scanners, partner APIs).
    #[serde(default)]
    pub allowlist: Vec<IpNet>,
    /// Optional file of one CIDR/IP per line (`#` comments allowed), merged into
    /// `allowlist`.
    #[serde(default)]
    pub allowlist_file: String,
}

fn default_blocklist_refresh() -> u64 {
    300
}

/// CRS-style anomaly scoring. `score`-action rules add points; when the
/// per-request total reaches `threshold` (and `threshold > 0`) the request is
/// blocked. `threshold = 0` (default) disables scoring.
#[derive(Debug, Clone, Deserialize)]
pub struct ScoringConfig {
    #[serde(default)]
    pub threshold: u32,
    #[serde(default = "default_anomaly_status")]
    pub status: u16,
    #[serde(default = "default_anomaly_msg")]
    pub msg: String,
}

impl Default for ScoringConfig {
    fn default() -> Self {
        Self {
            threshold: 0,
            status: default_anomaly_status(),
            msg: default_anomaly_msg(),
        }
    }
}

fn default_anomaly_status() -> u16 {
    403
}

fn default_anomaly_msg() -> String {
    "anomaly score threshold exceeded".to_string()
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct GeoIpConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub db_path: String,
    /// If non-empty, an allowlist: only these ISO-3166 country codes pass; all
    /// others are blocked. Takes precedence over `block_countries`.
    #[serde(default)]
    pub allow_countries: Vec<String>,
    /// ISO-3166 country codes to block (when `allow_countries` is empty).
    #[serde(default)]
    pub block_countries: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub limits: LimitsConfig,
    #[serde(default)]
    pub inspect: InspectConfig,
    pub ratelimit: RateLimitConfig,
    #[serde(default)]
    pub reputation: ReputationConfig,
    #[serde(default)]
    pub metrics: MetricsConfig,
    #[serde(default)]
    pub scoring: ScoringConfig,
    #[serde(default)]
    pub paths: PathsConfig,
    pub log: LogConfig,
    #[serde(default)]
    pub geoip: GeoIpConfig,
}

impl Config {
    /// Read and validate the config from a TOML file.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.display().to_string(),
            source,
        })?;
        let cfg: Config = toml::from_str(&text)?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Parse + validate from an in-memory TOML string (tests, hot-reload).
    pub fn parse_toml(text: &str) -> Result<Self, ConfigError> {
        let cfg: Config = toml::from_str(text)?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.server.upstream.scheme_str() != Some("http")
            && self.server.upstream.scheme_str() != Some("https")
        {
            return Err(ConfigError::Invalid(
                "server.upstream must be an http(s):// URL".into(),
            ));
        }
        if self.server.upstream.authority().is_none() {
            return Err(ConfigError::Invalid(
                "server.upstream must include a host[:port]".into(),
            ));
        }
        if self.server.client_ip_header.trim().is_empty() {
            return Err(ConfigError::Invalid(
                "server.client_ip_header must not be empty".into(),
            ));
        }
        if self.limits.max_uri_len == 0 {
            return Err(ConfigError::Invalid("limits.max_uri_len must be > 0".into()));
        }
        if self.ratelimit.requests_per_sec == 0 {
            return Err(ConfigError::Invalid(
                "ratelimit.requests_per_sec must be > 0".into(),
            ));
        }
        if self.server.upstream_timeout_secs == 0 {
            return Err(ConfigError::Invalid(
                "server.upstream_timeout_secs must be > 0".into(),
            ));
        }
        // The admin endpoint exposes internals and has no auth — refuse to bind
        // it to anything client-reachable.
        if let Some(addr) = self.metrics.listen {
            if !addr.ip().is_loopback() {
                return Err(ConfigError::Invalid(format!(
                    "metrics.listen must be a loopback address (got {}); the admin \
                     endpoint is unauthenticated and must not be client-facing",
                    addr.ip()
                )));
            }
        }
        Ok(())
    }
}

fn de_uri<'de, D>(d: D) -> Result<Uri, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(d)?;
    s.parse::<Uri>().map_err(serde::de::Error::custom)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
[server]
listen = "127.0.0.1:8088"
upstream = "http://192.168.10.20:8080"
client_ip_header = "X-Real-IP"
trusted_peer = "127.0.0.1/32"
on_error = "closed"

[limits]
max_uri_len = 8192
max_header_count = 100
max_inspect_body = "1MiB"

[inspect]
content_types = ["application/json"]

[ratelimit]
requests_per_sec = 50
burst = 100
ttl_secs = 300

[paths]
rules = "config/rules.toml"
signatures = "config/signatures.toml"

[log]
format = "json"
audit_file = "/var/log/budu/audit.log"

[geoip]
enabled = false
db_path = ""
"#;

    #[test]
    fn parses_sample() {
        let cfg = Config::parse_toml(SAMPLE).expect("valid config");
        assert_eq!(cfg.server.listen.port(), 8088);
        assert_eq!(cfg.server.on_error, OnError::Closed);
        assert_eq!(cfg.limits.max_inspect_body.bytes(), 1024 * 1024);
        assert_eq!(cfg.server.upstream.host(), Some("192.168.10.20"));
    }

    #[test]
    fn rejects_bad_upstream() {
        let bad = SAMPLE.replace("http://192.168.10.20:8080", "ftp://nope");
        assert!(Config::parse_toml(&bad).is_err());
    }

    #[test]
    fn rejects_non_loopback_admin() {
        let bad = format!("{SAMPLE}\n[metrics]\nlisten = \"0.0.0.0:9090\"\n");
        assert!(Config::parse_toml(&bad).is_err());
        let ok = format!("{SAMPLE}\n[metrics]\nlisten = \"127.0.0.1:9090\"\n");
        assert!(Config::parse_toml(&ok).is_ok());
    }

    #[test]
    fn upstream_timeout_defaults_and_validates() {
        // default applies when omitted
        let cfg = Config::parse_toml(SAMPLE).expect("valid");
        assert_eq!(cfg.server.upstream_timeout_secs, 30);
        // zero is rejected
        let bad = SAMPLE.replace("on_error = \"closed\"", "on_error = \"closed\"\nupstream_timeout_secs = 0");
        assert!(Config::parse_toml(&bad).is_err());
    }
}
