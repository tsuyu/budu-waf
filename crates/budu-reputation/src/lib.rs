//! Reputation layer (§8 step 2): a CIDR blocklist checked against the resolved
//! client IP. Fast and first — drops known-bad sources before any other work.

use std::ops::ControlFlow;
use std::sync::Arc;

use arc_swap::ArcSwap;
use budu_common::{RequestCtx, Stage, WafDecision};
use budu_config::ReputationConfig;
use http::StatusCode;
use ipnet::IpNet;

#[cfg(feature = "geoip")]
mod geoip;
#[cfg(feature = "geoip")]
pub use geoip::GeoStage;

/// Shared, atomically-swappable blocklist handle (§9 hot-reload).
pub type SharedBlocks = Arc<ArcSwap<Vec<IpNet>>>;

/// Build the effective blocklist from config: inline `blocklist` merged with
/// `blocklist_file`.
pub fn build_blocks(cfg: &ReputationConfig) -> std::io::Result<Vec<IpNet>> {
    let mut blocks = cfg.blocklist.clone();
    if !cfg.blocklist_file.trim().is_empty() {
        blocks.extend(load_file(&cfg.blocklist_file)?);
    }
    Ok(blocks)
}

/// Build the trusted-IP allowlist from config: inline `allowlist` merged with
/// `allowlist_file`.
pub fn build_allowlist(cfg: &ReputationConfig) -> std::io::Result<Vec<IpNet>> {
    let mut allow = cfg.allowlist.clone();
    if !cfg.allowlist_file.trim().is_empty() {
        allow.extend(load_file(&cfg.allowlist_file)?);
    }
    Ok(allow)
}

/// Build the allowlist into a shared, atomically-swappable handle (hot-reload).
pub fn shared_allowlist(cfg: &ReputationConfig) -> std::io::Result<SharedBlocks> {
    Ok(Arc::new(ArcSwap::from_pointee(build_allowlist(cfg)?)))
}

/// Whether `ip` falls inside any CIDR in `set`.
pub fn contains(set: &SharedBlocks, ip: &std::net::IpAddr) -> bool {
    set.load().iter().any(|net| net.contains(ip))
}

/// CIDR blocklist stage.
///
/// Backed by a plain `Vec<IpNet>` behind an `ArcSwap`: linear scan is fine for
/// the modest lists a hand-curated blocklist holds, and the swap lets a
/// supervisor reload it without a lock. If this grows to thousands of entries,
/// swap in an `IpRange`/trie without touching the [`Stage`] contract.
pub struct ReputationStage {
    blocks: SharedBlocks,
    rule_id: Arc<str>,
}

impl ReputationStage {
    /// Build from config into its own shared handle.
    pub fn from_config(cfg: &ReputationConfig) -> std::io::Result<Self> {
        Ok(Self::new(build_blocks(cfg)?))
    }

    pub fn new(blocks: Vec<IpNet>) -> Self {
        Self {
            blocks: Arc::new(ArcSwap::from_pointee(blocks)),
            rule_id: Arc::from("reputation.blocklist"),
        }
    }

    /// The handle, so a supervisor can hot-swap the blocklist.
    pub fn handle(&self) -> SharedBlocks {
        self.blocks.clone()
    }

    pub fn len(&self) -> usize {
        self.blocks.load().len()
    }

    pub fn is_empty(&self) -> bool {
        self.blocks.load().is_empty()
    }
}

/// Parse a CIDR-per-line blocklist body (from a file or a remote feed). Blank
/// lines and `#` comments are ignored; a bare IP (no `/prefix`) becomes a host
/// route (`/32` or `/128`). Invalid lines are logged and skipped — one bad
/// entry never sinks the whole feed.
pub fn parse_blocklist(text: &str, source: &str) -> Vec<IpNet> {
    let mut out = Vec::new();
    for (n, raw) in text.lines().enumerate() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        match line
            .parse::<IpNet>()
            .or_else(|_| line.parse::<std::net::IpAddr>().map(IpNet::from))
        {
            Ok(net) => out.push(net),
            Err(_) => {
                tracing::warn!(source, line = n + 1, value = line, "skipping invalid CIDR")
            }
        }
    }
    out
}

fn load_file(path: &str) -> std::io::Result<Vec<IpNet>> {
    let text = std::fs::read_to_string(path)?;
    Ok(parse_blocklist(&text, path))
}

/// Fetch and merge external blocklist feeds over HTTP(S). Best-effort: a feed
/// that fails to fetch or parse is logged and skipped so a flaky source can't
/// take the gate down. Requires the `remote-blocklist` feature.
#[cfg(feature = "remote-blocklist")]
pub async fn fetch_blocklist_urls(urls: &[String]) -> Vec<IpNet> {
    let mut out = Vec::new();
    if urls.is_empty() {
        return out;
    }
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .user_agent("budu-waf")
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "building blocklist HTTP client failed");
            return out;
        }
    };
    for url in urls {
        let resp = match client.get(url).send().await.and_then(|r| r.error_for_status()) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(url, error = %e, "blocklist fetch failed; skipping feed");
                continue;
            }
        };
        match resp.bytes().await {
            Ok(body) => {
                let text = String::from_utf8_lossy(&body);
                let nets = parse_blocklist(&text, url);
                tracing::info!(url, entries = nets.len(), "fetched remote blocklist feed");
                out.extend(nets);
            }
            Err(e) => tracing::warn!(url, error = %e, "reading blocklist body failed; skipping"),
        }
    }
    out
}

impl Stage for ReputationStage {
    fn name(&self) -> &'static str {
        "reputation"
    }

    fn inspect(&self, ctx: &mut RequestCtx<'_>) -> ControlFlow<WafDecision> {
        let ip = ctx.client.ip;
        if self.blocks.load().iter().any(|net| net.contains(&ip)) {
            return ControlFlow::Break(WafDecision::Block {
                rule_id: self.rule_id.clone(),
                status: StatusCode::FORBIDDEN,
                reason: Arc::from("source IP is blocklisted"),
            });
        }
        ControlFlow::Continue(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use budu_common::{BodyState, ClientInfo, NormalizedCache};
    use http::{HeaderMap, Method};
    use std::net::IpAddr;

    fn run(stage: &ReputationStage, ip: &str) -> ControlFlow<WafDecision> {
        let method = Method::GET;
        let headers = HeaderMap::new();
        let mut ctx = RequestCtx {
            method: &method,
            path: "/",
            query: None,
            headers: &headers,
            client: ClientInfo {
                ip: ip.parse::<IpAddr>().unwrap(),
                geo: None,
            },
            body: BodyState::NotBuffered,
            normalized: NormalizedCache::default(),
        };
        stage.inspect(&mut ctx)
    }

    #[test]
    fn blocks_matching_cidr() {
        let stage = ReputationStage::new(vec!["10.0.0.0/8".parse().unwrap()]);
        assert!(matches!(run(&stage, "10.1.2.3"), ControlFlow::Break(_)));
        assert!(matches!(run(&stage, "11.0.0.1"), ControlFlow::Continue(())));
    }

    #[test]
    fn allowlist_contains_matches_cidr_and_host() {
        let set: SharedBlocks = Arc::new(ArcSwap::from_pointee(vec![
            "192.168.0.0/16".parse::<IpNet>().unwrap(),
            "203.0.113.7".parse::<IpAddr>().map(IpNet::from).unwrap(),
        ]));
        assert!(contains(&set, &"192.168.5.5".parse().unwrap()));
        assert!(contains(&set, &"203.0.113.7".parse().unwrap()));
        assert!(!contains(&set, &"8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn build_allowlist_merges_inline() {
        let cfg = ReputationConfig {
            allowlist: vec!["10.0.0.0/8".parse().unwrap()],
            ..Default::default()
        };
        let set = build_allowlist(&cfg).unwrap();
        assert_eq!(set.len(), 1);
    }
}
