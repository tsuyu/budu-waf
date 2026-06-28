//! Reputation layer (§8 step 2): a CIDR blocklist checked against the resolved
//! client IP. Fast and first — drops known-bad sources before any other work.

use std::net::IpAddr;
use std::ops::ControlFlow;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwap;
use budu_common::{RequestCtx, Stage, WafDecision};
use budu_config::ReputationConfig;
use http::StatusCode;
use ipnet::IpNet;

#[cfg(feature = "geoip")]
mod geoip;
#[cfg(feature = "geoip")]
pub use geoip::GeoStage;

/// A blocklist (or allowlist) entry: a CIDR plus an optional expiry as a UNIX
/// timestamp (seconds). `until = None` is permanent; a timed entry stops
/// matching once `until <= now`, so a fail2ban-style WAF ban **auto-expires**
/// even if its unban is never delivered. Written into a list file as
/// `IP until=<epoch>`.
#[derive(Clone, Copy, Debug)]
pub struct BlockEntry {
    pub net: IpNet,
    pub until: Option<u64>,
}

impl BlockEntry {
    pub fn perm(net: IpNet) -> Self {
        Self { net, until: None }
    }

    /// Still in force at `now` (epoch seconds)?
    pub fn active(&self, now: u64) -> bool {
        self.until.is_none_or(|u| u > now)
    }

    /// Matches `ip` and hasn't expired.
    pub fn matches(&self, ip: &IpAddr, now: u64) -> bool {
        self.active(now) && self.net.contains(ip)
    }
}

impl From<IpNet> for BlockEntry {
    fn from(net: IpNet) -> Self {
        Self::perm(net)
    }
}

/// Current UNIX time in seconds (0 if the clock is before the epoch).
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Shared, atomically-swappable block/allow list handle (§9 hot-reload).
pub type SharedBlocks = Arc<ArcSwap<Vec<BlockEntry>>>;

/// Build the effective blocklist from config: inline `blocklist` (permanent)
/// merged with `blocklist_file` (which may carry per-entry `until=` expiries).
pub fn build_blocks(cfg: &ReputationConfig) -> std::io::Result<Vec<BlockEntry>> {
    let mut blocks: Vec<BlockEntry> = cfg.blocklist.iter().copied().map(BlockEntry::perm).collect();
    if !cfg.blocklist_file.trim().is_empty() {
        blocks.extend(load_file(&cfg.blocklist_file)?);
    }
    Ok(blocks)
}

/// Build the trusted-IP allowlist from config: inline `allowlist` merged with
/// `allowlist_file`.
pub fn build_allowlist(cfg: &ReputationConfig) -> std::io::Result<Vec<BlockEntry>> {
    let mut allow: Vec<BlockEntry> = cfg.allowlist.iter().copied().map(BlockEntry::perm).collect();
    if !cfg.allowlist_file.trim().is_empty() {
        allow.extend(load_file(&cfg.allowlist_file)?);
    }
    Ok(allow)
}

/// Build the allowlist into a shared, atomically-swappable handle (hot-reload).
pub fn shared_allowlist(cfg: &ReputationConfig) -> std::io::Result<SharedBlocks> {
    Ok(Arc::new(ArcSwap::from_pointee(build_allowlist(cfg)?)))
}

/// Whether `ip` falls inside any non-expired entry in `set`.
pub fn contains(set: &SharedBlocks, ip: &IpAddr) -> bool {
    let now = now_secs();
    set.load().iter().any(|e| e.matches(ip, now))
}

/// Drop expired timed entries from a shared list, swapping in the pruned list
/// only if something actually expired. Called from the maintenance tick so bans
/// are reclaimed even without a reload.
pub fn prune_expired(set: &SharedBlocks) {
    let now = now_secs();
    let cur = set.load();
    if cur.iter().any(|e| !e.active(now)) {
        let kept: Vec<BlockEntry> = cur.iter().copied().filter(|e| e.active(now)).collect();
        set.store(Arc::new(kept));
    }
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
        Ok(Self::from_entries(build_blocks(cfg)?))
    }

    /// Construct from permanent CIDRs (convenience for callers/tests).
    pub fn new(blocks: Vec<IpNet>) -> Self {
        Self::from_entries(blocks.into_iter().map(BlockEntry::perm).collect())
    }

    pub fn from_entries(blocks: Vec<BlockEntry>) -> Self {
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

/// Parse a list body (from a file or a remote feed). Each non-empty,
/// non-`#`-comment line is `CIDR_or_IP [until=<unix_epoch_seconds>]`:
/// a bare IP becomes a host route (`/32`/`/128`); an optional `until=` makes it
/// a **timed** entry that auto-expires. Already-expired and malformed lines are
/// logged and skipped — one bad entry never sinks the whole list.
pub fn parse_blocklist(text: &str, source: &str) -> Vec<BlockEntry> {
    let mut out = Vec::new();
    for (n, raw) in text.lines().enumerate() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let mut tokens = line.split_whitespace();
        let net_str = tokens.next().unwrap_or("");
        let net = match net_str
            .parse::<IpNet>()
            .or_else(|_| net_str.parse::<IpAddr>().map(IpNet::from))
        {
            Ok(net) => net,
            Err(_) => {
                tracing::warn!(source, line = n + 1, value = net_str, "skipping invalid CIDR");
                continue;
            }
        };
        // Optional `until=<epoch>` (with the `fail2ban` feature); a malformed or
        // already-expired entry is skipped. Without the feature, timed bans are
        // disabled and every entry is permanent.
        let until = match line_until(tokens, source, n) {
            Some(u) => u,
            None => continue,
        };
        out.push(BlockEntry { net, until });
    }
    out
}

/// Resolve a line's `until=` expiry. `Some(opt)` → use `opt`; `None` → skip the
/// line (malformed / already expired).
#[cfg(feature = "fail2ban")]
fn line_until<'a>(tokens: impl Iterator<Item = &'a str>, source: &str, n: usize) -> Option<Option<u64>> {
    let now = now_secs();
    let mut until = None;
    for tok in tokens {
        if let Some(v) = tok.strip_prefix("until=") {
            match v.parse::<u64>() {
                Ok(ts) => until = Some(ts),
                Err(_) => {
                    tracing::warn!(source, line = n + 1, value = tok, "skipping entry with invalid `until`");
                    return None;
                }
            }
        }
    }
    // Drop entries that have already expired.
    if until.is_some_and(|u| u <= now) {
        return None;
    }
    Some(until)
}

/// Without the `fail2ban` feature, `until=` isn't honored — entries are permanent.
#[cfg(not(feature = "fail2ban"))]
fn line_until<'a>(_tokens: impl Iterator<Item = &'a str>, _source: &str, _n: usize) -> Option<Option<u64>> {
    Some(None)
}

fn load_file(path: &str) -> std::io::Result<Vec<BlockEntry>> {
    let text = std::fs::read_to_string(path)?;
    Ok(parse_blocklist(&text, path))
}

/// Fetch and merge external blocklist feeds over HTTP(S). Best-effort: a feed
/// that fails to fetch or parse is logged and skipped so a flaky source can't
/// take the gate down. Requires the `remote-blocklist` feature.
#[cfg(feature = "remote-blocklist")]
pub async fn fetch_blocklist_urls(urls: &[String]) -> Vec<BlockEntry> {
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
        let now = now_secs();
        if self.blocks.load().iter().any(|e| e.matches(&ip, now)) {
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
            BlockEntry::perm("192.168.0.0/16".parse().unwrap()),
            BlockEntry::perm("203.0.113.7".parse::<IpAddr>().map(IpNet::from).unwrap()),
        ]));
        assert!(contains(&set, &"192.168.5.5".parse().unwrap()));
        assert!(contains(&set, &"203.0.113.7".parse().unwrap()));
        assert!(!contains(&set, &"8.8.8.8".parse().unwrap()));
    }

    #[cfg(feature = "fail2ban")]
    #[test]
    fn timed_ban_active_then_expired() {
        let now = now_secs();
        // future expiry → matches; past expiry → does not.
        let active = parse_blocklist(&format!("203.0.113.9 until={}", now + 3600), "t");
        assert_eq!(active.len(), 1);
        let st = ReputationStage::from_entries(active);
        assert!(matches!(run(&st, "203.0.113.9"), ControlFlow::Break(_)));

        // already-expired lines are dropped at parse time.
        let expired = parse_blocklist(&format!("203.0.113.9 until={}", now - 1), "t");
        assert!(expired.is_empty());

        // malformed `until` → line skipped (fail-open, not permanent).
        assert!(parse_blocklist("203.0.113.9 until=soon", "t").is_empty());

        // permanent line still parses (no until).
        let perm = parse_blocklist("10.0.0.0/8", "t");
        assert_eq!(perm.len(), 1);
        assert!(perm[0].until.is_none());
    }

    #[test]
    fn prune_drops_expired_entries() {
        let now = now_secs();
        let set: SharedBlocks = Arc::new(ArcSwap::from_pointee(vec![
            BlockEntry::perm("10.0.0.0/8".parse().unwrap()),
            BlockEntry {
                net: "203.0.113.9/32".parse().unwrap(),
                until: Some(now - 1), // expired
            },
        ]));
        assert_eq!(set.load().len(), 2);
        // expired entry doesn't match even before pruning
        assert!(!contains(&set, &"203.0.113.9".parse().unwrap()));
        prune_expired(&set);
        assert_eq!(set.load().len(), 1); // expired entry reclaimed
        assert!(contains(&set, &"10.1.2.3".parse().unwrap()));
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
