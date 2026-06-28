//! The WAF core (§8): an ordered stack of [`Stage`]s run cheapest-first, each
//! able to short-circuit with a [`WafDecision`]. Every stage runs inside
//! `catch_unwind` so a panic in one inspection can never take the proxy (and
//! therefore the app) down — the house rule from BUDU-DEV.md.

use std::ops::ControlFlow;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::Arc;

use budu_common::{RequestCtx, Stage, WafDecision};
use budu_config::{Config, OnError};
use http::StatusCode;

mod sanity;
pub use sanity::SanityStage;

/// An ordered pipeline split around the body-gate (§8): `early` stages run on
/// the head alone (cheapest-first), then the proxy may buffer the body, then
/// `late` stages (signatures) run with the body available. The fail policy is
/// applied when a stage panics.
pub struct Pipeline {
    early: Vec<Box<dyn Stage>>,
    late: Vec<Box<dyn Stage>>,
    /// Shared with the `late` stack; also used directly for response-phase rules.
    rules: Arc<budu_rules::RulesStage>,
    /// Trusted-IP allowlist: a matching client bypasses the whole pipeline.
    allowlist: budu_reputation::SharedBlocks,
    on_error: OnError,
}

impl Pipeline {
    /// Build the standard pipeline from config. Order follows §8:
    /// reputation → ratelimit → sanity → normalize  |body-gate|  signatures.
    ///
    /// Returns the pipeline plus a [`Reloadable`] handle that shares the
    /// hot-swappable state (signatures, blocklist) and the live rate-limit
    /// buckets with the pipeline, so a supervisor can reload/maintain them
    /// without rebuilding (and thus without dropping rate-limit state).
    pub fn from_config(cfg: &Config) -> anyhow::Result<(Self, Reloadable)> {
        let reputation = budu_reputation::ReputationStage::from_config(&cfg.reputation)?;
        let reputation_handle = reputation.handle();

        let ratelimit = Arc::new(budu_ratelimit::RateLimitStage::from_config(&cfg.ratelimit));

        let signatures = budu_signatures::SignatureStage::from_path(&cfg.paths.signatures)?;
        let signatures_handle = signatures.handle();

        let rules = Arc::new(budu_rules::RulesStage::from_path(&cfg.paths.rules, &cfg.scoring)?);
        let rules_handle = rules.handle();
        let rules_log_hits = rules.log_hits_handle();
        let rules_counters = rules.counters_handle();

        let allowlist = budu_reputation::shared_allowlist(&cfg.reputation)?;

        let mut early: Vec<Box<dyn Stage>> = vec![Box::new(reputation)];

        // GeoIP slots right after reputation: stamp the country, then enforce
        // any allow/block policy before spending work on rate-limit/inspection.
        #[cfg(feature = "geoip")]
        if let Some(geo) = budu_reputation::GeoStage::from_config(&cfg.geoip)? {
            early.push(Box::new(geo));
        }
        #[cfg(not(feature = "geoip"))]
        if cfg.geoip.enabled {
            tracing::warn!(
                "geoip.enabled = true but this build lacks the `geoip` feature; \
                 GeoIP is disabled. Rebuild with --features geoip."
            );
        }

        early.push(Box::new(ratelimit.clone()));
        early.push(Box::new(SanityStage::from_config(&cfg.limits)));
        early.push(Box::new(budu_parser::NormalizeStage));

        // Rules run before signatures so an `allow` rule can whitelist a
        // request past the heavier pattern inspection.
        let late: Vec<Box<dyn Stage>> = vec![Box::new(rules.clone()), Box::new(signatures)];

        let pipeline = Self {
            early,
            late,
            rules,
            allowlist: allowlist.clone(),
            on_error: cfg.server.on_error,
        };
        let reloadable = Reloadable {
            signatures: signatures_handle,
            rules: rules_handle,
            rules_log_hits,
            rules_counters,
            reputation: reputation_handle,
            allowlist,
            ratelimit,
        };
        Ok((pipeline, reloadable))
    }

    /// Construct from an explicit (early-only) stage list for tests.
    pub fn new(stages: Vec<Box<dyn Stage>>, on_error: OnError) -> Self {
        let rules = Arc::new(
            budu_rules::RulesStage::from_path("", &budu_config::ScoringConfig::default())
                .expect("empty rule set"),
        );
        let allowlist = budu_reputation::shared_allowlist(&budu_config::ReputationConfig::default())
            .expect("empty allowlist");
        Self {
            early: stages,
            late: Vec::new(),
            rules,
            allowlist,
            on_error,
        }
    }

    /// Whether `ip` is on the trusted-IP allowlist (fully bypass inspection).
    pub fn is_whitelisted(&self, ip: &std::net::IpAddr) -> bool {
        budu_reputation::contains(&self.allowlist, ip)
    }

    /// Run response-phase rules against the upstream response (`Allow` when
    /// nothing matched).
    pub fn evaluate_response(&self, rctx: &budu_common::ResponseCtx<'_>) -> WafDecision {
        self.rules.inspect_response(rctx)
    }

    /// Whether any response rule inspects the response body — i.e. whether the
    /// proxy needs to buffer the upstream body before forwarding it.
    pub fn needs_response_body(&self) -> bool {
        self.rules.needs_response_body()
    }

    /// Run the whole pipeline (early then late) over the same ctx. Convenience
    /// for tests / requests with no body to gate.
    pub fn evaluate(&self, ctx: &mut RequestCtx<'_>) -> WafDecision {
        match self.evaluate_early(ctx) {
            WafDecision::Allow => self.evaluate_late(ctx),
            blocked => blocked,
        }
    }

    /// Head-only stages, run before the body-gate decides whether to buffer.
    pub fn evaluate_early(&self, ctx: &mut RequestCtx<'_>) -> WafDecision {
        self.run(&self.early, ctx)
    }

    /// Body-aware stages (signatures), run after the body-gate.
    pub fn evaluate_late(&self, ctx: &mut RequestCtx<'_>) -> WafDecision {
        self.run(&self.late, ctx)
    }

    fn run(&self, stages: &[Box<dyn Stage>], ctx: &mut RequestCtx<'_>) -> WafDecision {
        for stage in stages {
            // AssertUnwindSafe: on a panic we discard the borrow and fall back
            // to the configured fail policy, so observing a half-mutated ctx
            // can't happen — we never use it again on that path.
            let result = catch_unwind(AssertUnwindSafe(|| stage.inspect(ctx)));
            match result {
                Ok(ControlFlow::Continue(())) => {}
                Ok(ControlFlow::Break(decision)) => return decision,
                Err(_) => {
                    tracing::error!(stage = stage.name(), "stage panicked");
                    match self.on_error {
                        // fail-closed: deny the request
                        OnError::Closed => {
                            return WafDecision::Block {
                                rule_id: Arc::from("pipeline.panic"),
                                status: StatusCode::INTERNAL_SERVER_ERROR,
                                reason: Arc::from("inspection error"),
                            }
                        }
                        // fail-open: skip the broken stage, keep inspecting
                        OnError::Open => {}
                    }
                }
            }
        }
        WafDecision::Allow
    }

    pub fn len(&self) -> usize {
        self.early.len() + self.late.len()
    }

    pub fn is_empty(&self) -> bool {
        self.early.is_empty() && self.late.is_empty()
    }
}

/// Handle to the pipeline's hot-swappable state and live rate-limit buckets,
/// shared with the running pipeline. Owned by the supervisor task (§9).
#[derive(Clone)]
pub struct Reloadable {
    signatures: budu_signatures::SharedDb,
    rules: budu_rules::SharedRules,
    rules_log_hits: Arc<std::sync::atomic::AtomicU64>,
    rules_counters: budu_ratelimit::CounterStore,
    reputation: budu_reputation::SharedBlocks,
    allowlist: budu_reputation::SharedBlocks,
    ratelimit: Arc<budu_ratelimit::RateLimitStage>,
}

/// Snapshot of pipeline state for metrics/logging.
#[derive(Debug, Clone, Copy)]
pub struct PipelineMetrics {
    pub signatures: usize,
    pub rules: usize,
    pub rule_log_matches: u64,
    pub blocklist: usize,
    pub allowlist: usize,
    pub rate_buckets: u64,
    pub counters: u64,
}

impl Reloadable {
    /// Recompile signatures from a fresh config and swap them in atomically.
    /// On error nothing is swapped — the running ruleset stays in force. The
    /// blocklist is handled separately by [`refresh_blocklist`](Self::refresh_blocklist)
    /// because it may involve async remote feeds.
    pub fn apply(&self, cfg: &Config) -> anyhow::Result<()> {
        // Compile both before swapping either, so a broken file leaves the
        // running config untouched.
        let new_sigs = budu_signatures::SignatureDb::load(&cfg.paths.signatures)?;
        let new_rules = budu_rules::RuleSet::load(&cfg.paths.rules, &cfg.scoring)?;
        // Allowlist is local-only (inline + file), so rebuild it synchronously here.
        let new_allow = budu_reputation::build_allowlist(&cfg.reputation)?;
        self.signatures.store(Arc::new(new_sigs));
        self.rules.store(Arc::new(new_rules));
        self.allowlist.store(Arc::new(new_allow));
        Ok(())
    }

    /// Rebuild the blocklist — inline + file (always) plus remote feeds (with
    /// the `remote-blocklist` feature) — and swap it in atomically. Called at
    /// startup, on a refresh timer, and on SIGHUP.
    pub async fn refresh_blocklist(&self, cfg: &Config) -> anyhow::Result<()> {
        // `mut` only used when the remote-blocklist feature extends the list.
        #[allow(unused_mut)]
        let mut blocks = budu_reputation::build_blocks(&cfg.reputation)?;
        #[cfg(feature = "remote-blocklist")]
        {
            blocks.extend(budu_reputation::fetch_blocklist_urls(&cfg.reputation.blocklist_urls).await);
        }
        #[cfg(not(feature = "remote-blocklist"))]
        if !cfg.reputation.blocklist_urls.is_empty() {
            tracing::warn!(
                "reputation.blocklist_urls is set but this build lacks the \
                 `remote-blocklist` feature; remote feeds are ignored"
            );
        }
        self.reputation.store(Arc::new(blocks));
        Ok(())
    }

    /// Periodic maintenance (rate-limit bucket + stateful counter GC).
    pub fn run_maintenance(&self) {
        self.ratelimit.run_maintenance();
        self.rules_counters.run_maintenance();
    }

    pub fn metrics(&self) -> PipelineMetrics {
        PipelineMetrics {
            signatures: self.signatures.load().len(),
            rules: self.rules.load().len(),
            rule_log_matches: self.rules_log_hits.load(std::sync::atomic::Ordering::Relaxed),
            blocklist: self.reputation.load().len(),
            allowlist: self.allowlist.load().len(),
            rate_buckets: self.ratelimit.tracked(),
            counters: self.rules_counters.tracked(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use budu_common::{BodyState, ClientInfo, NormalizedCache};
    use http::{HeaderMap, Method};
    use std::net::IpAddr;

    struct Panicky;
    impl Stage for Panicky {
        fn name(&self) -> &'static str {
            "panicky"
        }
        fn inspect(&self, _ctx: &mut RequestCtx<'_>) -> ControlFlow<WafDecision> {
            panic!("boom");
        }
    }

    fn run(pipe: &Pipeline) -> WafDecision {
        let method = Method::GET;
        let headers = HeaderMap::new();
        let mut ctx = RequestCtx {
            method: &method,
            path: "/",
            query: None,
            headers: &headers,
            client: ClientInfo {
                ip: "127.0.0.1".parse::<IpAddr>().unwrap(),
                geo: None,
            },
            body: BodyState::NotBuffered,
            normalized: NormalizedCache::default(),
        };
        pipe.evaluate(&mut ctx)
    }

    #[test]
    fn panic_fails_closed() {
        let pipe = Pipeline::new(vec![Box::new(Panicky)], OnError::Closed);
        assert!(matches!(run(&pipe), WafDecision::Block { .. }));
    }

    #[test]
    fn panic_fails_open() {
        let pipe = Pipeline::new(vec![Box::new(Panicky)], OnError::Open);
        assert!(matches!(run(&pipe), WafDecision::Allow));
    }
}
