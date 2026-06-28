//! The [`Stage`] wrapper around a [`RuleSet`], behind an `ArcSwap` for
//! hot-reload (§9). Runs before signatures in the late phase so an `allow` rule
//! can whitelist a request past the heavier inspection.

use std::ops::ControlFlow;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use arc_swap::ArcSwap;
use budu_common::{RequestCtx, ResponseCtx, Stage, WafDecision};

use crate::ruleset::{Outcome, RuleSet};

/// Shared, atomically-swappable rule set handle.
pub type SharedRules = Arc<ArcSwap<RuleSet>>;

/// Compile rules from `path` (empty path = no rules) into a shared handle.
pub fn shared_from_path(
    path: &str,
    scoring: &budu_config::ScoringConfig,
    default_tz: i16,
) -> Result<SharedRules, crate::RuleError> {
    Ok(Arc::new(ArcSwap::from_pointee(RuleSet::load(
        path, scoring, default_tz,
    )?)))
}

pub struct RulesStage {
    rules: SharedRules,
    /// Cumulative `log`-rule match count. Lives here (not in the swappable
    /// `RuleSet`) so it survives hot-reloads.
    log_hits: Arc<AtomicU64>,
    /// Stateful per-IP counters for `incr`/`counter` rules — persistent across
    /// rule hot-reloads.
    counters: budu_ratelimit::CounterStore,
}

impl RulesStage {
    pub fn new(rules: SharedRules) -> Self {
        Self {
            rules,
            log_hits: Arc::new(AtomicU64::new(0)),
            counters: budu_ratelimit::CounterStore::new(),
        }
    }

    pub fn from_path(
        path: &str,
        scoring: &budu_config::ScoringConfig,
        default_tz: i16,
    ) -> Result<Self, crate::RuleError> {
        Ok(Self::new(shared_from_path(path, scoring, default_tz)?))
    }

    /// Handle for the supervisor to hot-swap the rule set.
    pub fn handle(&self) -> SharedRules {
        self.rules.clone()
    }

    /// Handle to the cumulative `log`-rule match counter (for metrics).
    pub fn log_hits_handle(&self) -> Arc<AtomicU64> {
        self.log_hits.clone()
    }

    /// Handle to the stateful counter store (for supervisor maintenance/metrics).
    pub fn counters_handle(&self) -> budu_ratelimit::CounterStore {
        self.counters.clone()
    }

    /// Whether the current rule set has any response rule that inspects the
    /// response body (so the proxy knows whether to buffer it).
    pub fn needs_response_body(&self) -> bool {
        self.rules.load().needs_response_body()
    }

    /// Run response-phase rules against the upstream response. Returns the
    /// decision (`Allow` when nothing matched).
    pub fn inspect_response(&self, rctx: &ResponseCtx<'_>) -> WafDecision {
        match self
            .rules
            .load()
            .evaluate_response(rctx, &self.log_hits, &self.counters)
        {
            Some(Outcome::Block {
                rule_id,
                status,
                reason,
            }) => WafDecision::Block {
                rule_id,
                status,
                reason,
            },
            _ => WafDecision::Allow,
        }
    }
}

impl Stage for RulesStage {
    fn name(&self) -> &'static str {
        "rules"
    }

    fn inspect(&self, ctx: &mut RequestCtx<'_>) -> ControlFlow<WafDecision> {
        match self
            .rules
            .load()
            .evaluate_counting(ctx, &self.log_hits, &self.counters)
        {
            Some(Outcome::Block {
                rule_id,
                status,
                reason,
            }) => ControlFlow::Break(WafDecision::Block {
                rule_id,
                status,
                reason,
            }),
            Some(Outcome::Allow { rule_id }) => {
                tracing::debug!(rule_id = %rule_id, "allow rule matched; bypassing inspection");
                // Break with Allow short-circuits the rest of the pipeline (incl.
                // signatures) and forwards the request — an explicit whitelist.
                ControlFlow::Break(WafDecision::Allow)
            }
            Some(Outcome::RateLimited {
                rule_id,
                retry_after_secs,
            }) => {
                tracing::debug!(rule_id = %rule_id, "rate_limit rule throttled request");
                ControlFlow::Break(WafDecision::RateLimited { retry_after_secs })
            }
            None => ControlFlow::Continue(()),
        }
    }
}
