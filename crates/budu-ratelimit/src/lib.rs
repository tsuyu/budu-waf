//! Rate-limit layer (§8 step 3): a per-client-IP token bucket (`governor`)
//! stored in a TTL-evicting map (`moka`) so idle sources free their bucket
//! automatically (the self-evicting rate-limit state from §9).

use std::net::IpAddr;
use std::num::NonZeroU32;
use std::ops::ControlFlow;
use std::sync::Arc;
use std::time::Duration;

use budu_common::{RequestCtx, Stage, WafDecision};
use budu_config::RateLimitConfig;
use governor::clock::{Clock, DefaultClock};
use governor::{DefaultDirectRateLimiter, Quota, RateLimiter};
use moka::sync::Cache;

/// Reusable per-IP token-bucket limiter: `governor` buckets in a TTL-evicting
/// `moka` map (self-evicting idle state, §9). Shared by the global rate-limit
/// stage and by per-rule `rate_limit` actions.
#[derive(Clone)]
pub struct IpRateLimiter {
    buckets: Cache<IpAddr, Arc<DefaultDirectRateLimiter>>,
    quota: Quota,
    clock: DefaultClock,
}

impl IpRateLimiter {
    /// `burst = 0` falls back to `rps`; `rps = 0` falls back to 1.
    pub fn new(rps: u32, burst: u32, ttl_secs: u64) -> Self {
        let rps = NonZeroU32::new(rps).unwrap_or(NonZeroU32::MIN);
        let burst = NonZeroU32::new(burst).unwrap_or(rps);
        let quota = Quota::per_second(rps).allow_burst(burst);

        let buckets = Cache::builder()
            .time_to_idle(Duration::from_secs(ttl_secs.max(1)))
            .max_capacity(1_000_000) // bound memory under a source-spoofing flood
            .build();

        Self {
            buckets,
            quota,
            clock: DefaultClock::default(),
        }
    }

    /// Consume one token for `ip`. `Ok(())` = allowed; `Err(secs)` = throttled,
    /// with the suggested `Retry-After` in whole seconds (>= 1).
    pub fn check(&self, ip: IpAddr) -> Result<(), u32> {
        let limiter = self
            .buckets
            .get_with(ip, || Arc::new(RateLimiter::direct(self.quota)));
        match limiter.check() {
            Ok(()) => Ok(()),
            Err(not_until) => {
                let wait = not_until.wait_time_from(self.clock.now());
                let retry = (wait.as_secs() + u64::from(wait.subsec_nanos() > 0)).max(1) as u32;
                Err(retry)
            }
        }
    }

    /// Number of live per-IP buckets (approximate; for metrics/tests).
    pub fn tracked(&self) -> u64 {
        self.buckets.entry_count()
    }

    /// Drive moka's pending eviction/maintenance (§9 rate-limit GC).
    pub fn run_maintenance(&self) {
        self.buckets.run_pending_tasks();
    }
}

/// The global rate-limit pipeline stage (§8 step 3), keyed on client IP.
pub struct RateLimitStage {
    limiter: IpRateLimiter,
}

impl RateLimitStage {
    pub fn from_config(cfg: &RateLimitConfig) -> Self {
        Self {
            limiter: IpRateLimiter::new(cfg.requests_per_sec, cfg.burst, cfg.ttl_secs),
        }
    }

    pub fn tracked(&self) -> u64 {
        self.limiter.tracked()
    }

    pub fn run_maintenance(&self) {
        self.limiter.run_maintenance();
    }
}

impl Stage for RateLimitStage {
    fn name(&self) -> &'static str {
        "ratelimit"
    }

    fn inspect(&self, ctx: &mut RequestCtx<'_>) -> ControlFlow<WafDecision> {
        match self.limiter.check(ctx.client.ip) {
            Ok(()) => ControlFlow::Continue(()),
            Err(retry_after_secs) => {
                ControlFlow::Break(WafDecision::RateLimited { retry_after_secs })
            }
        }
    }
}

// ── Stateful counters (persistent collections) ──────────────────────────────

#[derive(Clone)]
struct Counter {
    count: u64,
    ttl: Duration,
}

/// Per-entry TTL: each counter expires `window_secs` after its last write
/// (sliding window).
struct CounterExpiry;

impl moka::Expiry<String, Counter> for CounterExpiry {
    fn expire_after_create(
        &self,
        _k: &String,
        v: &Counter,
        _now: std::time::Instant,
    ) -> Option<Duration> {
        Some(v.ttl)
    }
    fn expire_after_update(
        &self,
        _k: &String,
        v: &Counter,
        _now: std::time::Instant,
        _current: Option<Duration>,
    ) -> Option<Duration> {
        Some(v.ttl)
    }
}

/// Named, per-client-IP counters with TTL windows — the substrate for stateful
/// rules (brute-force / scanner detection). Cheaply cloneable (moka is `Arc`
/// inside) so it can be shared between the pipeline and the supervisor and
/// survive rule hot-reloads.
#[derive(Clone)]
pub struct CounterStore {
    cache: Cache<String, Counter>,
}

impl Default for CounterStore {
    fn default() -> Self {
        Self::new()
    }
}

impl CounterStore {
    pub fn new() -> Self {
        let cache = Cache::builder()
            .max_capacity(1_000_000)
            .expire_after(CounterExpiry)
            .build();
        Self { cache }
    }

    fn key(name: &str, ip: IpAddr) -> String {
        // \u{1} can't appear in a counter name, so this can't collide.
        format!("{name}\u{1}{ip}")
    }

    /// Add `amount` to `(name, ip)` and refresh its `window_secs` TTL; returns
    /// the new value. (Concurrent increments may rarely under-count — fine for
    /// security thresholds.)
    pub fn incr(&self, name: &str, ip: IpAddr, amount: u64, window_secs: u64) -> u64 {
        let key = Self::key(name, ip);
        let current = self.cache.get(&key).map(|c| c.count).unwrap_or(0);
        let count = current.saturating_add(amount);
        self.cache.insert(
            key,
            Counter {
                count,
                ttl: Duration::from_secs(window_secs.max(1)),
            },
        );
        count
    }

    /// Current value of `(name, ip)` (0 if unset/expired).
    pub fn get(&self, name: &str, ip: IpAddr) -> u64 {
        self.cache.get(&Self::key(name, ip)).map(|c| c.count).unwrap_or(0)
    }

    pub fn tracked(&self) -> u64 {
        self.cache.entry_count()
    }

    pub fn run_maintenance(&self) {
        self.cache.run_pending_tasks();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use budu_common::{BodyState, ClientInfo, NormalizedCache};
    use http::{HeaderMap, Method};
    use std::net::IpAddr;

    #[test]
    fn allows_then_throttles_burst() {
        let cfg = RateLimitConfig {
            requests_per_sec: 1,
            burst: 3,
            ttl_secs: 60,
        };
        let stage = RateLimitStage::from_config(&cfg);
        let method = Method::GET;
        let headers = HeaderMap::new();
        let ip: IpAddr = "198.51.100.9".parse().unwrap();

        let mut blocked = false;
        for _ in 0..6 {
            let mut ctx = RequestCtx {
                method: &method,
                path: "/",
                query: None,
                headers: &headers,
                client: ClientInfo { ip, geo: None },
                body: BodyState::NotBuffered,
                normalized: NormalizedCache::default(),
            };
            if let ControlFlow::Break(WafDecision::RateLimited { retry_after_secs }) =
                stage.inspect(&mut ctx)
            {
                assert!(retry_after_secs >= 1);
                blocked = true;
                break;
            }
        }
        assert!(blocked, "burst of 3 @ 1rps must throttle within 6 rapid hits");
    }
}
