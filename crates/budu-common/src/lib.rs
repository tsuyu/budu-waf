//! Core types shared across B.U.D.U crates.
//!
//! Defined first (see BUDU-DEV.md §7) so every later layer speaks the same
//! vocabulary: [`RequestCtx`] flows through the pipeline, each stage returns a
//! [`ControlFlow<WafDecision, ()>`](std::ops::ControlFlow) so a hit
//! short-circuits the rest.

use std::net::IpAddr;
use std::ops::ControlFlow;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use bytes::Bytes;
use http::{HeaderMap, Method, StatusCode};

pub mod error;
pub use error::BuduError;

/// Two-letter ISO-3166-1 country code (ASCII, upper-case), e.g. `b"MY"`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CountryCode(pub [u8; 2]);

impl CountryCode {
    pub fn as_str(&self) -> &str {
        // Always constructed from ASCII; safe to view as &str.
        std::str::from_utf8(&self.0).unwrap_or("??")
    }
}

/// Resolved facts about who is making the request.
#[derive(Clone, Copy, Debug)]
pub struct ClientInfo {
    pub ip: IpAddr,
    pub geo: Option<CountryCode>,
}

/// Whether the request body has been pulled into memory for inspection.
///
/// Bodies are buffered lazily and only when the body-gate decides it is worth
/// it (see pipeline §8). Everything else streams straight through.
#[derive(Clone, Debug, Default)]
pub enum BodyState {
    #[default]
    NotBuffered,
    Buffered(Bytes),
    TooLarge,
}

/// Lazily-filled, reused scratch buffers for normalization (percent-decode,
/// case-fold). Kept on the context so a request reuses one allocation across
/// stages instead of allocating per-check.
#[derive(Default)]
pub struct NormalizedCache {
    pub path: Option<String>,
    pub query: Option<String>,
    pub scratch: Vec<u8>,
}

/// Everything a WAF stage needs to make a decision, borrowed from the live
/// request head so inspection allocates nothing by default.
pub struct RequestCtx<'a> {
    pub method: &'a Method,
    pub path: &'a str,
    pub query: Option<&'a str>,
    pub headers: &'a HeaderMap,
    pub client: ClientInfo,
    pub body: BodyState,
    pub normalized: NormalizedCache,
}

/// View of the upstream response for response-phase rules. `status`/`headers`
/// are always present; `body` is [`BodyState::Buffered`] only when a response
/// rule references `resp_body` and the body was within the inspection limits —
/// otherwise it streams straight through and `body` is [`BodyState::NotBuffered`].
/// `path`/`client` are carried from the request for correlation and per-IP
/// counters.
pub struct ResponseCtx<'a> {
    pub status: StatusCode,
    pub headers: &'a HeaderMap,
    pub client: ClientInfo,
    pub path: &'a str,
    pub body: BodyState,
}

/// The verdict a stage can hand back. `Block`/`RateLimited` are answered by
/// B.U.D.U directly; the backend never sees the request.
#[derive(Clone, Debug)]
pub enum WafDecision {
    Allow,
    Block {
        rule_id: Arc<str>,
        status: StatusCode,
        reason: Arc<str>,
    },
    RateLimited {
        retry_after_secs: u32,
    },
}

impl WafDecision {
    pub fn is_allow(&self) -> bool {
        matches!(self, WafDecision::Allow)
    }
}

/// One inspection layer in the request pipeline (§8).
///
/// A stage borrows the [`RequestCtx`] and returns
/// [`ControlFlow::Continue`] to pass the request to the next stage, or
/// [`ControlFlow::Break`] with a [`WafDecision`] to short-circuit the rest. The
/// `&mut` lets a stage fill the reused [`NormalizedCache`] buffers for later
/// stages. Stages must be cheap to share across tasks (`Send + Sync`); per-IP
/// mutable state lives behind interior-mutable, lock-free maps inside the stage.
pub trait Stage: Send + Sync {
    /// Stable identifier used in logs/audit and as the basis for `rule_id`.
    fn name(&self) -> &'static str;

    fn inspect(&self, ctx: &mut RequestCtx<'_>) -> ControlFlow<WafDecision>;
}

/// Process-wide request counters (lock-free) exposed on the admin `/metrics`
/// endpoint. Increment with [`Metrics::record`] from the request path.
#[derive(Default, Debug)]
pub struct Metrics {
    pub requests_total: AtomicU64,
    pub allowed_total: AtomicU64,
    pub blocked_total: AtomicU64,
    pub ratelimited_total: AtomicU64,
    pub upstream_errors_total: AtomicU64,
    /// In `detect` enforcement mode: decisions that *would* have blocked but
    /// were forwarded anyway.
    pub would_block_total: AtomicU64,
    /// Requests from allowlisted (trusted) IPs that bypassed inspection.
    pub whitelisted_total: AtomicU64,
}

impl Metrics {
    pub fn request(&self) {
        self.requests_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Tally a final decision (after the body-gate may have turned an oversized
    /// body into a Block).
    pub fn record(&self, decision: &WafDecision) {
        match decision {
            WafDecision::Allow => &self.allowed_total,
            WafDecision::Block { .. } => &self.blocked_total,
            WafDecision::RateLimited { .. } => &self.ratelimited_total,
        }
        .fetch_add(1, Ordering::Relaxed);
    }

    pub fn upstream_error(&self) {
        self.upstream_errors_total.fetch_add(1, Ordering::Relaxed);
    }

    /// A would-be block that was forwarded because enforcement is `detect`.
    pub fn would_block(&self) {
        self.would_block_total.fetch_add(1, Ordering::Relaxed);
    }

    /// A request from a trusted (allowlisted) IP that bypassed inspection.
    pub fn whitelisted(&self) {
        self.whitelisted_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            requests: self.requests_total.load(Ordering::Relaxed),
            allowed: self.allowed_total.load(Ordering::Relaxed),
            blocked: self.blocked_total.load(Ordering::Relaxed),
            ratelimited: self.ratelimited_total.load(Ordering::Relaxed),
            upstream_errors: self.upstream_errors_total.load(Ordering::Relaxed),
            would_block: self.would_block_total.load(Ordering::Relaxed),
            whitelisted: self.whitelisted_total.load(Ordering::Relaxed),
        }
    }
}

/// A consistent-ish read of the counters for rendering.
#[derive(Debug, Clone, Copy)]
pub struct MetricsSnapshot {
    pub requests: u64,
    pub allowed: u64,
    pub blocked: u64,
    pub ratelimited: u64,
    pub upstream_errors: u64,
    pub would_block: u64,
    pub whitelisted: u64,
}

/// Lets a stage be shared (e.g. between the pipeline and a supervisor that runs
/// maintenance on it) by boxing an `Arc<T>` as a `Box<dyn Stage>`.
impl<T: Stage + ?Sized> Stage for Arc<T> {
    fn name(&self) -> &'static str {
        (**self).name()
    }
    fn inspect(&self, ctx: &mut RequestCtx<'_>) -> ControlFlow<WafDecision> {
        (**self).inspect(ctx)
    }
}
