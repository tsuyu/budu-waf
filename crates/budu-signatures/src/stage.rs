//! The [`Stage`] wrapper around a [`SignatureDb`]. Builds the normalized
//! haystack (path + query +, when buffered, the body) and scans it.
//!
//! The DB lives behind an [`ArcSwap`] so the supervisor can compile a new
//! ruleset off the hot path and swap it in atomically (§9): request-path reads
//! are a lock-free `Arc` clone.

use std::ops::ControlFlow;
use std::sync::Arc;

use arc_swap::ArcSwap;
use budu_common::{BodyState, RequestCtx, Stage, WafDecision};

use crate::db::SignatureDb;

/// Shared, atomically-swappable signature database handle.
pub type SharedDb = Arc<ArcSwap<SignatureDb>>;

/// Compile signatures from `path` (or builtin if empty) into a shared handle.
pub fn shared_from_path(path: &str) -> Result<SharedDb, crate::db::SignatureError> {
    Ok(Arc::new(ArcSwap::from_pointee(SignatureDb::load(path)?)))
}

pub struct SignatureStage {
    db: SharedDb,
}

impl SignatureStage {
    pub fn new(db: SharedDb) -> Self {
        Self { db }
    }

    /// Build a stage with its own shared handle from the configured path.
    pub fn from_path(path: &str) -> Result<Self, crate::db::SignatureError> {
        Ok(Self::new(shared_from_path(path)?))
    }

    /// The handle, so a supervisor can hot-swap the ruleset.
    pub fn handle(&self) -> SharedDb {
        self.db.clone()
    }

    /// Assemble the canonical haystack: normalized path, `?` + normalized
    /// query, and (when the body-gate buffered it) the percent-decoded,
    /// lowercased body — separated so a token can't bridge two parts.
    fn haystack(ctx: &RequestCtx<'_>) -> String {
        let mut hay = String::new();
        match &ctx.normalized.path {
            Some(p) => hay.push_str(p),
            None => budu_parser::normalize_into(ctx.path.as_bytes(), false, &mut hay),
        }
        match &ctx.normalized.query {
            Some(q) => {
                hay.push('?');
                hay.push_str(q);
            }
            None => {
                if let Some(q) = ctx.query {
                    hay.push('?');
                    budu_parser::normalize_into(q.as_bytes(), true, &mut hay);
                }
            }
        }
        if let BodyState::Buffered(bytes) = &ctx.body {
            hay.push('\n');
            budu_parser::normalize_into(bytes, true, &mut hay);
        }
        hay
    }
}

impl Stage for SignatureStage {
    fn name(&self) -> &'static str {
        "signatures"
    }

    fn inspect(&self, ctx: &mut RequestCtx<'_>) -> ControlFlow<WafDecision> {
        let hay = Self::haystack(ctx);
        // Lock-free read of the current ruleset.
        match self.db.load().scan(&hay) {
            Some(hit) => ControlFlow::Break(WafDecision::Block {
                rule_id: hit.rule_id,
                status: hit.status,
                reason: hit.reason,
            }),
            None => ControlFlow::Continue(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use budu_common::{ClientInfo, NormalizedCache};
    use http::{HeaderMap, Method};
    use std::net::IpAddr;

    fn scan_query(q: &str) -> ControlFlow<WafDecision> {
        let stage = SignatureStage::new(Arc::new(ArcSwap::from_pointee(SignatureDb::builtin())));
        let method = Method::GET;
        let headers = HeaderMap::new();
        let mut normalized = NormalizedCache::default();
        let mut nq = String::new();
        budu_parser::normalize_into(q.as_bytes(), true, &mut nq);
        normalized.path = Some("/".to_string());
        normalized.query = Some(nq);
        let mut ctx = RequestCtx {
            method: &method,
            path: "/",
            query: Some(q),
            headers: &headers,
            client: ClientInfo {
                ip: "127.0.0.1".parse::<IpAddr>().unwrap(),
                geo: None,
            },
            body: BodyState::NotBuffered,
            normalized,
        };
        stage.inspect(&mut ctx)
    }

    #[test]
    fn blocks_classic_sqli() {
        assert!(matches!(scan_query("q=' OR 1=1--"), ControlFlow::Break(_)));
        assert!(matches!(scan_query("id=1 UNION SELECT password"), ControlFlow::Break(_)));
    }

    #[test]
    fn blocks_xss_and_traversal() {
        assert!(matches!(scan_query("c=<script>alert(1)"), ControlFlow::Break(_)));
        assert!(matches!(scan_query("f=../../etc/passwd"), ControlFlow::Break(_)));
        assert!(matches!(scan_query("c=%3Cscript%3E"), ControlFlow::Break(_)));
    }

    #[test]
    fn allows_benign() {
        assert!(matches!(scan_query("q=hello+world&page=2"), ControlFlow::Continue(())));
        assert!(matches!(scan_query("name=o'brien"), ControlFlow::Continue(())));
    }
}
