//! Sanity layer (§8 step 4): cheap structural limits — URI length, header
//! count, well-formed Content-Length — to reject malformed/abusive requests
//! before any normalization or signature work.

use std::ops::ControlFlow;
use std::sync::Arc;

use budu_common::{RequestCtx, Stage, WafDecision};
use budu_config::LimitsConfig;
use http::{header, StatusCode};

pub struct SanityStage {
    max_uri_len: usize,
    max_header_count: usize,
}

impl SanityStage {
    pub fn from_config(cfg: &LimitsConfig) -> Self {
        Self {
            max_uri_len: cfg.max_uri_len,
            max_header_count: cfg.max_header_count,
        }
    }

    fn block(rule: &'static str, status: StatusCode, reason: &'static str) -> WafDecision {
        WafDecision::Block {
            rule_id: Arc::from(rule),
            status,
            reason: Arc::from(reason),
        }
    }
}

impl Stage for SanityStage {
    fn name(&self) -> &'static str {
        "sanity"
    }

    fn inspect(&self, ctx: &mut RequestCtx<'_>) -> ControlFlow<WafDecision> {
        // path + '?' + query
        let uri_len = ctx.path.len() + ctx.query.map_or(0, |q| q.len() + 1);
        if uri_len > self.max_uri_len {
            return ControlFlow::Break(Self::block(
                "sanity.uri_len",
                StatusCode::URI_TOO_LONG,
                "request URI exceeds configured limit",
            ));
        }

        if ctx.headers.len() > self.max_header_count {
            return ControlFlow::Break(Self::block(
                "sanity.header_count",
                StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
                "too many request headers",
            ));
        }

        // A Content-Length that doesn't parse as a number is malformed/smuggle-y.
        if let Some(cl) = ctx.headers.get(header::CONTENT_LENGTH) {
            let ok = cl.to_str().ok().and_then(|s| s.trim().parse::<u64>().ok());
            if ok.is_none() {
                return ControlFlow::Break(Self::block(
                    "sanity.content_length",
                    StatusCode::BAD_REQUEST,
                    "malformed Content-Length",
                ));
            }
        }

        ControlFlow::Continue(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use budu_common::{BodyState, ClientInfo, NormalizedCache};
    use http::{HeaderMap, HeaderValue, Method};
    use std::net::IpAddr;

    fn stage() -> SanityStage {
        SanityStage {
            max_uri_len: 16,
            max_header_count: 4,
        }
    }

    fn run(path: &str, headers: &HeaderMap) -> ControlFlow<WafDecision> {
        let method = Method::GET;
        let mut ctx = RequestCtx {
            method: &method,
            path,
            query: None,
            headers,
            client: ClientInfo {
                ip: "127.0.0.1".parse::<IpAddr>().unwrap(),
                geo: None,
            },
            body: BodyState::NotBuffered,
            normalized: NormalizedCache::default(),
        };
        stage().inspect(&mut ctx)
    }

    #[test]
    fn rejects_long_uri() {
        let h = HeaderMap::new();
        assert!(matches!(
            run("/this/is/a/really/long/path", &h),
            ControlFlow::Break(_)
        ));
        assert!(matches!(run("/ok", &h), ControlFlow::Continue(())));
    }

    #[test]
    fn rejects_bad_content_length() {
        let mut h = HeaderMap::new();
        h.insert(header::CONTENT_LENGTH, HeaderValue::from_static("notanumber"));
        assert!(matches!(run("/ok", &h), ControlFlow::Break(_)));
    }
}
