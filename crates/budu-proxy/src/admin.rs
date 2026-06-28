//! Admin endpoint (§12 step 5): a tiny, separate HTTP listener serving
//! `/metrics` (Prometheus text) and `/healthz`. Bind it to localhost or a
//! management interface — it is **not** part of the data path and must never be
//! client-facing.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use budu_common::{Metrics, MetricsSnapshot};
use budu_pipeline::{PipelineMetrics, Reloadable};
use http::{Method, Request, Response, StatusCode};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

use crate::{full_body, RespBody};

/// Serve the admin endpoints until `cancel` fires.
pub async fn serve_admin(
    listen: SocketAddr,
    metrics: Arc<Metrics>,
    reloadable: Reloadable,
    cancel: CancellationToken,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(listen).await?;
    tracing::info!(%listen, "admin endpoint listening (/metrics, /healthz)");

    loop {
        let (stream, _peer) = tokio::select! {
            biased;
            _ = cancel.cancelled() => {
                tracing::debug!("admin: shutting down");
                return Ok(());
            }
            accepted = listener.accept() => match accepted {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(error = %e, "admin accept failed");
                    continue;
                }
            },
        };

        let io = TokioIo::new(stream);
        let metrics = metrics.clone();
        let reloadable = reloadable.clone();
        tokio::spawn(async move {
            let service = service_fn(move |req| {
                let metrics = metrics.clone();
                let reloadable = reloadable.clone();
                async move { Ok::<_, Infallible>(route(req, &metrics, &reloadable)) }
            });
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, service)
                .await;
        });
    }
}

fn route(req: Request<Incoming>, metrics: &Metrics, reloadable: &Reloadable) -> Response<RespBody> {
    match (req.method(), req.uri().path()) {
        (&Method::GET, "/metrics") => {
            let body = render(metrics.snapshot(), reloadable.metrics());
            text(StatusCode::OK, body, "text/plain; version=0.0.4")
        }
        (&Method::GET, "/healthz") => text(StatusCode::OK, "ok\n".to_string(), "text/plain"),
        _ => text(StatusCode::NOT_FOUND, "not found\n".to_string(), "text/plain"),
    }
}

fn text(status: StatusCode, body: String, content_type: &'static str) -> Response<RespBody> {
    let mut resp = Response::new(full_body(body.into()));
    *resp.status_mut() = status;
    resp.headers_mut().insert(
        http::header::CONTENT_TYPE,
        http::HeaderValue::from_static(content_type),
    );
    resp
}

/// Prometheus exposition format.
fn render(m: MetricsSnapshot, p: PipelineMetrics) -> String {
    format!(
        "# HELP budu_requests_total Total requests seen by B.U.D.U\n\
         # TYPE budu_requests_total counter\n\
         budu_requests_total {requests}\n\
         # TYPE budu_allowed_total counter\n\
         budu_allowed_total {allowed}\n\
         # TYPE budu_blocked_total counter\n\
         budu_blocked_total {blocked}\n\
         # TYPE budu_ratelimited_total counter\n\
         budu_ratelimited_total {ratelimited}\n\
         # TYPE budu_upstream_errors_total counter\n\
         budu_upstream_errors_total {upstream_errors}\n\
         # TYPE budu_would_block_total counter\n\
         budu_would_block_total {would_block}\n\
         # TYPE budu_whitelisted_total counter\n\
         budu_whitelisted_total {whitelisted}\n\
         # TYPE budu_signatures gauge\n\
         budu_signatures {signatures}\n\
         # TYPE budu_rules gauge\n\
         budu_rules {rules}\n\
         # TYPE budu_rule_log_matches_total counter\n\
         budu_rule_log_matches_total {rule_log_matches}\n\
         # TYPE budu_blocklist_entries gauge\n\
         budu_blocklist_entries {blocklist}\n\
         # TYPE budu_allowlist_entries gauge\n\
         budu_allowlist_entries {allowlist}\n\
         # TYPE budu_rate_buckets gauge\n\
         budu_rate_buckets {rate_buckets}\n\
         # TYPE budu_counters gauge\n\
         budu_counters {counters}\n",
        requests = m.requests,
        allowed = m.allowed,
        blocked = m.blocked,
        ratelimited = m.ratelimited,
        upstream_errors = m.upstream_errors,
        would_block = m.would_block,
        whitelisted = m.whitelisted,
        signatures = p.signatures,
        rules = p.rules,
        rule_log_matches = p.rule_log_matches,
        blocklist = p.blocklist,
        allowlist = p.allowlist,
        rate_buckets = p.rate_buckets,
        counters = p.counters,
    )
}
