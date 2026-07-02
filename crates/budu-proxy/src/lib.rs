//! The proxy core: a hyper HTTP/1 server that runs the WAF pipeline and (on
//! `Allow`) forwards to the upstream backend.
//!
//! Flow per request: resolve client IP → run the early pipeline on the head →
//! body-gate (buffer the body only for inspectable {POST,PUT,PATCH}) → run the
//! late pipeline (signatures) → forward. `Block`/`RateLimited` are answered
//! locally; the backend never sees them (§8).

use std::convert::Infallible;
use std::net::IpAddr;
use std::sync::Arc;

use arc_swap::ArcSwap;
use budu_common::{
    BodyState, ClientInfo, Metrics, NormalizedCache, RequestCtx, ResponseCtx, WafDecision,
};
use budu_config::{Config, Enforcement};
use budu_pipeline::Pipeline;
use bytes::Bytes;
use tokio_util::sync::CancellationToken;
use http::header::{self, HeaderName};
use http::request::Parts;
use http::{HeaderMap, HeaderValue, Method, Request, Response, StatusCode, Uri};
use http_body_util::{combinators::BoxBody, BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::TcpListener;
use tracing::Instrument;

mod admin;
mod reqid;
pub use admin::serve_admin;

/// Unified body type for both directions: an upstream/incoming stream or a
/// locally-buffered full body, erased behind one boxed type.
type RespBody = BoxBody<Bytes, Box<dyn std::error::Error + Send + Sync>>;

type UpstreamClient = Client<HttpConnector, RespBody>;

/// Shared, cheaply-cloneable proxy handle. Config is read through an `ArcSwap`
/// so a SIGHUP reload (upstream, limits, inspect types) takes effect on the
/// next request with a lock-free load.
#[derive(Clone)]
struct Proxy {
    config: Arc<ArcSwap<Config>>,
    client: UpstreamClient,
    pipeline: Arc<Pipeline>,
    metrics: Arc<Metrics>,
}

/// Bind the listen socket and serve until `cancel` fires (graceful shutdown).
/// The listen address is read once at bind time; everything else is read live.
pub async fn run(
    config: Arc<ArcSwap<Config>>,
    pipeline: Arc<Pipeline>,
    metrics: Arc<Metrics>,
    cancel: CancellationToken,
) -> anyhow::Result<()> {
    let snapshot = config.load();
    let listen = snapshot.server.listen;
    if snapshot.inspect.content_types.is_empty() {
        tracing::warn!(
            "inspect.content_types is empty: request bodies will NOT be scanned \
             (only the URL/query is inspected)"
        );
    }
    drop(snapshot);

    let listener = TcpListener::bind(listen).await?;
    tracing::info!(
        %listen,
        upstream = %config.load().server.upstream,
        stages = pipeline.len(),
        "B.U.D.U proxy listening"
    );

    let client: UpstreamClient = Client::builder(TokioExecutor::new())
        .pool_idle_timeout(std::time::Duration::from_secs(30))
        .build_http();
    let proxy = Proxy {
        config,
        client,
        pipeline,
        metrics,
    };

    loop {
        let (stream, peer) = tokio::select! {
            biased;
            _ = cancel.cancelled() => {
                tracing::info!("shutdown: no longer accepting connections");
                return Ok(());
            }
            accepted = listener.accept() => match accepted {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(error = %e, "accept failed");
                    continue;
                }
            },
        };
        let io = TokioIo::new(stream);
        let proxy = proxy.clone();
        let peer_ip = peer.ip();

        tokio::spawn(async move {
            let service = service_fn(move |req| {
                let proxy = proxy.clone();
                async move { Ok::<_, Infallible>(proxy.handle(req, peer_ip).await) }
            });
            if let Err(e) = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, service)
                .await
            {
                tracing::debug!(error = %e, "connection closed with error");
            }
        });
    }
}

impl Proxy {
    /// Assign/resolve the request id, run the request inside a `request` span
    /// (so the id tags *every* log line emitted while handling it — pipeline,
    /// forward, upstream warnings), then echo the id on the response.
    async fn handle(&self, req: Request<Incoming>, peer_ip: IpAddr) -> Response<RespBody> {
        // One lock-free config snapshot for the whole request.
        let cfg = self.config.load_full();
        let id = reqid::resolve(req.headers(), &cfg.server.request_id_header);
        // ERROR level so the span is *recorded* regardless of `BUDU_LOG` (a span
        // emits no line itself — the level only gates whether its fields are
        // captured, and we want `request_id` on events up to and including error).
        let span = tracing::error_span!("request", request_id = %id);
        let mut resp = self
            .handle_inner(req, peer_ip, cfg.clone(), id.clone())
            .instrument(span)
            .await;
        set_request_id(resp.headers_mut(), &cfg.server.request_id_header, &id);
        resp
    }

    async fn handle_inner(
        &self,
        req: Request<Incoming>,
        peer_ip: IpAddr,
        cfg: Arc<Config>,
        id: Arc<str>,
    ) -> Response<RespBody> {
        self.metrics.request();
        let client = resolve_client(&cfg, &req, peer_ip);
        let (mut parts, incoming) = req.into_parts();
        let method = parts.method.clone();
        let path_for_log = parts.uri.path().to_string();
        tracing::debug!(request_id = %id, client_ip = %client.ip, method = %method, path = %path_for_log, "request");

        // Trusted-IP allowlist: a matching client fully bypasses the pipeline —
        // no blocking, no detection, no rate-limit, request *and* response
        // phases — and is forwarded straight upstream.
        if self.pipeline.is_whitelisted(&client.ip) {
            self.metrics.whitelisted();
            self.metrics.record(&WafDecision::Allow);
            tracing::debug!(request_id = %id, client_ip = %client.ip, "allowlisted; bypassing inspection");
            set_request_id(&mut parts.headers, &cfg.server.request_id_header, &id);
            return match self.forward(parts, stream_body(incoming), cfg.clone(), None).await {
                Ok(resp) => resp,
                Err(e) => self.on_forward_error(e, &client.ip),
            };
        }

        let max_body = cfg.limits.max_inspect_body.bytes() as usize;
        let detect = cfg.server.enforcement == Enforcement::Detect;
        let mut ctx = RequestCtx {
            method: &parts.method,
            path: parts.uri.path(),
            query: parts.uri.query(),
            headers: &parts.headers,
            client,
            body: BodyState::NotBuffered,
            normalized: NormalizedCache::default(),
        };

        // 1) Early stages on the head alone.
        if let Some(resp) =
            self.act_on(self.pipeline.evaluate_early(&mut ctx), detect, &client.ip, &method, &path_for_log, &id)
        {
            return resp;
        }

        // 2) Body-gate: buffer the body only when worth inspecting. The body-size
        //    limit is a resource control — enforced even in detect mode.
        let mut buffered_len: Option<usize> = None;
        let out_body: RespBody = if should_inspect_body(&parts, &cfg) {
            if declared_too_large(&parts, max_body) {
                return self
                    .act_on(body_too_large(), false, &client.ip, &method, &path_for_log, &id)
                    .expect("body-too-large is always enforced");
            }
            match Limited::new(incoming, max_body).collect().await {
                Ok(collected) => {
                    let bytes = collected.to_bytes();
                    buffered_len = Some(bytes.len());
                    ctx.body = BodyState::Buffered(bytes.clone());
                    full_body(bytes)
                }
                Err(_) => {
                    // Over the inspection limit (or a read error): can't inspect
                    // what we won't buffer — fail closed.
                    return self
                        .act_on(body_too_large(), false, &client.ip, &method, &path_for_log, &id)
                        .expect("body-too-large is always enforced");
                }
            }
        } else {
            stream_body(incoming)
        };

        // 3) Late stages (signatures + custom rules) with the body available.
        if let Some(resp) =
            self.act_on(self.pipeline.evaluate_late(&mut ctx), detect, &client.ip, &method, &path_for_log, &id)
        {
            return resp;
        }

        // ctx is no longer used past here, releasing its borrow of `parts`.
        drop(ctx);
        self.metrics.record(&WafDecision::Allow);
        set_request_id(&mut parts.headers, &cfg.server.request_id_header, &id);

        // 4) Allowed → forward to upstream.
        match self.forward(parts, out_body, cfg.clone(), buffered_len).await {
            // 5) Response phase: run response rules (status/headers always;
            //    the body too when a rule needs it and it fits the limits).
            Ok(resp) => {
                self.inspect_response(resp, client, detect, method, path_for_log, cfg.clone(), id)
                    .await
            }
            // No app to fall through to from an inline gate; on_error governs
            // *inspection*, not upstream reachability.
            Err(e) => self.on_forward_error(e, &client.ip),
        }
    }

    /// Map an upstream forward failure to the client-facing error response.
    fn on_forward_error(&self, err: ForwardError, ip: &IpAddr) -> Response<RespBody> {
        self.metrics.upstream_error();
        match err {
            ForwardError::Timeout => {
                tracing::warn!(client_ip = %ip, "upstream timed out");
                error_response(StatusCode::GATEWAY_TIMEOUT, "upstream timeout")
            }
            ForwardError::Upstream(e) => {
                tracing::warn!(error = %e, client_ip = %ip, "upstream forward failed");
                error_response(StatusCode::BAD_GATEWAY, "upstream unavailable")
            }
        }
    }

    /// Apply a pipeline decision, honoring detection-only mode. Returns
    /// `Some(response)` to short-circuit, or `None` to keep processing (which
    /// happens for `Allow`, and for a `Block` that is downgraded to "detect").
    /// `RateLimited` and (resource-limit) blocks always short-circuit.
    fn act_on(
        &self,
        decision: WafDecision,
        detect: bool,
        ip: &IpAddr,
        method: &Method,
        path: &str,
        id: &str,
    ) -> Option<Response<RespBody>> {
        match decision {
            WafDecision::Allow => None,
            WafDecision::Block { .. } if detect => {
                // Would have blocked; in detect mode we forward and just record.
                self.metrics.would_block();
                audit_decision(ip, method, path, &decision, false, id);
                None
            }
            // Enforced block, or any rate-limit (a capacity control kept in both
            // modes): answer the client now.
            _ => {
                self.metrics.record(&decision);
                audit_decision(ip, method, path, &decision, true, id);
                Some(decision_response(decision))
            }
        }
    }

    /// Run response-phase rules over the upstream reply and produce the
    /// client-facing response.
    ///
    /// Fast path (the default): only status/header rules exist, so nothing is
    /// buffered — evaluate on the head and stream the body straight back.
    ///
    /// Body path: when a `resp_body` rule is configured *and* the response is an
    /// inspectable Content-Type within `max_inspect_body`, buffer the body,
    /// evaluate, then either replace the reply (enforced block) or re-emit the
    /// buffered bytes. Oversized inspectable bodies are streamed unbuffered
    /// (status/header rules still apply) so large downloads are never held in
    /// memory; a body that overruns the cap mid-stream fails closed (`502`).
    // Distinct per-request inputs (decision context + correlation id); grouping
    // them into a struct would only move the plumbing around.
    #[allow(clippy::too_many_arguments)]
    async fn inspect_response(
        &self,
        resp: Response<RespBody>,
        client: ClientInfo,
        detect: bool,
        method: Method,
        path: String,
        cfg: Arc<Config>,
        id: Arc<str>,
    ) -> Response<RespBody> {
        let max_body = cfg.limits.max_inspect_body.bytes() as usize;
        let buffer = self.pipeline.needs_response_body()
            && response_body_inspectable(resp.headers(), &cfg)
            && !declared_len_over(resp.headers(), max_body);

        if !buffer {
            // No body needed (or not worth buffering): evaluate on status+headers.
            let decision = self.pipeline.evaluate_response(&ResponseCtx {
                status: resp.status(),
                headers: resp.headers(),
                client,
                path: &path,
                body: BodyState::NotBuffered,
            });
            return match self.act_on(decision, detect, &client.ip, &method, &path, &id) {
                Some(blocked) => blocked,
                None => resp,
            };
        }

        // Buffer the body (bounded), then evaluate with it available. We pull
        // frames manually with a running cap rather than `Limited`, so the
        // already-boxed body error needs no lossy reboxing.
        let (parts, mut body) = resp.into_parts();
        let mut buf: Vec<u8> = Vec::new();
        loop {
            match body.frame().await {
                Some(Ok(frame)) => {
                    if let Ok(chunk) = frame.into_data() {
                        if buf.len() + chunk.len() > max_body {
                            // Overran the cap after we committed to buffering:
                            // the stream is partly consumed and can't be
                            // re-emitted. Fail closed (resource control).
                            self.metrics.upstream_error();
                            tracing::warn!(client_ip = %client.ip, "response body exceeds inspection limit");
                            return error_response(
                                StatusCode::BAD_GATEWAY,
                                "response too large to inspect",
                            );
                        }
                        buf.extend_from_slice(&chunk);
                    }
                }
                Some(Err(e)) => {
                    self.metrics.upstream_error();
                    tracing::warn!(error = %e, client_ip = %client.ip, "reading upstream response body failed");
                    return error_response(StatusCode::BAD_GATEWAY, "upstream read error");
                }
                None => break,
            }
        }
        let bytes = Bytes::from(buf);

        let decision = self.pipeline.evaluate_response(&ResponseCtx {
            status: parts.status,
            headers: &parts.headers,
            client,
            path: &path,
            body: BodyState::Buffered(bytes.clone()),
        });
        if let Some(blocked) = self.act_on(decision, detect, &client.ip, &method, &path, &id) {
            return blocked; // enforced response block replaces the upstream reply
        }

        // Allowed (or detect-downgraded): re-emit the buffered body with framing
        // pinned to the exact buffered length.
        let len = bytes.len();
        let mut out = Response::from_parts(parts, full_body(bytes));
        out.headers_mut().remove(header::TRANSFER_ENCODING);
        out.headers_mut().remove(header::CONTENT_LENGTH);
        out.headers_mut()
            .insert(header::CONTENT_LENGTH, HeaderValue::from(len as u64));
        out
    }

    /// Rewrite the request to target the upstream authority and forward it.
    /// The body is streamed back unless [`inspect_response`](Self::inspect_response)
    /// later buffers it for a `resp_body` rule. Bounded by `upstream_timeout_secs`.
    async fn forward(
        &self,
        mut parts: Parts,
        body: RespBody,
        cfg: Arc<Config>,
        buffered_len: Option<usize>,
    ) -> Result<Response<RespBody>, ForwardError> {
        parts.uri = rewrite_uri(&cfg.server.upstream, &parts.uri)
            .map_err(ForwardError::Upstream)?;
        sanitize_forward_headers(&mut parts.headers, buffered_len);
        let out = Request::from_parts(parts, body);

        let timeout = std::time::Duration::from_secs(cfg.server.upstream_timeout_secs);
        let resp = match tokio::time::timeout(timeout, self.client.request(out)).await {
            Err(_elapsed) => return Err(ForwardError::Timeout),
            Ok(Err(e)) => return Err(ForwardError::Upstream(anyhow::anyhow!("upstream request: {e}"))),
            Ok(Ok(resp)) => resp,
        };

        // Stream the body straight back; map its error into our boxed type.
        Ok(resp.map(|b| b.map_err(box_err).boxed()))
    }
}

/// Why a forward attempt failed, so the caller can answer 504 vs 502.
enum ForwardError {
    Timeout,
    Upstream(anyhow::Error),
}

/// Body-gate (§8 step 6): buffer the body only for {POST,PUT,PATCH} with an
/// inspectable Content-Type. An empty `inspect.content_types` means "inspect no
/// bodies" — bodies stream straight through untouched.
fn should_inspect_body(parts: &Parts, cfg: &Config) -> bool {
    if !matches!(parts.method, Method::POST | Method::PUT | Method::PATCH) {
        return false;
    }
    let ct = match parts.headers.get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()) {
        Some(v) => v.to_ascii_lowercase(),
        None => return false,
    };
    // Match on the media type prefix (ignore `; charset=`/`; boundary=`).
    cfg.inspect
        .content_types
        .iter()
        .any(|t| ct.starts_with(&t.to_ascii_lowercase()))
}

/// Cheap pre-check: reject a body whose declared Content-Length already exceeds
/// the inspection cap before reading a single byte.
fn declared_too_large(parts: &Parts, max: usize) -> bool {
    declared_len_over(&parts.headers, max)
}

/// Does a `Content-Length` header declare more than `max` bytes? Used to skip
/// buffering on both the request and response sides.
fn declared_len_over(headers: &HeaderMap, max: usize) -> bool {
    headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<u64>().ok())
        .is_some_and(|len| len > max as u64)
}

/// Is the upstream response an inspectable Content-Type (per
/// `inspect.response_content_types`)? Matches on the media-type prefix so
/// `text/html; charset=utf-8` matches `text/html`.
fn response_body_inspectable(headers: &HeaderMap, cfg: &Config) -> bool {
    let ct = match headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
    {
        Some(v) => v.to_ascii_lowercase(),
        None => return false,
    };
    cfg.inspect
        .response_content_types
        .iter()
        .any(|t| ct.starts_with(&t.to_ascii_lowercase()))
}

fn body_too_large() -> WafDecision {
    WafDecision::Block {
        rule_id: Arc::from("bodygate.too_large"),
        status: StatusCode::PAYLOAD_TOO_LARGE,
        reason: Arc::from("request body exceeds inspection limit"),
    }
}

fn full_body(bytes: Bytes) -> RespBody {
    Full::new(bytes).map_err(|e: Infallible| match e {}).boxed()
}

fn stream_body(incoming: Incoming) -> RespBody {
    incoming.map_err(box_err).boxed()
}

/// Resolve the true client IP. Trust the configured `client_ip_header` only
/// when the immediate peer is the trusted proxy (front Apache); otherwise fall
/// back to the socket peer so a header can't be spoofed by a direct connector.
fn resolve_client(cfg: &Config, req: &Request<Incoming>, peer_ip: IpAddr) -> ClientInfo {
    let trusted = cfg.server.trusted_peer.contains(&peer_ip);
    let ip = if trusted {
        req.headers()
            .get(&cfg.server.client_ip_header)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.split(',').next())
            .and_then(|s| s.trim().parse::<IpAddr>().ok())
            .unwrap_or(peer_ip)
    } else {
        tracing::warn!(%peer_ip, "request from untrusted peer; ignoring client IP header");
        peer_ip
    };
    ClientInfo { ip, geo: None }
}

/// RFC 7230 §6.1 hop-by-hop headers — must not be forwarded by a proxy.
const HOP_BY_HOP: [&str; 8] = [
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Strip headers that must not cross the proxy before forwarding upstream:
/// the fixed hop-by-hop set and any header named in `Connection`. When we
/// buffered the body into a fixed-length `Full` (`buffered_len = Some(n)`), pin
/// `Content-Length` to the exact buffered size so framing is unambiguous. This
/// closes request-smuggling gaps from stale `Transfer-Encoding`/`Content-Length`
/// on a rewritten body.
fn sanitize_forward_headers(headers: &mut HeaderMap, buffered_len: Option<usize>) {
    // Headers listed in `Connection` are themselves hop-by-hop.
    let listed: Vec<String> = headers
        .get(header::CONNECTION)
        .and_then(|v| v.to_str().ok())
        .map(|v| {
            v.split(',')
                .map(|s| s.trim().to_ascii_lowercase())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default();
    for name in listed {
        headers.remove(name.as_str());
    }
    for name in HOP_BY_HOP {
        headers.remove(name);
    }
    if let Some(len) = buffered_len {
        // Body was replaced by a fixed-length copy: pin the exact length.
        headers.remove(header::CONTENT_LENGTH);
        headers.insert(header::CONTENT_LENGTH, HeaderValue::from(len as u64));
    }
}

/// Build the upstream-facing URI: upstream scheme+authority + original
/// path-and-query. Host header is left untouched (ProxyPreserveHost On).
fn rewrite_uri(upstream: &Uri, orig: &Uri) -> anyhow::Result<Uri> {
    let mut builder = Uri::builder();
    if let Some(scheme) = upstream.scheme() {
        builder = builder.scheme(scheme.clone());
    }
    let authority = upstream
        .authority()
        .ok_or_else(|| anyhow::anyhow!("upstream has no authority"))?;
    builder = builder.authority(authority.clone());
    let pq = orig
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or("/");
    builder
        .path_and_query(pq)
        .build()
        .map_err(|e| anyhow::anyhow!("building upstream uri: {e}"))
}

fn box_err<E>(e: E) -> Box<dyn std::error::Error + Send + Sync>
where
    E: std::error::Error + Send + Sync + 'static,
{
    Box::new(e)
}

/// A locally-served response (blocks, rate-limits, errors).
pub fn error_response(status: StatusCode, msg: &str) -> Response<RespBody> {
    let body = Full::new(Bytes::from(format!("{msg}\n")))
        .map_err(|e: Infallible| match e {})
        .boxed();
    let mut resp = Response::new(body);
    *resp.status_mut() = status;
    resp.headers_mut().insert(
        HeaderName::from_static("content-type"),
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    resp
}

/// Turn a non-`Allow` [`WafDecision`] into the client-facing response.
fn decision_response(decision: WafDecision) -> Response<RespBody> {
    match decision {
        WafDecision::Block { status, reason, .. } => error_response(status, &reason),
        WafDecision::RateLimited { retry_after_secs } => {
            let mut resp = error_response(StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded");
            if let Ok(v) = HeaderValue::from_str(&retry_after_secs.to_string()) {
                resp.headers_mut()
                    .insert(HeaderName::from_static("retry-after"), v);
            }
            resp
        }
        // handle() never routes Allow here; be total just in case.
        WafDecision::Allow => error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
    }
}

/// Emit a structured audit record for a blocked/limited request (§8 step 9), to
/// the `audit` tracing target. `enforced = false` means detection-only mode:
/// the request was forwarded and this is what *would* have happened.
fn audit_decision(
    ip: &IpAddr,
    method: &Method,
    path: &str,
    decision: &WafDecision,
    enforced: bool,
    request_id: &str,
) {
    match decision {
        WafDecision::Block {
            rule_id,
            status,
            reason,
        } => {
            tracing::warn!(
                target: "audit",
                request_id,
                client_ip = %ip,
                method = %method,
                path,
                rule_id = %rule_id,
                status = status.as_u16(),
                reason = %reason,
                enforced,
                "{}", if enforced { "blocked" } else { "detected" }
            );
        }
        WafDecision::RateLimited { retry_after_secs } => {
            tracing::warn!(
                target: "audit",
                request_id,
                client_ip = %ip,
                method = %method,
                path,
                rule_id = "ratelimit",
                status = 429,
                retry_after_secs,
                enforced,
                "rate_limited"
            );
        }
        WafDecision::Allow => {}
    }
}

/// Set the request-id header on a header map (response or upstream request), if
/// the header name is configured and both name+value are valid.
fn set_request_id(headers: &mut HeaderMap, header_name: &str, id: &str) {
    if header_name.is_empty() {
        return;
    }
    if let (Ok(name), Ok(value)) = (
        HeaderName::from_bytes(header_name.as_bytes()),
        HeaderValue::from_str(id),
    ) {
        headers.insert(name, value);
    }
}
