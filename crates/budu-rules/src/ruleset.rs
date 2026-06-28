//! Rule model, compilation and evaluation.

use std::borrow::Cow;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use budu_common::{BodyState, RequestCtx, ResponseCtx};
use http::StatusCode;
use ipnet::IpNet;
use regex::Regex;
use serde::Deserialize;

#[derive(Debug, thiserror::Error)]
pub enum RuleError {
    #[error("reading rules: {0}")]
    Read(String),
    #[error("parsing rules: {0}")]
    Parse(String),
    #[error("rule '{rule}': {msg}")]
    Invalid { rule: String, msg: String },
}

// ── TOML model ─────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct RuleFile {
    #[serde(default)]
    rule: Vec<RuleDef>,
}

#[derive(Deserialize)]
struct RuleDef {
    id: String,
    #[serde(default)]
    phase: PhaseKind,
    #[serde(default)]
    action: ActionKind,
    #[serde(default = "default_status")]
    status: u16,
    #[serde(default)]
    msg: String,
    // rate_limit action params
    #[serde(default)]
    rps: u32,
    #[serde(default)]
    burst: u32,
    #[serde(default = "default_rl_ttl")]
    ttl_secs: u64,
    // score action: points contributed when matched
    #[serde(default)]
    score: u32,
    // incr action: counter to bump, by `incr` (default 1), kept for `ttl_secs`
    #[serde(default)]
    counter: String,
    #[serde(default = "default_incr")]
    incr: u64,
    #[serde(default)]
    when: Vec<CondDef>,
}

fn default_incr() -> u64 {
    1
}

fn default_status() -> u16 {
    403
}

fn default_rl_ttl() -> u64 {
    300
}

#[derive(Deserialize, Default, Clone, Copy, PartialEq)]
#[serde(rename_all = "lowercase")]
enum PhaseKind {
    #[default]
    Request,
    Response,
}

#[derive(Deserialize, Default, Clone, Copy)]
#[serde(rename_all = "snake_case")]
enum ActionKind {
    #[default]
    Block,
    Allow,
    Log,
    RateLimit,
    Score,
    Incr,
}

#[derive(Deserialize)]
struct CondDef {
    field: String,
    /// Header name (only used when `field = "header"`).
    #[serde(default)]
    name: String,
    op: String,
    #[serde(default)]
    value: String,
    /// Value list for `op = "in"`.
    #[serde(default)]
    values: Vec<String>,
    /// Invert the match result.
    #[serde(default)]
    negate: bool,
    /// Transforms applied to the field value before matching, in order
    /// (e.g. `["url_decode", "lowercase"]`).
    #[serde(default)]
    transform: Vec<String>,
    /// Timezone offset for `op = "time_between"`, e.g. `"+08:00"` (default UTC).
    #[serde(default)]
    tz: String,
}

// ── Compiled form ──────────────────────────────────────────────────────────

enum Field {
    Method,
    Path,
    Query,
    Uri,
    Header(String),
    Body,
    Ip,
    Country,
    /// Response status code (response phase only). Scalar, numeric.
    Status,
    /// A response header value by name (response phase only).
    RespHeader(String),
    /// The (buffered) response body (response phase only). Empty when the body
    /// was streamed unbuffered (too large / non-inspectable type).
    RespBody,
    /// Current value of a per-client-IP stateful counter (by name). Scalar,
    /// numeric — 0 when unset/expired.
    Counter(String),
    /// A specific query/form parameter value (by name). Multi-valued.
    Arg(String),
    /// The set of query/form parameter names. Multi-valued.
    ArgNames,
    /// Number of query/form parameters (scalar, numeric).
    ArgsCount,
    /// A specific cookie value (by name). Multi-valued.
    Cookie(String),
    /// The set of cookie names. Multi-valued.
    CookieNames,
    /// All request parameter **values** (query + body). Multi-valued.
    Args,
    /// All request header **values**. Multi-valued.
    Headers,
    /// All request header **names**. Multi-valued.
    HeaderNames,
    /// All cookie **values**. Multi-valued.
    Cookies,
    /// Current wall-clock time of day (request phase). Use with
    /// `op = "time_between"` for business-hours / maintenance-window rules.
    Time,
    /// Current day of week (request phase). Use with `op = "day_of_week"`.
    Day,
}

enum Op {
    Eq(String),
    Ne(String),
    Contains(String),
    StartsWith(String),
    EndsWith(String),
    Regex(Regex),
    Cidr(IpNet),
    In(Vec<String>),
    // numeric comparisons (field parsed as i64)
    Gt(i64),
    Lt(i64),
    Ge(i64),
    Le(i64),
    // libinjection (feature "libinjection"); value ignored
    #[cfg(feature = "libinjection")]
    DetectSqli,
    #[cfg(feature = "libinjection")]
    DetectXss,
    /// Local time-of-day within `[start, end]` (minutes since midnight); an
    /// `start > end` window wraps past midnight. `offset_min` shifts UTC to the
    /// rule's timezone.
    TimeBetween { start: u16, end: u16, offset_min: i16 },
    /// Current local day-of-week is in `mask` (bit 0 = Sunday … bit 6 = Saturday).
    /// `offset_min` shifts UTC to the rule's timezone (can change the day).
    DayOfWeek { mask: u8, offset_min: i16 },
}

#[derive(Clone, Copy)]
enum Transform {
    Lowercase,
    Uppercase,
    UrlDecode,
    CompressWs,
    RemoveNulls,
    Trim,
}

struct CompiledCond {
    field: Field,
    op: Op,
    negate: bool,
    transforms: Vec<Transform>,
}

enum Action {
    Block { status: StatusCode, msg: Arc<str> },
    Allow,
    Log,
    RateLimit(budu_ratelimit::IpRateLimiter),
    Score(u32),
    Incr {
        counter: Arc<str>,
        amount: u64,
        window_secs: u64,
    },
}

struct CompiledRule {
    id: Arc<str>,
    action: Action,
    conds: Vec<CompiledCond>,
}

/// A compiled, immutable set of custom rules (held behind `ArcSwap` for reload).
pub struct RuleSet {
    /// Request-phase rules (run during inspection, before forwarding).
    rules: Vec<CompiledRule>,
    /// Response-phase rules (run after the upstream responds).
    response_rules: Vec<CompiledRule>,
    /// CRS-style anomaly scoring (0 = disabled).
    threshold: u32,
    anomaly_status: StatusCode,
    anomaly_msg: Arc<str>,
}

/// Result of evaluating the rule set against a request.
pub enum Outcome {
    /// A `block` rule fired.
    Block {
        rule_id: Arc<str>,
        status: StatusCode,
        reason: Arc<str>,
    },
    /// An `allow` rule fired: bypass remaining inspection.
    Allow { rule_id: Arc<str> },
    /// A `rate_limit` rule fired and the client is over its budget.
    RateLimited {
        rule_id: Arc<str>,
        retry_after_secs: u32,
    },
}

impl RuleSet {
    pub fn empty() -> Self {
        Self {
            rules: Vec::new(),
            response_rules: Vec::new(),
            threshold: 0,
            anomaly_status: StatusCode::FORBIDDEN,
            anomaly_msg: Arc::from("anomaly score threshold exceeded"),
        }
    }

    /// Load from a TOML file; an empty path yields an empty (no-op) set. The
    /// `scoring` config supplies the anomaly threshold / response; `default_tz`
    /// is the server-wide timezone offset (minutes) applied to `time_between`
    /// rules that don't set their own `tz`.
    pub fn load(
        path: &str,
        scoring: &budu_config::ScoringConfig,
        default_tz: i16,
    ) -> Result<Self, RuleError> {
        if path.trim().is_empty() {
            let mut rs = Self::empty();
            rs.apply_scoring(scoring)?;
            return Ok(rs);
        }
        let text =
            std::fs::read_to_string(path).map_err(|e| RuleError::Read(format!("{path}: {e}")))?;
        let file: RuleFile =
            toml::from_str(&text).map_err(|e| RuleError::Parse(e.to_string()))?;
        Self::compile_with_tz(file.rule, scoring, default_tz)
    }

    fn apply_scoring(&mut self, scoring: &budu_config::ScoringConfig) -> Result<(), RuleError> {
        self.threshold = scoring.threshold;
        self.anomaly_status =
            StatusCode::from_u16(scoring.status).map_err(|_| RuleError::Invalid {
                rule: "[scoring]".into(),
                msg: format!("bad status {}", scoring.status),
            })?;
        self.anomaly_msg = Arc::from(scoring.msg.as_str());
        Ok(())
    }

    /// Compile rules with the default (UTC) timezone for `time_between`. Used by
    /// tests; the runtime path goes through [`load`](Self::load).
    #[cfg(test)]
    fn compile(defs: Vec<RuleDef>, scoring: &budu_config::ScoringConfig) -> Result<Self, RuleError> {
        Self::compile_with_tz(defs, scoring, 0)
    }

    fn compile_with_tz(
        defs: Vec<RuleDef>,
        scoring: &budu_config::ScoringConfig,
        default_tz: i16,
    ) -> Result<Self, RuleError> {
        let mut rules = Vec::new();
        let mut response_rules = Vec::new();
        for def in defs {
            let conds = def
                .when
                .iter()
                .map(|c| compile_cond(&def.id, c, default_tz))
                .collect::<Result<Vec<_>, _>>()?;
            if conds.is_empty() {
                return Err(RuleError::Invalid {
                    rule: def.id.clone(),
                    msg: "needs at least one `when` condition".into(),
                });
            }
            // Phase / field / action compatibility.
            for cond in &conds {
                let resp_field =
                    matches!(cond.field, Field::Status | Field::RespHeader(_) | Field::RespBody);
                match def.phase {
                    PhaseKind::Request if resp_field => {
                        return Err(RuleError::Invalid {
                            rule: def.id.clone(),
                            msg: "status/resp_header/resp_body are only valid in phase = \"response\"".into(),
                        })
                    }
                    PhaseKind::Response
                        if !matches!(
                            cond.field,
                            Field::Status
                                | Field::RespHeader(_)
                                | Field::RespBody
                                | Field::Ip
                                | Field::Path
                                | Field::Counter(_)
                        ) =>
                    {
                        return Err(RuleError::Invalid {
                            rule: def.id.clone(),
                            msg: "phase = \"response\" rules may only use status/resp_header/resp_body/ip/path/counter".into(),
                        })
                    }
                    _ => {}
                }
            }
            if def.phase == PhaseKind::Response
                && !matches!(def.action, ActionKind::Block | ActionKind::Log | ActionKind::Incr)
            {
                return Err(RuleError::Invalid {
                    rule: def.id.clone(),
                    msg: "phase = \"response\" supports only block/log/incr actions".into(),
                });
            }
            let action = match def.action {
                ActionKind::Block => Action::Block {
                    status: StatusCode::from_u16(def.status).map_err(|_| RuleError::Invalid {
                        rule: def.id.clone(),
                        msg: format!("bad status {}", def.status),
                    })?,
                    msg: Arc::from(if def.msg.is_empty() {
                        def.id.as_str()
                    } else {
                        def.msg.as_str()
                    }),
                },
                ActionKind::Allow => Action::Allow,
                ActionKind::Log => Action::Log,
                ActionKind::RateLimit => {
                    if def.rps == 0 {
                        return Err(RuleError::Invalid {
                            rule: def.id.clone(),
                            msg: "action = \"rate_limit\" requires rps > 0".into(),
                        });
                    }
                    Action::RateLimit(budu_ratelimit::IpRateLimiter::new(
                        def.rps,
                        def.burst,
                        def.ttl_secs,
                    ))
                }
                ActionKind::Score => {
                    if def.score == 0 {
                        return Err(RuleError::Invalid {
                            rule: def.id.clone(),
                            msg: "action = \"score\" requires score > 0".into(),
                        });
                    }
                    Action::Score(def.score)
                }
                ActionKind::Incr => {
                    if def.counter.trim().is_empty() {
                        return Err(RuleError::Invalid {
                            rule: def.id.clone(),
                            msg: "action = \"incr\" requires a `counter` name".into(),
                        });
                    }
                    Action::Incr {
                        counter: Arc::from(def.counter.as_str()),
                        amount: def.incr,
                        window_secs: def.ttl_secs,
                    }
                }
            };
            let compiled = CompiledRule {
                id: Arc::from(def.id.as_str()),
                action,
                conds,
            };
            match def.phase {
                PhaseKind::Request => rules.push(compiled),
                PhaseKind::Response => response_rules.push(compiled),
            }
        }
        let mut set = Self {
            rules,
            response_rules,
            threshold: 0,
            anomaly_status: StatusCode::FORBIDDEN,
            anomaly_msg: Arc::from("anomaly score threshold exceeded"),
        };
        set.apply_scoring(scoring)?;
        Ok(set)
    }

    /// Whether any response-phase rule inspects the response body. The proxy
    /// uses this to decide whether to buffer the upstream body at all — when no
    /// rule needs it, the body always streams straight through.
    pub fn needs_response_body(&self) -> bool {
        self.response_rules
            .iter()
            .any(|r| r.conds.iter().any(|c| matches!(c.field, Field::RespBody)))
    }

    /// Total compiled rules (request + response phase).
    pub fn len(&self) -> usize {
        self.rules.len() + self.response_rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty() && self.response_rules.is_empty()
    }

    /// Evaluate in order. The first `block`/`allow`/throttled `rate_limit` rule
    /// whose conditions all match wins; `log`/`score`/`incr` rules are recorded
    /// and evaluation continues. Uses a throwaway counter store (tests).
    pub fn evaluate(&self, ctx: &RequestCtx<'_>) -> Option<Outcome> {
        use std::sync::OnceLock;
        static EMPTY: OnceLock<budu_ratelimit::CounterStore> = OnceLock::new();
        let counters = EMPTY.get_or_init(budu_ratelimit::CounterStore::new);
        self.evaluate_inner(ctx, None, counters)
    }

    /// Evaluate with explicit state: `log_counter` tallies `log`-rule matches,
    /// `counters` is the persistent per-IP counter store for `incr`/`counter`.
    pub fn evaluate_counting(
        &self,
        ctx: &RequestCtx<'_>,
        log_counter: &AtomicU64,
        counters: &budu_ratelimit::CounterStore,
    ) -> Option<Outcome> {
        self.evaluate_inner(ctx, Some(log_counter), counters)
    }

    /// Evaluate with an explicit counter store (tests).
    pub fn evaluate_with_counters(
        &self,
        ctx: &RequestCtx<'_>,
        counters: &budu_ratelimit::CounterStore,
    ) -> Option<Outcome> {
        self.evaluate_inner(ctx, None, counters)
    }

    fn evaluate_inner(
        &self,
        ctx: &RequestCtx<'_>,
        log_counter: Option<&AtomicU64>,
        counters: &budu_ratelimit::CounterStore,
    ) -> Option<Outcome> {
        // CRS-style: `score` rules accumulate; explicit block/allow/ratelimit
        // still short-circuit (an `allow` thus overrides an accumulated score).
        let mut score_total: u32 = 0;
        for rule in &self.rules {
            if !rule.conds.iter().all(|c| c.matches_request(ctx, counters)) {
                continue;
            }
            match &rule.action {
                Action::Block { status, msg } => {
                    return Some(Outcome::Block {
                        rule_id: rule.id.clone(),
                        status: *status,
                        reason: msg.clone(),
                    })
                }
                Action::Allow => return Some(Outcome::Allow { rule_id: rule.id.clone() }),
                Action::Log => {
                    tracing::warn!(target: "audit", rule_id = %rule.id, "rule matched (log)");
                    if let Some(c) = log_counter {
                        c.fetch_add(1, Ordering::Relaxed);
                    }
                }
                Action::RateLimit(limiter) => {
                    // Only the matching traffic is throttled. Under budget →
                    // keep evaluating; over budget → short-circuit 429.
                    if let Err(retry_after_secs) = limiter.check(ctx.client.ip) {
                        return Some(Outcome::RateLimited {
                            rule_id: rule.id.clone(),
                            retry_after_secs,
                        });
                    }
                }
                Action::Score(points) => {
                    score_total = score_total.saturating_add(*points);
                    tracing::debug!(rule_id = %rule.id, points, score_total, "anomaly score");
                }
                Action::Incr {
                    counter,
                    amount,
                    window_secs,
                } => {
                    let v = counters.incr(counter, ctx.client.ip, *amount, *window_secs);
                    tracing::debug!(rule_id = %rule.id, counter = %counter, value = v, "counter incr");
                }
            }
        }
        if self.threshold > 0 && score_total >= self.threshold {
            return Some(Outcome::Block {
                rule_id: Arc::from("anomaly.score"),
                status: self.anomaly_status,
                reason: Arc::from(format!(
                    "{} (score {score_total} >= {})",
                    self.anomaly_msg, self.threshold
                )),
            });
        }
        None
    }

    /// Run response-phase rules against the upstream response. The first `block`
    /// wins; `log`/`incr` rules are recorded and evaluation continues.
    pub fn evaluate_response(
        &self,
        rctx: &ResponseCtx<'_>,
        log_counter: &AtomicU64,
        counters: &budu_ratelimit::CounterStore,
    ) -> Option<Outcome> {
        for rule in &self.response_rules {
            if !rule.conds.iter().all(|c| c.matches_response(rctx, counters)) {
                continue;
            }
            match &rule.action {
                Action::Block { status, msg } => {
                    return Some(Outcome::Block {
                        rule_id: rule.id.clone(),
                        status: *status,
                        reason: msg.clone(),
                    })
                }
                Action::Log => {
                    tracing::warn!(target: "audit", rule_id = %rule.id, "response rule matched (log)");
                    log_counter.fetch_add(1, Ordering::Relaxed);
                }
                Action::Incr {
                    counter,
                    amount,
                    window_secs,
                } => {
                    let v = counters.incr(counter, rctx.client.ip, *amount, *window_secs);
                    tracing::debug!(rule_id = %rule.id, counter = %counter, value = v, "counter incr (response)");
                }
                // validated out at compile for response phase
                Action::Allow | Action::RateLimit(_) | Action::Score(_) => {}
            }
        }
        None
    }
}

fn compile_cond(rule: &str, c: &CondDef, default_tz: i16) -> Result<CompiledCond, RuleError> {
    let invalid = |msg: String| RuleError::Invalid {
        rule: rule.to_string(),
        msg,
    };

    let field = match c.field.as_str() {
        "method" => Field::Method,
        "path" => Field::Path,
        "query" => Field::Query,
        "uri" => Field::Uri,
        "body" => Field::Body,
        "ip" => Field::Ip,
        "country" => Field::Country,
        "header" => {
            if c.name.trim().is_empty() {
                return Err(invalid("field = \"header\" requires `name`".into()));
            }
            Field::Header(c.name.to_ascii_lowercase())
        }
        "arg" => {
            if c.name.trim().is_empty() {
                return Err(invalid("field = \"arg\" requires `name`".into()));
            }
            Field::Arg(c.name.clone())
        }
        "counter" => {
            if c.name.trim().is_empty() {
                return Err(invalid("field = \"counter\" requires `name`".into()));
            }
            Field::Counter(c.name.clone())
        }
        "status" => Field::Status,
        "resp_header" => {
            if c.name.trim().is_empty() {
                return Err(invalid("field = \"resp_header\" requires `name`".into()));
            }
            Field::RespHeader(c.name.to_ascii_lowercase())
        }
        "resp_body" => Field::RespBody,
        "arg_names" => Field::ArgNames,
        "args_count" => Field::ArgsCount,
        "args" => Field::Args,
        "headers" => Field::Headers,
        "header_names" => Field::HeaderNames,
        "cookies" => Field::Cookies,
        "cookie" => {
            if c.name.trim().is_empty() {
                return Err(invalid("field = \"cookie\" requires `name`".into()));
            }
            Field::Cookie(c.name.clone())
        }
        "cookie_names" => Field::CookieNames,
        "time" => Field::Time,
        "day" => Field::Day,
        other => return Err(invalid(format!("unknown field {other:?}"))),
    };

    // Per-rule `tz` overrides the server default (`default_tz`); shared by the
    // time-of-day and day-of-week operators.
    let resolve_tz = || -> Result<i16, RuleError> {
        if c.tz.trim().is_empty() {
            Ok(default_tz)
        } else {
            parse_tz_offset(&c.tz)
                .ok_or_else(|| invalid(format!("bad tz {:?}; expected e.g. \"+08:00\"", c.tz)))
        }
    };

    let num = |s: &str| -> Result<i64, RuleError> {
        s.trim()
            .parse::<i64>()
            .map_err(|_| invalid(format!("op {:?} needs a numeric value, got {s:?}", c.op)))
    };

    let op = match c.op.as_str() {
        "eq" => Op::Eq(c.value.clone()),
        "ne" => Op::Ne(c.value.clone()),
        "contains" => Op::Contains(c.value.clone()),
        "starts_with" => Op::StartsWith(c.value.clone()),
        "ends_with" => Op::EndsWith(c.value.clone()),
        // unicode(false): ASCII semantics so `(?i)` works without the regex
        // crate's unicode-case feature (intentionally off workspace-wide).
        "regex" => Op::Regex(
            regex::RegexBuilder::new(&c.value)
                .unicode(false)
                .build()
                .map_err(|e| invalid(format!("bad regex: {e}")))?,
        ),
        "cidr" => {
            if !matches!(field, Field::Ip) {
                return Err(invalid("op = \"cidr\" only applies to field = \"ip\"".into()));
            }
            let net = c
                .value
                .parse::<IpNet>()
                .or_else(|_| c.value.parse::<std::net::IpAddr>().map(IpNet::from))
                .map_err(|_| invalid(format!("bad CIDR {:?}", c.value)))?;
            Op::Cidr(net)
        }
        "in" => {
            if c.values.is_empty() {
                return Err(invalid("op = \"in\" requires a non-empty `values`".into()));
            }
            Op::In(c.values.clone())
        }
        "gt" => Op::Gt(num(&c.value)?),
        "lt" => Op::Lt(num(&c.value)?),
        "ge" => Op::Ge(num(&c.value)?),
        "le" => Op::Le(num(&c.value)?),
        "time_between" => {
            if !matches!(field, Field::Time) {
                return Err(invalid(
                    "op = \"time_between\" only applies to field = \"time\"".into(),
                ));
            }
            let (start, end) = parse_time_window(&c.value).ok_or_else(|| {
                invalid(format!(
                    "bad time window {:?}; expected \"HH:MM-HH:MM\"",
                    c.value
                ))
            })?;
            Op::TimeBetween {
                start,
                end,
                offset_min: resolve_tz()?,
            }
        }
        "day_of_week" => {
            if !matches!(field, Field::Day) {
                return Err(invalid(
                    "op = \"day_of_week\" only applies to field = \"day\"".into(),
                ));
            }
            let mask = parse_day_mask(&c.value).ok_or_else(|| {
                invalid(format!(
                    "bad day spec {:?}; expected e.g. \"Mon-Fri\" or \"Sat,Sun\"",
                    c.value
                ))
            })?;
            Op::DayOfWeek {
                mask,
                offset_min: resolve_tz()?,
            }
        }
        #[cfg(feature = "libinjection")]
        "detect_sqli" => Op::DetectSqli,
        #[cfg(feature = "libinjection")]
        "detect_xss" => Op::DetectXss,
        #[cfg(not(feature = "libinjection"))]
        bad @ ("detect_sqli" | "detect_xss") => {
            return Err(invalid(format!(
                "op {bad:?} requires the `libinjection` build feature"
            )))
        }
        other => return Err(invalid(format!("unknown op {other:?}"))),
    };

    match field {
        Field::Time if !matches!(op, Op::TimeBetween { .. }) => {
            return Err(invalid(
                "field = \"time\" only supports op = \"time_between\"".into(),
            ))
        }
        Field::Day if !matches!(op, Op::DayOfWeek { .. }) => {
            return Err(invalid(
                "field = \"day\" only supports op = \"day_of_week\"".into(),
            ))
        }
        _ => {}
    }

    let transforms = c
        .transform
        .iter()
        .map(|t| compile_transform(rule, t))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(CompiledCond {
        field,
        op,
        negate: c.negate,
        transforms,
    })
}

fn compile_transform(rule: &str, t: &str) -> Result<Transform, RuleError> {
    Ok(match t {
        "lowercase" => Transform::Lowercase,
        "uppercase" => Transform::Uppercase,
        "url_decode" => Transform::UrlDecode,
        "compress_ws" => Transform::CompressWs,
        "remove_nulls" => Transform::RemoveNulls,
        "trim" => Transform::Trim,
        other => {
            return Err(RuleError::Invalid {
                rule: rule.to_string(),
                msg: format!("unknown transform {other:?}"),
            })
        }
    })
}

fn apply_transform(t: Transform, s: &str) -> String {
    match t {
        Transform::Lowercase => s.to_ascii_lowercase(),
        Transform::Uppercase => s.to_ascii_uppercase(),
        Transform::UrlDecode => {
            let mut out = String::with_capacity(s.len());
            budu_parser::decode_into(s.as_bytes(), true, &mut out);
            out
        }
        Transform::CompressWs => s.split_whitespace().collect::<Vec<_>>().join(" "),
        Transform::RemoveNulls => s.replace('\0', ""),
        Transform::Trim => s.trim().to_string(),
    }
}

impl CompiledCond {
    fn matches_request(&self, ctx: &RequestCtx<'_>, counters: &budu_ratelimit::CounterStore) -> bool {
        let raw = match &self.op {
            // CIDR operates on the IP directly (no transforms).
            Op::Cidr(net) => net.contains(&ctx.client.ip),
            _ => self.eval_candidates(collect_candidates(&self.field, ctx, counters)),
        };
        raw ^ self.negate
    }

    fn matches_response(
        &self,
        rctx: &ResponseCtx<'_>,
        counters: &budu_ratelimit::CounterStore,
    ) -> bool {
        let raw = match &self.op {
            Op::Cidr(net) => net.contains(&rctx.client.ip),
            _ => self.eval_candidates(collect_response_candidates(&self.field, rctx, counters)),
        };
        raw ^ self.negate
    }

    /// Multi-valued fields match if ANY candidate satisfies the operator (after
    /// transforms); scalar fields yield 0 or 1 candidate.
    fn eval_candidates(&self, candidates: Vec<Cow<'_, str>>) -> bool {
        candidates.iter().any(|raw| {
            if self.transforms.is_empty() {
                eval_op(&self.op, raw)
            } else {
                let mut s = raw.to_string();
                for t in &self.transforms {
                    s = apply_transform(*t, &s);
                }
                eval_op(&self.op, &s)
            }
        })
    }
}

/// Candidate value(s) for a response-phase field.
fn collect_response_candidates<'a>(
    field: &'a Field,
    rctx: &'a ResponseCtx<'_>,
    counters: &budu_ratelimit::CounterStore,
) -> Vec<Cow<'a, str>> {
    match field {
        Field::Status => vec![Cow::Owned(rctx.status.as_u16().to_string())],
        Field::RespHeader(name) => rctx
            .headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(Cow::Borrowed)
            .into_iter()
            .collect(),
        Field::RespBody => match &rctx.body {
            BodyState::Buffered(b) => vec![Cow::Owned(String::from_utf8_lossy(b).into_owned())],
            _ => Vec::new(),
        },
        Field::Ip => vec![Cow::Owned(rctx.client.ip.to_string())],
        Field::Path => vec![Cow::Borrowed(rctx.path)],
        Field::Counter(name) => vec![Cow::Owned(counters.get(name, rctx.client.ip).to_string())],
        // other fields aren't valid in response phase (rejected at compile)
        _ => Vec::new(),
    }
}

fn eval_op(op: &Op, value: &str) -> bool {
    match op {
        Op::Eq(s) => value == s,
        Op::Ne(s) => value != s,
        Op::Contains(s) => value.contains(s.as_str()),
        Op::StartsWith(s) => value.starts_with(s.as_str()),
        Op::EndsWith(s) => value.ends_with(s.as_str()),
        Op::Regex(re) => re.is_match(value),
        Op::In(list) => list.iter().any(|x| x == value),
        Op::Gt(n) => value.trim().parse::<i64>().is_ok_and(|v| v > *n),
        Op::Lt(n) => value.trim().parse::<i64>().is_ok_and(|v| v < *n),
        Op::Ge(n) => value.trim().parse::<i64>().is_ok_and(|v| v >= *n),
        Op::Le(n) => value.trim().parse::<i64>().is_ok_and(|v| v <= *n),
        #[cfg(feature = "libinjection")]
        Op::DetectSqli => libinjectionrs::detect_sqli(value.as_bytes()).is_injection(),
        #[cfg(feature = "libinjection")]
        Op::DetectXss => libinjectionrs::detect_xss(value.as_bytes()).is_injection(),
        Op::Cidr(_) => false, // handled before transforms
        Op::TimeBetween {
            start,
            end,
            offset_min,
        } => value
            .trim()
            .parse::<u16>()
            .is_ok_and(|now_utc| in_window(now_utc, *start, *end, *offset_min)),
        Op::DayOfWeek { mask, offset_min } => value
            .trim()
            .parse::<i64>()
            .is_ok_and(|epoch_min| mask & (1 << weekday(epoch_min, *offset_min)) != 0),
    }
}

/// Minutes since the UNIX epoch (UTC) right now.
fn utc_epoch_minutes() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| (d.as_secs() / 60) as i64)
        .unwrap_or(0)
}

/// Local day of week for `epoch_min` shifted by `offset_min`: bit index
/// 0 = Sunday … 6 = Saturday (the UNIX epoch, 1970-01-01, was a Thursday).
fn weekday(epoch_min: i64, offset_min: i16) -> u8 {
    let days = (epoch_min + offset_min as i64).div_euclid(1440);
    ((days + 4).rem_euclid(7)) as u8
}

/// Parse a day spec into a 7-bit mask (bit 0 = Sunday). Accepts comma-separated
/// day names and inclusive ranges that wrap, e.g. `"Mon-Fri"`, `"Sat,Sun"`,
/// `"Mon,Wed,Fri"`, `"Fri-Mon"`.
fn parse_day_mask(s: &str) -> Option<u8> {
    let mut mask = 0u8;
    for tok in s.split(',') {
        let tok = tok.trim();
        if tok.is_empty() {
            continue;
        }
        match tok.split_once('-') {
            Some((a, b)) => {
                let (a, b) = (parse_day_name(a)?, parse_day_name(b)?);
                let mut d = a;
                loop {
                    mask |= 1 << d;
                    if d == b {
                        break;
                    }
                    d = (d + 1) % 7;
                }
            }
            None => mask |= 1 << parse_day_name(tok)?,
        }
    }
    (mask != 0).then_some(mask)
}

/// Map a weekday name to a bit index (Sunday = 0 … Saturday = 6).
fn parse_day_name(s: &str) -> Option<u8> {
    Some(match s.trim().to_ascii_lowercase().as_str() {
        "sun" | "sunday" => 0,
        "mon" | "monday" => 1,
        "tue" | "tues" | "tuesday" => 2,
        "wed" | "weds" | "wednesday" => 3,
        "thu" | "thur" | "thurs" | "thursday" => 4,
        "fri" | "friday" => 5,
        "sat" | "saturday" => 6,
        _ => return None,
    })
}

/// Minutes since midnight (UTC) right now. The UNIX epoch is UTC-midnight
/// aligned, so `secs % 86400` is the UTC time of day.
fn utc_minutes_now() -> u16 {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    ((secs % 86_400) / 60) as u16
}

/// Is `now_utc` (minutes since UTC midnight), shifted by `offset_min`, inside the
/// `[start, end]` window? A `start > end` window wraps past midnight
/// (e.g. `22:00-06:00`).
fn in_window(now_utc: u16, start: u16, end: u16, offset_min: i16) -> bool {
    let local = (now_utc as i32 + offset_min as i32).rem_euclid(1440) as u16;
    if start <= end {
        local >= start && local <= end
    } else {
        local >= start || local <= end
    }
}

/// Parse `"HH:MM-HH:MM"` into start/end minutes. Accepts `.` as well as `:`
/// between hours and minutes (so `"23.59"` works).
fn parse_time_window(s: &str) -> Option<(u16, u16)> {
    let (a, b) = s.split_once('-')?;
    Some((parse_hhmm(a)?, parse_hhmm(b)?))
}

fn parse_hhmm(s: &str) -> Option<u16> {
    let s = s.trim();
    let (h, m) = s.split_once(':').or_else(|| s.split_once('.'))?;
    let h: u16 = h.trim().parse().ok()?;
    let m: u16 = m.trim().parse().ok()?;
    (h <= 23 && m <= 59).then_some(h * 60 + m)
}

/// Parse a timezone offset like `"+08:00"`, `"-05:30"`, `"+8"`, `"UTC+8"`, or
/// `""` (→ UTC). Returns the signed offset in minutes. Public so the binary can
/// validate `[server] timezone` and pass the offset into rule compilation.
pub fn parse_tz_offset(s: &str) -> Option<i16> {
    let s = s.trim();
    if s.is_empty() {
        return Some(0);
    }
    let s = s
        .strip_prefix("UTC")
        .or_else(|| s.strip_prefix("utc"))
        .unwrap_or(s)
        .trim();
    if s.is_empty() {
        return Some(0);
    }
    let (sign, rest) = match s.strip_prefix('-') {
        Some(r) => (-1i16, r),
        None => (1i16, s.strip_prefix('+').unwrap_or(s)),
    };
    let (h, m) = match rest.split_once(':') {
        Some((h, m)) => (h, m),
        None => (rest, "0"),
    };
    let h: i16 = h.trim().parse().ok()?;
    let m: i16 = m.trim().parse().ok()?;
    (h <= 14 && m <= 59).then_some(sign * (h * 60 + m))
}

/// Candidate value(s) for a field. Scalar fields give 0 or 1; `arg`/`cookie`/
/// `*_names` give all matching values/names; `args_count` gives the count.
fn collect_candidates<'a>(
    field: &'a Field,
    ctx: &'a RequestCtx<'_>,
    counters: &budu_ratelimit::CounterStore,
) -> Vec<Cow<'a, str>> {
    match field {
        Field::Counter(name) => vec![Cow::Owned(counters.get(name, ctx.client.ip).to_string())],
        Field::Method => vec![Cow::Borrowed(ctx.method.as_str())],
        Field::Path => vec![Cow::Borrowed(ctx.path)],
        Field::Query => vec![Cow::Borrowed(ctx.query.unwrap_or(""))],
        Field::Uri => vec![match ctx.query {
            Some(q) => Cow::Owned(format!("{}?{}", ctx.path, q)),
            None => Cow::Borrowed(ctx.path),
        }],
        Field::Header(name) => ctx
            .headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(Cow::Borrowed)
            .into_iter()
            .collect(),
        Field::Body => match &ctx.body {
            BodyState::Buffered(b) => vec![Cow::Owned(String::from_utf8_lossy(b).into_owned())],
            _ => Vec::new(),
        },
        Field::Ip => vec![Cow::Owned(ctx.client.ip.to_string())],
        Field::Country => ctx
            .client
            .geo
            .map(|c| Cow::Owned(c.as_str().to_string()))
            .into_iter()
            .collect(),
        Field::Arg(name) => collect_args(ctx)
            .into_iter()
            .filter(|(k, _)| k == name)
            .map(|(_, v)| Cow::Owned(v))
            .collect(),
        Field::ArgNames => collect_args(ctx)
            .into_iter()
            .map(|(k, _)| Cow::Owned(k))
            .collect(),
        Field::ArgsCount => vec![Cow::Owned(collect_args(ctx).len().to_string())],
        Field::Cookie(name) => collect_cookies(ctx)
            .into_iter()
            .filter(|(k, _)| k == name)
            .map(|(_, v)| Cow::Owned(v))
            .collect(),
        Field::CookieNames => collect_cookies(ctx)
            .into_iter()
            .map(|(k, _)| Cow::Owned(k))
            .collect(),
        Field::Args => collect_args(ctx)
            .into_iter()
            .map(|(_, v)| Cow::Owned(v))
            .collect(),
        Field::Headers => ctx
            .headers
            .iter()
            .filter_map(|(_, v)| v.to_str().ok())
            .map(Cow::Borrowed)
            .collect(),
        Field::HeaderNames => ctx
            .headers
            .keys()
            .map(|k| Cow::Borrowed(k.as_str()))
            .collect(),
        Field::Cookies => collect_cookies(ctx)
            .into_iter()
            .map(|(_, v)| Cow::Owned(v))
            .collect(),
        // Time-of-day candidate is the current UTC minutes; the window's tz
        // offset is applied in `eval_op`.
        Field::Time => vec![Cow::Owned(utc_minutes_now().to_string())],
        // Day-of-week candidate is the current UTC epoch-minute; the tz offset
        // (which can change the day) is applied in `eval_op`.
        Field::Day => vec![Cow::Owned(utc_epoch_minutes().to_string())],
        // Response-only fields never appear in request-phase rules (compile rejects).
        Field::Status | Field::RespHeader(_) | Field::RespBody => Vec::new(),
    }
}

/// Query-string + buffered-body parameters for per-arg targeting. The body is
/// parsed by Content-Type: `application/x-www-form-urlencoded` (percent-decoded
/// pairs), `application/json` / `*+json` (flattened to dotted paths), and
/// `multipart/form-data` (each part's `name` → its value, or filename for file
/// parts). Other/absent body types contribute nothing.
fn collect_args(ctx: &RequestCtx<'_>) -> Vec<(String, String)> {
    let mut out = Vec::new();
    if let Some(q) = ctx.query {
        parse_pairs(q, &mut out);
    }
    if let BodyState::Buffered(b) = &ctx.body {
        if let Some(ct) = ctx
            .headers
            .get(http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
        {
            let ctl = ct.to_ascii_lowercase();
            if ctl.starts_with("application/x-www-form-urlencoded") {
                parse_pairs(&String::from_utf8_lossy(b), &mut out);
            } else if ctl.starts_with("application/json") || ctl.starts_with("text/json") || ctl.ends_with("+json") {
                parse_json_args(b, &mut out);
            } else if ctl.starts_with("multipart/form-data") {
                parse_multipart_args(b, ct, &mut out);
            }
        }
    }
    out
}

/// Parse a JSON body into `(path, value)` pairs. Nested objects/arrays are
/// flattened with dotted paths (`user.name`, `items.0.id`); scalars become
/// their string form (null → empty). A non-JSON / malformed body yields nothing.
fn parse_json_args(bytes: &[u8], out: &mut Vec<(String, String)>) {
    if let Ok(value) = serde_json::from_slice::<serde_json::Value>(bytes) {
        flatten_json("", &value, out);
    }
}

fn flatten_json(prefix: &str, value: &serde_json::Value, out: &mut Vec<(String, String)>) {
    use serde_json::Value;
    let child = |key: &str| {
        if prefix.is_empty() {
            key.to_string()
        } else {
            format!("{prefix}.{key}")
        }
    };
    match value {
        Value::Object(map) => {
            for (k, v) in map {
                flatten_json(&child(k), v, out);
            }
        }
        Value::Array(arr) => {
            for (i, v) in arr.iter().enumerate() {
                flatten_json(&child(&i.to_string()), v, out);
            }
        }
        Value::String(s) => out.push((prefix.to_string(), s.clone())),
        Value::Number(n) => out.push((prefix.to_string(), n.to_string())),
        Value::Bool(b) => out.push((prefix.to_string(), b.to_string())),
        Value::Null => out.push((prefix.to_string(), String::new())),
    }
}

/// Parse a `multipart/form-data` body into `(name, value)` pairs: regular fields
/// yield their content; file parts (a `filename` in `Content-Disposition`) yield
/// the filename (the raw upload bytes are still covered by the body signature
/// scan). Robust to binary part bodies (operates on bytes).
fn parse_multipart_args(body: &[u8], content_type: &str, out: &mut Vec<(String, String)>) {
    let boundary = match extract_boundary(content_type) {
        Some(b) => b,
        None => return,
    };
    let mut sep = Vec::with_capacity(boundary.len() + 2);
    sep.extend_from_slice(b"--");
    sep.extend_from_slice(boundary.as_bytes());

    for seg in split_on(body, &sep) {
        // Each part segment is `\r\n<headers>\r\n\r\n<body>\r\n`. The preamble
        // (before the first boundary) and the closing `--` segment are skipped.
        let seg = seg.strip_prefix(b"\r\n").unwrap_or(seg);
        if seg.is_empty() || seg.starts_with(b"--") {
            continue; // closing boundary / epilogue
        }
        let Some(pos) = find_sub(seg, b"\r\n\r\n") else {
            continue;
        };
        let head = &seg[..pos];
        let mut val = &seg[pos + 4..];
        val = val.strip_suffix(b"\r\n").unwrap_or(val);
        if let Some((name, filename)) = disposition_fields(head) {
            let value = match filename {
                Some(f) => f,
                None => String::from_utf8_lossy(val).into_owned(),
            };
            out.push((name, value));
        }
    }
}

/// Extract the `boundary=` value from a `multipart/...` Content-Type (the token
/// name is case-insensitive; the value is taken verbatim, optionally quoted).
fn extract_boundary(content_type: &str) -> Option<String> {
    for part in content_type.split(';').skip(1) {
        let part = part.trim();
        let (k, v) = part.split_once('=')?;
        if k.trim().eq_ignore_ascii_case("boundary") {
            return Some(v.trim().trim_matches('"').to_string());
        }
    }
    None
}

/// Pull `name` and optional `filename` out of a part's header block by reading
/// its `Content-Disposition` line.
fn disposition_fields(head: &[u8]) -> Option<(String, Option<String>)> {
    let head = String::from_utf8_lossy(head);
    for line in head.split("\r\n") {
        let (k, v) = line.split_once(':')?;
        if !k.trim().eq_ignore_ascii_case("content-disposition") {
            continue;
        }
        let mut name = None;
        let mut filename = None;
        for param in v.split(';').skip(1) {
            let param = param.trim();
            if let Some(rest) = param.strip_prefix("name=") {
                name = Some(rest.trim_matches('"').to_string());
            } else if let Some(rest) = param.strip_prefix("filename=") {
                filename = Some(rest.trim_matches('"').to_string());
            }
        }
        return name.map(|n| (n, filename));
    }
    None
}

/// Split `haystack` into the segments between (non-overlapping) occurrences of
/// `needle`. Returns the leading/trailing segments too (which the caller skips).
fn split_on<'a>(haystack: &'a [u8], needle: &[u8]) -> Vec<&'a [u8]> {
    let mut segs = Vec::new();
    let mut start = 0;
    let mut i = 0;
    if needle.is_empty() {
        return vec![haystack];
    }
    while i + needle.len() <= haystack.len() {
        if &haystack[i..i + needle.len()] == needle {
            segs.push(&haystack[start..i]);
            i += needle.len();
            start = i;
        } else {
            i += 1;
        }
    }
    segs.push(&haystack[start..]);
    segs
}

/// First index of `needle` in `haystack`, or `None`.
fn find_sub(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    (0..=haystack.len() - needle.len()).find(|&i| &haystack[i..i + needle.len()] == needle)
}

fn parse_pairs(s: &str, out: &mut Vec<(String, String)>) {
    for pair in s.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        let mut key = String::new();
        budu_parser::decode_into(k.as_bytes(), true, &mut key);
        let mut val = String::new();
        budu_parser::decode_into(v.as_bytes(), true, &mut val);
        out.push((key, val));
    }
}

/// Cookies from the `Cookie` header (values kept raw — not URL-decoded).
fn collect_cookies(ctx: &RequestCtx<'_>) -> Vec<(String, String)> {
    let mut out = Vec::new();
    if let Some(cookie) = ctx
        .headers
        .get(http::header::COOKIE)
        .and_then(|v| v.to_str().ok())
    {
        for part in cookie.split(';') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            let (k, v) = part.split_once('=').unwrap_or((part, ""));
            out.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use budu_common::{ClientInfo, NormalizedCache};
    use http::{HeaderMap, HeaderValue, Method};
    use std::net::IpAddr;

    fn compile(toml_str: &str) -> RuleSet {
        let file: RuleFile = toml::from_str(toml_str).expect("toml");
        RuleSet::compile(file.rule, &budu_config::ScoringConfig::default()).expect("compile")
    }

    fn compile_scored(toml_str: &str, threshold: u32) -> RuleSet {
        let file: RuleFile = toml::from_str(toml_str).expect("toml");
        let scoring = budu_config::ScoringConfig {
            threshold,
            status: 403,
            msg: "anomaly".into(),
        };
        RuleSet::compile(file.rule, &scoring).expect("compile")
    }

    fn ctx<'a>(
        method: &'a Method,
        path: &'a str,
        query: Option<&'a str>,
        headers: &'a HeaderMap,
        ip: &str,
    ) -> RequestCtx<'a> {
        RequestCtx {
            method,
            path,
            query,
            headers,
            client: ClientInfo {
                ip: ip.parse::<IpAddr>().unwrap(),
                geo: None,
            },
            body: BodyState::NotBuffered,
            normalized: NormalizedCache::default(),
        }
    }

    fn ctx_body<'a>(
        method: &'a Method,
        path: &'a str,
        headers: &'a HeaderMap,
        ip: &str,
        body: &[u8],
    ) -> RequestCtx<'a> {
        RequestCtx {
            method,
            path,
            query: None,
            headers,
            client: ClientInfo {
                ip: ip.parse::<IpAddr>().unwrap(),
                geo: None,
            },
            body: BodyState::Buffered(body.to_vec().into()),
            normalized: NormalizedCache::default(),
        }
    }

    #[test]
    fn block_admin_post_outside_cidr() {
        let rs = compile(
            r#"
[[rule]]
id = "admin-post"
action = "block"
status = 403
when = [
  { field = "path", op = "starts_with", value = "/admin" },
  { field = "method", op = "eq", value = "POST" },
]
"#,
        );
        let m = Method::POST;
        let h = HeaderMap::new();
        let c = ctx(&m, "/admin/users", None, &h, "10.0.0.1");
        assert!(matches!(rs.evaluate(&c), Some(Outcome::Block { .. })));

        let g = Method::GET;
        let c2 = ctx(&g, "/admin/users", None, &h, "10.0.0.1");
        assert!(rs.evaluate(&c2).is_none()); // GET doesn't match
    }

    #[test]
    fn allow_healthz_bypass() {
        let rs = compile(
            r#"
[[rule]]
id = "allow-health"
action = "allow"
when = [ { field = "path", op = "eq", value = "/healthz" } ]
"#,
        );
        let m = Method::GET;
        let h = HeaderMap::new();
        let c = ctx(&m, "/healthz", None, &h, "10.0.0.1");
        assert!(matches!(rs.evaluate(&c), Some(Outcome::Allow { .. })));
    }

    #[test]
    fn header_and_cidr_and_in() {
        let rs = compile(
            r#"
[[rule]]
id = "ua-block"
action = "block"
when = [ { field = "header", name = "User-Agent", op = "contains", value = "sqlmap" } ]

[[rule]]
id = "cidr-block"
action = "block"
when = [ { field = "ip", op = "cidr", value = "192.168.0.0/16" } ]

[[rule]]
id = "method-in"
action = "block"
when = [ { field = "method", op = "in", values = ["TRACE", "TRACK"] } ]
"#,
        );
        let m = Method::GET;
        let mut h = HeaderMap::new();
        h.insert("user-agent", HeaderValue::from_static("sqlmap/1.0"));
        assert!(matches!(
            rs.evaluate(&ctx(&m, "/", None, &h, "8.8.8.8")),
            Some(Outcome::Block { .. })
        ));

        let h2 = HeaderMap::new();
        assert!(matches!(
            rs.evaluate(&ctx(&m, "/", None, &h2, "192.168.5.5")),
            Some(Outcome::Block { .. })
        ));
        assert!(rs.evaluate(&ctx(&m, "/", None, &h2, "8.8.8.8")).is_none());
    }

    #[test]
    fn rate_limit_throttles_matching_traffic() {
        let rs = compile(
            r#"
[[rule]]
id = "throttle-login"
action = "rate_limit"
rps = 1
burst = 2
when = [ { field = "path", op = "starts_with", value = "/login" } ]
"#,
        );
        let m = Method::POST;
        let h = HeaderMap::new();
        // non-matching path is never throttled
        assert!(rs.evaluate(&ctx(&m, "/other", None, &h, "10.0.0.9")).is_none());
        // matching path: burst of 2 passes, then throttles
        let mut throttled = false;
        for _ in 0..6 {
            if let Some(Outcome::RateLimited { retry_after_secs, .. }) =
                rs.evaluate(&ctx(&m, "/login", None, &h, "10.0.0.9"))
            {
                assert!(retry_after_secs >= 1);
                throttled = true;
                break;
            }
        }
        assert!(throttled, "matching traffic must throttle past the burst");
    }

    #[test]
    fn rejects_rate_limit_without_rps() {
        let file: RuleFile = toml::from_str(
            "[[rule]]\nid='x'\naction='rate_limit'\nwhen=[{field='path',op='eq',value='/a'}]\n",
        )
        .expect("parses");
        assert!(RuleSet::compile(file.rule, &budu_config::ScoringConfig::default()).is_err());
    }

    #[test]
    fn transform_url_decode_then_match() {
        // Raw `%2e%2e%2f` only matches `../` after url_decode.
        let rs = compile(
            r#"
[[rule]]
id = "traversal"
action = "block"
when = [ { field = "query", op = "contains", value = "../", transform = ["url_decode"] } ]
"#,
        );
        let m = Method::GET;
        let h = HeaderMap::new();
        assert!(matches!(
            rs.evaluate(&ctx(&m, "/", Some("f=%2e%2e%2fetc"), &h, "10.0.0.1")),
            Some(Outcome::Block { .. })
        ));
        // without the transform it would not match raw %2e%2e%2f — sanity that
        // plain contains on the raw value is false
        let rs2 = compile(
            r#"
[[rule]]
id = "traversal-raw"
action = "block"
when = [ { field = "query", op = "contains", value = "../" } ]
"#,
        );
        assert!(rs2
            .evaluate(&ctx(&m, "/", Some("f=%2e%2e%2fetc"), &h, "10.0.0.1"))
            .is_none());
    }

    #[test]
    fn negate_inverts_match() {
        let rs = compile(
            r#"
[[rule]]
id = "non-api"
action = "block"
when = [ { field = "path", op = "starts_with", value = "/api", negate = true } ]
"#,
        );
        let m = Method::GET;
        let h = HeaderMap::new();
        // /api is NOT blocked (negate makes the condition false for /api)
        assert!(rs.evaluate(&ctx(&m, "/api/x", None, &h, "10.0.0.1")).is_none());
        // anything else IS blocked
        assert!(matches!(
            rs.evaluate(&ctx(&m, "/public", None, &h, "10.0.0.1")),
            Some(Outcome::Block { .. })
        ));
    }

    #[test]
    fn numeric_ops_on_header() {
        let rs = compile(
            r#"
[[rule]]
id = "big-body"
action = "block"
when = [ { field = "header", name = "Content-Length", op = "gt", value = "1000" } ]
"#,
        );
        let m = Method::POST;
        let mut h = HeaderMap::new();
        h.insert("content-length", HeaderValue::from_static("5000"));
        assert!(matches!(
            rs.evaluate(&ctx(&m, "/", None, &h, "10.0.0.1")),
            Some(Outcome::Block { .. })
        ));
        let mut h2 = HeaderMap::new();
        h2.insert("content-length", HeaderValue::from_static("10"));
        assert!(rs.evaluate(&ctx(&m, "/", None, &h2, "10.0.0.1")).is_none());
    }

    #[test]
    fn targets_specific_query_arg() {
        let rs = compile(
            r#"
[[rule]]
id = "bad-redirect"
action = "block"
when = [ { field = "arg", name = "redirect", op = "starts_with", value = "http" } ]
"#,
        );
        let m = Method::GET;
        let h = HeaderMap::new();
        // arg redirect=http... matches
        assert!(matches!(
            rs.evaluate(&ctx(&m, "/", Some("redirect=http%3A%2F%2Fevil&x=1"), &h, "10.0.0.1")),
            Some(Outcome::Block { .. })
        ));
        // a different arg containing "http" does NOT match (precision)
        assert!(rs
            .evaluate(&ctx(&m, "/", Some("note=http-is-fine"), &h, "10.0.0.1"))
            .is_none());
    }

    #[test]
    fn arg_names_and_count() {
        let rs = compile(
            r#"
[[rule]]
id = "has-cmd"
action = "block"
when = [ { field = "arg_names", op = "eq", value = "cmd" } ]

[[rule]]
id = "too-many-args"
action = "block"
when = [ { field = "args_count", op = "gt", value = "3" } ]
"#,
        );
        let m = Method::GET;
        let h = HeaderMap::new();
        assert!(matches!(
            rs.evaluate(&ctx(&m, "/", Some("a=1&cmd=ls"), &h, "10.0.0.1")),
            Some(Outcome::Block { .. })
        ));
        assert!(matches!(
            rs.evaluate(&ctx(&m, "/", Some("a=1&b=2&c=3&d=4"), &h, "10.0.0.1")),
            Some(Outcome::Block { .. })
        ));
        assert!(rs.evaluate(&ctx(&m, "/", Some("a=1&b=2"), &h, "10.0.0.1")).is_none());
    }

    #[test]
    fn targets_cookie() {
        let rs = compile(
            r#"
[[rule]]
id = "bad-session"
action = "block"
when = [ { field = "cookie", name = "sid", op = "eq", value = "admin" } ]
"#,
        );
        let m = Method::GET;
        let mut h = HeaderMap::new();
        h.insert("cookie", HeaderValue::from_static("foo=bar; sid=admin; x=y"));
        assert!(matches!(
            rs.evaluate(&ctx(&m, "/", None, &h, "10.0.0.1")),
            Some(Outcome::Block { .. })
        ));
        let mut h2 = HeaderMap::new();
        h2.insert("cookie", HeaderValue::from_static("sid=guest"));
        assert!(rs.evaluate(&ctx(&m, "/", None, &h2, "10.0.0.1")).is_none());
    }

    #[test]
    fn json_body_arg_targets_nested_path() {
        let rs = compile(
            r#"
[[rule]]
id = "json-admin"
action = "block"
when = [ { field = "arg", name = "user.role", op = "eq", value = "admin" } ]
"#,
        );
        let m = Method::POST;
        let mut h = HeaderMap::new();
        h.insert("content-type", HeaderValue::from_static("application/json"));
        let body = br#"{"user":{"name":"bob","role":"admin"},"tags":["x","y"]}"#;
        assert!(matches!(
            rs.evaluate(&ctx_body(&m, "/api", &h, "10.0.0.1", body)),
            Some(Outcome::Block { .. })
        ));
        // different role → no match
        let ok = br#"{"user":{"name":"bob","role":"guest"}}"#;
        assert!(rs.evaluate(&ctx_body(&m, "/api", &h, "10.0.0.1", ok)).is_none());
    }

    #[test]
    fn json_body_array_index_and_names() {
        let rs = compile(
            r#"
[[rule]]
id = "json-arrname"
action = "block"
when = [ { field = "arg", name = "items.1.id", op = "eq", value = "42" } ]

[[rule]]
id = "has-token-key"
action = "block"
when = [ { field = "arg_names", op = "eq", value = "token" } ]
"#,
        );
        let m = Method::POST;
        let mut h = HeaderMap::new();
        h.insert("content-type", HeaderValue::from_static("application/json; charset=utf-8"));
        let body = br#"{"items":[{"id":7},{"id":42}]}"#;
        assert!(matches!(
            rs.evaluate(&ctx_body(&m, "/api", &h, "10.0.0.1", body)),
            Some(Outcome::Block { .. })
        ));
        let body2 = br#"{"token":"abc"}"#;
        assert!(matches!(
            rs.evaluate(&ctx_body(&m, "/api", &h, "10.0.0.1", body2)),
            Some(Outcome::Block { .. })
        ));
    }

    #[test]
    fn multipart_field_and_filename() {
        // form field `comment` and a file upload `avatar` with a .php filename
        let rs = compile(
            r#"
[[rule]]
id = "bad-comment"
action = "block"
when = [ { field = "arg", name = "comment", op = "contains", value = "<script" } ]

[[rule]]
id = "bad-upload"
action = "block"
when = [ { field = "arg", name = "avatar", op = "ends_with", value = ".php" } ]
"#,
        );
        let m = Method::POST;
        let mut h = HeaderMap::new();
        h.insert(
            "content-type",
            HeaderValue::from_static("multipart/form-data; boundary=XYZ"),
        );
        let body = b"--XYZ\r\nContent-Disposition: form-data; name=\"comment\"\r\n\r\nhello <script>x</script>\r\n--XYZ\r\nContent-Disposition: form-data; name=\"avatar\"; filename=\"shell.php\"\r\nContent-Type: application/octet-stream\r\n\r\n<?php evil(); ?>\r\n--XYZ--\r\n";
        // comment field matches the <script payload
        assert!(matches!(
            rs.evaluate(&ctx_body(&m, "/upload", &h, "10.0.0.1", body)),
            Some(Outcome::Block { .. })
        ));

        // a clean multipart submission passes
        let clean = b"--XYZ\r\nContent-Disposition: form-data; name=\"comment\"\r\n\r\nhi there\r\n--XYZ--\r\n";
        assert!(rs.evaluate(&ctx_body(&m, "/upload", &h, "10.0.0.1", clean)).is_none());

        // filename targeting: only the avatar part triggers bad-upload
        let upload = b"--XYZ\r\nContent-Disposition: form-data; name=\"avatar\"; filename=\"x.php\"\r\n\r\nbinary\r\n--XYZ--\r\n";
        assert!(matches!(
            rs.evaluate(&ctx_body(&m, "/upload", &h, "10.0.0.1", upload)),
            Some(Outcome::Block { .. })
        ));
    }

    #[test]
    fn time_window_parsing_and_membership() {
        // 08:00-23:59 = minutes 480..=1439
        assert_eq!(parse_time_window("08:00-23:59"), Some((480, 1439)));
        // dot separator is accepted too
        assert_eq!(parse_time_window("8:00-23.59"), Some((480, 1439)));
        assert!(parse_time_window("24:00-08:00").is_none()); // 24 invalid
        assert!(parse_time_window("08:00").is_none()); // no range

        // daytime window, UTC
        assert!(in_window(600, 480, 1439, 0)); // 10:00 inside
        assert!(!in_window(420, 480, 1439, 0)); // 07:00 outside
        assert!(in_window(1439, 480, 1439, 0)); // 23:59 boundary inside

        // tz offset: 02:00 UTC + 08:00 = 10:00 local → inside 08:00-23:59
        assert!(in_window(120, 480, 1439, 8 * 60));
        // 22:00 UTC + 08:00 = 06:00 local → outside 08:00-23:59
        assert!(!in_window(1320, 480, 1439, 8 * 60));

        // overnight window 22:00-06:00 wraps midnight
        assert!(in_window(1380, 1320, 360, 0)); // 23:00 inside
        assert!(in_window(120, 1320, 360, 0)); // 02:00 inside
        assert!(!in_window(720, 1320, 360, 0)); // 12:00 outside
    }

    #[test]
    fn tz_offset_parsing() {
        assert_eq!(parse_tz_offset(""), Some(0));
        assert_eq!(parse_tz_offset("+08:00"), Some(480));
        assert_eq!(parse_tz_offset("-05:30"), Some(-330));
        assert_eq!(parse_tz_offset("+8"), Some(480));
        assert_eq!(parse_tz_offset("UTC+8"), Some(480));
        assert!(parse_tz_offset("+15:00").is_none()); // > 14h
        assert!(parse_tz_offset("noon").is_none());
    }

    #[test]
    fn time_rule_compiles_and_rejects_bad_combos() {
        // valid business-hours rule
        let rs = compile(
            r#"
[[rule]]
id = "office-hours"
action = "block"
status = 403
when = [ { field = "time", op = "time_between", value = "08:00-23:59", tz = "+08:00", negate = true } ]
"#,
        );
        assert_eq!(rs.len(), 1);

        // time_between on a non-time field is rejected
        let bad: RuleFile = toml::from_str(
            "[[rule]]\nid='x'\nwhen=[{field='path',op='time_between',value='08:00-23:59'}]\n",
        )
        .expect("parses");
        assert!(RuleSet::compile(bad.rule, &budu_config::ScoringConfig::default()).is_err());

        // time field with a non-time op is rejected
        let bad2: RuleFile =
            toml::from_str("[[rule]]\nid='x'\nwhen=[{field='time',op='eq',value='600'}]\n")
                .expect("parses");
        assert!(RuleSet::compile(bad2.rule, &budu_config::ScoringConfig::default()).is_err());

        // malformed window is rejected
        let bad3: RuleFile = toml::from_str(
            "[[rule]]\nid='x'\nwhen=[{field='time',op='time_between',value='notatime'}]\n",
        )
        .expect("parses");
        assert!(RuleSet::compile(bad3.rule, &budu_config::ScoringConfig::default()).is_err());
    }

    #[test]
    fn day_mask_parsing_and_weekday() {
        // Sun=0 .. Sat=6
        assert_eq!(parse_day_name("Mon"), Some(1));
        assert_eq!(parse_day_name("sunday"), Some(0));
        assert!(parse_day_name("funday").is_none());

        // Mon-Fri = bits 1..5
        assert_eq!(parse_day_mask("Mon-Fri"), Some(0b0111110));
        // set
        assert_eq!(parse_day_mask("Sat,Sun"), Some(0b1000001));
        // wrap-around range Fri-Mon = Fri,Sat,Sun,Mon
        assert_eq!(parse_day_mask("Fri-Mon"), Some(0b1100011));
        // single day
        assert_eq!(parse_day_mask("Wed"), Some(0b0001000));
        assert!(parse_day_mask("nope").is_none());

        // 2021-01-01 00:00 UTC was a Friday (=5). epoch minutes:
        let epoch_min = 1_609_459_200i64 / 60;
        assert_eq!(weekday(epoch_min, 0), 5);
        // +08:00 still Friday at midday-ish; -09:00 rolls back to Thursday (=4)
        assert_eq!(weekday(epoch_min, 8 * 60), 5);
        assert_eq!(weekday(epoch_min, -9 * 60), 4);
    }

    #[test]
    fn day_rule_compiles_and_inherits_tz() {
        let rs = compile(
            r#"
[[rule]]
id = "weekends-closed"
action = "block"
status = 403
when = [ { field = "day", op = "day_of_week", value = "Sat,Sun" } ]
"#,
        );
        assert_eq!(rs.len(), 1);

        // server default tz is baked into the day op when the cond omits tz
        let file: RuleFile = toml::from_str(
            "[[rule]]\nid='d'\naction='block'\nwhen=[{field='day',op='day_of_week',value='Mon-Fri'}]\n",
        )
        .unwrap();
        let rs2 =
            RuleSet::compile_with_tz(file.rule, &budu_config::ScoringConfig::default(), 8 * 60)
                .unwrap();
        match &rs2.rules[0].conds[0].op {
            Op::DayOfWeek { mask, offset_min } => {
                assert_eq!(*mask, 0b0111110);
                assert_eq!(*offset_min, 480);
            }
            _ => panic!("expected DayOfWeek"),
        }

        // mismatched field/op combos are rejected
        let bad: RuleFile = toml::from_str(
            "[[rule]]\nid='x'\nwhen=[{field='path',op='day_of_week',value='Mon'}]\n",
        )
        .unwrap();
        assert!(RuleSet::compile(bad.rule, &budu_config::ScoringConfig::default()).is_err());
        let bad2: RuleFile =
            toml::from_str("[[rule]]\nid='x'\nwhen=[{field='day',op='eq',value='Mon'}]\n").unwrap();
        assert!(RuleSet::compile(bad2.rule, &budu_config::ScoringConfig::default()).is_err());
    }

    #[test]
    fn default_tz_applies_and_per_rule_overrides() {
        let toml = "[[rule]]\nid='h'\naction='block'\nwhen=[{field='time',op='time_between',value='08:00-17:00'}]\n";
        let file: RuleFile = toml::from_str(toml).unwrap();
        // server default +08:00 is baked in when the condition omits tz
        let rs =
            RuleSet::compile_with_tz(file.rule, &budu_config::ScoringConfig::default(), 8 * 60)
                .unwrap();
        match &rs.rules[0].conds[0].op {
            Op::TimeBetween { start, end, offset_min } => {
                assert_eq!((*start, *end), (480, 1020));
                assert_eq!(*offset_min, 480);
            }
            _ => panic!("expected TimeBetween"),
        }

        // a per-rule tz overrides the server default
        let toml2 = "[[rule]]\nid='h'\naction='block'\nwhen=[{field='time',op='time_between',value='08:00-17:00',tz='-05:00'}]\n";
        let file2: RuleFile = toml::from_str(toml2).unwrap();
        let rs2 =
            RuleSet::compile_with_tz(file2.rule, &budu_config::ScoringConfig::default(), 8 * 60)
                .unwrap();
        match &rs2.rules[0].conds[0].op {
            Op::TimeBetween { offset_min, .. } => assert_eq!(*offset_min, -300),
            _ => panic!("expected TimeBetween"),
        }
    }

    #[test]
    fn rejects_unknown_transform() {
        let file: RuleFile = toml::from_str(
            "[[rule]]\nid='x'\nwhen=[{field='path',op='eq',value='/a',transform=['nope']}]\n",
        )
        .expect("parses");
        assert!(RuleSet::compile(file.rule, &budu_config::ScoringConfig::default()).is_err());
    }

    #[test]
    fn anomaly_score_blocks_at_threshold() {
        let toml = r#"
[[rule]]
id = "s1"
action = "score"
score = 3
when = [ { field = "method", op = "eq", value = "GET" } ]

[[rule]]
id = "s2"
action = "score"
score = 2
when = [ { field = "path", op = "starts_with", value = "/admin" } ]
"#;
        let m = Method::GET;
        let h = HeaderMap::new(); // s1 (method=GET) always matches → base score 3
        // threshold 5: /admin (3+2=5) blocks; non-admin (3) passes
        let rs = compile_scored(toml, 5);
        assert!(matches!(
            rs.evaluate(&ctx(&m, "/admin/x", None, &h, "10.0.0.1")),
            Some(Outcome::Block { .. })
        ));
        assert!(rs.evaluate(&ctx(&m, "/public", None, &h, "10.0.0.1")).is_none());

        // threshold 0 (disabled): never blocks even when rules match
        let rs0 = compile_scored(toml, 0);
        assert!(rs0.evaluate(&ctx(&m, "/admin/x", None, &h, "10.0.0.1")).is_none());
    }

    #[test]
    fn allow_overrides_anomaly_score() {
        let toml = r#"
[[rule]]
id = "allow-health"
action = "allow"
when = [ { field = "path", op = "eq", value = "/health" } ]

[[rule]]
id = "s-big"
action = "score"
score = 100
when = [ { field = "path", op = "starts_with", value = "/" } ]
"#;
        let rs = compile_scored(toml, 10);
        let m = Method::GET;
        let h = HeaderMap::new();
        // /health hits allow first → not blocked despite the big score rule
        assert!(matches!(
            rs.evaluate(&ctx(&m, "/health", None, &h, "10.0.0.1")),
            Some(Outcome::Allow { .. })
        ));
        // other paths accumulate 100 ≥ 10 → blocked
        assert!(matches!(
            rs.evaluate(&ctx(&m, "/other", None, &h, "10.0.0.1")),
            Some(Outcome::Block { .. })
        ));
    }

    #[test]
    fn stateful_counter_brute_force() {
        // incr a counter on each /login hit; block once it exceeds 3.
        let rs = compile(
            r#"
[[rule]]
id = "count-login"
action = "incr"
counter = "login"
ttl_secs = 300
when = [ { field = "path", op = "eq", value = "/login" } ]

[[rule]]
id = "block-bruteforce"
action = "block"
status = 429
when = [ { field = "counter", name = "login", op = "gt", value = "3" } ]
"#,
        );
        let store = budu_ratelimit::CounterStore::new();
        let m = Method::POST;
        let h = HeaderMap::new();
        let ip = "203.0.113.50";
        let mut blocked_on = 0;
        for i in 1..=6 {
            let out = rs.evaluate_with_counters(&ctx(&m, "/login", None, &h, ip), &store);
            if matches!(out, Some(Outcome::Block { .. })) {
                blocked_on = i;
                break;
            }
        }
        // counts 1,2,3 pass; 4th makes counter=4 > 3 → block
        assert_eq!(blocked_on, 4);

        // a different IP has its own counter — not affected
        assert!(rs
            .evaluate_with_counters(&ctx(&m, "/login", None, &h, "198.51.100.9"), &store)
            .is_none());
    }

    #[test]
    fn rejects_incr_without_counter_name() {
        let file: RuleFile = toml::from_str(
            "[[rule]]\nid='x'\naction='incr'\nwhen=[{field='path',op='eq',value='/a'}]\n",
        )
        .expect("parses");
        assert!(RuleSet::compile(file.rule, &budu_config::ScoringConfig::default()).is_err());
    }

    #[test]
    fn rejects_score_without_points() {
        let file: RuleFile = toml::from_str(
            "[[rule]]\nid='x'\naction='score'\nwhen=[{field='path',op='eq',value='/a'}]\n",
        )
        .expect("parses");
        assert!(RuleSet::compile(file.rule, &budu_config::ScoringConfig::default()).is_err());
    }

    fn rctx<'a>(status: u16, headers: &'a HeaderMap, path: &'a str, ip: &str) -> ResponseCtx<'a> {
        ResponseCtx {
            status: StatusCode::from_u16(status).unwrap(),
            headers,
            client: ClientInfo {
                ip: ip.parse::<IpAddr>().unwrap(),
                geo: None,
            },
            path,
            body: BodyState::NotBuffered,
        }
    }

    fn rctx_body<'a>(status: u16, headers: &'a HeaderMap, path: &'a str, ip: &str, body: &str) -> ResponseCtx<'a> {
        ResponseCtx {
            status: StatusCode::from_u16(status).unwrap(),
            headers,
            client: ClientInfo {
                ip: ip.parse::<IpAddr>().unwrap(),
                geo: None,
            },
            path,
            body: BodyState::Buffered(body.as_bytes().to_vec().into()),
        }
    }

    #[test]
    fn response_phase_blocks_on_status_and_header() {
        let rs = compile(
            r#"
[[rule]]
id = "block-5xx"
phase = "response"
action = "block"
status = 502
when = [ { field = "status", op = "ge", value = "500" } ]

[[rule]]
id = "leaky-header"
phase = "response"
action = "block"
when = [ { field = "resp_header", name = "X-Powered-By", op = "contains", value = "PHP" } ]
"#,
        );
        let store = budu_ratelimit::CounterStore::new();
        let h = HeaderMap::new();
        // request-phase eval ignores response rules
        let m = Method::GET;
        assert!(rs.evaluate(&ctx(&m, "/x", None, &h, "10.0.0.1")).is_none());

        // 500 → block
        assert!(matches!(
            rs.evaluate_response(&rctx(500, &h, "/x", "10.0.0.1"), &AtomicU64::new(0), &store),
            Some(Outcome::Block { .. })
        ));
        // 200 → pass
        assert!(rs
            .evaluate_response(&rctx(200, &h, "/x", "10.0.0.1"), &AtomicU64::new(0), &store)
            .is_none());
        // leaky header → block
        let mut h2 = HeaderMap::new();
        h2.insert("x-powered-by", HeaderValue::from_static("PHP/8.1"));
        assert!(matches!(
            rs.evaluate_response(&rctx(200, &h2, "/x", "10.0.0.1"), &AtomicU64::new(0), &store),
            Some(Outcome::Block { .. })
        ));
    }

    #[test]
    fn response_phase_blocks_on_body() {
        let rs = compile(
            r#"
[[rule]]
id = "leak-pan"
phase = "response"
action = "block"
status = 502
when = [ { field = "resp_body", op = "regex", value = "\\b\\d{16}\\b" } ]
"#,
        );
        assert!(rs.needs_response_body());
        let store = budu_ratelimit::CounterStore::new();
        let h = HeaderMap::new();
        // body with a 16-digit number → block (data-leak guard)
        assert!(matches!(
            rs.evaluate_response(
                &rctx_body(200, &h, "/x", "10.0.0.1", "card 4111111111111111 ok"),
                &AtomicU64::new(0),
                &store
            ),
            Some(Outcome::Block { .. })
        ));
        // clean body → pass
        assert!(rs
            .evaluate_response(
                &rctx_body(200, &h, "/x", "10.0.0.1", "nothing to see"),
                &AtomicU64::new(0),
                &store
            )
            .is_none());
        // unbuffered body (too large / not inspected) → rule can't match, passes
        assert!(rs
            .evaluate_response(&rctx(200, &h, "/x", "10.0.0.1"), &AtomicU64::new(0), &store)
            .is_none());
    }

    #[test]
    fn needs_response_body_only_when_referenced() {
        // status/header-only response rules don't require buffering
        let rs = compile(
            r#"
[[rule]]
id = "mask-5xx"
phase = "response"
action = "block"
status = 502
when = [ { field = "status", op = "ge", value = "500" } ]
"#,
        );
        assert!(!rs.needs_response_body());
    }

    #[test]
    fn rejects_resp_body_in_request_phase() {
        let bad: RuleFile = toml::from_str(
            "[[rule]]\nid='x'\naction='block'\nwhen=[{field='resp_body',op='contains',value='x'}]\n",
        )
        .expect("parses");
        assert!(RuleSet::compile(bad.rule, &budu_config::ScoringConfig::default()).is_err());
    }

    #[test]
    fn rejects_response_field_in_request_phase() {
        let bad: RuleFile = toml::from_str(
            "[[rule]]\nid='x'\naction='block'\nwhen=[{field='status',op='ge',value='500'}]\n",
        )
        .expect("parses");
        assert!(RuleSet::compile(bad.rule, &budu_config::ScoringConfig::default()).is_err());
    }

    #[test]
    fn rejects_request_field_in_response_phase() {
        let bad: RuleFile = toml::from_str(
            "[[rule]]\nid='x'\nphase='response'\naction='block'\nwhen=[{field='query',op='contains',value='x'}]\n",
        )
        .expect("parses");
        assert!(RuleSet::compile(bad.rule, &budu_config::ScoringConfig::default()).is_err());
    }

    #[test]
    fn rejects_rule_without_conditions() {
        let file: RuleFile =
            toml::from_str("[[rule]]\nid = 'x'\naction = 'block'\n").expect("parses");
        assert!(RuleSet::compile(file.rule, &budu_config::ScoringConfig::default()).is_err());
    }

    #[test]
    fn rejects_cidr_on_non_ip_field() {
        let file: RuleFile = toml::from_str(
            "[[rule]]\nid='x'\nwhen=[{ field='path', op='cidr', value='10.0.0.0/8' }]\n",
        )
        .expect("parses");
        assert!(RuleSet::compile(file.rule, &budu_config::ScoringConfig::default()).is_err());
    }
}
