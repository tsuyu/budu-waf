# Custom rules (`rules.toml`)

Custom rules are *your* business-logic gate, complementing the attack-pattern
[signatures](SIGNATURES.md). Point `[paths] rules` at a TOML file:

```toml
[paths]
rules = "config/rules.toml"
```

Validate and live-reload:

```bash
budu --config config/budu.toml check     # compiles rules, reports count
kill -HUP <pid>                           # hot-reload without restart
```

A starter file ships at [config/rules.toml](../config/rules.toml).

---

## Anatomy of a rule

```toml
[[rule]]
id     = "admin-internal-only"   # required, unique label (used in logs/metrics)
action = "block"                 # block | allow | log | rate_limit
status = 403                     # block only; HTTP status (default 403)
msg    = "admin is internal-only"# block only; response body / audit reason
when = [                         # 1+ conditions, ALL must match (logical AND)
  { field = "path",   op = "starts_with", value = "/admin" },
  { field = "method", op = "eq",          value = "POST" },
]
```

- Rules are evaluated **in file order**.
- A rule fires only when **every** `when` condition matches.
- The first `block` / `allow` / throttled `rate_limit` match **short-circuits**
  the pipeline. `log` matches are recorded and evaluation continues.
- Custom rules run **before signatures**, so an `allow` rule can whitelist a
  request past signature inspection.

---

## Fields

| `field` | Matches against |
|---|---|
| `method` | HTTP method (`GET`, `POST`, …) |
| `path` | URL path (no query) |
| `query` | Raw query string (without `?`) |
| `uri` | `path` + `?` + `query` |
| `header` | A request header value — **requires `name`** (case-insensitive header name) |
| `body` | Request body, **only if it was buffered** (inspectable `{POST,PUT,PATCH}` ≤ `max_inspect_body`); otherwise the condition is false |
| `ip` | Resolved client IP (string form; or use `op = "cidr"`) |
| `country` | ISO-3166 country code — **requires the `geoip` feature + DB**; false when geo is unknown |
| `counter` | Current value of a per-client-IP **stateful counter** by `name` (0 if unset/expired) — use a numeric op (`gt`/`ge`/…) |
| `status` | **Response phase only.** Upstream response status code (numeric). |
| `resp_header` | **Response phase only.** A response header value — **requires `name`**. |
| `resp_body` | **Response phase only.** The buffered upstream response body (UTF-8 lossy). Empty when the body wasn't buffered (non-inspectable Content-Type or over the size cap). |
| `arg` | A specific request parameter **value** — **requires `name`**. Drawn from the query string and the buffered body (form-urlencoded, JSON, or multipart). Multi-valued (matches if any value satisfies the op). |
| `arg_names` | The set of request parameter **names** (matches if any name satisfies the op). |
| `args_count` | Number of request parameters (use a numeric op). |
| `cookie` | A specific cookie **value** — **requires `name`** (from the `Cookie` header; value kept raw). |
| `cookie_names` | The set of cookie names. |
| `args` | **All** request parameter values (query + body), multi-valued. The broad counterpart to `arg`. |
| `headers` | **All** request header values, multi-valued. |
| `header_names` | The set of request header names, multi-valued. |
| `cookies` | **All** cookie values, multi-valued. |
| `time` | Current wall-clock time of day — use only with `op = "time_between"` (see [Time-window rules](#time-window-rules-time--time_between)). |
| `day` | Current day of week — use only with `op = "day_of_week"` (see [Time-window rules](#time-window-rules-time--time_between)). |

> Targeted fields are the precision tool: matching `arg name="redirect"` only
> inspects that parameter, not the whole query — far fewer false positives than a
> blob `query` match.
>
> **Query-string args** are always available. **Body parameters** are only seen
> when the body was buffered — its Content-Type must be listed in
> `[inspect] content_types` and within `max_inspect_body`. Three body formats are
> parsed:
>
> - **`application/x-www-form-urlencoded`** — percent-decoded `key=value` pairs.
> - **`application/json`** (and `*+json`) — flattened to dotted paths. `{"user":
>   {"role":"admin"}}` exposes arg `user.role`; arrays use indices, so
>   `{"items":[{"id":42}]}` exposes `items.0.id`. Scalars become their string
>   form (`null` → empty).
> - **`multipart/form-data`** — each part's `name` maps to its value; a **file**
>   part (one with a `filename`) maps to its **filename** instead of its bytes
>   (the raw upload is still covered by the body signature scan), so you can write
>   `arg name="avatar" regex "(?i)\.(php|exe)$"`.

By default values are matched against the **raw** request (case-sensitive). Use
`transform` (below) to normalize first, or a `regex` with `(?i)`.

## Operators

| `op` | Meaning | Notes |
|---|---|---|
| `eq` | exact equal | |
| `ne` | not equal | absent field ⇒ does **not** match |
| `contains` | substring present | |
| `starts_with` | prefix | |
| `ends_with` | suffix | |
| `regex` | regular expression | `value = "..."`; ASCII semantics, `(?i)` supported |
| `in` | value is one of a list | use `values = [..]` instead of `value` |
| `cidr` | IP within a CIDR | **`field` must be `ip`**; `value` is a CIDR or bare IP |
| `gt` `lt` `ge` `le` | numeric compare | field parsed as an integer; non-numeric ⇒ no match. E.g. `Content-Length > N` |
| `detect_sqli` | libinjection SQLi detection | **requires `--features libinjection`**; `value` ignored |
| `detect_xss` | libinjection XSS detection | **requires `--features libinjection`**; `value` ignored |
| `time_between` | current time-of-day within a window | **`field` must be `time`**; `value = "HH:MM-HH:MM"`, optional `tz`. See below. |
| `day_of_week` | current day within a set/range of weekdays | **`field` must be `day`**; `value = "Mon-Fri"` / `"Sat,Sun"`, optional `tz`. See below. |

> A header name must be given with `name`: `{ field = "header", name = "User-Agent", op = "contains", value = "curl" }`.

## Negation

Add `negate = true` to any condition to invert its result (`cidr` included):

```toml
{ field = "path", op = "starts_with", value = "/api", negate = true }   # matches non-/api paths
```

## Transforms

`transform = [..]` rewrites the field value **before** the operator runs, applied
in order — the key tool for evasion resistance (rules otherwise see raw bytes):

| transform | effect |
|---|---|
| `lowercase` / `uppercase` | ASCII case fold |
| `url_decode` | percent-decode (`%2e` → `.`, `+` → space) |
| `compress_ws` | collapse runs of whitespace to a single space, trim ends |
| `remove_nulls` | strip `\0` bytes |
| `trim` | strip leading/trailing whitespace |

```toml
# catches ../ even when written %2e%2e%2f or ..%2F
{ field = "uri", op = "contains", value = "../", transform = ["url_decode", "lowercase"] }
```

## Actions

| `action` | Effect | Extra keys |
|---|---|---|
| `block` | Answer the client and stop. | `status` (default `403`), `msg` (default = rule id) |
| `allow` | **Whitelist**: forward immediately, skipping remaining inspection incl. signatures. | — |
| `log` | Write an audit line and **keep evaluating** later rules. | — |
| `rate_limit` | Throttle the matching traffic per client IP. | `rps` (required, > 0), `burst` (default = `rps`), `ttl_secs` (default `300`) |
| `score` | Add points to the request's anomaly score (CRS-style); **doesn't block on its own**. | `score` (required, > 0) |
| `incr` | Bump a per-client-IP **stateful counter**; **doesn't block on its own**. | `counter` (required name), `incr` (default 1), `ttl_secs` (window, default 300) |

### Anomaly scoring (`score`)

`score` rules don't block — they accumulate points. When a request's total reaches
`[scoring] threshold` (and `threshold > 0`), B.U.D.U blocks it with the configured
status/msg (rule id `anomaly.score`, reason includes the score). This is the OWASP
CRS model: many weak signals add up instead of any single rule blocking, which
greatly reduces false positives. An `allow`/`block`/`rate_limit` rule that matches
first still short-circuits (so an `allow` overrides an accumulated score). Set
`[scoring] threshold` to enable it (`0` = disabled). See
[CONFIGURATION.md](CONFIGURATION.md#scoring).

```toml
[[rule]]
id = "score-no-ua"
action = "score"
score = 3
when = [ { field = "header", name = "User-Agent", op = "regex", value = "^$", negate = true } ]

[[rule]]
id = "score-sqli-ish"
action = "score"
score = 5
when = [ { field = "query", op = "regex", value = "(?i)(union|select|sleep\\()" } ]
```

For `rate_limit`, only requests matching the rule's conditions count against the
bucket; over budget → `429` + `Retry-After`. This is independent of the global
`[ratelimit]`.

---

### Response-phase rules (`phase = "response"`)

By default rules run in the **request** phase (before forwarding). Set
`phase = "response"` to run a rule **after** the upstream responds, matching on
the response. Response-phase rules may use only these fields — `status`,
`resp_header` (+`name`), `resp_body`, `ip`, `path`, `counter` — and only
`block`/`log`/`incr` actions. A `block` replaces the upstream reply with the
rule's status/msg.

`status`/`resp_header` are always available (cheap; no buffering). `resp_body`
is more expensive: B.U.D.U buffers the upstream body before forwarding it, so it
only does this when a `resp_body` rule exists **and** the response Content-Type
is in [`inspect.response_content_types`](CONFIGURATION.md) **and** the body fits
`limits.max_inspect_body`. Larger or non-inspectable responses stream
unbuffered (so a `resp_body` rule simply doesn't match them — `status`/header
rules still apply). A body that overruns the cap mid-stream, once buffering has
begun, fails closed with `502`.

```toml
# replace upstream 5xx with a generic error (don't leak stack traces)
[[rule]]
id = "mask-5xx"
phase = "response"
action = "block"
status = 502
msg = "upstream error"
when = [ { field = "status", op = "ge", value = "500" } ]

# withhold responses that appear to leak a 16-digit card number (PAN)
[[rule]]
id = "block-pan-leak"
phase = "response"
action = "block"
status = 502
msg = "response withheld (possible data leak)"
when = [ { field = "resp_body", op = "regex", value = "\\b(?:\\d[ -]*?){16}\\b" } ]

# count auth failures per IP on the response, then block on the next request
[[rule]]
id = "count-auth-fail"
phase = "response"
action = "incr"
counter = "authfail"
ttl_secs = 600
when = [ { field = "status", op = "eq", value = "401" } ]

[[rule]]
id = "block-credential-stuffing"
action = "block"          # request phase: checks the counter set by the response rule
status = 429
when = [ { field = "counter", name = "authfail", op = "gt", value = "20" } ]
```

### Stateful rules (`incr` + `counter`)

`incr` bumps a named per-client-IP counter (with a TTL window via `ttl_secs`);
`field = "counter"` reads it. Together they enable cross-request detection like
brute force or scanning — count events in one rule, act on the total in another.
Counters survive rule hot-reloads and self-expire. Put the `incr` rule **before**
the rule that reads the counter so the current request is included.

```toml
# bump "login" each time this IP POSTs /login (5-min window)
[[rule]]
id = "count-login"
action = "incr"
counter = "login"
ttl_secs = 300
when = [
  { field = "path",   op = "eq", value = "/login" },
  { field = "method", op = "eq", value = "POST" },
]

# block once more than 10 attempts within the window
[[rule]]
id = "block-bruteforce"
action = "block"
status = 429
msg = "too many login attempts"
when = [ { field = "counter", name = "login", op = "gt", value = "10" } ]
```

> Counters are keyed per client IP and are approximate under heavy concurrency
> (a rare lost increment) — fine for security thresholds. `budu_counters` on
> `/metrics` shows the number of live counter entries.

### Time-window rules (`time` + `time_between`)

`op = "time_between"` matches when the **current time of day** falls inside a
window. Use it for business-hours access, maintenance windows, or
time-restricted endpoints.

- `value = "HH:MM-HH:MM"` — the window (24-hour clock; `.` also works as the
  separator, so `23.59` is accepted). A `start > end` window **wraps past
  midnight** (e.g. `"22:00-06:00"` = 22:00 through 06:00 next day).
- `tz = "+HH:MM"` — the timezone the window is expressed in (e.g. `"+08:00"`,
  `"-05:30"`). The server clock is read in UTC and shifted by this offset. If
  omitted, the per-rule `tz` falls back to the global **`[server] timezone`**
  (which itself defaults to UTC) — so set the timezone once in config instead of
  on every rule, and override per-rule only when needed.
- The op matches when the time is **inside** the window, so to **block outside**
  the window add `negate = true`.

```toml
# Allow the app only 08:00–23:59 (tz from [server] timezone); block outside it.
[[rule]]
id = "business-hours-only"
action = "block"
status = 403
msg = "service available 08:00-23:59 only"
when = [
  { field = "time", op = "time_between", value = "08:00-23:59", negate = true },
]
```

### Day-of-week (`day` + `day_of_week`)

`op = "day_of_week"` matches when the current **day of week** is in a set/range.
`value` is a comma-separated list of day names and/or **inclusive ranges**
(`Sun`,`Mon`,…,`Sat`, case-insensitive; full names work too). Ranges **wrap**,
so `"Fri-Mon"` = Fri, Sat, Sun, Mon. It uses the same timezone resolution as
`time_between` (per-rule `tz`, else `[server] timezone`).

```toml
# Closed on weekends
[[rule]]
id = "weekends-closed"
action = "block"
status = 403
when = [ { field = "day", op = "day_of_week", value = "Sat,Sun" } ]
```

**Combining day + time.** Conditions inside one rule are AND-ed, so to enforce
"open **Mon–Fri 09:00–18:00**" you block the two ways a request can be *outside*
that window — on a weekend, **or** off-hours on a weekday — with two rules:

```toml
[[rule]]                       # any weekend → closed
id = "closed-weekends"
action = "block"
when = [ { field = "day", op = "day_of_week", value = "Mon-Fri", negate = true } ]

[[rule]]                       # weekday but outside 09:00–18:00 → closed
id = "closed-offhours"
action = "block"
when = [
  { field = "day",  op = "day_of_week", value = "Mon-Fri" },
  { field = "time", op = "time_between", value = "09:00-18:00", negate = true },
]
```

To **rate-limit** rather than block off-hours, use `action = "rate_limit"` on the
same conditions. The check is on the **server's** clock shifted by `tz` — set the
timezone to match the audience you're gating.

## Examples

**Lock an area to an internal network**

```toml
[[rule]]
id = "admin-internal-only"
action = "block"
status = 403
msg = "admin area is internal-only"
when = [
  { field = "path", op = "starts_with", value = "/admin" },
  { field = "ip",   op = "cidr",        value = "10.0.0.0/8" },   # block 10.x; adjust to your policy
]
```

**Block scanner user-agents (case-insensitive)**

```toml
[[rule]]
id = "block-scanners"
action = "block"
when = [
  { field = "header", name = "User-Agent", op = "regex", value = "(?i)(sqlmap|nikto|nmap|masscan)" },
]
```

**Reject odd methods**

```toml
[[rule]]
id = "block-weird-methods"
action = "block"
status = 405
when = [ { field = "method", op = "in", values = ["TRACE", "TRACK", "CONNECT"] } ]
```

**Whitelist health checks past all inspection**

```toml
[[rule]]
id = "allow-healthz"
action = "allow"
when = [ { field = "path", op = "eq", value = "/healthz" } ]
```

**Low-false-positive SQLi on a specific arg** (needs `--features libinjection`)

```toml
[[rule]]
id = "sqli-libinjection"
action = "block"
when = [
  { field = "query", op = "detect_sqli", transform = ["url_decode"] },
]
```

**Open-redirect guard on a specific parameter**

```toml
[[rule]]
id = "open-redirect"
action = "block"
when = [
  { field = "arg", name = "next", op = "regex", value = "(?i)^https?://" },
]
```

**Block a suspicious parameter name, or too many params**

```toml
[[rule]]
id = "suspicious-param"
action = "block"
when = [ { field = "arg_names", op = "in", values = ["cmd", "exec", "system"] } ]

[[rule]]
id = "param-flood"
action = "block"
when = [ { field = "args_count", op = "gt", value = "100" } ]
```

**Block oversized uploads by header**

```toml
[[rule]]
id = "max-upload"
action = "block"
status = 413
when = [ { field = "header", name = "Content-Length", op = "gt", value = "10485760" } ]
```

**Per-route throttle**

```toml
[[rule]]
id = "throttle-login"
action = "rate_limit"
rps = 5
burst = 10
when = [
  { field = "path",   op = "starts_with", value = "/login" },
  { field = "method", op = "eq",          value = "POST" },
]
```

**Observe before enforcing** — deploy as `log`, watch the metric, then promote:

```toml
[[rule]]
id = "watch-export"
action = "log"
when = [ { field = "path", op = "contains", value = "/export" } ]
```

`budu_rule_log_matches_total` on `/metrics` counts how often `log` rules fire.
When you're confident it only matches what you intend, switch `action` to
`block`.

---

## Tips

- **Country rules** require `--features geoip` and `geoip.enabled = true` with a
  DB; otherwise `field = "country"` never matches.
- **Body rules** only see the body when it was buffered — ensure the content type
  is in `[inspect] content_types` and within `max_inspect_body`.
- Run `budu ... check` after editing; it reports `rules=N` and rejects invalid
  rules (unknown field/op, `cidr` on a non-IP field, `rate_limit` with `rps = 0`,
  a condition list that's empty, a bad regex/status).
- Ordering matters: put broad `allow` whitelists first, specific `block`s next.
