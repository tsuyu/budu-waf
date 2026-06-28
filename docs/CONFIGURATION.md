# Configuration reference

B.U.D.U is configured with a single TOML file (default `config/budu.toml`,
override with `-c/--config`). Validate any config without starting the proxy:

```bash
budu --config /path/to/budu.toml check
```

`check` parses + validates the config **and** compiles `rules.toml` /
`signatures.toml`, so authoring mistakes surface before deploy.

**Mandatory sections:** `[server]`, `[limits]`, `[ratelimit]`, `[log]`.
All other sections have defaults and may be omitted.

---

## `[server]`

| Key | Type | Default | Description |
|---|---|---|---|
| `listen` | socket addr | — (required) | Address B.U.D.U binds. Keep it on `127.0.0.1` so only the edge proxy can reach it. |
| `upstream` | URL | — (required) | Backend base URL, `http(s)://host[:port]`. Must include a host. |
| `client_ip_header` | string | — (required) | Header carrying the real client IP, set by the trusted edge (e.g. `X-Real-IP`). |
| `trusted_peer` | CIDR | — (required) | Only when the socket peer is inside this CIDR is `client_ip_header` trusted; otherwise the socket IP is used. Prevents header spoofing. |
| `on_error` | `closed` \| `open` | `closed` | Behaviour when an inspection stage **panics**: fail-closed (deny, `500`) or fail-open (skip the stage). |
| `enforcement` | `block` \| `detect` | `block` | `detect` = **detection-only**: evaluate every layer and log/meter what it *would* block, but forward the request anyway. Resource limits (rate-limit `429`, body-size `413`) stay enforced in both modes. |
| `upstream_timeout_secs` | integer > 0 | `30` | Max wait for the backend before answering `504`. |
| `timezone` | offset string | `""` (UTC) | Default timezone for `time_between` rules, e.g. `"+08:00"`, `"-05:30"`. A per-rule `tz` overrides it. Invalid values are rejected at startup / `check`. |

The `listen` address is read once at startup; changing it needs a restart.
`upstream`, `limits`, `inspect`, and the rule/signature/blocklist sources all
reload live on `SIGHUP`.

## `[limits]`

| Key | Type | Default | Description |
|---|---|---|---|
| `max_uri_len` | integer > 0 | — (required) | Max length of path + query; longer → `414`. |
| `max_header_count` | integer | — (required) | Max number of request headers; more → `431`. |
| `max_inspect_body` | size string | — (required) | Largest body buffered for inspection. Over this on an inspectable body → `413`. Accepts `"1MiB"`, `"512KiB"`, `"2MB"`, or a byte count. |

Size units: `B`, `KB`/`MB`/`GB` (decimal, ×1000) and `KiB`/`MiB`/`GiB` (binary,
×1024). Bare numbers are bytes.

## `[inspect]`

| Key | Type | Default | Description |
|---|---|---|---|
| `content_types` | array of strings | `[]` | Media-type prefixes whose **request** bodies are buffered and inspected. **Empty = no body inspection** (a warning is logged at startup). |
| `response_content_types` | array of strings | `text/html`, `application/json`, `application/xml`, `text/xml`, `text/plain` | Media-type prefixes whose **response** bodies may be buffered for `resp_body` rules. Only consulted when a `resp_body` rule exists; non-listed types (e.g. binary downloads) always stream unbuffered. |

Matching is on the media-type prefix, so `application/json` also matches
`application/json; charset=utf-8`. Bodies of non-`{POST,PUT,PATCH}` requests, or
of non-listed content types, stream through untouched. Response-body buffering
is bounded by `limits.max_inspect_body` (shared with request bodies); a response
that overruns the cap once buffering has started fails closed with `502`.

## `[ratelimit]`

Global per-client-IP token bucket (the rate-limit pipeline stage).

| Key | Type | Default | Description |
|---|---|---|---|
| `requests_per_sec` | integer > 0 | — (required) | Sustained rate per IP. |
| `burst` | integer | — (required) | Bucket capacity (allowed burst). `0` falls back to `requests_per_sec`. |
| `ttl_secs` | integer | — (required) | Idle time before a per-IP bucket is evicted. |

Over budget → `429` with a `Retry-After` header. Per-route throttles are also
possible as custom `rate_limit` rules — see [RULES.md](RULES.md).

## `[reputation]`

CIDR blocklist checked against the resolved client IP (first pipeline stage),
plus a trusted-IP allowlist.

| Key | Type | Default | Description |
|---|---|---|---|
| `blocklist` | array of CIDRs | `[]` | Inline entries, e.g. `["203.0.113.0/24", "10.0.0.5/32"]`. |
| `blocklist_file` | path | `""` | Local file, one CIDR or bare IP per line; `#` comments and blank lines ignored. |
| `blocklist_urls` | array of URLs | `[]` | External HTTP(S) feeds in the same line format. **Requires `--features remote-blocklist`.** |
| `refresh_secs` | integer | `300` | How often to re-fetch `blocklist_urls`. `0` = fetch once at startup. |
| `allowlist` | array of CIDRs | `[]` | **Trusted IPs that fully bypass inspection** — see below. |
| `allowlist_file` | path | `""` | Local file (same format) merged into `allowlist`. |

The three blocklist sources are merged. A match → `403`. Bad lines and failed
feeds are logged and skipped (one bad entry/feed never breaks the gate).

### Allowlist (trusted IPs)

A client whose resolved IP matches `allowlist`/`allowlist_file` **fully bypasses
the pipeline**: no blocklist, GeoIP, rate-limit, custom rules, signatures, or
response-phase inspection — the request is forwarded straight upstream and the
response streamed back untouched. This is **stronger than an `allow` rule**
(which only short-circuits the request phase) and **overrides the blocklist** if
an IP appears in both. Reserve it for sources you fully trust (health checkers,
internal scanners, partner integrations). Each bypass increments
`budu_whitelisted_total`; the gauge `budu_allowlist_entries` reports the list
size. Reloads on `SIGHUP`.

## `[scoring]`

CRS-style anomaly scoring for custom rules (see [RULES.md](RULES.md#anomaly-scoring-score)).

| Key | Type | Default | Description |
|---|---|---|---|
| `threshold` | integer | `0` | Block when a request's accumulated `score`-rule points reach this. `0` disables scoring. |
| `status` | integer | `403` | HTTP status for an anomaly block. |
| `msg` | string | `"anomaly score threshold exceeded"` | Reason text (the actual score is appended). |

## `[metrics]`

| Key | Type | Default | Description |
|---|---|---|---|
| `listen` | socket addr | unset (disabled) | Admin endpoint for `/metrics` + `/healthz`. **Must be a loopback address** (validated) — it is unauthenticated and must not be client-facing. |

## `[paths]`

| Key | Type | Default | Description |
|---|---|---|---|
| `rules` | path | `""` | Custom rules file ([RULES.md](RULES.md)). Empty = no custom rules. |
| `signatures` | path | `""` | Attack signatures file ([SIGNATURES.md](SIGNATURES.md)). **Empty = use the built-in set.** A path **replaces** the built-ins. |

## `[log]`

| Key | Type | Default | Description |
|---|---|---|---|
| `format` | string | `json` | Currently JSON to stdout. |
| `audit_file` | path | `""` | When set, block/rate-limit (`audit`-target) events go to this file instead of stdout, keeping the audit trail separate from operational logs. |

This section is **required** (it may be empty: `[log]` with no keys uses the
defaults).

## `[geoip]`

Country-based filtering. **Requires `--features geoip`** and a MaxMind
`GeoLite2-Country.mmdb`. When the feature is absent, `enabled = true` only logs a
warning.

| Key | Type | Default | Description |
|---|---|---|---|
| `enabled` | bool | `false` | Turn the GeoIP stage on. |
| `db_path` | path | `""` | Path to the `.mmdb`. Required when enabled; a missing file fails startup. |
| `allow_countries` | array | `[]` | ISO-3166 codes. If non-empty, an **allowlist**: only these pass; unknown-origin requests are blocked. |
| `block_countries` | array | `[]` | ISO-3166 codes to block (used when `allow_countries` is empty). Unknown origin is allowed (fail-open). |

The resolved country is also stamped on the request context and included in
custom-rule matching (`field = "country"`).

---

## Validation rules (enforced by `check` and at startup)

- `upstream` must be `http`/`https` and include a host.
- `client_ip_header` must be non-empty.
- `max_uri_len > 0`, `requests_per_sec > 0`, `upstream_timeout_secs > 0`.
- `metrics.listen`, if set, must be a loopback address.
- `rules.toml` / `signatures.toml`, if referenced, must compile.

## Live reload vs restart

| Change | How it applies |
|---|---|
| `rules`, `signatures`, `reputation`, most of `server`/`limits`/`inspect` | `SIGHUP` (atomic, no dropped connections) |
| `blocklist_urls` content | `SIGHUP` or the `refresh_secs` timer |
| `server.listen`, `metrics.listen` | restart |
