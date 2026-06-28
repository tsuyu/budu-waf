# B.U.D.U

**Blocklist & Unified Defence Utility** — an inline reverse-proxy Web Application
Firewall written in Rust.

B.U.D.U sits between your edge (e.g. Apache/nginx doing TLS) and your application
backend. It inspects every request through a layered pipeline and either forwards
it upstream or answers the client itself (block / rate-limit). Allowed responses
stream straight back; blocked requests never reach the app.

```
            TLS                         inspect + forward
client ─────────► edge proxy ─────────► B.U.D.U ─────────► backend ─► app
                  (Apache :443)         (127.0.0.1:8088)   (:8080)
```

> Deployment topology, the three "bypass locks", and edge/backend proxy configs
> are documented in [BUDU-DEV.md](BUDU-DEV.md). This README covers building,
> configuring, and operating the WAF itself.

---

## Features

- **Reverse proxy** over HTTP/1.1 with pooled keep-alive upstream connections and
  a bounded **upstream timeout** (→ `504`).
- **Layered inspection pipeline**, cheapest-first, short-circuiting on the first
  hit:
  1. **Reputation** — CIDR blocklist (inline, file, and optional remote feeds),
     plus a trusted-IP **allowlist** that fully bypasses inspection.
  2. **GeoIP** *(optional feature)* — country allow/block + geo stamping.
  3. **Rate limit** — per-client-IP token bucket.
  4. **Sanity** — URI length, header count, well-formed `Content-Length`.
  5. **Normalize** — percent-decode + case-fold for evasion-resistant matching.
  6. **Body gate** — buffer the body only for inspectable `{POST,PUT,PATCH}`.
  7. **Custom rules** — your own field/operator/action logic (see below).
  8. **Signatures** — built-in SQLi/XSS/LFI/RCE patterns (aho-corasick + RegexSet),
     extensible via `signatures.toml`.
- **Two complementary rule systems**: attack-pattern **signatures** and
  user-authored **custom rules** (block / allow / log / rate_limit / score / incr),
  with per-condition **transforms** (url_decode, lowercase, …), **negation**,
  numeric comparisons, optional **libinjection** SQLi/XSS operators, per-arg/cookie
  targeting (reaching into **JSON & multipart** bodies), **CRS-style anomaly
  scoring**, **stateful per-IP counters**, **time- & day-of-week rules**
  (business-hours / weekday-only / maintenance-window access control), and
  **response-phase rules** (match on upstream status, headers, *and body* — e.g.
  mask 5xx errors or withhold responses that leak sensitive data).
- **CRS import**: convert ModSecurity / OWASP Core Rule Set `SecRule` files into
  budu rules with `budu import-crs` (see [docs/CRS-IMPORT.md](docs/CRS-IMPORT.md)).
- **Detection-only mode** (`enforcement = "detect"`) to roll out rules safely —
  log/meter what *would* block without enforcing.
- **Hot reload** of rules, signatures, blocklist and config on `SIGHUP` — no
  restart, lock-free reads (`ArcSwap`).
- **Auto-refreshing remote blocklist feeds** *(optional feature)*.
- **Observability**: structured JSON logs, a separate **audit log** sink, and a
  Prometheus **`/metrics`** + **`/healthz`** admin endpoint.
- **Fail2Ban integration** *(optional `fail2ban` feature)*: the audit log records
  the *resolved* client IP, so Fail2Ban can escalate repeat offenders to a WAF or
  firewall ban — drop-in filter/jail/action in [contrib/fail2ban/](contrib/fail2ban/),
  plus `ban`/`unban`/`bans` CLI and auto-expiring bans (see
  [docs/FAIL2BAN.md](docs/FAIL2BAN.md)).
- **Resilient by design**: every inspection stage runs under `catch_unwind`; one
  bad request can't take the proxy (or the app) down. Fail-closed or fail-open is
  configurable.

---

## Quick start

```bash
# 1. Build (release)
cargo build --release

# 2. Validate your config (also compiles rules + signatures)
./target/release/budu --config config/budu.toml check

# 3. Run
./target/release/budu --config config/budu.toml run
```

`budu` reads `config/budu.toml` by default; override with `-c/--config`.

### CLI

```
budu [OPTIONS] [COMMAND]

Commands:
  run         Run the WAF proxy (default if omitted)
  check       Load + validate config, compile rules/signatures, then exit
  import-crs  Convert ModSecurity / OWASP CRS SecRule files to a budu rules TOML
  ban         Add an IP/CIDR to the blocklist file        [--features fail2ban]
  unban       Remove an IP/CIDR from the blocklist file    [--features fail2ban]
  bans        List blocklist-file entries with remaining TTL [--features fail2ban]

Options:
  -c, --config <CONFIG>   Path to the TOML config [default: config/budu.toml]
  -h, --help              Print help
  -V, --version           Print version
```

Set log verbosity with the `BUDU_LOG` env var (`error|warn|info|debug|trace`, or
full [`tracing` EnvFilter](https://docs.rs/tracing-subscriber/) syntax). Default
is `info`.

---

## Build features

Optional capabilities are gated behind Cargo features so the default binary stays
lean (no TLS / GeoIP dependencies):

| Feature | Enables | Pulls in |
|---|---|---|
| *(default)* | Full proxy + pipeline + custom rules + signatures + metrics | — |
| `geoip` | Country allow/block via a MaxMind DB | `maxminddb` |
| `remote-blocklist` | Fetch + auto-refresh external blocklist feeds over HTTP(S) | `reqwest` (rustls) |
| `libinjection` | `detect_sqli` / `detect_xss` rule operators (low false positives) | `libinjectionrs` (pure Rust) |
| `fail2ban` | `ban`/`unban`/`bans` CLI, pidfile + `--reload`, auto-expiring `until=` blocklist entries | — |
| `full` | Convenience: all of the above in one flag | (their deps) |

```bash
cargo build --release --features geoip
cargo build --release --features fail2ban
cargo build --release --features "geoip,remote-blocklist,fail2ban"
cargo build --release --features full      # everything (recommended for release builds)
```

Enabling a config option whose feature isn't compiled in (e.g. `geoip.enabled`
without `--features geoip`) logs a warning and is ignored — it never silently
half-works.

---

## Configuration

A minimal config requires the `[server]`, `[limits]`, `[ratelimit]` and `[log]`
sections; everything else has defaults. See
[docs/CONFIGURATION.md](docs/CONFIGURATION.md) for every key, and
[config/budu.toml](config/budu.toml) for an annotated example.

```toml
[server]
listen           = "127.0.0.1:8088"            # bind localhost only
upstream         = "http://192.168.10.20:8080" # your backend
client_ip_header = "X-Real-IP"                 # real client IP, set by the edge
trusted_peer     = "127.0.0.1/32"              # only the edge may set that header
on_error         = "closed"                    # fail closed | open on inspection error
upstream_timeout_secs = 30

[limits]
max_uri_len      = 8192
max_header_count = 100
max_inspect_body = "1MiB"

[inspect]
content_types = ["application/json", "application/x-www-form-urlencoded", "multipart/form-data"]
# Response Content-Types buffered for `resp_body` rules (only when such a rule
# exists). Defaults to common text/markup types; binary downloads never buffer.
response_content_types = ["text/html", "application/json", "text/plain", "application/xml", "text/xml"]

[ratelimit]
requests_per_sec = 50
burst            = 100
ttl_secs         = 300

[metrics]
listen = "127.0.0.1:9090"          # admin /metrics + /healthz (loopback only)

[paths]
rules      = "config/rules.toml"
signatures = ""                    # "" = built-in attack signatures

[log]
format     = "json"
audit_file = "/var/log/budu/audit.log"
```

---

## Rules vs signatures

B.U.D.U has two rule systems that work together:

- **Signatures** (`signatures.toml`, or the built-in set) — pattern matching for
  *attacks* (SQLi, XSS, traversal, RCE) over the normalized request. Start here
  for generic protection. See [docs/SIGNATURES.md](docs/SIGNATURES.md).
- **Custom rules** (`rules.toml`) — *your* business logic: match on method, path,
  query, headers, body, IP or country, and `block` / `allow` / `log` /
  `rate_limit`. See [docs/RULES.md](docs/RULES.md).

Example custom rule:

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

Both reload live on `SIGHUP`.

---

## Operating

- **Hot reload**: `kill -HUP <pid>` (or `systemctl reload budu`) re-reads config,
  rules, signatures and blocklist atomically. A broken file is logged and the
  running ruleset is kept.
- **Graceful shutdown**: `SIGTERM`/`Ctrl-C` stops accepting and exits cleanly.
- **Metrics**: `curl http://127.0.0.1:9090/metrics` (Prometheus) and `/healthz`.
- **Audit log**: blocks/rate-limits are written as JSON to `log.audit_file`
  (separate from operational stdout logs).

Full runbook — systemd unit, signals, metrics reference, troubleshooting, and a
go-live security checklist — in [docs/OPERATIONS.md](docs/OPERATIONS.md).

---

## Workspace layout

```
budu/
├── Cargo.toml                  # workspace
├── config/                     # budu.toml, rules.toml (+ optional signatures.toml)
├── docs/                       # CONFIGURATION, RULES, SIGNATURES, OPERATIONS
└── crates/
    ├── budu/                   # bin: CLI, wiring, supervisor task
    ├── budu-common/            # core types (RequestCtx, WafDecision, Stage, Metrics)
    ├── budu-config/            # TOML load + validate
    ├── budu-proxy/             # hyper server + upstream client + admin endpoint
    ├── budu-pipeline/          # the Stage stack + hot-reload handle
    ├── budu-parser/            # percent-decode / case-fold normalize
    ├── budu-rules/             # custom rule DSL (model + eval)
    ├── budu-signatures/        # aho-corasick + RegexSet attack signatures
    ├── budu-ratelimit/         # governor + moka TTL limiter
    └── budu-reputation/        # CIDR blocklist (+ optional GeoIP / remote feeds)
```

## Development

```bash
cargo build                     # debug build, default features
cargo test                      # unit tests across the workspace
cargo clippy --workspace --all-targets
cargo build --release --features "geoip,remote-blocklist"
```

House rules: no `unwrap`/`expect` on the request path; `panic = "unwind"` is kept
so `catch_unwind` can contain a bad request; borrow header values, `bytes::Bytes`
end-to-end.

## License

MIT — see [LICENSE](LICENSE).
