# B.U.D.U — Dev & Deployment Guide

**Blocklist & Unified Defence Utility** — a reverse-proxy WAF in Rust, inline between Apache (Ubuntu reverse proxy) and the application backend (Windows).

> Start in **pass-through mode**, confirm the whole chain + `X-Real-IP` work end-to-end, then enable inspection layers one at a time.

---

## 1. Deployment topology

```
                          UBUNTU box (192.168.10.10)                 WINDOWS box (192.168.10.20)
        TLS         ┌──────────────────────────────┐         ┌────────────────────────────────────┐
Client ─────► front Apache :443 ──localhost──► B.U.D.U ──LAN──► backend Apache :8080 ──localhost──► App
                                  127.0.0.1:8088        :8080                          127.0.0.1:9000
              └──────────────────────────────┘         └────────────────────────────────────┘
```

| Hop | Host | Bind | Role |
|---|---|---|---|
| front Apache | Ubuntu | `:443` | TLS termination, forwards to B.U.D.U |
| **B.U.D.U** | Ubuntu | `127.0.0.1:8088` | WAF gate — inspect, then forward |
| backend Apache | Windows | `192.168.10.20:8080` | accepts only from Ubuntu box |
| App (PHP-FPM / Axum) | Windows | `127.0.0.1:9000` | the real application |

**Only allowed traffic crosses to Windows.** Blocked/rate-limited requests are answered by B.U.D.U on Ubuntu and never reach the app.

---

## 2. The three bypass locks (do these or the gate is fake)

1. **B.U.D.U binds `127.0.0.1`** on Ubuntu → only front Apache reaches it.
2. **Windows Apache: `Require ip 192.168.10.10` + Windows Firewall** inbound rule allowing `:8080` only from the Ubuntu box → no other LAN host hits the backend directly.
3. **Windows app binds `127.0.0.1:9000`** → only Windows Apache reaches it.

Result: `front Apache → BUDU → backend Apache → app` is the **only** path in.

---

## 3. Config — front Apache (Ubuntu, `:443`)

```apache
<VirtualHost *:443>
    ServerName live.org
    SSLEngine on
    # SSLCertificateFile / SSLCertificateKeyFile ...

    # Faces clients → REMOTE_ADDR is the real client. Emit one clean header:
    RequestHeader set X-Real-IP "expr=%{REMOTE_ADDR}"
    ProxyPreserveHost On
    ProxyPass        / http://127.0.0.1:8088/
    ProxyPassReverse / http://127.0.0.1:8088/
</VirtualHost>
```
> If a load balancer sits in front of this Apache, add `mod_remoteip` here to resolve the real client first.

---

## 4. Config — backend Apache (Windows, `:8080`)

```apache
Listen 192.168.10.20:8080
<VirtualHost *:8080>
    ServerName app.example.org

    # LOCK #2: only the Ubuntu WAF box may connect
    <Location />
        Require ip 192.168.10.10
    </Location>

    # WAF box is the trusted proxy → resolve real client for app + logs
    RemoteIPHeader X-Real-IP
    RemoteIPTrustedProxy 192.168.10.10

    ProxyPreserveHost On
    ProxyPass        / http://127.0.0.1:9000/
    ProxyPassReverse / http://127.0.0.1:9000/
</VirtualHost>
```
> Also add a Windows Firewall inbound rule: allow TCP 8080 **only** from 192.168.10.10.

---

## 5. Config — B.U.D.U (`config/budu.toml`)

```toml
[server]
listen           = "127.0.0.1:8088"            # LOCK #1: localhost only
upstream         = "http://192.168.10.20:8080" # the Windows backend Apache
client_ip_header = "X-Real-IP"                 # single pre-resolved value
trusted_peer     = "127.0.0.1/32"              # only front Apache
on_error         = "closed"                    # closed | open

[limits]
max_uri_len      = 8192
max_header_count = 100
max_inspect_body = "1MiB"

[inspect]
content_types = ["application/json", "application/x-www-form-urlencoded", "multipart/form-data"]

[ratelimit]
requests_per_sec = 50
burst            = 100
ttl_secs         = 300

[paths]
rules      = "config/rules.toml"
signatures = "config/signatures.toml"

[log]
format     = "json"
audit_file = "/var/log/budu/audit.log"

[geoip]
enabled = false
db_path = ""
```

---

## 6. Workspace layout

```
budu/
├── Cargo.toml                  # [workspace]
├── config/budu.toml
├── crates/
│   ├── budu/                   # bin: main.rs + CLI (clap), wires + runs server
│   ├── budu-common/            # RequestCtx, WafDecision, ClientInfo, errors
│   ├── budu-config/            # TOML load + validate + hot-reload
│   ├── budu-proxy/             # hyper server + upstream client, body buffering
│   ├── budu-pipeline/          # tower Layer stack (the waf-core)
│   ├── budu-parser/            # decode / normalize
│   ├── budu-rules/             # rule model + DSL eval
│   ├── budu-signatures/        # aho-corasick + RegexSet, ArcSwap<SignatureDb>
│   ├── budu-ratelimit/         # governor + TTL-evicting map
│   ├── budu-reputation/        # CIDR blocklist + optional GeoIP
│   └── budu-logging/           # tracing + audit log
```

---

## 7. Core types (define first — `budu-common`)

```rust
pub struct RequestCtx<'a> {
    pub method:     &'a Method,
    pub path:       &'a str,
    pub query:      Option<&'a str>,
    pub headers:    &'a HeaderMap,
    pub client:     ClientInfo,
    pub body:       BodyState,
    pub normalized: NormalizedCache, // lazily-filled reused buffers
}

pub struct ClientInfo { pub ip: IpAddr, pub geo: Option<CountryCode> }

pub enum BodyState { NotBuffered, Buffered(Bytes), TooLarge }

pub enum WafDecision {
    Allow,
    Block { rule_id: Arc<str>, status: StatusCode, reason: Arc<str> },
    RateLimited { retry_after_secs: u32 },
}
```
Each stage returns `ControlFlow<WafDecision, ()>` so a hit **short-circuits** the rest.

---

## 8. Request pipeline (cheap → expensive, tower layers)

```
1. INGEST       parse head; client IP = X-Real-IP header (trusted_peer only)
2. REPUTATION   CIDR blocklist            → Block        (fast)
3. RATELIMIT    governor, keyed on IP     → 429
4. SANITY       method / URI len / header count / Content-Length
5. NORMALIZE    percent-decode, case-fold into a REUSED buffer
6. BODY GATE    buffer body ONLY if {POST,PUT,PATCH} + inspectable type + ≤ max
7. SIGNATURES   aho-corasick literals  → RegexSet on survivors only
8. FORWARD      Allow → proxy to Windows backend (pooled keepalive)
9. LOG          decision → tracing; blocks → audit log
```

`Allow` ⇒ forward to `upstream`. `Block`/`RateLimited` ⇒ B.U.D.U answers the client; backend never sees it. Responses **stream back** (inspect status + headers only, no body buffering by default).

---

## 9. Shared state & hot reload

| State | Type | Reload |
|---|---|---|
| Config | `ArcSwap<Config>` | SIGHUP |
| Signature DB | `ArcSwap<SignatureDb>` | bg compile + atomic swap, lock-free reads |
| Rules | `ArcSwap<RuleSet>` | same |
| Rate-limit buckets | `moka::sync::Cache` (TTL) | self-evicting |

A **supervisor task** (Tokio + `CancellationToken` + `tokio::select!`) owns file-watch/recompile, rate-limit GC, metrics flush, and graceful shutdown on SIGTERM. Hot-path reads = `ArcSwap::load()` (cheap `Arc` clone), never a lock.

---

## 10. Dependencies (`budu` crate)

```toml
[dependencies]
hyper           = { version = "1", features = ["http1", "server", "client"] }
hyper-util      = { version = "0.1", features = ["tokio", "server-auto", "client-legacy"] }
http-body-util  = "0.1"
bytes           = "1"
tower           = "0.5"
tokio           = { version = "1", features = ["rt-multi-thread","net","io-util","time","macros","signal"] }
aho-corasick    = "1"
regex           = { version = "1", default-features = false, features = ["std","perf"] } # no unicode
governor        = "0.6"
moka            = { version = "0.12", features = ["sync"] }
ipnet           = "2"
arc-swap        = "1"
tracing         = "0.1"
tracing-subscriber = { version = "0.3", features = ["json","env-filter"] }
serde           = { version = "1", features = ["derive"] }
toml            = "0.8"
clap            = { version = "4", features = ["derive"] }
thiserror       = "1"
anyhow          = "1"
maxminddb       = { version = "0.24", optional = true }  # feature "geoip"

[profile.release]
lto           = "thin"
codegen-units = 1
strip         = true
opt-level     = 3
# panic stays on UNWIND — never "abort" for an inline WAF
```
> Verify latest crate versions on crates.io before locking; the regex `unicode` feature is intentionally off (matching HTTP bytes).

---

## 11. systemd unit (Ubuntu) — `/etc/systemd/system/budu.service`

```ini
[Unit]
Description=B.U.D.U WAF
After=network.target

[Service]
Type=simple
User=budu
ExecStart=/opt/budu/budu --config /opt/budu/config/budu.toml
Restart=on-failure
RestartSec=2
# graceful reload of rules/signatures:
ExecReload=/bin/kill -HUP $MAINPID

[Install]
WantedBy=multi-user.target
```
```bash
sudo systemctl daemon-reload && sudo systemctl enable --now budu
```

---

## 12. Build order

1. **Pass-through proxy** — `budu-common` + `budu-config` + `budu-proxy`. Forward everything untouched. Confirm `X-Real-IP` + the full chain work. **Ship this first** — even a bare chokepoint is useful.
2. `budu-pipeline` skeleton with `catch_panic` + logging.
3. Add layers in order: reputation → ratelimit → sanity → normalize → body gate → signatures.
4. `ArcSwap` hot-reload + supervisor task.
5. Metrics (`/metrics` admin port) + audit log.
6. Optional: GeoIP feature, CRS-compatibility rule layer.

---

## 13. Verify before going live

```bash
# real client IP should appear in the Windows Apache access log (%a)
curl -v https://app.example.org/

# prove the bypass is CLOSED — run from any host that is NOT the Ubuntu WAF box:
curl -v http://192.168.10.20:8080/      # must be refused / 403

# after inspection is on — a probe should be blocked by BUDU, not the app:
curl -v "https://app.example..org/?q=' OR 1=1--"   # expect 403 from BUDU
```
If the second curl succeeds, **lock #2 is wrong — fix before launch.**

---

## Rust rules (house style)

- Never `unwrap()` / `expect()` on the request path → `?`, `match`, `thiserror`/`anyhow`.
- Keep `panic = "unwind"` + `catch_panic` so one bad request can't take the proxy (and the app) down.
- Borrow header values (`&str`); `bytes::Bytes` end-to-end; decode into reused buffers.
