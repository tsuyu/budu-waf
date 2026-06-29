# Operations runbook

Running, observing, and maintaining B.U.D.U in production. For the network
topology and edge/backend proxy setup, see [BUDU-DEV.md](../BUDU-DEV.md).

---

## Install

```bash
cargo build --release                       # or with --features "geoip,remote-blocklist"
sudo install -Dm755 target/release/budu /opt/budu/budu
sudo install -Dm644 config/budu.toml      /opt/budu/config/budu.toml
sudo install -Dm644 config/rules.toml     /opt/budu/config/rules.toml
sudo useradd --system --no-create-home budu || true
sudo mkdir -p /var/log/budu && sudo chown budu /var/log/budu
```

Always validate before (re)starting:

```bash
/opt/budu/budu --config /opt/budu/config/budu.toml check
```

## systemd unit

`/etc/systemd/system/budu.service`:

```ini
[Unit]
Description=B.U.D.U WAF
After=network.target

[Service]
Type=simple
User=budu
ExecStart=/opt/budu/budu --config /opt/budu/config/budu.toml run
Environment=BUDU_LOG=info
Restart=on-failure
RestartSec=2
# graceful hot-reload of config/rules/signatures/blocklist:
ExecReload=/bin/kill -HUP $MAINPID

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now budu
sudo systemctl reload budu        # SIGHUP — hot reload
sudo systemctl status budu
```

---

## Signals

| Signal | Effect |
|---|---|
| `SIGHUP` (`systemctl reload`) | Re-read config + recompile rules/signatures + rebuild blocklist (incl. remote feeds) and swap atomically. On a broken file: logged, **running ruleset kept**. |
| `SIGTERM` / `Ctrl-C` (`systemctl stop`) | Graceful shutdown: stop accepting, exit cleanly. |

`listen` and `metrics.listen` changes require a full restart (the sockets are
bound once at startup).

---

## Observability

### Logs

Operational logs are JSON on stdout (captured by journald under systemd). Control
verbosity with `BUDU_LOG` (`error|warn|info|debug|trace`).

```bash
journalctl -u budu -f
journalctl -u budu -f -o cat | jq .          # pretty JSON
```

### Audit log

When `[log] audit_file` is set, **block / rate-limit decisions** are written there
as JSON (separate from operational logs), one event per line:

```json
{"timestamp":"…","level":"WARN","fields":{"message":"blocked","client_ip":"203.0.113.9",
 "method":"GET","path":"/p","rule_id":"sqli.union_select","status":403,
 "reason":"SQL injection: UNION SELECT"},"target":"audit"}
```

`rule_id` tells you exactly which signature/rule fired. Each line also carries a
`request_id` (see below). Rotate this file with `logrotate` (copytruncate, since
the process holds it open).

### Request correlation

Every request gets a correlation id — reused from the inbound
`[server] request_id_header` (default `X-Request-Id`) when it's a valid token, so
a trace begun at your edge continues through, otherwise freshly generated. The id
is:

- on the request's **operational log line** and every **audit event**
  (`request_id` field),
- **echoed on the response** (`X-Request-Id`) so the client/edge can correlate,
- **forwarded upstream**, so your backend logs the same id.

To follow one request end-to-end, grep the id across budu's logs, the audit file,
and the backend's logs.

> **On metrics:** Prometheus counters are *aggregate* — a unique per-request id
> must **not** become a label (unbounded cardinality melts a TSDB). Per-request
> correlation lives in logs/audit/traces; `/metrics` stays aggregate by design.

### Metrics

Enable `[metrics] listen` (loopback only) and scrape `/metrics` (Prometheus
text). `/healthz` returns `200 ok` for liveness probes.

| Metric | Type | Meaning |
|---|---|---|
| `budu_requests_total` | counter | All requests seen |
| `budu_allowed_total` | counter | Forwarded to the backend |
| `budu_blocked_total` | counter | Blocked (reputation/geo/sanity/rules/signatures/body-gate) |
| `budu_ratelimited_total` | counter | `429`s (global or per-rule) |
| `budu_upstream_errors_total` | counter | `502`/`504` upstream failures |
| `budu_would_block_total` | counter | Would-be blocks **forwarded** because `enforcement = detect` |
| `budu_whitelisted_total` | counter | Requests from allowlisted (trusted) IPs that bypassed inspection |
| `budu_rule_log_matches_total` | counter | `log`-action rule matches |
| `budu_signatures` | gauge | Loaded signature count |
| `budu_rules` | gauge | Loaded custom-rule count |
| `budu_blocklist_entries` | gauge | Blocklist size (inline+file+feeds) |
| `budu_allowlist_entries` | gauge | Allowlist (trusted-IP) size (inline+file) |
| `budu_rate_buckets` | gauge | Live per-IP rate-limit buckets |

```bash
curl -s http://127.0.0.1:9090/metrics
curl -s http://127.0.0.1:9090/healthz
```

---

## Tuning

- **Body inspection**: set `[inspect] content_types` to the types you actually
  serve. Empty = bodies are *not* scanned (a startup warning is logged). Keep
  `max_inspect_body` only as large as needed — bodies over it on an inspectable
  request are rejected with `413`.
- **Rate limits**: `[ratelimit]` is the global per-IP cap; add `rate_limit`
  custom rules for hot routes (e.g. `/login`). Watch `budu_rate_buckets` for
  memory under source-spoofing floods (capped at 1M buckets, TTL-evicted).
- **Upstream timeout**: tune `server.upstream_timeout_secs` to just above your
  backend's worst-case latency to free stuck connections (→ `504`).
- **Fail mode**: `server.on_error = "closed"` (default) denies on an inspection
  *panic*; `"open"` skips the broken stage. Keep `closed` for a security gate.

## Rolling out safely with detection-only mode

Set `server.enforcement = "detect"` to run the full pipeline **without blocking**:
every would-be block is logged (audit `message:"detected"`) and counted in
`budu_would_block_total`, but the request is forwarded. Use it to:

1. Deploy new rules/signatures and watch `budu_would_block_total` + the audit log
   for false positives against real traffic.
2. Add `allow` exceptions for any legitimate traffic that would be caught.
3. Flip to `enforcement = "block"` (a `SIGHUP` reload) once clean.

Resource controls — the rate-limit `429` and the body-size `413` — stay enforced
in detect mode; only WAF *verdicts* (reputation, geo, sanity, rules, signatures)
are downgraded to log-and-forward.

## Remote blocklist feeds (`--features remote-blocklist`)

```toml
[reputation]
blocklist_urls = ["https://example.com/threat-ips.txt"]
refresh_secs   = 300        # 0 = fetch once at startup
```

Feeds are fetched at startup, on the `refresh_secs` timer, and on `SIGHUP`, then
merged with `blocklist` + `blocklist_file`. Feed format = one CIDR/IP per line,
`#` comments allowed. A failed or malformed feed is logged and skipped — the
previous list stays in force. Watch `budu_blocklist_entries`.

## Fail2Ban

Fail2Ban can watch the audit log and escalate repeat offenders to a WAF or
firewall ban. The audit `client_ip` is the *resolved* client (from your edge
header), so the right attacker is banned even behind a proxy. Drop-in
filter/jail/action are in [`contrib/fail2ban/`](../contrib/fail2ban/); full
setup in [FAIL2BAN.md](FAIL2BAN.md). The recommended action writes bans into
`[reputation] blocklist_file` and `systemctl reload budu` (SIGHUP) — banning at
the WAF layer, which is what works in the standard edge-proxy topology.

## Manual bans (CLI) — `--features fail2ban`

Built with `--features fail2ban`, you can ban/unban by hand against the same
`[reputation] blocklist_file` (with the same auto-expiring `until=` format as
Fail2Ban):

```bash
budu -c /etc/budu/budu.toml ban 203.0.113.45 --for 1h --reload  # apply immediately
budu -c /etc/budu/budu.toml ban 203.0.113.0/24                  # permanent CIDR (apply on next reload)
budu -c /etc/budu/budu.toml bans                                # list entries + remaining TTL
budu -c /etc/budu/budu.toml unban 203.0.113.45 --reload
```

Durations: `30m`, `1h`, `7d`, `90s`, or a bare seconds count. Edits are atomic
and de-duplicated; timed bans auto-expire even without an explicit `unban`.

`--reload` signals the running proxy (`SIGHUP`) so the change takes effect at
once — it needs **`[server] pidfile`** set (so the CLI can find the process). If
the reload fails (proxy not running, stale pidfile) the edit is still written and
the CLI falls back to printing how to apply it. Without `--reload`, changes are
picked up on the next `SIGHUP` / refresh tick.

## GeoIP (`--features geoip`)

```toml
[geoip]
enabled = true
db_path = "/opt/budu/GeoLite2-Country.mmdb"
block_countries = ["CN", "RU"]      # or allow_countries = ["MY","SG"]
```

A missing DB path fails startup (fail-fast). Refresh the `.mmdb` out-of-band and
`SIGHUP` to reload. Without the feature compiled in, `enabled = true` only warns.

---

## Go-live checklist

- [ ] `budu check` passes (config + rules + signatures compile).
- [ ] B.U.D.U binds `127.0.0.1` (lock #1) — only the edge can reach it.
- [ ] Edge proxy sets `client_ip_header` from the real client and `trusted_peer`
      matches the edge's source IP.
- [ ] Backend only accepts connections from the B.U.D.U host (lock #2) and the
      app binds loopback (lock #3) — see [BUDU-DEV.md](../BUDU-DEV.md) §2.
- [ ] `metrics.listen` is loopback / firewalled (it's unauthenticated).
- [ ] `audit_file` set and rotated; journald retention configured.
- [ ] Probes verified: a real client IP appears in the backend log; an attack
      probe (`?q=%27%20OR%201%3D1--`) returns `403` from B.U.D.U; a request from a
      host that is **not** the WAF box to the backend is refused.

## Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| All requests `502` | Backend unreachable / wrong `upstream`. Check the backend and firewall. |
| Requests `504` | Backend slower than `upstream_timeout_secs`; raise it or fix the backend. |
| Real client IP wrong in logs | `trusted_peer` doesn't match the edge's source IP, so the header is ignored. |
| Bodies not blocked | Content type missing from `[inspect] content_types`, or body over `max_inspect_body`. |
| Country rules never match | `geoip` feature not built in, `enabled=false`, or DB missing. |
| Reload didn't take | Check logs for `reload failed` — a broken rules/signatures file keeps the old set; fix and `SIGHUP` again. |
| `metrics.listen must be a loopback address` at start | Move the admin endpoint to `127.0.0.1`. |
