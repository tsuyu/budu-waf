# Fail2Ban integration

B.U.D.U detects attacks at the application layer (rules, signatures, anomaly
scoring, rate limits) and records each block to its **audit log**. Fail2Ban
watches that log and escalates repeat offenders to a longer ban — either at the
WAF (B.U.D.U's own blocklist) or at the firewall.

Ready-to-use config lives in [`contrib/fail2ban/`](../contrib/fail2ban/):

```
contrib/fail2ban/
├── filter.d/budu.conf            # parses budu's JSON audit log → client IP
├── jail.d/budu.conf              # the jail (thresholds + action)
└── action.d/budu-blocklist.conf  # ban via budu's blocklist (app-layer)
```

## Why this is "seamless"

The audit log's `client_ip` is the **resolved** client IP — the value B.U.D.U
extracts from your edge's `client_ip_header` (e.g. `X-Real-IP`), not the TCP peer.
So Fail2Ban bans the *real* attacker even though B.U.D.U sits behind a reverse
proxy. A sample audit line:

```json
{"timestamp":"2026-06-28T19:01:28.160234Z","level":"WARN","fields":{"message":"blocked","client_ip":"203.0.113.45","method":"GET","path":"/x","rule_id":"block-scanners","status":403,"reason":"scanner blocked","enforced":true},"target":"audit"}
```

The filter matches `"message":"blocked"` and `"rate_limited"` events and pulls out
`client_ip` as `<HOST>`. Detection-only (`enforcement = "detect"`) events are
**not** banned by default (commented hint in the filter to opt in).

## Two ways to ban — pick by topology

### (A) App-layer ban via budu's blocklist — recommended behind an edge proxy

This is B.U.D.U's standard topology (Apache/nginx → budu → app). A firewall ban
on the budu host would only block your edge proxy, so instead Fail2Ban writes the
banned IP into budu's `blocklist_file` and reloads:

- `action.d/budu-blocklist.conf` writes `<ip> until=<now + bantime>` and runs
  `systemctl reload budu`.
- B.U.D.U rebuilds its blocklist on `SIGHUP` (inline + file + remote feeds) with
  **no dropped connections**, and every subsequent request from that IP gets a
  `403` at the reputation stage.
- **Bans auto-expire.** The `until=<epoch>` is checked per request and the entry
  is pruned in the maintenance tick, so the WAF lifts the ban at `bantime` even
  if Fail2Ban's unban is never delivered (a restart, a lost signal). Fail2Ban's
  own unban still runs too — belt and suspenders. A permanent Fail2Ban ban
  (`bantime <= 0`) is written without `until=`, so it never auto-expires.

Wire-up:

```toml
# budu.toml
[reputation]
blocklist_file = "/etc/budu/banned.txt"     # same path as the action's blocklist_file
```

```ini
# jail.d/budu.conf (already the default in the shipped file)
action = budu-blocklist[blocklist_file="/etc/budu/banned.txt", reloadcmd="systemctl reload budu"]
```

The file must be writable by Fail2Ban (root) and readable by the budu user. Bans
survive a budu restart (they're in the file); unbans remove the line and reload.

> Alternatively, if `[server] pidfile` is set you can let the **CLI** do the
> file edit *and* the reload, e.g. `actionban = budu -c /etc/budu/budu.toml ban
> <ip> --for <bantime>s --reload` (and the matching `unban … --reload`). The
> shipped `action.d/budu-blocklist.conf` uses the plain-shell form so it works
> without assuming budu is on `PATH`.

### (B) Network ban at the firewall — when budu is directly internet-facing

If clients connect to budu directly (no proxy in front), a normal iptables/nft
ban is more efficient (the kernel drops them before budu sees them):

```ini
# jail.d/budu.conf
action = %(action_)s        # default banaction (iptables-multiport / nftables)
```

## Install

```bash
sudo cp contrib/fail2ban/filter.d/budu.conf   /etc/fail2ban/filter.d/
sudo cp contrib/fail2ban/action.d/budu-blocklist.conf /etc/fail2ban/action.d/
sudo cp contrib/fail2ban/jail.d/budu.conf     /etc/fail2ban/jail.d/
# edit jail.d/budu.conf: set logpath = your [log] audit_file, tune thresholds
sudo systemctl reload fail2ban
```

Defaults in the jail: ban after **5** audit hits within **10m**, for **1h**
(`maxretry` / `findtime` / `bantime`). Tune to taste; enable
`bantime.increment` to punish repeat offenders progressively.

## Verify

```bash
# the filter matches your real audit log (counts the hits it would act on):
fail2ban-regex /var/log/budu/audit.log /etc/fail2ban/filter.d/budu.conf

# jail status / currently-banned IPs:
sudo fail2ban-client status budu
```

For action (A) you can also confirm the loop directly:

```bash
echo "203.0.113.45" | sudo tee -a /etc/budu/banned.txt
sudo systemctl reload budu
budu --config /etc/budu/budu.toml check        # → blocklist=… count goes up
```

## Notes

- **Audit log only** — point the jail at `[log] audit_file`, not stdout. Keep
  `audit_file` set so security events are isolated from operational logs.
- **Whitelisting** — never ban your own monitoring/health checkers. Either add
  them to Fail2Ban `ignoreip`, or to B.U.D.U's `[reputation] allowlist` (which
  also skips all inspection for them).
- **Detect mode** — to have Fail2Ban act while B.U.D.U only *observes*
  (`enforcement = "detect"`), add the `"detected"` failregex line shown in
  `filter.d/budu.conf`.
- **Rotation** — if you rotate the audit log, use `backend = auto` (default) so
  Fail2Ban follows the new file; signal budu to reopen per your logrotate setup.
