//! Manual blocklist management (`budu ban` / `unban` / `bans`).
//!
//! These edit the same `[reputation] blocklist_file` the running proxy reads,
//! using the same `IP [until=<epoch>]` line format as the Fail2Ban integration —
//! so a manual ban auto-expires too. Edits are atomic (write-temp + rename); the
//! proxy applies them on the next reload (`SIGHUP` / the refresh timer).

use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use budu_config::Config;
use ipnet::IpNet;

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Resolve the configured blocklist file, erroring if none is set.
fn blocklist_path(cfg: &Config) -> anyhow::Result<PathBuf> {
    let p = cfg.reputation.blocklist_file.trim();
    if p.is_empty() {
        anyhow::bail!(
            "no [reputation] blocklist_file is configured; set one to use `ban`/`unban`/`bans`"
        );
    }
    Ok(PathBuf::from(p))
}

/// Parse an IP or CIDR into a canonical `IpNet` (bare IP → host route).
fn parse_target(s: &str) -> anyhow::Result<IpNet> {
    s.parse::<IpNet>()
        .or_else(|_| s.parse::<std::net::IpAddr>().map(IpNet::from))
        .map_err(|_| anyhow::anyhow!("invalid IP/CIDR {s:?}"))
}

/// Parse a duration like `30m`, `1h`, `7d`, `90s`, or a bare seconds count.
pub fn parse_duration(s: &str) -> anyhow::Result<u64> {
    let s = s.trim();
    if let Ok(n) = s.parse::<u64>() {
        return Ok(n);
    }
    let (num, mult) = match s.chars().last() {
        Some('s') => (&s[..s.len() - 1], 1),
        Some('m') => (&s[..s.len() - 1], 60),
        Some('h') => (&s[..s.len() - 1], 3600),
        Some('d') => (&s[..s.len() - 1], 86400),
        _ => anyhow::bail!("invalid duration {s:?}; use e.g. 30m, 1h, 7d, or a seconds count"),
    };
    let n: u64 = num
        .trim()
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid duration {s:?}"))?;
    Ok(n.saturating_mul(mult))
}

/// The first whitespace token of a list line parsed as an `IpNet` (ignoring
/// blank / comment lines). `None` if the line isn't an address entry.
fn line_net(line: &str) -> Option<IpNet> {
    let body = line.split('#').next().unwrap_or("").trim();
    let tok = body.split_whitespace().next()?;
    tok.parse::<IpNet>()
        .or_else(|_| tok.parse::<std::net::IpAddr>().map(IpNet::from))
        .ok()
}

fn read_lines(path: &Path) -> Vec<String> {
    match std::fs::read_to_string(path) {
        Ok(text) => text.lines().map(str::to_string).collect(),
        Err(_) => Vec::new(), // missing file = empty list
    }
}

/// Write `lines` to `path` atomically (temp file + rename in the same dir).
fn write_lines(path: &Path, lines: &[String]) -> anyhow::Result<()> {
    let tmp = path.with_extension("tmp");
    let mut f = std::fs::File::create(&tmp)
        .map_err(|e| anyhow::anyhow!("creating {}: {e}", tmp.display()))?;
    for l in lines {
        writeln!(f, "{l}")?;
    }
    f.flush()?;
    std::fs::rename(&tmp, path).map_err(|e| anyhow::anyhow!("writing {}: {e}", path.display()))?;
    Ok(())
}

/// Drop every entry-line that resolves to `target` (used by ban-dedup + unban).
fn without(lines: &[String], target: IpNet) -> Vec<String> {
    lines
        .iter()
        .filter(|l| line_net(l) != Some(target))
        .cloned()
        .collect()
}

/// One reload hint, tailored to whether the refresh timer will pick it up.
fn reload_hint(cfg: &Config) {
    let refresh = cfg.reputation.refresh_secs;
    eprint!("→ apply now:  budu --reload …  /  systemctl reload budu  /  kill -HUP <pid>\n  ");
    if refresh > 0 {
        eprintln!("otherwise applied automatically within {refresh}s (refresh_secs).");
    } else {
        eprintln!("otherwise applied on the next SIGHUP reload (refresh_secs = 0).");
    }
}

/// Apply an edit: either signal the running proxy now (`--reload`) or print the
/// manual hint. A failed reload degrades to a warning + hint (the edit itself
/// already landed in the file).
fn apply(cfg: &Config, reload: bool) {
    if !reload {
        reload_hint(cfg);
        return;
    }
    if let Err(e) = send_sighup(cfg) {
        eprintln!("warning: --reload failed: {e}");
        reload_hint(cfg);
    }
}

/// Send `SIGHUP` to the running proxy, located via `[server] pidfile`.
#[cfg(unix)]
fn send_sighup(cfg: &Config) -> anyhow::Result<()> {
    let pidfile = cfg.server.pidfile.trim();
    if pidfile.is_empty() {
        anyhow::bail!("--reload needs `[server] pidfile` set (so the proxy can be located)");
    }
    let raw = std::fs::read_to_string(pidfile)
        .map_err(|e| anyhow::anyhow!("reading pidfile {pidfile}: {e} (is the proxy running?)"))?;
    let pid: i32 = raw
        .trim()
        .parse()
        .map_err(|_| anyhow::anyhow!("pidfile {pidfile} has no PID: {:?}", raw.trim()))?;
    // Best-effort guard against a stale pidfile pointing at a recycled PID.
    let comm = std::fs::read_to_string(format!("/proc/{pid}/comm")).unwrap_or_default();
    if !comm.is_empty() && !comm.trim_end().starts_with("budu") {
        anyhow::bail!("pid {pid} is not a budu process ({:?}); stale pidfile?", comm.trim_end());
    }
    let ok = std::process::Command::new("kill")
        .args(["-s", "HUP", &pid.to_string()])
        .status()
        .map_err(|e| anyhow::anyhow!("running kill: {e}"))?
        .success();
    if !ok {
        anyhow::bail!("kill -HUP {pid} failed (proxy gone? stale pidfile?)");
    }
    println!("reloaded budu (SIGHUP → pid {pid})");
    Ok(())
}

#[cfg(not(unix))]
fn send_sighup(_cfg: &Config) -> anyhow::Result<()> {
    anyhow::bail!("--reload is only supported on unix")
}

/// A pidfile that removes itself on drop. `write("")` is a no-op (disabled).
pub struct PidFile(Option<PathBuf>);

impl PidFile {
    pub fn write(path: &str) -> anyhow::Result<Self> {
        let path = path.trim();
        if path.is_empty() {
            return Ok(Self(None));
        }
        let p = PathBuf::from(path);
        std::fs::write(&p, format!("{}\n", std::process::id()))
            .map_err(|e| anyhow::anyhow!("writing pidfile {}: {e}", p.display()))?;
        Ok(Self(Some(p)))
    }
}

impl Drop for PidFile {
    fn drop(&mut self) {
        if let Some(p) = &self.0 {
            let _ = std::fs::remove_file(p);
        }
    }
}

/// `budu ban <target> [--for <duration>] [--reload]`
pub fn ban(cfg: &Config, target: &str, duration: Option<&str>, reload: bool) -> anyhow::Result<()> {
    let net = parse_target(target)?;
    let path = blocklist_path(cfg)?;
    let mut lines = without(&read_lines(&path), net); // de-dupe existing entry

    let entry = match duration {
        Some(d) => {
            let secs = parse_duration(d)?;
            let until = now_secs().saturating_add(secs);
            println!("banned {net} for {d} (until epoch {until})");
            format!("{net} until={until}")
        }
        None => {
            println!("banned {net} permanently");
            net.to_string()
        }
    };
    lines.push(entry);
    write_lines(&path, &lines)?;
    apply(cfg, reload);
    Ok(())
}

/// `budu unban <target> [--reload]`
pub fn unban(cfg: &Config, target: &str, reload: bool) -> anyhow::Result<()> {
    let net = parse_target(target)?;
    let path = blocklist_path(cfg)?;
    let before = read_lines(&path);
    let after = without(&before, net);
    let removed = before.len() - after.len();
    if removed == 0 {
        println!("{net} was not in {}", path.display());
        return Ok(());
    }
    write_lines(&path, &after)?;
    println!("unbanned {net} ({removed} line(s) removed)");
    apply(cfg, reload);
    Ok(())
}

/// `budu bans` — list current blocklist-file entries with remaining TTL.
pub fn list(cfg: &Config) -> anyhow::Result<()> {
    let path = blocklist_path(cfg)?;
    let now = now_secs();
    let mut count = 0;
    for line in read_lines(&path) {
        let body = line.split('#').next().unwrap_or("").trim();
        if body.is_empty() {
            continue;
        }
        let mut tok = body.split_whitespace();
        let Some(net) = line_net(&line) else { continue };
        let until = tok
            .find_map(|t| t.strip_prefix("until="))
            .and_then(|v| v.parse::<u64>().ok());
        let state = match until {
            None => "permanent".to_string(),
            Some(u) if u > now => format!("expires in {}s (at {u})", u - now),
            Some(u) => format!("EXPIRED (at {u})"),
        };
        println!("{net:<20} {state}");
        count += 1;
    }
    if count == 0 {
        println!("(no entries in {})", path.display());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duration_forms() {
        assert_eq!(parse_duration("90").unwrap(), 90);
        assert_eq!(parse_duration("90s").unwrap(), 90);
        assert_eq!(parse_duration("30m").unwrap(), 1800);
        assert_eq!(parse_duration("1h").unwrap(), 3600);
        assert_eq!(parse_duration("7d").unwrap(), 604800);
        assert!(parse_duration("soon").is_err());
        assert!(parse_duration("1y").is_err());
    }

    #[test]
    fn line_matching_normalizes() {
        // bare IP and /32 are the same target
        let target: IpNet = "203.0.113.45".parse::<std::net::IpAddr>().unwrap().into();
        let lines = vec![
            "203.0.113.45 until=999".to_string(),
            "203.0.113.45/32".to_string(),
            "10.0.0.0/8".to_string(),
            "# a comment".to_string(),
        ];
        let kept = without(&lines, target);
        assert_eq!(kept, vec!["10.0.0.0/8".to_string(), "# a comment".to_string()]);
    }

    #[test]
    fn line_net_parses_first_token_only() {
        assert_eq!(line_net("203.0.113.7 until=123"), "203.0.113.7/32".parse().ok());
        assert_eq!(line_net("  # comment"), None);
        assert_eq!(line_net("garbage"), None);
    }
}
