//! Optional GeoIP layer (BUDU-DEV.md §10, behind the `geoip` Cargo feature).
//!
//! Resolves the client IP to an ISO-3166 country via a MaxMind DB, stamps it on
//! `ctx.client.geo` for downstream stages and logging, and optionally enforces
//! an allow/block country policy. Compiled out entirely unless `geoip` is on.

use std::net::IpAddr;
use std::ops::ControlFlow;
use std::sync::Arc;

use budu_common::{CountryCode, RequestCtx, Stage, WafDecision};
use budu_config::GeoIpConfig;
use http::StatusCode;
use maxminddb::{geoip2, Reader};

pub struct GeoStage {
    reader: Arc<Reader<Vec<u8>>>,
    allow: Vec<[u8; 2]>,
    block: Vec<[u8; 2]>,
    rule_id: Arc<str>,
}

impl GeoStage {
    /// Build from config. Returns `Ok(None)` when GeoIP is disabled so callers
    /// can simply skip the stage.
    pub fn from_config(cfg: &GeoIpConfig) -> anyhow::Result<Option<Self>> {
        if !cfg.enabled {
            return Ok(None);
        }
        if cfg.db_path.trim().is_empty() {
            anyhow::bail!("geoip.enabled = true but geoip.db_path is empty");
        }
        let reader = Reader::open_readfile(&cfg.db_path)
            .map_err(|e| anyhow::anyhow!("opening geoip db {}: {e}", cfg.db_path))?;

        Ok(Some(Self {
            reader: Arc::new(reader),
            allow: to_codes(&cfg.allow_countries),
            block: to_codes(&cfg.block_countries),
            rule_id: Arc::from("geoip.country"),
        }))
    }

    fn lookup(&self, ip: IpAddr) -> Option<CountryCode> {
        // Treat any miss/error as "no geo": lookup → LookupResult → decode.
        let found = self.reader.lookup(ip).ok()?;
        let country: geoip2::Country = found.decode().ok().flatten()?;
        let iso = country.country.iso_code?;
        let b = iso.as_bytes();
        if b.len() == 2 {
            Some(CountryCode([b[0].to_ascii_uppercase(), b[1].to_ascii_uppercase()]))
        } else {
            None
        }
    }
}

impl Stage for GeoStage {
    fn name(&self) -> &'static str {
        "geoip"
    }

    fn inspect(&self, ctx: &mut RequestCtx<'_>) -> ControlFlow<WafDecision> {
        let geo = self.lookup(ctx.client.ip);
        ctx.client.geo = geo; // stamp for downstream stages + audit logging
        match country_decision(geo, &self.allow, &self.block) {
            true => ControlFlow::Continue(()),
            false => ControlFlow::Break(WafDecision::Block {
                rule_id: self.rule_id.clone(),
                status: StatusCode::FORBIDDEN,
                reason: Arc::from("source country not permitted"),
            }),
        }
    }
}

/// Normalize a list of country strings to upper-case 2-byte codes (bad entries
/// dropped).
fn to_codes(list: &[String]) -> Vec<[u8; 2]> {
    list.iter()
        .filter_map(|s| {
            let b = s.trim().as_bytes();
            (b.len() == 2).then(|| [b[0].to_ascii_uppercase(), b[1].to_ascii_uppercase()])
        })
        .collect()
}

/// Pure policy decision: `true` = allow, `false` = block. Allowlist wins when
/// present. A missing geo result is allowed (fail-open on lookup gaps) unless an
/// allowlist is configured — then unknown origin can't satisfy it, so it blocks.
fn country_decision(geo: Option<CountryCode>, allow: &[[u8; 2]], block: &[[u8; 2]]) -> bool {
    match geo {
        Some(cc) => {
            if !allow.is_empty() {
                return allow.contains(&cc.0);
            }
            !block.contains(&cc.0)
        }
        None => allow.is_empty(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cc(s: &str) -> CountryCode {
        let b = s.as_bytes();
        CountryCode([b[0], b[1]])
    }

    #[test]
    fn allowlist_only_permits_listed() {
        let allow = to_codes(&["MY".into(), "sg".into()]);
        assert!(country_decision(Some(cc("MY")), &allow, &[]));
        assert!(country_decision(Some(cc("SG")), &allow, &[])); // case-normalized
        assert!(!country_decision(Some(cc("CN")), &allow, &[]));
        // unknown origin can't satisfy an allowlist
        assert!(!country_decision(None, &allow, &[]));
    }

    #[test]
    fn blocklist_blocks_listed_allows_rest() {
        let block = to_codes(&["CN".into(), "RU".into()]);
        assert!(!country_decision(Some(cc("CN")), &[], &block));
        assert!(country_decision(Some(cc("MY")), &[], &block));
        // no policy + no geo → allow (fail-open)
        assert!(country_decision(None, &[], &block));
    }
}
