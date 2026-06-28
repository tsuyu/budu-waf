//! Normalization layer (§8 step 5): percent-decode + ASCII case-fold the path
//! and query into the request's reused [`NormalizedCache`] buffers, so the
//! signature layer matches against a canonical form (defeats `%27`/case-variant
//! evasions) without re-decoding per signature.
//!
//! No-op for control flow — it always returns `Continue`; its job is to fill
//! `ctx.normalized` for later stages.

use std::ops::ControlFlow;

use budu_common::{RequestCtx, Stage, WafDecision};

pub struct NormalizeStage;

impl Stage for NormalizeStage {
    fn name(&self) -> &'static str {
        "normalize"
    }

    fn inspect(&self, ctx: &mut RequestCtx<'_>) -> ControlFlow<WafDecision> {
        let mut path = String::new();
        normalize_into(ctx.path.as_bytes(), false, &mut path);
        ctx.normalized.path = Some(path);

        if let Some(q) = ctx.query {
            let mut query = String::new();
            normalize_into(q.as_bytes(), true, &mut query);
            ctx.normalized.query = Some(query);
        } else {
            ctx.normalized.query = None;
        }

        ControlFlow::Continue(())
    }
}

/// Percent-decode `input`, ASCII-lowercase it, and append to `out`. When
/// `plus_is_space` (query strings) a literal `+` decodes to a space. Invalid
/// `%` escapes are passed through verbatim (matching lenient server behaviour,
/// which attackers rely on). Non-UTF-8 decoded bytes are replaced with `?` so
/// the result stays a `&str` for the regex layer — the byte is still "seen" as
/// a non-letter, which is all signatures need.
pub fn normalize_into(input: &[u8], plus_is_space: bool, out: &mut String) {
    decode_fold_into(input, plus_is_space, true, out);
}

/// Percent-decode only (no case-folding), appending to `out`. Used by the rule
/// engine's `url_decode` transform, which composes case-folding separately.
pub fn decode_into(input: &[u8], plus_is_space: bool, out: &mut String) {
    decode_fold_into(input, plus_is_space, false, out);
}

fn decode_fold_into(input: &[u8], plus_is_space: bool, lowercase: bool, out: &mut String) {
    let mut i = 0;
    while i < input.len() {
        let b = input[i];
        let decoded = match b {
            b'%' if i + 2 < input.len() => {
                match (hex(input[i + 1]), hex(input[i + 2])) {
                    (Some(h), Some(l)) => {
                        i += 3;
                        push_byte(out, (h << 4) | l, lowercase);
                        continue;
                    }
                    _ => b'%',
                }
            }
            b'+' if plus_is_space => b' ',
            other => other,
        };
        i += 1;
        push_byte(out, decoded, lowercase);
    }
}

fn push_byte(out: &mut String, b: u8, lowercase: bool) {
    if b.is_ascii() {
        let c = b as char;
        out.push(if lowercase { c.to_ascii_lowercase() } else { c });
    } else {
        // Non-ASCII decoded byte: keep position visible without breaking str
        // validity.
        out.push('?');
    }
}

fn hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn norm(s: &str, plus: bool) -> String {
        let mut out = String::new();
        normalize_into(s.as_bytes(), plus, &mut out);
        out
    }

    #[test]
    fn decodes_and_lowercases() {
        assert_eq!(norm("%27%20OR%201=1", false), "' or 1=1");
        assert_eq!(norm("SELECT", false), "select");
        assert_eq!(norm("a+b", true), "a b");
        assert_eq!(norm("a+b", false), "a+b");
        // double-encoding only decodes one layer (server would decode once)
        assert_eq!(norm("%2527", false), "%27");
        // malformed escape passes through
        assert_eq!(norm("%zz", false), "%zz");
    }
}
