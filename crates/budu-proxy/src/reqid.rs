//! Per-request correlation IDs.
//!
//! Every request gets a unique id: either an inbound one (from the configured
//! `request_id_header`, if present and well-formed) so a trace started at the
//! edge carries through, or a freshly generated one. The id is attached to the
//! request's logs and audit events, echoed back on the response, and forwarded
//! upstream — so a single request can be followed across systems.
//!
//! The id is `<seed><counter>` in hex: a per-process random `seed` (so ids don't
//! collide across instances/restarts) plus a per-process atomic `counter` (so
//! they never collide within a process). No external RNG dependency.

use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use http::HeaderMap;

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// A 64-bit seed mixed once per process from time, PID and ASLR entropy.
fn seed() -> u64 {
    static SEED: OnceLock<u64> = OnceLock::new();
    *SEED.get_or_init(|| {
        let mut h = std::collections::hash_map::DefaultHasher::new();
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
            .hash(&mut h);
        std::process::id().hash(&mut h);
        let stack = 0u8;
        (&stack as *const u8 as usize).hash(&mut h); // ASLR varies the address per run
        h.finish()
    })
}

/// Generate a fresh, process-unique request id (32 lowercase hex chars).
pub fn generate() -> String {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{:016x}{:016x}", seed(), n)
}

/// Accept an inbound id only if it's a short, safe token (no log-injection, no
/// header smuggling): 1..=128 chars of `[A-Za-z0-9._:-]`.
pub fn sanitize(s: &str) -> Option<String> {
    let s = s.trim();
    if s.is_empty() || s.len() > 128 {
        return None;
    }
    s.bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'))
        .then(|| s.to_string())
}

/// Resolve the request id: reuse a valid inbound header value, else generate.
pub fn resolve(headers: &HeaderMap, header_name: &str) -> Arc<str> {
    if !header_name.is_empty() {
        if let Some(clean) = headers
            .get(header_name)
            .and_then(|v| v.to_str().ok())
            .and_then(sanitize)
        {
            return Arc::from(clean.as_str());
        }
    }
    Arc::from(generate().as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_ids_are_unique_and_hex() {
        let a = generate();
        let b = generate();
        assert_ne!(a, b);
        assert_eq!(a.len(), 32);
        assert!(a.bytes().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn sanitize_rejects_unsafe() {
        assert_eq!(sanitize("abc-123_DEF.4:5").as_deref(), Some("abc-123_DEF.4:5"));
        assert!(sanitize("").is_none());
        assert!(sanitize("has space").is_none());
        assert!(sanitize("inject\nline").is_none());
        assert!(sanitize(&"x".repeat(200)).is_none());
    }

    #[test]
    fn resolve_reuses_valid_inbound() {
        let mut h = HeaderMap::new();
        h.insert("x-request-id", "edge-abc123".parse().unwrap());
        assert_eq!(&*resolve(&h, "x-request-id"), "edge-abc123");

        // invalid inbound → fresh generated id (32 hex)
        let mut bad = HeaderMap::new();
        bad.insert("x-request-id", "no good!".parse().unwrap());
        assert_eq!(resolve(&bad, "x-request-id").len(), 32);

        // absent → generated
        assert_eq!(resolve(&HeaderMap::new(), "x-request-id").len(), 32);

        // disabled header name → generated
        assert_eq!(resolve(&h, "").len(), 32);
    }
}
