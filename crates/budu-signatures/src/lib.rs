//! Signature layer (§8 step 7): a two-tier matcher over the normalized request.
//!
//! 1. **Literals** — an `aho-corasick` automaton scans the haystack in one pass
//!    for high-confidence fixed strings (`<script`, `../`, `union select`, …).
//! 2. **Regex** — a `RegexSet` (unicode off; we match HTTP bytes) catches the
//!    fuzzy variants literals can't (`' or 1 = 1`, whitespace-padded `union
//!    select`). Run after the literal pass so the cheap automaton handles the
//!    common case.
//!
//! The compiled [`SignatureDb`] is immutable and wrapped in `Arc` so it can be
//! atomically hot-swapped later (`ArcSwap<SignatureDb>`, §9) with lock-free
//! reads on the hot path.

mod builtin;
mod db;
mod stage;

pub use db::{Signature, SignatureDb, SignatureError};
pub use stage::{shared_from_path, SharedDb, SignatureStage};
