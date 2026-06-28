//! Custom rule engine (`budu-rules`, BUDU-DEV.md §6): user-authored rules in
//! `config/rules.toml`, each a set of field/operator conditions (AND-ed) plus
//! an action. This is the *business-logic* layer — "block POST to /admin from
//! outside our CIDR", "allow-list /healthz past inspection" — complementing the
//! attack-pattern `budu-signatures` layer.
//!
//! ```toml
//! [[rule]]
//! id = "admin-locked-down"
//! action = "block"          # block | allow | log
//! status = 403
//! msg = "admin restricted"
//! when = [
//!     { field = "path",   op = "starts_with", value = "/admin" },
//!     { field = "ip",     op = "cidr",        value = "0.0.0.0/0" },  # placeholder
//! ]
//! ```
//!
//! All `when` conditions must match for the rule to fire. Rules are evaluated in
//! order; the first `block`/`allow` short-circuits. `allow` bypasses the
//! remaining inspection (whitelist); `log` records and keeps going.

pub mod modsec;
mod ruleset;
mod stage;

pub use ruleset::{parse_tz_offset, RuleError, RuleSet};
pub use stage::{shared_from_path, RulesStage, SharedRules};
