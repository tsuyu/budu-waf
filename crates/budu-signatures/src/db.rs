//! Signature definitions and the compiled, lock-free-readable database.

use std::sync::Arc;

use aho_corasick::AhoCorasick;
use http::StatusCode;
use regex::RegexSet;
use serde::Deserialize;

/// One signature, as authored in `signatures.toml` or the builtin set. Exactly
/// one of `literal` / `regex` is used; `literal` takes precedence if both set.
#[derive(Debug, Clone, Deserialize)]
pub struct Signature {
    pub id: String,
    #[serde(default)]
    pub literal: Option<String>,
    #[serde(default)]
    pub regex: Option<String>,
    #[serde(default = "default_status")]
    pub status: u16,
    #[serde(default)]
    pub reason: String,
}

fn default_status() -> u16 {
    403
}

#[derive(Debug, thiserror::Error)]
pub enum SignatureError {
    #[error("reading signatures: {0}")]
    Read(String),
    #[error("parsing signatures: {0}")]
    Parse(String),
    #[error("compiling signatures: {0}")]
    Compile(String),
    #[error("no signatures defined")]
    Empty,
}

/// Per-signature metadata kept alongside the matcher, indexed by pattern id.
struct Meta {
    id: Arc<str>,
    status: StatusCode,
    reason: Arc<str>,
}

/// A signature hit: which rule fired and how to answer.
pub struct Hit {
    pub rule_id: Arc<str>,
    pub status: StatusCode,
    pub reason: Arc<str>,
}

/// Compiled matcher: literal automaton + regex set, each with aligned metadata.
pub struct SignatureDb {
    literals: AhoCorasick,
    literal_meta: Vec<Meta>,
    regexes: RegexSet,
    regex_meta: Vec<Meta>,
    count: usize,
}

impl SignatureDb {
    /// Compile a set of signatures into a queryable database.
    pub fn compile(sigs: &[Signature]) -> Result<Self, SignatureError> {
        let mut literal_pats = Vec::new();
        let mut literal_meta = Vec::new();
        let mut regex_pats = Vec::new();
        let mut regex_meta = Vec::new();

        for s in sigs {
            let meta = Meta {
                id: Arc::from(s.id.as_str()),
                status: StatusCode::from_u16(s.status)
                    .map_err(|_| SignatureError::Compile(format!("{}: bad status {}", s.id, s.status)))?,
                reason: Arc::from(if s.reason.is_empty() {
                    s.id.as_str()
                } else {
                    s.reason.as_str()
                }),
            };
            if let Some(lit) = &s.literal {
                // Haystack is normalized to lowercase; store literals likewise.
                literal_pats.push(lit.to_ascii_lowercase());
                literal_meta.push(meta);
            } else if let Some(re) = &s.regex {
                regex_pats.push(re.clone());
                regex_meta.push(meta);
            } else {
                return Err(SignatureError::Compile(format!(
                    "{}: needs a literal or regex",
                    s.id
                )));
            }
        }

        if literal_pats.is_empty() && regex_pats.is_empty() {
            return Err(SignatureError::Empty);
        }

        let literals = AhoCorasick::new(&literal_pats)
            .map_err(|e| SignatureError::Compile(format!("aho-corasick: {e}")))?;
        // unicode(false): ASCII byte semantics (matches HTTP bytes, lets custom
        // signatures use `(?i)` without the regex unicode-case feature).
        let regexes = regex::RegexSetBuilder::new(&regex_pats)
            .unicode(false)
            .build()
            .map_err(|e| SignatureError::Compile(format!("regex: {e}")))?;

        Ok(Self {
            literals,
            literal_meta,
            regexes,
            regex_meta,
            count: sigs.len(),
        })
    }

    /// The builtin SQLi/XSS/traversal ruleset.
    pub fn builtin() -> Self {
        // Builtin patterns are vetted; compile cannot fail in practice.
        Self::compile(&super::builtin::signatures()).expect("builtin signatures compile")
    }

    /// Load from a TOML file of `[[signature]]` entries; falls back to
    /// [`builtin`](Self::builtin) when `path` is empty.
    pub fn load(path: &str) -> Result<Self, SignatureError> {
        if path.trim().is_empty() {
            return Ok(Self::builtin());
        }
        let text =
            std::fs::read_to_string(path).map_err(|e| SignatureError::Read(format!("{path}: {e}")))?;
        #[derive(Deserialize)]
        struct File {
            #[serde(default)]
            signature: Vec<Signature>,
        }
        let file: File = toml::from_str(&text).map_err(|e| SignatureError::Parse(e.to_string()))?;
        Self::compile(&file.signature)
    }

    pub fn len(&self) -> usize {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Scan a normalized haystack; returns the first matching signature, if any.
    /// Literal tier first (one automaton pass), then the regex set.
    pub fn scan(&self, haystack: &str) -> Option<Hit> {
        if let Some(m) = self.literals.find(haystack) {
            let meta = &self.literal_meta[m.pattern().as_usize()];
            return Some(meta.into());
        }
        if let Some(idx) = self.regexes.matches(haystack).iter().next() {
            let meta = &self.regex_meta[idx];
            return Some(meta.into());
        }
        None
    }
}

impl From<&Meta> for Hit {
    fn from(m: &Meta) -> Self {
        Hit {
            rule_id: m.id.clone(),
            status: m.status,
            reason: m.reason.clone(),
        }
    }
}
