//! Human-friendly byte sizes (`"1MiB"`, `"512KiB"`, `"1048576"`) for config.

use serde::{Deserialize, Deserializer};

/// A size in bytes, deserialized from a string like `"1MiB"` or a bare integer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ByteSize(u64);

impl ByteSize {
    pub fn bytes(&self) -> u64 {
        self.0
    }
}

fn parse(s: &str) -> Result<u64, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty size".into());
    }
    let digits_end = s
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(s.len());
    let (num, unit) = s.split_at(digits_end);
    let num: u64 = num
        .parse()
        .map_err(|_| format!("invalid size number in {s:?}"))?;
    let mult: u64 = match unit.trim().to_ascii_lowercase().as_str() {
        "" | "b" => 1,
        "k" | "kb" => 1_000,
        "kib" => 1 << 10,
        "m" | "mb" => 1_000_000,
        "mib" => 1 << 20,
        "g" | "gb" => 1_000_000_000,
        "gib" => 1 << 30,
        other => return Err(format!("unknown size unit {other:?}")),
    };
    num.checked_mul(mult).ok_or_else(|| format!("size overflow in {s:?}"))
}

impl<'de> Deserialize<'de> for ByteSize {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // Accept either a string ("1MiB") or a bare integer (1048576).
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Repr {
            Str(String),
            Int(u64),
        }
        match Repr::deserialize(d)? {
            Repr::Int(n) => Ok(ByteSize(n)),
            Repr::Str(s) => parse(&s).map(ByteSize).map_err(serde::de::Error::custom),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::parse;

    #[test]
    fn units() {
        assert_eq!(parse("1MiB").unwrap(), 1 << 20);
        assert_eq!(parse("512KiB").unwrap(), 512 << 10);
        assert_eq!(parse("1048576").unwrap(), 1_048_576);
        assert_eq!(parse("2kb").unwrap(), 2000);
        assert!(parse("10pb").is_err());
        assert!(parse("").is_err());
    }
}
