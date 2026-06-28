//! Built-in baseline signatures (SQLi / XSS / path traversal / command
//! injection). Deliberately small and high-signal — a starting set, not a full
//! CRS. Operates on the *normalized* (percent-decoded, lowercased) request, so
//! patterns are written in lowercase and assume single decoding.

use crate::db::Signature;

fn lit(id: &str, literal: &str, reason: &str) -> Signature {
    Signature {
        id: id.to_string(),
        literal: Some(literal.to_string()),
        regex: None,
        status: 403,
        reason: reason.to_string(),
    }
}

fn re(id: &str, regex: &str, reason: &str) -> Signature {
    Signature {
        id: id.to_string(),
        literal: None,
        regex: Some(regex.to_string()),
        status: 403,
        reason: reason.to_string(),
    }
}

pub fn signatures() -> Vec<Signature> {
    vec![
        // ── SQL injection ──────────────────────────────────────────────
        lit("sqli.union_select", "union select", "SQL injection: UNION SELECT"),
        lit("sqli.sleep", "sleep(", "SQL injection: time-based (sleep)"),
        lit("sqli.benchmark", "benchmark(", "SQL injection: time-based (benchmark)"),
        lit("sqli.information_schema", "information_schema", "SQL injection: schema probe"),
        // boolean tautologies: ' or 1=1 / or 1 = 1  (ASCII-only classes: the
        // regex crate's unicode feature is intentionally off, so no \d/\s/\b)
        re(
            "sqli.or_boolean",
            r#"(?:'|"| )or +[0-9]+ *= *[0-9]+"#,
            "SQL injection: boolean tautology",
        ),
        re(
            "sqli.union_select_ws",
            r"union +select",
            "SQL injection: UNION SELECT (spaced)",
        ),
        re(
            "sqli.comment_tail",
            r"(?:--|#|/\*) *$",
            "SQL injection: trailing comment",
        ),

        // ── Cross-site scripting ───────────────────────────────────────
        lit("xss.script_open", "<script", "XSS: <script> tag"),
        lit("xss.js_proto", "javascript:", "XSS: javascript: URI"),
        lit("xss.svg_onload", "<svg", "XSS: <svg> vector"),
        lit("xss.img_onerror", "onerror=", "XSS: onerror handler"),
        re(
            "xss.event_handler",
            r" on(?:load|click|mouseover|focus|error) *=",
            "XSS: inline event handler",
        ),

        // ── Path traversal / LFI ───────────────────────────────────────
        lit("lfi.dotdot", "../", "Path traversal: ../"),
        lit("lfi.dotdot_back", "..\\", "Path traversal: ..\\"),
        lit("lfi.etc_passwd", "/etc/passwd", "LFI: /etc/passwd"),
        lit("lfi.win_ini", "boot.ini", "LFI: boot.ini"),

        // ── OS command injection ───────────────────────────────────────
        re(
            "rce.shell_meta",
            r"(?:;|\|\||&&|`|\$\() *(?:cat|ls|id|whoami|curl|wget|nc|bash|sh)",
            "Command injection: shell metacharacter + command",
        ),
    ]
}
