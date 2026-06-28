//! A focused **ModSecurity `SecRule` → B.U.D.U** converter, for importing the
//! OWASP Core Rule Set (CRS) and similar `.conf` rule files.
//!
//! This is intentionally a *useful subset*, not a full ModSecurity engine. It
//! converts the common rule shape — `SecRule VARIABLES "OPERATOR" "ACTIONS"` —
//! into B.U.D.U's TOML rules, mapping variables to fields, operators to ops,
//! `t:` to transforms, and either a disruptive action (→ `block`) or a CRS
//! anomaly-score `setvar` (→ `score`, feeding B.U.D.U's `[scoring]` threshold).
//! Simple `chain`s (single-variable members) are combined into one AND-ed rule.
//!
//! What it does **not** do (each such rule is skipped and reported, so the
//! import is auditable): response/logging phases (3/4/5), `SecRuleScript`/Lua,
//! macro expansion in operator arguments (`%{tx.*}`), regex variable selectors,
//! `@pmFromFile`/`@ipMatchFromFile`, and multi-variable chain members. Run the
//! output through `budu … check` and review it before deploying — this is a
//! migration aid, not a drop-in CRS runtime.

use serde::Serialize;

/// Outcome of a conversion: the generated rules TOML plus an audit trail.
pub struct ConvertReport {
    /// Generated B.U.D.U rules, as a TOML string (`[[rule]]` entries).
    pub toml: String,
    /// Number of source `SecRule` directives successfully converted.
    pub converted: usize,
    /// Source rules that were skipped, with the reason (id + why).
    pub skipped: Vec<SkipNote>,
    /// Non-fatal lossy conversions (e.g. an unsupported transform was dropped
    /// but the rule was still emitted).
    pub warnings: Vec<String>,
}

pub struct SkipNote {
    pub id: String,
    pub reason: String,
}

// ── Serializable emit model (mirrors config/rules.toml's [[rule]] schema) ────

#[derive(Serialize)]
struct EmittedFile {
    #[serde(rename = "rule")]
    rules: Vec<EmittedRule>,
}

#[derive(Serialize)]
struct EmittedRule {
    id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    phase: Option<&'static str>,
    action: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<u16>,
    #[serde(skip_serializing_if = "String::is_empty")]
    msg: String,
    #[serde(skip_serializing_if = "is_zero")]
    score: u32,
    when: Vec<EmittedCond>,
}

fn is_zero(n: &u32) -> bool {
    *n == 0
}

#[derive(Serialize, Clone)]
struct EmittedCond {
    field: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    op: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<String>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    negate: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    transform: Vec<&'static str>,
}

/// Convert ModSecurity rule text into B.U.D.U rules.
pub fn convert(input: &str) -> ConvertReport {
    let lines = join_continuations(input);
    let mut rules: Vec<EmittedRule> = Vec::new();
    let mut skipped: Vec<SkipNote> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();
    let mut converted = 0usize;

    let mut i = 0;
    while i < lines.len() {
        let line = lines[i].trim();
        i += 1;
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some(rest) = directive_arg(line, "SecRule") else {
            // SecAction / SecDefaultAction / SecMarker / Include / Sec* — not a
            // rule we convert. Silently ignored (config plumbing, not a rule).
            continue;
        };

        // Parse the starter, then pull in any chained members that follow.
        let starter = match parse_secrule(rest) {
            Ok(r) => r,
            Err(reason) => {
                skipped.push(SkipNote { id: "?".into(), reason });
                continue;
            }
        };
        let mut members = vec![starter];
        while members.last().map(|m| m.chain).unwrap_or(false) {
            // Find the next SecRule line (skip comments/blanks).
            while i < lines.len() {
                let l = lines[i].trim();
                if l.is_empty() || l.starts_with('#') {
                    i += 1;
                    continue;
                }
                break;
            }
            if i >= lines.len() {
                break;
            }
            let l = lines[i].trim();
            i += 1;
            match directive_arg(l, "SecRule").map(parse_secrule) {
                Some(Ok(r)) => members.push(r),
                _ => break, // chained member must be a SecRule
            }
        }

        match build_rules(&members, &mut warnings) {
            Ok(mut emitted) => {
                converted += 1;
                rules.append(&mut emitted);
            }
            Err(reason) => {
                let id = members
                    .first()
                    .and_then(|m| m.id.clone())
                    .unwrap_or_else(|| "?".into());
                skipped.push(SkipNote { id, reason });
            }
        }
    }

    let toml = if rules.is_empty() {
        String::new()
    } else {
        toml::to_string(&EmittedFile { rules }).unwrap_or_default()
    };
    ConvertReport {
        toml,
        converted,
        skipped,
        warnings,
    }
}

// ── Parsed (pre-mapping) representation ──────────────────────────────────────

struct ParsedRule {
    vars: Vec<RawVar>,
    op_name: String,
    op_arg: String,
    negate: bool,
    transforms: Vec<&'static str>,
    id: Option<String>,
    phase: u8,
    /// block / deny / drop seen.
    disrupt: bool,
    allow: bool,
    pass: bool,
    status: Option<u16>,
    msg: String,
    score: Option<u32>,
    chain: bool,
}

struct RawVar {
    name: String,
    selector: Option<String>,
    count: bool,
    exclude: bool,
}

fn parse_secrule(rest: &str) -> Result<ParsedRule, String> {
    let tokens = tokenize(rest);
    if tokens.len() < 2 {
        return Err("malformed SecRule (need variables + operator)".into());
    }
    let vars = parse_vars(&tokens[0]);
    let (op_name, op_arg, negate) = parse_operator(&tokens[1]);
    let actions = tokens.get(2).map(String::as_str).unwrap_or("");

    let mut rule = ParsedRule {
        vars,
        op_name,
        op_arg,
        negate,
        transforms: Vec::new(),
        id: None,
        phase: 2,
        disrupt: false,
        allow: false,
        pass: false,
        status: None,
        msg: String::new(),
        score: None,
        chain: false,
    };

    for (key, val) in split_actions(actions) {
        match key.as_str() {
            "id" => rule.id = val.map(|v| v.trim().to_string()),
            "phase" => {
                rule.phase = match val.as_deref() {
                    Some("request") => 2,
                    Some("response") => 4,
                    Some(n) => n.trim().parse().unwrap_or(2),
                    None => 2,
                }
            }
            "deny" | "block" | "drop" => rule.disrupt = true,
            "allow" => rule.allow = true,
            "pass" => rule.pass = true,
            "status" => {
                if let Some(s) = val.as_deref().and_then(|v| v.trim().parse().ok()) {
                    rule.status = Some(s);
                }
            }
            "msg" => rule.msg = val.unwrap_or_default(),
            "t" => {
                if let Some(t) = val.as_deref() {
                    match map_transform(t) {
                        Transform::Keep(name) => rule.transforms.push(name),
                        Transform::None => rule.transforms.clear(),
                        Transform::Unsupported => { /* recorded by caller */ }
                    }
                }
            }
            "setvar" => {
                if let Some(points) = anomaly_score(val.as_deref().unwrap_or("")) {
                    rule.score = Some(points);
                }
            }
            "chain" => rule.chain = true,
            _ => {} // tag, rev, ver, severity, capture, nolog, ctl, skip… ignored
        }
    }
    Ok(rule)
}

// ── Mapping parsed rules into emitted B.U.D.U rules ──────────────────────────

fn build_rules(members: &[ParsedRule], warnings: &mut Vec<String>) -> Result<Vec<EmittedRule>, String> {
    let starter = &members[0];
    if starter.phase >= 3 {
        return Err(format!(
            "phase {} (response/logging) not supported in this importer",
            starter.phase
        ));
    }
    let id_base = starter
        .id
        .clone()
        .map(|n| format!("crs-{n}"))
        .unwrap_or_else(|| "crs-noid".into());

    // Determine the action once, from the starter.
    let (action, status, score) = if starter.allow {
        ("allow", None, 0)
    } else if let Some(points) = starter.score {
        ("score", None, points)
    } else if starter.disrupt {
        ("block", Some(starter.status.unwrap_or(403)), 0)
    } else if starter.pass {
        ("log", None, 0)
    } else {
        // No disruptive action and no anomaly score: log so the import is safe.
        ("log", None, 0)
    };

    // Build one condition per member; OR-across-variables is only representable
    // for a single (non-chained) rule, by emitting one rule per variable.
    let mut member_conds: Vec<Vec<EmittedCond>> = Vec::with_capacity(members.len());
    for m in members {
        let conds = map_member_conditions(m, warnings)?;
        member_conds.push(conds);
    }

    if members.len() == 1 {
        // Non-chained: each variable becomes its own rule (OR semantics).
        let conds = &member_conds[0];
        let multi = conds.len() > 1;
        let mut out = Vec::with_capacity(conds.len());
        for (idx, c) in conds.iter().enumerate() {
            let id = if multi {
                format!("{id_base}-{}", (b'a' + idx as u8) as char)
            } else {
                id_base.clone()
            };
            out.push(EmittedRule {
                id,
                phase: None,
                action,
                status,
                msg: starter.msg.clone(),
                score,
                when: vec![c.clone()],
            });
        }
        Ok(out)
    } else {
        // Chained: every member must contribute exactly one condition (AND).
        let mut when = Vec::with_capacity(members.len());
        for conds in &member_conds {
            match conds.as_slice() {
                [one] => when.push(one.clone()),
                _ => {
                    return Err(
                        "chained rule with a multi-variable member not supported".into(),
                    )
                }
            }
        }
        Ok(vec![EmittedRule {
            id: id_base,
            phase: None,
            action,
            status,
            msg: starter.msg.clone(),
            score,
            when,
        }])
    }
}

/// Map a single parsed member to its conditions (one per usable variable).
fn map_member_conditions(
    m: &ParsedRule,
    warnings: &mut Vec<String>,
) -> Result<Vec<EmittedCond>, String> {
    let (op, value) = map_operator(&m.op_name, &m.op_arg, warnings)?;
    let mut conds = Vec::new();
    for v in &m.vars {
        if v.exclude {
            continue; // can't represent ModSec exclusions; drop this target
        }
        let Some((field, name)) = map_var(v) else {
            continue; // unsupported variable target; skip just this one
        };
        conds.push(EmittedCond {
            field,
            name,
            op,
            value: value.clone(),
            negate: m.negate,
            transform: m.transforms.clone(),
        });
    }
    if conds.is_empty() {
        return Err("no supported variable targets".into());
    }
    Ok(conds)
}

/// Map a ModSecurity variable to a (field, name) pair. `None` = unsupported.
fn map_var(v: &RawVar) -> Option<(&'static str, Option<String>)> {
    let upper = v.name.to_ascii_uppercase();
    let sel = v.selector.clone();
    // `&VAR` (count) is only representable for ARGS → args_count.
    if v.count {
        return match upper.as_str() {
            "ARGS" | "ARGS_GET" | "ARGS_POST" => Some(("args_count", None)),
            _ => None,
        };
    }
    let r = match upper.as_str() {
        "ARGS" | "ARGS_GET" | "ARGS_POST" | "ARGS_COMBINED" => match sel {
            Some(s) => ("arg", Some(s)),
            None => ("args", None),
        },
        "ARGS_NAMES" | "ARGS_GET_NAMES" | "ARGS_POST_NAMES" => ("arg_names", None),
        "QUERY_STRING" => ("query", None),
        "REQUEST_URI" | "REQUEST_URI_RAW" => ("uri", None),
        "REQUEST_FILENAME" | "REQUEST_BASENAME" | "PATH_INFO" => ("path", None),
        "REQUEST_METHOD" => ("method", None),
        "REQUEST_BODY" => ("body", None),
        "REQUEST_HEADERS" => match sel {
            Some(s) => ("header", Some(s)),
            None => ("headers", None),
        },
        "REQUEST_HEADERS_NAMES" => ("header_names", None),
        "REQUEST_COOKIES" => match sel {
            Some(s) => ("cookie", Some(s)),
            None => ("cookies", None),
        },
        "REQUEST_COOKIES_NAMES" => ("cookie_names", None),
        "REMOTE_ADDR" => ("ip", None),
        _ => return None,
    };
    // Reject regex selectors (`/.../`) — we can't expand them.
    if let Some(name) = &r.1 {
        if name.starts_with('/') {
            return None;
        }
    }
    Some(r)
}

/// Map a ModSecurity operator + argument to a B.U.D.U (op, value). `None` value
/// for argument-less operators (e.g. `detect_sqli`).
fn map_operator(
    name: &str,
    arg: &str,
    warnings: &mut Vec<String>,
) -> Result<(&'static str, Option<String>), String> {
    if arg.contains("%{") {
        return Err(format!("operator argument uses a macro ({arg:?})"));
    }
    let r = match name {
        "rx" => ("regex", Some(arg.to_string())),
        "contains" => ("contains", Some(arg.to_string())),
        "beginsWith" => ("starts_with", Some(arg.to_string())),
        "endsWith" => ("ends_with", Some(arg.to_string())),
        "streq" => ("eq", Some(arg.to_string())),
        "eq" => ("eq", Some(arg.to_string())),
        "gt" => ("gt", Some(arg.to_string())),
        "lt" => ("lt", Some(arg.to_string())),
        "ge" => ("ge", Some(arg.to_string())),
        "le" => ("le", Some(arg.to_string())),
        "detectSQLi" => ("detect_sqli", None),
        "detectXSS" => ("detect_xss", None),
        "pm" => ("regex", Some(phrases_to_regex(arg))),
        "ipMatch" => {
            let nets: Vec<&str> = arg.split(',').map(str::trim).filter(|s| !s.is_empty()).collect();
            match nets.as_slice() {
                [one] => ("cidr", Some((*one).to_string())),
                _ => return Err("@ipMatch with multiple CIDRs not supported".into()),
            }
        }
        "pmf" | "pmFromFile" | "ipMatchF" | "ipMatchFromFile" => {
            return Err(format!("@{name} (from-file) not supported"))
        }
        other => return Err(format!("unsupported operator @{other}")),
    };
    if matches!(name, "detectSQLi" | "detectXSS") {
        warnings.push(format!(
            "@{name} → {} requires building budu with --features libinjection",
            r.0
        ));
    }
    Ok(r)
}

/// CRS `@pm`/`@pmf` phrase set → a case-insensitive alternation regex.
fn phrases_to_regex(arg: &str) -> String {
    let alts: Vec<String> = arg
        .split_whitespace()
        .map(regex_escape)
        .filter(|s| !s.is_empty())
        .collect();
    format!("(?i)({})", alts.join("|"))
}

fn regex_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if "\\.+*?()|[]{}^$".contains(c) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

enum Transform {
    Keep(&'static str),
    None,
    Unsupported,
}

fn map_transform(t: &str) -> Transform {
    match t.trim() {
        "none" => Transform::None,
        "lowercase" => Transform::Keep("lowercase"),
        "uppercase" => Transform::Keep("uppercase"),
        "urlDecode" | "urlDecodeUni" => Transform::Keep("url_decode"),
        "compressWhitespace" => Transform::Keep("compress_ws"),
        "removeNulls" => Transform::Keep("remove_nulls"),
        "trim" | "trimLeft" | "trimRight" => Transform::Keep("trim"),
        _ => Transform::Unsupported,
    }
}

/// Pull an anomaly-score increment out of a `setvar` argument, if it is one.
/// Handles `tx.anomaly_score_plN=+%{tx.critical_anomaly_score}` (severity macro)
/// and literal `...=+N` / `...+=N` forms.
fn anomaly_score(setvar: &str) -> Option<u32> {
    let lower = setvar.to_ascii_lowercase();
    if !lower.contains("anomaly_score") {
        return None;
    }
    if lower.contains("critical_anomaly_score") {
        return Some(5);
    }
    if lower.contains("error_anomaly_score") {
        return Some(4);
    }
    if lower.contains("warning_anomaly_score") {
        return Some(3);
    }
    if lower.contains("notice_anomaly_score") {
        return Some(2);
    }
    // Literal increment: take the last run of digits after a '+'.
    if let Some(pos) = setvar.rfind('+') {
        let digits: String = setvar[pos..]
            .chars()
            .filter(|c| c.is_ascii_digit())
            .collect();
        if let Ok(n) = digits.parse::<u32>() {
            return Some(n);
        }
    }
    Some(5) // anomaly_score setvar with an unrecognised amount → critical default
}

// ── Low-level tokenizers ─────────────────────────────────────────────────────

/// Join lines that end with a backslash continuation into single logical lines.
fn join_continuations(input: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for raw in input.lines() {
        let line = raw.strip_suffix('\r').unwrap_or(raw);
        if let Some(prefix) = line.strip_suffix('\\') {
            cur.push_str(prefix);
            cur.push(' ');
        } else {
            cur.push_str(line);
            out.push(std::mem::take(&mut cur));
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// If `line` is the named directive, return its argument tail (after the name +
/// whitespace). Case-sensitive on the directive name (as ModSecurity is).
fn directive_arg<'a>(line: &'a str, name: &str) -> Option<&'a str> {
    let rest = line.strip_prefix(name)?;
    let trimmed = rest.trim_start();
    // Ensure we matched a whole word (next char was whitespace), not a prefix.
    if rest.len() == trimmed.len() {
        return None;
    }
    Some(trimmed)
}

/// Split a SecRule body into whitespace-separated tokens, treating single- and
/// double-quoted spans as one token (with `\"`/`\\` escapes inside).
fn tokenize(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut chars = s.chars().peekable();
    while let Some(&c) = chars.peek() {
        if c.is_whitespace() {
            chars.next();
            continue;
        }
        let mut tok = String::new();
        if c == '"' || c == '\'' {
            let quote = c;
            chars.next();
            while let Some(ch) = chars.next() {
                if ch == '\\' {
                    if let Some(&next) = chars.peek() {
                        // Keep the escape for the regex layer, but collapse \" → "
                        if next == quote {
                            tok.push(next);
                            chars.next();
                        } else {
                            tok.push('\\');
                            tok.push(next);
                            chars.next();
                        }
                    } else {
                        tok.push('\\');
                    }
                } else if ch == quote {
                    break;
                } else {
                    tok.push(ch);
                }
            }
        } else {
            while let Some(&ch) = chars.peek() {
                if ch.is_whitespace() {
                    break;
                }
                tok.push(ch);
                chars.next();
            }
        }
        out.push(tok);
    }
    out
}

/// Parse the variable list (first SecRule token): `A|B:sel|&C|!D`.
fn parse_vars(s: &str) -> Vec<RawVar> {
    s.split('|')
        .filter(|p| !p.trim().is_empty())
        .map(|part| {
            let mut p = part.trim();
            let mut count = false;
            let mut exclude = false;
            if let Some(r) = p.strip_prefix('&') {
                count = true;
                p = r;
            } else if let Some(r) = p.strip_prefix('!') {
                exclude = true;
                p = r;
            }
            let (name, selector) = match p.split_once(':') {
                Some((n, sel)) => (n.to_string(), Some(sel.trim_matches('\'').to_string())),
                None => (p.to_string(), None),
            };
            RawVar {
                name,
                selector,
                count,
                exclude,
            }
        })
        .collect()
}

/// Parse the operator token: optional `!`, optional `@name`, then the argument.
/// A bare argument (no `@`) implies `@rx`.
fn parse_operator(s: &str) -> (String, String, bool) {
    let s = s.trim();
    let (negate, s) = match s.strip_prefix('!') {
        Some(r) => (true, r.trim_start()),
        None => (false, s),
    };
    if let Some(at) = s.strip_prefix('@') {
        let (name, arg) = match at.split_once(char::is_whitespace) {
            Some((n, a)) => (n.to_string(), a.trim().to_string()),
            None => (at.to_string(), String::new()),
        };
        (name, arg, negate)
    } else {
        ("rx".to_string(), s.to_string(), negate)
    }
}

/// Split the actions token into `(key, Option<value>)` pairs, respecting single
/// quotes (so commas inside `msg:'a,b'` don't split).
fn split_actions(s: &str) -> Vec<(String, Option<String>)> {
    let mut out = Vec::new();
    let mut buf = String::new();
    let mut in_quote = false;
    for c in s.chars() {
        match c {
            '\'' => in_quote = !in_quote,
            ',' if !in_quote => {
                push_action(&mut out, &buf);
                buf.clear();
            }
            _ => buf.push(c),
        }
    }
    push_action(&mut out, &buf);
    out
}

fn push_action(out: &mut Vec<(String, Option<String>)>, raw: &str) {
    let a = raw.trim();
    if a.is_empty() {
        return;
    }
    match a.split_once(':') {
        Some((k, v)) => {
            let v = v.trim().trim_matches('\'').to_string();
            out.push((k.trim().to_string(), Some(v)));
        }
        None => out.push((a.to_string(), None)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(toml: &str) -> toml::Value {
        toml::from_str(toml).expect("emitted toml parses")
    }

    #[test]
    fn converts_basic_rx_block() {
        let r = convert(
            r#"SecRule REQUEST_HEADERS:User-Agent "@contains sqlmap" "id:1,phase:1,deny,status:403,msg:'scanner'""#,
        );
        assert_eq!(r.converted, 1);
        assert!(r.skipped.is_empty());
        let v = rules(&r.toml);
        let rule = &v["rule"][0];
        assert_eq!(rule["id"].as_str().unwrap(), "crs-1");
        assert_eq!(rule["action"].as_str().unwrap(), "block");
        assert_eq!(rule["status"].as_integer().unwrap(), 403);
        let cond = &rule["when"][0];
        assert_eq!(cond["field"].as_str().unwrap(), "header");
        assert_eq!(cond["name"].as_str().unwrap(), "User-Agent");
        assert_eq!(cond["op"].as_str().unwrap(), "contains");
        assert_eq!(cond["value"].as_str().unwrap(), "sqlmap");
    }

    #[test]
    fn anomaly_setvar_becomes_score() {
        let r = convert(
            r#"SecRule ARGS "@rx select" "id:942100,phase:2,pass,t:none,t:lowercase,setvar:'tx.sql_injection_score=+%{tx.critical_anomaly_score}'""#,
        );
        assert_eq!(r.converted, 1);
        let v = rules(&r.toml);
        let rule = &v["rule"][0];
        assert_eq!(rule["action"].as_str().unwrap(), "score");
        assert_eq!(rule["score"].as_integer().unwrap(), 5);
        let cond = &rule["when"][0];
        assert_eq!(cond["field"].as_str().unwrap(), "args");
        assert_eq!(cond["op"].as_str().unwrap(), "regex");
        let xf = cond["transform"].as_array().unwrap();
        assert_eq!(xf.len(), 1); // t:none reset, then lowercase
        assert_eq!(xf[0].as_str().unwrap(), "lowercase");
    }

    #[test]
    fn multi_var_expands_to_one_rule_each() {
        let r = convert(r#"SecRule ARGS|ARGS_NAMES "@rx evil" "id:5,phase:2,deny""#);
        assert_eq!(r.converted, 1);
        let v = rules(&r.toml);
        let arr = v["rule"].as_array().unwrap();
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0]["id"].as_str().unwrap(), "crs-5-a");
        assert_eq!(arr[1]["id"].as_str().unwrap(), "crs-5-b");
        assert_eq!(arr[0]["when"][0]["field"].as_str().unwrap(), "args");
        assert_eq!(arr[1]["when"][0]["field"].as_str().unwrap(), "arg_names");
    }

    #[test]
    fn chain_combines_conditions() {
        let src = r#"
SecRule REQUEST_METHOD "@streq POST" "id:7,phase:2,deny,chain"
    SecRule REQUEST_URI "@beginsWith /admin" "t:lowercase"
"#;
        let r = convert(src);
        assert_eq!(r.converted, 1);
        let v = rules(&r.toml);
        let rule = &v["rule"][0];
        assert_eq!(rule["id"].as_str().unwrap(), "crs-7");
        let when = rule["when"].as_array().unwrap();
        assert_eq!(when.len(), 2);
        assert_eq!(when[0]["field"].as_str().unwrap(), "method");
        assert_eq!(when[1]["field"].as_str().unwrap(), "uri");
    }

    #[test]
    fn negation_and_pm_and_ipmatch() {
        let r = convert(r#"SecRule REQUEST_METHOD "!@rx ^(GET|POST)$" "id:8,deny""#);
        let v = rules(&r.toml);
        assert!(v["rule"][0]["when"][0]["negate"].as_bool().unwrap());

        let r2 = convert(r#"SecRule REQUEST_FILENAME "@pm /etc/passwd cmd.exe" "id:9,deny""#);
        let v2 = rules(&r2.toml);
        let val = v2["rule"][0]["when"][0]["value"].as_str().unwrap();
        assert!(val.starts_with("(?i)("));
        assert!(val.contains("cmd\\.exe"));

        let r3 = convert(r#"SecRule REMOTE_ADDR "@ipMatch 10.0.0.0/8" "id:10,deny""#);
        let v3 = rules(&r3.toml);
        assert_eq!(v3["rule"][0]["when"][0]["op"].as_str().unwrap(), "cidr");
    }

    #[test]
    fn skips_response_phase_and_macros() {
        let r = convert(
            r#"SecRule RESPONSE_BODY "@rx secret" "id:11,phase:4,deny"
SecRule ARGS "@rx %{tx.foo}" "id:12,phase:2,deny""#,
        );
        assert_eq!(r.converted, 0);
        assert_eq!(r.skipped.len(), 2);
    }

    #[test]
    fn line_continuations_join() {
        let src = "SecRule ARGS \"@rx evil\" \\\n  \"id:13,phase:2,deny\"";
        let r = convert(src);
        assert_eq!(r.converted, 1);
    }
}
