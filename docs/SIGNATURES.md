# Signatures (`signatures.toml`)

Signatures are attack-pattern matchers (SQLi, XSS, path traversal, command
injection) applied to the **normalized** request — percent-decoded and
case-folded path, query, and (when buffered) body. This defeats common encoding
and case-variation evasions.

Matching is two-tier for speed:

1. An **aho-corasick** automaton scans once for fixed literal strings.
2. A **RegexSet** catches fuzzy variants the literals can't.

The compiled set is held behind `ArcSwap` and **hot-reloads on `SIGHUP`**.

---

## Built-in vs custom

```toml
[paths]
signatures = ""                     # "" → use the built-in baseline set
# signatures = "config/signatures.toml"   # a path REPLACES the built-ins
```

- **Empty path** → the built-in baseline (SQLi/XSS/LFI/RCE) is used.
- **A file path** → your file **replaces** the built-ins entirely. If you want the
  baseline *plus* your own, copy the built-ins into your file (or rely on custom
  [rules](RULES.md) for the extra cases).

The built-in set covers, among others: `union select`, boolean tautologies
(`' or 1=1`), time-based SQLi (`sleep(`, `benchmark(`), `<script`, `javascript:`,
`onerror=`, event handlers, `../`, `/etc/passwd`, and shell-metacharacter command
injection.

---

## File format

```toml
# Each entry uses EITHER `literal` OR `regex`.
[[signature]]
id     = "sqli.union_select"      # required, unique
literal = "union select"          # fixed string (fast path)
status = 403                      # response status (default 403)
reason = "SQL injection: UNION SELECT"   # block reason (default = id)

[[signature]]
id    = "sqli.or_boolean"
regex = "(?:'|\"| )or +[0-9]+ *= *[0-9]+"   # fuzzy variant
status = 403
reason = "SQL injection: boolean tautology"
```

| Key | Required | Notes |
|---|---|---|
| `id` | yes | Reported as `rule_id` in blocks/audit. |
| `literal` | one of | A fixed lowercase substring. |
| `regex` | one of | ASCII regex; `(?i)` supported. Provide exactly one of `literal`/`regex`. |
| `status` | no | HTTP status on match (default `403`). |
| `reason` | no | Human-readable reason (default = `id`). |

### Writing patterns

- The haystack is **already lowercased and percent-decoded**, so write literals in
  lowercase and assume single decoding (e.g. `%3cscript%3e` arrives as
  `<script>`).
- Regex uses **ASCII** semantics (the `unicode` feature is off, matching HTTP
  bytes). Use explicit classes like `[0-9]` and `[ ]`; Perl shorthands `\d`/`\s`
  also work in ASCII mode, and `(?i)` gives ASCII-case-insensitive matching.
- Prefer a `literal` when possible — it's the cheap automaton path; reserve
  `regex` for variants that need whitespace/alternation flexibility.

---

## How it fits the pipeline

Signatures run **after** custom rules in the inspection phase, so:

- A custom `allow` rule can whitelist a request *past* signature scanning.
- A custom `block` rule fires *before* signatures.

A signature match → `403` (or the configured `status`), an audit-log entry, and
`budu_blocked_total` increments. The current signature count is exposed as
`budu_signatures` on `/metrics`.

Validate after editing:

```bash
budu --config config/budu.toml check     # compiles signatures, reports count
```
