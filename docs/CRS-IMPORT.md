# Importing ModSecurity / OWASP CRS rules

B.U.D.U can convert ModSecurity `SecRule` files — including the
[OWASP Core Rule Set](https://github.com/coreruleset/coreruleset) — into its own
TOML rules with the `import-crs` subcommand:

```bash
budu import-crs path/to/rules/*.conf -o config/crs-rules.toml
# then point [paths] rules at the output and validate:
budu --config config/budu.toml check
```

Without `-o` the TOML is written to stdout; a conversion **report** (how many
rules converted, which were skipped and why) always goes to stderr.

> This is a **migration aid, not a drop-in CRS runtime.** It converts the common
> rule shapes and *skips what it can't represent* (rather than mistranslating
> it). Always review the generated file and run `check` before deploying.

## What gets converted

| ModSecurity | → B.U.D.U |
|---|---|
| `SecRule VARS "@op arg" "actions"` | one `[[rule]]` (or one per variable — see below) |
| `ARGS`, `ARGS:name`, `ARGS_NAMES`, `&ARGS` | `args`, `arg`(+name), `arg_names`, `args_count` |
| `QUERY_STRING`, `REQUEST_URI`, `REQUEST_FILENAME`, `REQUEST_METHOD`, `REQUEST_BODY` | `query`, `uri`, `path`, `method`, `body` |
| `REQUEST_HEADERS`, `REQUEST_HEADERS:Name`, `REQUEST_HEADERS_NAMES` | `headers`, `header`(+name), `header_names` |
| `REQUEST_COOKIES`, `REQUEST_COOKIES:Name`, `REQUEST_COOKIES_NAMES` | `cookies`, `cookie`(+name), `cookie_names` |
| `REMOTE_ADDR` | `ip` |
| `@rx @contains @beginsWith @endsWith @streq @eq @gt @lt @ge @le` | `regex contains starts_with ends_with eq eq gt lt ge le` |
| `@detectSQLi` / `@detectXSS` | `detect_sqli` / `detect_xss` *(needs `--features libinjection`)* |
| `@pm a b c` | `regex` `(?i)(a|b|c)` (alternation of the phrases) |
| `@ipMatch 10.0.0.0/8` (single CIDR) | `cidr` |
| `!@op …` | the condition with `negate = true` |
| `t:lowercase t:urlDecodeUni t:compressWhitespace t:removeNulls t:trim t:none` | `transform = [...]` |
| `deny` / `block` / `drop` (+`status`,`msg`) | `action = "block"` |
| `allow` | `action = "allow"` |
| `pass` with `setvar:'tx.*_anomaly_score=+%{tx.<sev>_anomaly_score}'` | `action = "score"` (critical=5, error=4, warning=3, notice=2) |
| `chain` (single-variable members) | the members' conditions AND-ed into one rule |

### Anomaly scoring

CRS doesn't block on individual rules — most rules `pass` and add to a per-request
**anomaly score**, and a separate blocking rule trips at a threshold. B.U.D.U has
the same model, so `setvar` score increments become `score` actions. Set the
threshold in your config:

```toml
[scoring]
threshold = 5      # CRS "paranoia"/blocking threshold; 5 = block on one critical hit
```

### Multiple variables (OR)

`SecRule ARGS|ARGS_NAMES "@rx evil" "id:5,deny"` matches if **either** target
matches (OR). B.U.D.U conditions within a rule are AND-ed, so the importer emits
**one rule per variable** (`crs-5-a`, `crs-5-b`, …), each able to block on its
own — preserving the OR semantics.

## What is skipped (and reported)

Each skipped source rule is listed on stderr with its `id` and the reason:

- **Response / logging phases** (`phase:3`, `phase:4`, `phase:5`). The importer
  emits request-phase rules only (phases 1–2). B.U.D.U *does* support
  response-phase rules (status/header/body) — port those by hand; see
  [RULES.md](RULES.md).
- **Macro expansion** in operator arguments (`@rx %{tx.foo}`) — runtime variable
  interpolation isn't modelled.
- **`@pmFromFile` / `@ipMatchFromFile`**, `@ipMatch` with multiple CIDRs.
- **Regex variable selectors** (`REQUEST_HEADERS:/^X-/`).
- **Multi-variable members inside a `chain`** (the OR×AND product isn't expanded).
- **`SecRuleScript` / Lua**, `SecAction`, `ctl:`, `skipAfter:` and other control
  flow — silently ignored (they're engine plumbing, not detection rules).

Unsupported `t:` transforms (e.g. `htmlEntityDecode`, `base64Decode`) are dropped
from a rule that is otherwise emitted; these appear under **warnings** in the
report, because dropping a transform can change match semantics. Review them.

## Example

```bash
$ budu import-crs crs/*.conf -o config/crs-rules.toml
wrote config/crs-rules.toml (842 rule blocks)
--- import-crs report ---
converted: 731
skipped:   149
  skip [920100]: phase 4 (response/logging) not supported in this importer
  skip [942521]: operator argument uses a macro ("%{tx.sql_injection_score}")
  ...
warnings:
  @detectSQLi → detect_sqli requires building budu with --features libinjection
```

Then wire it in and validate:

```toml
# config/budu.toml
[scoring]
threshold = 5
[paths]
rules = "config/crs-rules.toml"
```

```bash
budu --config config/budu.toml check   # compiles the imported rules
```
