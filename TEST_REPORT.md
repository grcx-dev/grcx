# GRCX Test Report

**Date:** 2026-05-18
**Suite:** 225 tests, 98% line coverage, 97% branch coverage
**Run time:** ~38 seconds offline, zero API tokens
**Status:** All tests passing. No production source code modified except [grcx/resolver/resolver.py](grcx/resolver/resolver.py) (new `claude-cli` backend) and [dashboard/\_\_init\_\_.py](dashboard/__init__.py) (made into a proper Python package).

---

## TL;DR for the maintainer

The test suite is now a solid backstop for refactoring. **All findings below were discovered while writing tests — none were invented.** They are pinned in the suite, meaning the *current behaviour* is now a contract: if you fix any of them, the corresponding test will fail and you'll know which test to update.

Read this report top to bottom — findings are sorted by severity. The two CRITICAL items affect the product's core compliance promise. The HIGH items will manifest with real regulator data within months of running in production. The MEDIUM/LOW items are edge cases that won't show up daily but you should know about.

---

## Findings

| # | Severity | Title | File |
|---|---|---|---|
| 1 | **CRITICAL** | Resolver silently drops findings on missing `has_implications` | [resolver.py:239](grcx/resolver/resolver.py#L239) |
| 2 | **CRITICAL** | AuditLog is not process-safe — concurrent writers corrupt the chain | [audit/log.py:46-94](grcx/audit/log.py#L46-L94) |
| 3 | **HIGH** | Brittle JSON parsing — only ` ``` ` fences handled, any other LLM decoration drops the finding | [resolver.py:230-236](grcx/resolver/resolver.py#L230-L236) |
| 4 | **HIGH** | No control-ID validation — hallucinated IDs flow into audit log | [resolver.py:241](grcx/resolver/resolver.py#L241) |
| 5 | **HIGH** | `affected_controls` accepted as string instead of list | [resolver.py:241](grcx/resolver/resolver.py#L241) |
| 6 | **HIGH** | `RssSentinel._load_seen` crashes on non-UTF-8 state file | [rss.py:46-49](grcx/sentinel/regulatory/rss.py#L46-L49) |
| 7 | **MEDIUM** | `_decode_header_value` crashes on unknown charsets | [imap_email.py:95-103](grcx/sentinel/regulatory/imap_email.py#L95-L103) |
| 8 | **MEDIUM** | Hash algorithm not pinned at SHA-256 (mutation test survivor) | [audit/log.py:40-44](grcx/audit/log.py#L40-L44) |
| 9 | **LOW** | `AuditLog.tail(0)` returns ALL entries, not zero | [audit/log.py:135-139](grcx/audit/log.py#L135-L139) |
| 10 | **LOW** | `_LinkExtractor` silently drops unclosed anchor tags | [imap_email.py:65-92](grcx/sentinel/regulatory/imap_email.py#L65-L92) |

---

## CRITICAL findings

### 1. Resolver silently drops findings when LLM omits `has_implications`

**Location:** [grcx/resolver/resolver.py:239](grcx/resolver/resolver.py#L239)

```python
result = ResolverResult(
    has_implications=data.get("has_implications", False),   # <-- the issue
    ...
)
```

**What's wrong:** If the LLM returns a JSON response that does not include the `has_implications` key (truncation, hallucination, format drift), the resolver defaults it to `False`. The `if result.has_implications:` check at [resolver.py:248](grcx/resolver/resolver.py#L248) is then `False`, and **no audit assessment entry is written**. The finding is silently dropped, looking identical to a clean "no compliance implications" outcome.

**Why it matters:** This is a compliance product. The core promise is "we will not miss a regulatory finding." Today, an LLM that truncates one response per day silently drops one real finding per day. Worst case: a critical new rule from the FCA gets dropped because the LLM hit a context limit on a long publication. The compliance team has no signal anything went wrong.

**How it's pinned in tests:** [tests/test_resolver_llm_weirdness.py::test_response_missing_has_implications_defaults_to_false](tests/test_resolver_llm_weirdness.py#L1)

**Suggested fix:**
```python
if "has_implications" not in data:
    raise ValueError(f"LLM response missing required key 'has_implications': {data}")
```
The existing `except Exception` at [resolver.py:289](grcx/resolver/resolver.py#L289) will convert this into a `resolver.error` audit entry, which IS what we want — operators will see "resolver failed for X" and can re-run it. Silent drops are worse than loud errors here.

---

### 2. AuditLog is not process-safe — concurrent writers corrupt the chain

**Location:** [grcx/audit/log.py:46-94](grcx/audit/log.py#L46-L94) (the `write` method)

**What's wrong:** Each `AuditLog` instance holds `self._last_hash` in memory. If two processes (or two `AuditLog` instances in the same process) write to the same log file, each one chains off its stale in-memory `_last_hash` value. The result: two entries claiming the same `prev_hash`, breaking the chain immediately. `verify()` will then return `(False, errors)` permanently — the log is corrupted with no recovery.

**Why it matters:** The audit log is the compliance evidence — it must remain verifiable forever. Today the codebase implicitly assumes a single writer process, but nothing enforces it. Two things will trip this in production:

1. Running `grcx watch` twice (e.g. operator forgets the first instance is running in another terminal).
2. The `backfill-titles` CLI command running while `grcx watch` is also running.

**How it's pinned in tests:** [tests/test_concurrent_state.py::test_two_audit_logs_writing_to_same_file_chain_breaks_predictably](tests/test_concurrent_state.py)

**Suggested fix (one of):**
1. **Cheap:** Document that the audit log requires a single writer. Add a startup check in `AuditLog.__init__` that creates a lockfile (`grcx-audit/.lock`) using `fcntl.flock` or similar. Refuse to start if locked. This catches the operator-forgot case loudly.
2. **Correct:** Re-read `_last_hash` from disk inside `write()` under a file lock, before computing the new entry. Adds a disk read per write but eliminates the race. This also fixes the `backfill-titles` scenario.
3. **Best long-term:** Move to a SQLite-backed audit log. SQLite serialises writes natively and you keep the JSONL export as a derived view.

---

## HIGH findings

### 3. Brittle JSON parsing — most LLM decoration patterns drop the finding

**Location:** [grcx/resolver/resolver.py:230-236](grcx/resolver/resolver.py#L230-L236)

```python
if raw.startswith("```"):
    raw = raw.split("```")[1]
    if raw.startswith("json"):
        raw = raw[4:]
raw = raw.strip()
data = json.loads(raw)
```

**What's wrong:** The fence-stripping logic handles only triple-backtick fences that appear at the *very start* of the response. It does **not** handle:
- Prose before the JSON: `"Here is my analysis:\n{...}"`
- Prose after the JSON: `"{...}\n\nNote: this is preliminary."`
- Single-quoted Python-style dicts: `"{'has_implications': true, ...}"`
- Trailing commas: `"{..., \"affected_controls\": [],}"`
- JSON with comments
- Truncated JSON

In every case above, `json.loads` raises and the entire finding is dropped to a `resolver.error` audit entry.

**Why it matters:** Modern LLMs (especially smaller ones like Haiku and Gemini Flash) are inconsistent about wrapping. A model that follows instructions 99% of the time will produce malformed output ~1% of the time. At ~180 calls/day that's ~2 dropped findings/day. Over a quarter that's ~180 findings lost.

**How it's pinned in tests:** Five tests in [tests/test_resolver_llm_weirdness.py](tests/test_resolver_llm_weirdness.py) cover trailing prose, leading prose, single quotes, trailing commas, and truncated JSON. They all currently assert the finding is dropped to `resolver.error`.

**Suggested fix:** Replace the manual fence-stripping with a tolerant JSON extractor:
```python
import re
# Find the first '{' through the matching '}' using regex/balanced-brace search
m = re.search(r'\{.*\}', raw, re.DOTALL)
if not m:
    raise ValueError("No JSON object found in LLM response")
data = json.loads(m.group(0))
```
This handles prose-before, prose-after, and code fences uniformly. It does NOT fix single-quote or trailing-comma issues — for those, consider `json5` or `demjson`. The cleanest is to use Anthropic's `response_format` / Gemini's `response_mime_type=application/json` parameters, which already exist in the codebase for Gemini but not Anthropic.

---

### 4. No control-ID validation — hallucinated IDs flow into audit log

**Location:** [grcx/resolver/resolver.py:241](grcx/resolver/resolver.py#L241)

```python
affected_controls=data.get("affected_controls", []),
```

**What's wrong:** The resolver accepts whatever control IDs the LLM returns, without checking they exist in the framework yaml it loaded at [resolver.py:130](grcx/resolver/resolver.py#L130). An LLM that hallucinates `"BOGUS-99"` or `"5.1.1.2"` (where the framework only has `"5.1"`) will write that bogus ID into the audit log. The dashboard then shows a flagged finding with a control ID that has no source-of-truth.

**Why it matters:** Compliance teams cross-reference control IDs against their control catalog. A hallucinated ID is worse than no ID — it looks legitimate and routes work to the wrong owner.

**How it's pinned in tests:** [tests/test_resolver_llm_weirdness.py::test_response_with_hallucinated_control_ids](tests/test_resolver_llm_weirdness.py) — currently documents that hallucinated IDs flow through unchecked.

**Suggested fix:**
```python
valid_ids = {c["id"] for c in framework.get("controls", [])}
returned = data.get("affected_controls", [])
filtered = [cid for cid in returned if cid in valid_ids]
if returned and not filtered:
    # All returned IDs were hallucinated — log and skip
    console.print(f"[yellow]Resolver returned only invalid control IDs for {item.title[:40]}: {returned}[/yellow]")
result.affected_controls = filtered
```

---

### 5. `affected_controls` accepted as string instead of list

**Location:** [grcx/resolver/resolver.py:241](grcx/resolver/resolver.py#L241)

**What's wrong:** If the LLM returns `"affected_controls": "5.1"` (string) instead of `"affected_controls": ["5.1"]` (list), `data.get("affected_controls", [])` returns the string. Downstream code at:
- [resolver.py:257](grcx/resolver/resolver.py#L257) writes the string into the audit log
- [resolver.py:272-275](grcx/resolver/resolver.py#L272-L275) does `', '.join(result.affected_controls)` which on a string iterates *over characters* and prints `"5, ., 1"`
- [dashboard/app.py:225](dashboard/app.py#L225) does `entry["detail"].get("affected_controls", [])` and the template iterates → renders one badge per character

**Why it matters:** Silent data corruption. No exception, no log entry — just garbage on the dashboard.

**How it's pinned in tests:** [tests/test_resolver_llm_weirdness.py::test_response_with_affected_controls_as_string](tests/test_resolver_llm_weirdness.py)

**Suggested fix:** Type-coerce on the way in:
```python
raw_controls = data.get("affected_controls", [])
if isinstance(raw_controls, str):
    raw_controls = [raw_controls]
if not isinstance(raw_controls, list):
    raw_controls = []
```

---

### 6. `RssSentinel._load_seen` crashes on non-UTF-8 state file

**Location:** [grcx/sentinel/regulatory/rss.py:46-49](grcx/sentinel/regulatory/rss.py#L46-L49)

```python
def _load_seen(self) -> set:
    if self.state_path.exists():
        return set(self.state_path.read_text().splitlines())   # <-- unsafe
    return set()
```

**What's wrong:** `Path.read_text()` defaults to UTF-8 with strict error handling. If the state file (`grcx-audit/seen_boe.txt`) contains any non-UTF-8 bytes — which happens after a mid-write OS crash, disk corruption, or a partially-written file from a previous abort — this raises `UnicodeDecodeError` and the entire sentinel fails to construct. The watcher dies on startup with no useful recovery path.

**Why it matters:** This is the *startup path*. If it crashes, grcx is offline. A single corrupted state byte takes the whole feed offline until manual intervention.

**How it's pinned in tests:** [tests/test_concurrent_state.py::test_rss_state_file_survives_corrupt_content_on_reload](tests/test_concurrent_state.py) — currently asserts the `UnicodeDecodeError`. A future fix should make this test assert successful recovery instead.

**Suggested fix:** One line:
```python
return set(self.state_path.read_text(errors="replace").splitlines())
```
Stripping the replacement character (`�`) from the set afterward is paranoid but cheap. Same issue exists in [imap_email.py:174-177](grcx/sentinel/regulatory/imap_email.py#L174-L177).

---

## MEDIUM findings

### 7. `_decode_header_value` crashes on unknown charsets

**Location:** [grcx/sentinel/regulatory/imap_email.py:95-103](grcx/sentinel/regulatory/imap_email.py#L95-L103)

```python
def _decode_header_value(raw: str) -> str:
    parts = decode_header(raw)
    decoded = []
    for chunk, charset in parts:
        if isinstance(chunk, bytes):
            decoded.append(chunk.decode(charset or "utf-8", errors="replace"))   # <-- LookupError here
        else:
            decoded.append(chunk)
    return "".join(decoded)
```

**What's wrong:** `errors="replace"` handles bad bytes within a known encoding, but it does **not** handle the case where the codec name itself is unknown. An email header like `Subject: =?bogus-charset?Q?Hi?=` raises `LookupError: unknown encoding: bogus-charset`, which propagates up out of `_parse_message` and crashes the IMAP fetch loop. The `try/except` at [imap_email.py:197-201](grcx/sentinel/regulatory/imap_email.py#L197-L201) catches it and skips the entire mailbox for that poll cycle, but one malformed email from one regulator silently breaks all of that jurisdiction's monitoring.

**Why it matters:** Spam, malware, or genuinely old MUAs occasionally emit headers with non-standard charset labels. One such email arriving in the FCA mailbox would stop FCA monitoring until that email is deleted.

**How it's pinned in tests:** [tests/test_unicode_encoding.py::test_email_subject_decode_falls_back_on_unknown_charset](tests/test_unicode_encoding.py) — currently documents the crash behaviour.

**Suggested fix:**
```python
try:
    decoded.append(chunk.decode(charset or "utf-8", errors="replace"))
except LookupError:
    decoded.append(chunk.decode("utf-8", errors="replace"))
```

---

### 8. Hash algorithm not pinned at SHA-256

**Location:** [grcx/audit/log.py:40-44](grcx/audit/log.py#L40-L44)

```python
def _hash_entry(self, entry: dict) -> str:
    """SHA-256 hash of the entry content (excluding the hash field itself)."""
    hashable = {k: v for k, v in entry.items() if k != "entry_hash"}
    content = json.dumps(hashable, sort_keys=True)
    return hashlib.sha256(content.encode()).hexdigest()
```

**What's wrong:** This finding came from **mutation testing**: I manually swapped `sha256` for `sha1` and ran the audit suite. Every existing test passed. The reason: the chain-integrity property only requires `write()` and `verify()` to use the *same* hash, not specifically SHA-256. So a contributor who innocently swaps the algorithm (or imports the wrong one) would not be caught.

**Why it matters:** SHA-1 has been broken for collision attacks since 2017. The docstring promises SHA-256 — that's part of the trust contract with auditors. If the actual algorithm drifted to SHA-1 or MD5 by a one-character typo, regulators would have grounds to invalidate the audit log entirely.

**How it's pinned in tests:** Now pinned at [tests/test_audit_log_hash_pin.py](tests/test_audit_log_hash_pin.py) — two tests assert (a) the entry hash is exactly 64 hex chars (SHA-256 shape) and (b) the entry hash matches an independently-computed SHA-256 of the canonical entry.

**Suggested fix:** Not a code fix — a tests-side strengthening that's already in place. If you ever want to allow alternate algorithms, you'd update the pin test alongside the code change.

---

## LOW findings

### 9. `AuditLog.tail(0)` returns ALL entries, not zero

**Location:** [grcx/audit/log.py:135-139](grcx/audit/log.py#L135-L139)

```python
def tail(self, n: int = 10) -> list[dict]:
    """Return the last n entries."""
    if not self.log_path.exists():
        return []
    lines = self.log_path.read_text().strip().splitlines()
    return [json.loads(l) for l in lines[-n:]]   # lines[-0:] == lines[:]
```

**What's wrong:** Python quirk: `-0 == 0`, so `lines[-0:]` evaluates to `lines[0:]`, which is the entire list. A caller doing `log.tail(0)` expecting "give me nothing" gets the whole log back instead.

**Why it matters:** Today nothing calls `tail(0)`. But anyone writing a new feature like "show the last N entries where N is configurable, and N=0 means hide the panel" would silently hit this and load potentially gigabytes of log into memory.

**How it's pinned in tests:** [tests/test_audit_chain_stress.py::test_tail_returns_correct_count_at_boundary](tests/test_audit_chain_stress.py)

**Suggested fix:**
```python
def tail(self, n: int = 10) -> list[dict]:
    if n <= 0 or not self.log_path.exists():
        return []
    lines = self.log_path.read_text().strip().splitlines()
    return [json.loads(l) for l in lines[-n:]]
```

---

### 10. `_LinkExtractor` silently drops unclosed anchor tags

**Location:** [grcx/sentinel/regulatory/imap_email.py:65-92](grcx/sentinel/regulatory/imap_email.py#L65-L92)

**What's wrong:** The parser only appends a link to `self.links` inside `handle_endtag` when it sees `</a>`. If an email body is truncated mid-anchor (e.g. legitimate email cut off by a mail server's size limit, or a corrupt MIME part), the partial anchor is silently dropped. The fallback at [imap_email.py:263-274](grcx/sentinel/regulatory/imap_email.py#L263-L274) only fires if the *initial* link list is empty — but a single closed anchor anywhere else in the body prevents that fallback too.

**Why it matters:** Genuinely rare in practice but worth noting. A regulator email with a content-length mismatch (truncated mid-anchor on the last regulation link) would silently drop the most important link of that email.

**How it's pinned in tests:** [tests/test_malformed_feeds.py::test_email_html_with_broken_tags](tests/test_malformed_feeds.py)

**Suggested fix:** In `_LinkExtractor.close()` (a method on `HTMLParser` you can override), flush any in-progress `_current_href` + `_current_text` as a last link. Or: use a real HTML parser like `selectolax` or `lxml.html` and rely on its lenient mode.

---

## Defensive properties that PASSED — no fix needed

For completeness, here is what testing confirmed is working correctly. These are encouraging:

- **SQL injection in dashboard signup** — fully protected by parameterised queries. Verified in [tests/test_dashboard_security.py](tests/test_dashboard_security.py).
- **XSS in dashboard rendering** — Jinja2 auto-escaping correctly handles `<script>` in titles and recommended actions.
- **Password storage** — werkzeug hashes (`scrypt:` / `pbkdf2:` prefix), never plaintext.
- **Session cookies** — `HttpOnly` flag set by Flask defaults.
- **XML External Entity (XXE) attacks** — Python's `xml.etree.ElementTree` is XXE-safe by default; verified with `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>` payload.
- **Fingerprint determinism + collision resistance** — Hypothesis ran ~500 random URL/title pairs, found zero collisions (truncated SHA-256 at 16 hex = 64 bits, collision probability ~1e-19).
- **Audit chain integrity under stress** — 1000-entry chain verifies in <2s. Any single-byte tamper at any position is detected.
- **Resolver never crashes on arbitrary LLM text** — Hypothesis verified across thousands of random outputs. Always either returns a result list or writes a `resolver.error` entry.

---

## Test suite summary

```
Total tests:       225 (134 unit, 89 integration, 2 live)
Line coverage:     98% (789 statements, 13 missed)
Branch coverage:   97% (230 branches, 15 partial)
Run time:          ~38 seconds offline
API token cost:    $0 (all LLM clients mocked)
```

Module-by-module coverage:

| Module | Line | Branch |
|---|---|---|
| [grcx/audit/log.py](grcx/audit/log.py) | 100% | 100% |
| [grcx/resolver/resolver.py](grcx/resolver/resolver.py) | 100% | 100% |
| [grcx/sentinel/runner.py](grcx/sentinel/runner.py) | 100% | 98% |
| [grcx/sentinel/regulatory/rss.py](grcx/sentinel/regulatory/rss.py) | 100% | 98% |
| [grcx/sentinel/regulatory/imap_email.py](grcx/sentinel/regulatory/imap_email.py) | 98% | 97% |
| [grcx/cli.py](grcx/cli.py) | 97% | 96% |
| [dashboard/app.py](dashboard/app.py) | 96% | 94% |

### Test file inventory

- [tests/test_audit_log.py](tests/test_audit_log.py) — hash chain, tamper detection, cross-instance resume
- [tests/test_audit_log_corruption.py](tests/test_audit_log_corruption.py) — empty file, corrupted last line, JSON decode errors
- [tests/test_audit_log_hash_pin.py](tests/test_audit_log_hash_pin.py) — pins SHA-256 algorithm (mutation testing finding)
- [tests/test_audit_chain_stress.py](tests/test_audit_chain_stress.py) — 1000-entry chains, unicode, complex nested detail
- [tests/test_fingerprint.py](tests/test_fingerprint.py) — golden-value pin on `sha256(url+title)[:16]`
- [tests/test_frameworks_yaml.py](tests/test_frameworks_yaml.py) — every framework yaml structurally valid
- [tests/test_rss_parse.py](tests/test_rss_parse.py) — RSS 2.0 + Atom, malformed, missing fields
- [tests/test_rss_dedup.py](tests/test_rss_dedup.py) — seen-state file, retry behaviour
- [tests/test_email_parse.py](tests/test_email_parse.py) — HTML/plaintext extraction, skip patterns
- [tests/test_email_helpers.py](tests/test_email_helpers.py) — header decoding, link extraction
- [tests/test_imap_connection.py](tests/test_imap_connection.py) — IMAP4_SSL layer (login failure, search status, UID cap)
- [tests/test_unicode_encoding.py](tests/test_unicode_encoding.py) — Unicode, MIME, NFC/NFD
- [tests/test_malformed_feeds.py](tests/test_malformed_feeds.py) — XXE, BOM, broken anchors
- [tests/test_resolver_pure.py](tests/test_resolver_pure.py) — framework loading, controls summary
- [tests/test_resolver_routing.py](tests/test_resolver_routing.py) — Claude/Gemini/Ollama provider selection
- [tests/test_resolver_analyse.py](tests/test_resolver_analyse.py) — end-to-end with mocked providers
- [tests/test_resolver_claude_cli.py](tests/test_resolver_claude_cli.py) — new `claude-cli` subprocess branch
- [tests/test_resolver_llm_weirdness.py](tests/test_resolver_llm_weirdness.py) — malformed LLM responses (8 findings here)
- [tests/test_resolver_prompt_injection.py](tests/test_resolver_prompt_injection.py) — adversarial regulator content
- [tests/test_backfill_titles.py](tests/test_backfill_titles.py) — CLI hash chain rebuild
- [tests/test_runner.py](tests/test_runner.py) — main poll loop integration
- [tests/test_cli.py](tests/test_cli.py) — `init`, `audit`, `watch` commands
- [tests/test_cli_error_paths.py](tests/test_cli_error_paths.py) — error paths, env-var substitution
- [tests/test_dashboard_load_data.py](tests/test_dashboard_load_data.py) — audit schema → UI aggregation
- [tests/test_dashboard_auth.py](tests/test_dashboard_auth.py) — signup, sign-in, login-required
- [tests/test_dashboard_security.py](tests/test_dashboard_security.py) — SQL/XSS protection, cookie flags
- [tests/test_dashboard_edge_paths.py](tests/test_dashboard_edge_paths.py) — timestamps, SMTP, validation
- [tests/test_concurrent_state.py](tests/test_concurrent_state.py) — multi-writer corruption, race conditions
- [tests/test_hypothesis_properties.py](tests/test_hypothesis_properties.py) — property-based invariants
- [tests/test_contract.py](tests/test_contract.py) — end-to-end runner → dashboard contract
- [tests/test_live.py](tests/test_live.py) — real BOE + ESMA feeds (opt-in)

### Fixture data

- [tests/conftest.py](tests/conftest.py) — shared fixtures and LLM mocking
- [tests/fixtures/](tests/fixtures/) — RSS samples (BOE, ESMA, unicode, malformed), email samples (FCA HTML, MAS URL-anchor, unicode .eml, plaintext, nested-anchor edge cases)

---

## How to run

```bash
# Default suite (offline, $0 cost)
.venv/bin/python -m pytest

# With coverage
.venv/bin/python -m pytest --cov=grcx --cov=dashboard --cov-branch --cov-report=term-missing

# Live tests (real BOE + ESMA RSS, no LLM)
.venv/bin/python -m pytest -m live

# Single test file
.venv/bin/python -m pytest tests/test_resolver_llm_weirdness.py -v
```

---

## Future work

Items intentionally left for the maintainer:

1. **Fix the 10 findings above.** Each has a pinned test that will need updating when the underlying behaviour changes.
2. **CI integration.** Add `pytest -m "not live"` to a GitHub Action on every PR. Add `pytest -m live` to a nightly run.
3. **Mutation testing infrastructure.** `mutmut` 3.x is too brittle for this repo's structure (it ignores the `runner` config). Either downgrade to mutmut 2.x with a `setup.cfg`-style config, or wait for mutmut 3.x to add proper runner customisation. Manual mutation testing was done on the audit module only.
4. **Resolver output schema.** Define a Pydantic model for the expected LLM JSON response. Validate on parse. Most of findings #1, #3, #4, #5 collapse into one defensive boundary.
5. **JSON Schema for `--output-format json` calls.** The Claude CLI supports `--json-schema` which would force the LLM to return well-shaped JSON. Worth wiring up alongside the resolver schema.
6. **Concurrent-write protection on AuditLog.** Either a lockfile or a SQLite backend — both fix finding #2.

---

## Token cost of building this report and test suite

- All LLM calls in this work used the user's Max 5x subscription, not API tokens.
- **Zero API tokens consumed.** Anthropic API bill: $0.
- Subscription consumption was ~7.6M tokens across the whole session, but that's not a dollar cost on Max 5x — it's cap consumption.
- The suite itself runs **forever for free** locally — pytest never makes a network call by default.
