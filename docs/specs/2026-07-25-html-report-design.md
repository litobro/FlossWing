# HTML report — `report.html` as a fourth Report format

Status: designed, not implemented.
Supersedes nothing. Extends `docs/specs/2026-06-02-v1.0-report-design.md`.

## Goal

Give the operator a triage-oriented view of a scan's findings that can be
opened in a browser, without leaving the local CLI model. The Report stage
gains a fourth output format, `report.html`, alongside `report.md`,
`report.json` and the per-finding directories.

The motivating problem: `report.md` groups findings **by severity**. On a
real scan that axis is frequently degenerate — the 2026-07-25
`home-assistant/core` run produced six `medium` and two `low`, so severity
sorted nothing. The information that actually drives triage is the
adjudication the pipeline already performs: Validate's verdict and Trace's
reachability. `report.html` orders on that axis and lets dismissed findings
collapse out of the way.

## Decisions (from brainstorming, 2026-07-25)

1. **A static HTML file is a report *format*, not the "web UI" non-goal.**
   Operator decision. `ARCHITECTURE.md` lists "no web UI" as a hard non-goal
   and "Web UI / local server mode" as deferred to v2. Those target *service*
   architecture — a daemon, a server, routes, multi-tenancy. A single
   self-contained file written to the run's output directory and opened with
   `file://` introduces none of that. `ARCHITECTURE.md` is amended in the
   same change to record this explicitly, so the boundary stays legible.

2. **`html` joins the default format set**, which becomes `md,json,html`.
   The operator asked for the view to be generated automatically. Cost is one
   extra file per run (~60 KB for an 8-finding run).

3. **Rendering strategy: embed JSON, build the DOM client-side via
   `textContent`.** Not server-side string interpolation, and not a
   templating dependency. Rationale under *Error handling & security*.

4. **No new dependency.** Rejected Jinja2: one fixed template does not
   justify a top-level runtime dep, and autoescape would not improve on the
   chosen strategy's structural guarantee.

5. **No `--open` flag.** Auto-launching a browser is the step that starts to
   resemble a UI rather than a file. Out of scope.

## Architecture

### New: `flosswing/stages/report_html.py`

Single public function:

```python
def render_html(report: ReportV1) -> str: ...
```

It consumes the **existing** `ReportV1` model that `report.py` already builds
via `_load()`. No new queries, no new state access, no agent, no I/O. The
function is pure: `ReportV1` in, HTML string out. That makes it trivially
testable and keeps the renderer isolated from the orchestration.

Module-level constants hold the CSS and JS as plain strings. This is the
reason for a separate module: `report.py` is already 893 lines, and folding
a stylesheet plus a client script into it would push it well past the point
where it is doing one thing.

### Data flow

```
state DB --_load()--> ReportV1 --render_html()--> str --report.py--> output/report.html
```

`report.py` gains `"html"` in `_VALID_FORMATS` and one write branch
appending `"html"` to `formats_written`. No other change to its logic.

### Rendering strategy

The emitted document is:

1. A fixed HTML shell (no `<!doctype>`/`<html>`/`<head>` concerns — this is a
   standalone file, so it emits a complete document).
2. Inline `<style>` — no external stylesheet, no webfont, no CDN.
3. One `<script>` containing `const REPORT = <json.dumps(..., ensure_ascii=True)>`.
4. Inline JS that builds the DOM from `REPORT`, assigning all text through
   `textContent`.

### Content and ordering

Findings sort by **triage priority**, not severity:

| key | order |
| --- | --- |
| 1. status | `confirmed` -> `uncertain` -> `rejected` |
| 2. reachability | `reachable` -> `uncertain` -> unset |
| 3. severity | existing `_SEVERITY_ORDER` |

The page contains:

- Run metadata header (run id, target repo + sha, model, duration, cost,
  token counts) — the same fields already in `ReportV1.run`.
- Summary tiles counting findings by status.
- Filter controls: all / confirmed / uncertain / rejected.
- One collapsible row per finding, its detail sectioned by the pipeline stage
  that produced it: **Hunt** (description), **Validate** (verdict +
  rationale), **Trace** (reachability + rationale), **Suggested fix**, **PoC**.
  Sections are omitted when the underlying record is absent, so a report
  rendered before Validate/Trace land degrades cleanly — consistent with
  `2026-06-02-v1.0-report-design.md` § *Graceful degradation*.
- A footer stating that a scan with zero findings is **not** evidence the
  target is secure, and that coverage is limited to the attack classes Recon
  queued. Required by `ARCHITECTURE.md` § Threat model item 5.

### Seam changes (internal — not the frozen agent-facing tool contracts)

`docs/specs/2026-06-02-v1.0-report-design.md` types the render entry point as
`formats: frozenset[Literal["md", "json", "sarif"]]`. That `Literal` gains
`"html"`. This is an internal Python signature, not a frozen contract in
`docs/tool-contracts.md`, which governs agent-facing tools only. No agent
tool signature changes.

## Configuration / CLI

- `flosswing scan --format` default: `md,json` -> `md,json,html`
  (`cli.py:172`).
- `flosswing report --format` default: `md,json` -> `md,json,html`
  (`cli.py:224`).
- Help text updated in both: `valid: md, json, sarif, html`.
- `flosswing/tui/screens/new_scan.py` holds its own copy of both: `_FORMATS`
  (line 33) gains `"html"` so the TUI stops rejecting it as invalid, and the
  input default (line 48) becomes `md,json,html`.
- `flosswing/tui/launcher.py` needs no change — it accepts
  `formats: list[str]` and passes it through verbatim.

## Error handling & security

**Markup injection is the central concern.** Finding titles, descriptions,
functions and file paths are derived from an untrusted target repository
(`CLAUDE.md`: "The target repo is untrusted input"). A renderer that
interpolates that text into HTML is an injection sink: a crafted symbol name
or README string could inject script into a document the operator opens in a
browser. This is the same class of problem the TUI already guards against by
wrapping repo-derived strings in `rich.Text` so they render literally.

The chosen strategy is **structurally** immune rather than
escaping-dependent: repo-derived text exists only inside a JSON string
literal and reaches the page through `textContent`, which cannot interpret
markup. There is no code path where a finding field is concatenated into
markup, so there is no `html.escape()` call to forget.

`json.dumps(..., ensure_ascii=True)` additionally guarantees the output is
pure ASCII. Agent-authored rationales routinely contain em-dashes and arrows;
a raw UTF-8 byte in a file opened over `file://` mojibakes when the browser
falls back to latin-1, and a standalone file cannot rely on a server charset
header.

**No credential scrubbing.** Consistent with `report.py:47-49`: finding text
is not scrubbed by Report, because that would corrupt the operator's view of
the finding. Scrubbing is the upstream stage's responsibility.

**No network.** No external stylesheet, script, font or image. The document
must render fully offline from `file://`.

## Testing

New `tests/unit/test_report_html.py`, against a `ReportV1` fixture:

1. **Injection** — a finding whose title contains
   `<script>alert(1)</script>` must not produce live markup: the sequence
   appears only inside the JSON blob, JSON-escaped. This is the test that
   matters most; it is written first and verified to fail against a naive
   interpolating renderer.
2. **ASCII-only** — every byte of the output is `< 0x80`.
3. **No external resources** — no `http://` or `https://` in any `src`/`href`.
4. **Ordering** — a confirmed finding sorts ahead of a rejected one
   regardless of severity.
5. **Graceful degradation** — a finding with no validation and no trace
   renders without those sections and without raising.
6. **Zero findings** — renders, and states that this is not evidence of
   security.

Updated: `tests/unit/test_cli_help.py`. Note it currently asserts
`"md,json" in result.output` (lines 104, 113), which would **still pass**
against `md,json,html` as a substring while silently no longer testing the
real default. Tighten it to the full string rather than leaving a test that
cannot fail.

No change needed: `test_cli_report.py` (passes `--format` explicitly) and
`test_tui_launcher.py` (passes `formats=["md", "json"]` explicitly).

Gates: `ruff check .`, `mypy --strict flosswing`, `pytest tests/unit`. No
schema change, so `docs/schema.sql` and the migration-reversibility check are
untouched.

## Documentation changes

`ARCHITECTURE.md` § *Stage 8: Report* — add to the output list:

> - `report.html` — self-contained triage view, findings ordered by
>   validation verdict and reachability; opened directly from disk

and extend the v1.0 scope note to record decision 1, worded so it does not
read as license for a server:

> `report.html` is a static file rendered from the same state, not a
> service. The "no web UI" non-goal and the v2 "local server mode" item
> stand: FlossWing serves nothing, listens on no port, and opens no browser.

No change to `docs/tool-contracts.md` (no agent-facing tool is affected) or
`docs/schema.sql` (no schema change).

## Out of scope

- `--open` / auto-launching a browser.
- Any local server or listening socket.
- Per-finding HTML pages (the per-finding directories stay as they are).
- Changes to `report.md`, `report.json`, or the per-finding directory layout.
- Charts, graphs, or trend analysis across runs (`flosswing diff` is v2).
- Printing/PDF stylesheets.

## Files touched

| action | path | why |
| --- | --- | --- |
| new | `flosswing/stages/report_html.py` | the renderer |
| edit | `flosswing/stages/report.py` | `_VALID_FORMATS` + write branch |
| edit | `flosswing/cli.py` | two `--format` defaults + help text |
| edit | `flosswing/tui/screens/new_scan.py` | `_FORMATS` set + input default |
| edit | `ARCHITECTURE.md` | Report output list + v1.0 scope note |
| new | `tests/unit/test_report_html.py` | renderer tests |
| edit | `tests/unit/test_cli_help.py` | tighten default-format assertion |

Seven files. Verified as needing **no** change: `flosswing/tui/launcher.py`,
`tests/unit/test_cli_report.py`, `tests/unit/test_tui_launcher.py`.
