# Attack class: xss

Untrusted data is rendered into an HTML, JavaScript, or DOM context
without contextual output encoding, so attacker-supplied markup or
script executes in a victim's browser. Covers reflected (echoed from
the current request), stored (persisted then served), and DOM-based
(client-side sink) variants. The bug lives where a value crosses into a
browser-interpreted context without encoding appropriate to *that*
context.

## What to look for

A value tracing back to attacker-controlled input (query strings, form
fields, JSON bodies, headers, uploaded content, or previously stored
records) reaches an HTML/JS/DOM sink without being encoded for it.

- **Server templates.** Autoescaping disabled or bypassed: Jinja
  `| safe` / `{% autoescape false %}`, Django `mark_safe` /
  `{% autoescape off %}`, Handlebars/Mustache triple-braces
  `{{{ ... }}}`, ERB `raw`/`<%== %>`, Go `template.HTML(user)` widening
  a string into trusted markup.
- **JavaScript / DOM.** `element.innerHTML = user`, `outerHTML`,
  `document.write`, `insertAdjacentHTML`, `$(el).html(user)`,
  React `dangerouslySetInnerHTML`, `eval`/`Function`/`setTimeout` fed a
  user string, and assigning user data to `location`/`href`/`src` with a
  `javascript:` scheme.
- **Server-emitted HTML.** `res.send`/`res.write`/`res.end` (Express) or
  equivalent writing a concatenated HTML string that embeds request
  data, rather than a templated, escaped response.
- **JSP / JSF / EL.** `<%= user %>` scriptlet output, unescaped
  `${user}` EL, `<c:out escapeXml="false">`, or `h:outputText
  escape="false"`.

## Evidence

Hunt's v0.3 toolset is `read_file`, `list_dir`, `grep`, `find_definition`,
`find_callers`, and `record_finding` — there is no `compile_and_run`, so a
finding cannot carry a real execution result. Use `find_definition` and
`find_callers` to trace how untrusted data reaches the sink. A finding should
carry `file`, `function`, `line_start`, `line_end` at the sink plus a
`description` of that flow, and a short **textual** `poc_code` sketch of the
triggering input. Do **not** fabricate a `poc_result` — leave it unset.
Confidence: `likely` when you can trace the flow end-to-end, `speculative`
when a link in the chain is unclear. Do **not** use `confirmed`; it requires
execution Hunt cannot perform in v0.3.

## Common false positives

- Framework autoescaping is on and the value flows through the default
  escaped path (no `| safe`/`raw`/triple-brace/`escape=false`). This is
  the safe shape — do not report it.
- The value is written via `textContent` / `innerText` /
  `setAttribute` / `createTextNode`, which do not parse markup.
- The data passes through a vetted, context-appropriate sanitizer
  (DOMPurify, OWASP Java HTML Sanitizer) before reaching the sink.
- Correct context-aware encoding is applied (HTML-entity, JS-string, or
  URL encoding matching the sink's context).

## Stop condition

After one pass through the `scope_hint`, stop. Record zero or more
findings via `record_finding`. Recording zero findings is a valid
outcome.
