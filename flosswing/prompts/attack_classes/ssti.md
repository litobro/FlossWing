# Attack class: ssti

Untrusted data reaches a template engine as template *source* — the
string the engine compiles — rather than as a bound data variable
handed to an already-compiled template. Because template languages
expose object attributes, method calls, and often arbitrary expression
evaluation, an attacker who controls the template body can evaluate
their own syntax server-side, typically escalating to information
disclosure or remote code execution (`{{7*7}}` → `49` is the probe;
`{{''.__class__...}}` / `#{...}` is the exploit). The bug lives at the
`compile(user_string)` boundary. Contrast with `xss`: XSS is about
output *encoding* of data rendered in a browser and executes in the
victim's client; SSTI evaluates on the *server* because user input
became template code, not template data.

## What to look for

A call that compiles or renders a template whose *source* is built from
request data — not a static, developer-authored template invoked with
user data in its context.

- **Python / Jinja2.** `render_template_string(user)`,
  `Template(user).render(...)`, `Environment.from_string(user)`, or an
  f-string/`+` that builds the template body from a request field before
  rendering. Flask views that format user input into the template text
  are textbook.
- **Java.** Freemarker `new Template(name, new StringReader(userSource),
  cfg)`, Velocity `evaluate`/`mergeTemplate` with a user-built template
  string, Thymeleaf with a user-controlled expression/fragment.
- **JavaScript / Node.** Handlebars/Pug/EJS/Nunjucks `compile(user)` /
  `render(userTemplateString, ...)` where the *template* argument (not
  the data argument) carries request input.
- **Ruby / PHP / others.** ERB `ERB.new(user).result`, Slim/Haml
  compiling user source, Twig `createTemplate(user)`, Smarty
  `fetch('string:'.$user)`. Any path where concatenation assembles the
  template body from untrusted input.

## Evidence

You have `read_file`, `list_dir`, `grep`, `find_definition`,
`find_callers`, and `compile_and_run`, reporting through
`record_finding`. The pivotal distinction is *which argument* the user
value lands in — the compiled source (vulnerable) or the render context
(safe). Use `find_definition`/`find_callers` to trace the request field
to the compile/render call and confirm it is the template argument. A
finding should carry `file`, `function`, `line_start`, `line_end` at the
compile/render sink, a `description` establishing that user input is the
template source and why the engine evaluates it, and a `poc_code`
payload (`{{7*7}}` as a probe, then the engine-specific RCE gadget).
`compile_and_run` is strong evidence here: rendering is self-contained,
so a harness that feeds the payload through the same engine/config and
shows `7*7` evaluating to `49` (or a sandbox-side command executing)
earns `confidence=confirmed` — attach `poc_result`. A clean end-to-end
trace without execution is `likely`; unclear reachability of the sink
with attacker data is `speculative`.

## Common false positives

- User data is passed as a *context variable* to a static,
  developer-authored template (`render_template("page.html", name=user)`,
  `template.render(user=user)`). This is the safe, normal shape — the
  engine treats it as data, not code. Do not report it (any HTML-escaping
  concern there is `xss`, not SSTI).
- A logic-less / sandboxed engine (e.g. Mustache) renders a static
  template and no user-authored template source exists.
- The "template" is a fully program-controlled constant with only bound
  variables from the context.

## Stop condition

After one pass through the `scope_hint`, stop. Record zero or more
findings via `record_finding`. Recording zero findings is a valid
outcome.
