# FlossWing Architecture

> **Audience:** This document is the primary specification for implementers (human and AI).
> It is prescriptive. Deviations from this document require explicit operator approval —
> not a unilateral decision by an implementing agent.

## What FlossWing is

FlossWing is a **local-CLI vulnerability research harness** that a developer points at a
cloned open-source repository. It runs a multi-stage LLM-agent pipeline that produces a
ranked list of confirmed vulnerabilities with reproduction PoCs and in-repo reachability
analysis.

Inspired by Cloudflare's Project Glasswing harness, adapted for single-developer,
single-repo, BYO-API-key use.

## What FlossWing is NOT

These are **hard non-goals**. Do not implement them. Do not partially implement them.
If a feature seems to require one of these, stop and ask the operator.

- **Not a service.** No daemon, no web UI, no multi-tenant anything. Local CLI only.
- **Not a SaaS.** No telemetry, no phone-home, no usage tracking. Findings stay on the
  dev's machine unless they explicitly export them.
- **Not a coding agent.** FlossWing never modifies the target repository. It has no
  `write_file` tool that points at the target tree. Patches, fixes, and PRs are out of
  scope.
- **Not a cross-repo system.** v1 traces reachability only within the cloned repo and
  its declared first-party source. No multi-repo symbol indexing.
- **Not an autonomous discloser.** FlossWing never sends email, never opens issues,
  never posts to GitHub, never contacts maintainers. Disclosure drafts are printed to
  stdout for the operator to send manually.
- **Not a replacement for human triage.** Output is structured for human review.
  Do not add "auto-apply fixes" or "auto-close low severity" modes.
- **Not a fuzzer.** FlossWing may invoke fuzzers (libFuzzer, AFL++) as tools inside the
  sandbox, but it is not itself a fuzzing framework.

## Operating model

```
$ flosswing scan ./path/to/repo --depth standard
```

1. Operator clones a target repo locally.
2. Operator invokes `flosswing scan` from outside the target tree (FlossWing's state
   lives in `~/.flosswing/`, separate from the target tree — the target repo is never
   written to).
3. FlossWing reads the target tree read-only, runs the pipeline, writes findings to its
   own state directory, generates a report.
4. Operator reviews findings, triages, optionally drafts disclosures.

The target repo is treated as **untrusted input**. README files, comments, and source
code may contain prompt injection attempts. The harness must remain functional and safe
when this occurs.

## Pipeline stages

The pipeline has eight stages. v1 implements six; two are deferred.

```
  ┌────────┐   ┌──────┐   ┌──────────┐   ┌─────────┐
  │ Recon  │──►│ Hunt │──►│ Validate │──►│ Dedupe  │
  └────────┘   └──────┘   └──────────┘   └─────────┘
                  ▲                            │
                  │                            ▼
              ┌───────┐                   ┌──────────┐
              │Gapfill│◄──────────────────│  Trace   │
              └───────┘                   └──────────┘
                                               │
                                               ▼
                                          ┌────────┐
                                          │ Report │
                                          └────────┘
```

**Feedback** (cross-repo task propagation) is not in the diagram. It is a v2 stage.

### Stage 1: Recon — **v1**

One agent, sequential. Inputs: target repo path. Outputs:
- `architecture.json` — language(s), build commands, entry points, trust boundaries,
  subsystem inventory
- Initial Hunt task queue: list of `(attack_class, scope_hint)` pairs
- Symbol index (tree-sitter, written to SQLite)

Recon reads README, build manifests (`Cargo.toml`, `package.json`, `go.mod`,
`pyproject.toml`, `pom.xml`, `CMakeLists.txt`, etc.), CI config, and top-level source
layout. It does **not** read every source file — that's Hunt's job.

Tool allowlist: `read_file`, `list_dir`, `grep`, `record_recon_artifact`,
`add_hunt_task`. No `compile_and_run`. No `record_finding`.

**Symbol index build:** Recon's outputs (languages, build commands, recon artifact)
feed a deterministic index-build phase that runs *between* Recon and Hunt in the
orchestrator. The build parses in-scope files with tree-sitter and populates the
`symbols`, `call_sites`, and `entry_points` tables for the current `run_id`. The
build is not an agent stage — there is no `agent_sessions` row for it. See
`docs/specs/2026-06-02-v0.5-symbol-index-design.md` and the cross-cutting
§ Symbol index section below.

**v1 attack class library** (Recon will only enqueue tasks for these):

- Polyglot: `command_injection`, `path_traversal`, `ssrf`, `auth_bypass`,
  `hardcoded_secrets`, `insecure_deserialization`, `xxe`, `open_redirect`
- C/C++: `buffer_overflow`, `use_after_free`, `integer_overflow`, `format_string`,
  `null_deref`
- Web: `sqli`, `xss`, `csrf`, `prototype_pollution` (JS), `unsafe_yaml`/`unsafe_pickle`
  (Python), `java_deserialization`
- Go: `nil_deref_in_error_path`, `unsafe_pointer_misuse`, `goroutine_leak`
- Rust: `unsafe_audit`, `unwrap_in_reachable_path`, `soundness_bug`

Adding new attack classes is a `prompts/attack_classes/<name>.md` file plus an entry in
`glasswing/attack_classes.py`. No code changes elsewhere required.

### Stage 2: Hunt — **v1**

N parallel agents (bounded by `--budget`, default 20 for `standard` depth, 50 for `deep`).

Each Hunt task is one `(attack_class, scope)` pair. The Hunter agent gets:
- The attack class prompt template (`prompts/attack_classes/<class>.md`)
- The scope hint (specific files/functions to investigate)
- The Recon `architecture.json`
- Prior findings in this scope (to avoid re-reporting)

Tool allowlist: `read_file`, `grep`, `find_callers`, `find_definition`, `list_dir`,
`compile_and_run`, `record_finding`. **No `write_file` against the target tree ever.**
Hunter scratch space is `~/.flosswing/runs/<run_id>/hunt/<task_id>/`.

Concurrency cap: `--budget N` is a hard ceiling on total Hunt agent invocations across
the run (not per-stage). Token-per-task budget enforced by orchestrator with hard kill.

Hunters can call `compile_and_run` to write and execute PoC code. All execution goes
through the sandbox layer (see below). Network is disabled by default.

> **v0.3 scope note (pending implementation):** The first Hunt plumbing milestone
> registers only `read_file`, `list_dir`, `grep`, `record_finding`. `compile_and_run`
> and symbol-lookup tools land with later milestones (v0.4 sandbox; v0.5 symbol
> index). Until they do, Hunt findings carry `confidence` of `likely` or
> `speculative` only — `confirmed` requires PoC execution or reachability trace,
> neither of which is yet available. Sequential per-task execution; parallel
> concurrency with `--budget` semaphore is its own milestone. See
> `docs/specs/2026-06-02-v0.3-hunt-plumbing-design.md`.

### Stage 3: Validate — **v1**

One agent per finding from Hunt, sequential or low-parallel (cap at 5 concurrent).

Adversarial reviewer. Different system prompt, different model if available (e.g.
Sonnet for Hunt, Opus for Validate). The Validator's job is **to disprove the finding**.

Tool allowlist: `read_file`, `grep`, `find_callers`, `find_definition`,
`compile_and_run`, `validate_finding`. **No `record_finding`.** The Validator cannot
create new findings, only confirm or reject existing ones.

Output verdicts: `CONFIRMED` | `REJECTED` | `UNCERTAIN`. UNCERTAIN findings flow
through to Dedupe and Report tagged as such — operator decides.

> **v0.6 scope note (pending implementation):** The first Validate plumbing
> milestone registers the full per-matrix tool set: `read_file`, `list_dir`,
> `grep`, `find_definition`, `find_callers`, `compile_and_run`,
> `query_findings`, `validate_finding` — eight tools, matching
> `docs/tool-contracts.md` § Tool scope matrix. Both prerequisite milestones
> (v0.4 sandbox, v0.5 symbol index) have shipped, so Validators can run PoCs
> to confirm/reject and walk the symbol index for reachability evidence from
> day one. Sequential per-finding execution; the ARCH-authorised cap of 5
> concurrent sessions is deferred to its own milestone, likely paired with
> Hunt parallelism. Default per-session budget: 100k input tokens. See
> `docs/specs/2026-06-02-v0.6-validate-design.md`.

### Stage 4: Gapfill — **v1**

One agent, sequential. Reads the Recon architecture doc and the full Hunt task log.
Identifies subsystems touched but not thoroughly investigated, and attack classes
under-represented relative to the architecture.

Outputs new Hunt tasks (capped at 20% of original budget). These re-enter the Hunt
queue. Gapfill runs **once** per run; no recursive expansion in v1.

Tool allowlist: `query_run_state` (read-only over the SQLite state), `add_hunt_task`.

> **v0.7 scope note (pending implementation):** The first Gapfill plumbing
> milestone queues new Hunt tasks but does **not** auto-trigger a second Hunt
> pass against them within the same run. Newly queued tasks sit in
> `status='pending'` for the operator's next invocation; auto-re-pass is a
> follow-on milestone. See `docs/specs/2026-06-02-v0.7-gapfill-design.md`.

### Stage 5: Dedupe — **v1**

Two-pass:

1. **Deterministic pass.** Cluster findings by
   `(file, function, attack_class, line_range ± 5)`. No agent involved.
2. **Agent pass.** For each cluster of size > 1, an agent reviews and decides if they
   share a root cause. Merges duplicates into a primary finding with linked variants.

Tool allowlist: `query_findings`, `merge_findings`, `link_variant`.

> **v0.8 scope note (pending implementation):** The first Dedupe plumbing
> milestone registers `query_findings`, `merge_findings`, `link_variant` only.
> The scope matrix in `docs/tool-contracts.md` lists `read_file` under Dedupe;
> this stage description's allowlist is authoritative, and the matrix cell is
> flagged for operator resolution. Pass 1 and Pass 2 run as separate
> transactions; if the process dies mid-Pass-2 the run is not resumable (new
> `run_id` required). Singleton clusters get a `dedupe_clusters` row but no
> agent session. Sequential per-cluster execution; parallel dedupe is its own
> milestone. See `docs/specs/2026-06-02-v0.8-dedupe-design.md`.

### Stage 6: Trace — **v1 (in-repo only)**

One Tracer agent per CONFIRMED finding. For each, the Tracer:

1. Starts at the buggy function.
2. Uses `find_callers` to walk backwards through the symbol index.
3. Determines whether the path terminates at a Recon-identified entry point
   (HTTP handler, CLI command, exported library function, deserializer, etc.).
4. Outputs `reachable | unreachable | uncertain` plus the call chain.

**v1 scope:** trace only within the cloned repo. Do not follow calls into third-party
dependencies. If a call chain leaves the repo's source tree, mark `uncertain` and stop.

Tool allowlist: `read_file`, `find_callers`, `find_definition`, `query_entry_points`,
`record_trace`.

> **v0.9 scope note (pending implementation):** The first Trace plumbing
> milestone registers `read_file`, `list_dir`, `grep`, `find_definition`,
> `find_callers`, `query_entry_points`, `query_findings`, `record_trace`. The
> Tracer walks backwards from the bug site only; forward traces are deferred.
> Vendored directories (`vendor/`, `node_modules/`, `third_party/`, etc.) are
> treated as out-of-repo for the "leaves the repo's source tree" rule even when
> they sit inside the working tree. Walk depth is capped (default 8 hops) via
> `--trace-max-depth`; cap-exceeded walks emit `uncertain`. Sequential
> per-finding execution. See `docs/specs/2026-06-02-v0.9-trace-design.md`.

### Stage 7: Feedback — **DEFERRED to v2**

In Cloudflare's harness, Trace findings in shared libraries become new Hunt tasks in
consumer repos. With single-repo scope this is degenerate. Do not implement in v1.

### Stage 8: Report — **v1**

Deterministic. No agent. Reads the SQLite state and renders:

- `report.md` — human-readable, findings grouped by severity and reachability
- `report.json` — schema-validated structured output
- `report.sarif` — for GitHub code scanning upload (optional, behind `--format sarif`)
- `findings/<id>/` — one directory per CONFIRMED finding containing:
  - `finding.json`
  - `poc/` — PoC code as written by the Hunter, with run output
  - `trace.json` — reachability analysis
  - `suggested_fix.md` — only if the Hunter included one in `record_finding`

All output goes to `~/.flosswing/runs/<run_id>/output/`. Operator copies what they want
out manually.

> **v1.0 scope note (pending implementation):** v1.0 ships `report.md`,
> `report.json`, and per-finding directories. The `--format sarif` flag is
> accepted in v1.0 (so existing CI configurations don't break) but emits a
> placeholder JSON containing only a header comment. Real SARIF 2.1.0 output,
> hand-rolled without an additional dependency, is targeted for v1.1. See
> `docs/specs/2026-06-02-v1.0-report-design.md`.

## Symbol index

The symbol index is built once per scan by a deterministic phase that runs between
Recon and Hunt. It populates three tables — `symbols`, `call_sites`, `entry_points` —
all scoped by `run_id`. The index is not incremental across runs; each scan rebuilds
it. Tree-sitter handles the parsing. Languages supported in v1 match the v1 scope
summary list (C, C++, Rust, Go, Python, JavaScript/TypeScript, Java). The
agent-facing tools that read the index are `find_definition`, `find_callers`, and
`query_entry_points`, all under § Scope: symbols in `docs/tool-contracts.md`. Build
behaviour, failure modes, and entry-point heuristics are documented in
`docs/specs/2026-06-02-v0.5-symbol-index-design.md`.

## Component layout

```
flosswing/
  __init__.py
  cli.py                   # click entry points
  orchestrator.py          # stage scheduling, budget enforcement, agent invocation
  attack_classes.py        # registry of attack classes
  config.py                # config loading (CLI flags, env, config file)
  errors.py                # exception hierarchy

  stages/
    __init__.py
    recon.py
    hunt.py
    validate.py
    gapfill.py
    dedupe.py
    trace.py
    report.py

  tools/                   # agent-facing tool implementations
    __init__.py
    fs.py                  # read_file, list_dir
    search.py              # grep (ripgrep wrapper)
    symbols.py             # find_callers, find_definition (tree-sitter)
    findings.py            # record_finding, query_findings, validate_finding, etc.
    execution.py           # compile_and_run (sandbox interface)

  sandbox/
    __init__.py
    docker.py              # docker-based sandbox impl
    firejail.py            # firejail fallback for users without docker
    base.py                # Sandbox protocol
    images/                # Dockerfiles per language family
      c.Dockerfile
      rust.Dockerfile
      go.Dockerfile
      python.Dockerfile
      js.Dockerfile
      java.Dockerfile

  state/
    __init__.py
    db.py                  # SQLite connection, migrations
    models.py              # pydantic models matching schema
    migrations/            # numbered .sql files

  agent/
    __init__.py
    runtime.py             # Claude Agent SDK wrapper
    tool_registry.py       # binds Python tools to agent tool calls
    session.py             # per-invocation context, token accounting

  prompts/
    system/                # system prompts per stage
      recon.md
      hunt.md
      validate.md
      gapfill.md
      dedupe.md
      trace.md
    attack_classes/        # one .md per attack class
      command_injection.md
      path_traversal.md
      ...

  eval/
    __init__.py
    corpus.py              # known-vulnerable repo registry
    scoring.py             # precision/recall against ground truth
    runner.py              # `flosswing eval` subcommand backend

docs/
  tool-contracts.md        # frozen agent-facing tool API (separate doc)
  schema.sql               # SQLite schema (separate doc)
  prompts.md               # prompt authoring guidelines
  threat-model.md          # what FlossWing assumes about its environment

tests/
  unit/                    # mocked Claude responses
  integration/             # real API, gated by FLOSSWING_INTEGRATION=1
  corpus/                  # tiny pinned vulnerable repos for eval

pyproject.toml
CLAUDE.md                  # agent session bootstrap
ARCHITECTURE.md            # this file
README.md
LICENSE                    # Apache-2.0 (see Licensing below)
```

## State store

Single SQLite database at `~/.flosswing/state.db`. Per-run scratch and outputs at
`~/.flosswing/runs/<run_id>/`. Schema definition lives in `docs/schema.sql`. **Schema
changes require a numbered migration file in `state/migrations/`. Do not edit existing
migrations.**

The state DB is the source of truth for everything: tasks, findings, validations,
traces, dedup clusters, agent sessions, token usage. Reports are derived; nothing else
should be.

## Agent runtime

Claude Agent SDK in headless mode. One agent invocation = one subprocess. Tools are
exposed via MCP (using the SDK's MCP server primitives) so the same tool implementations
work for any future LLM provider that speaks MCP.

**Model defaults** (overridable per stage via config):
- Recon: `claude-opus-4-7` (one-shot, high stakes for downstream)
- Hunt: `claude-sonnet-4-6` (cheap, many invocations)
- Validate: `claude-opus-4-7` (adversarial, want high capability)
- Gapfill: `claude-sonnet-4-6`
- Dedupe (agent pass): `claude-sonnet-4-6`
- Trace: `claude-sonnet-4-6`

Heterogeneity between Hunt and Validate is deliberate — reduces correlated errors.

**Per-session token budget** enforced by the orchestrator. Default hard cap: 200k input
tokens per Hunt session, 100k per Validate session. Configurable via `--token-budget`.
When exceeded, session is killed and the task is marked `budget_exceeded`. Not a retry
condition.

**Refusal handling.** Track refusals as a distinct outcome (not a failure). When a
session refuses, the orchestrator retries **once** with a rephrased prompt drawn from
`prompts/refusal_rephrasings/`. If the retry also refuses, the task is marked
`refused` and surfaced in the report. Do not retry more than once. Do not silently
swallow refusals.

## Tool contracts

The agent-facing tool API is specified in `docs/tool-contracts.md` and is **frozen**.
Tool signatures, parameter names, return shapes, and error semantics do not change
without operator approval. This is because every prompt in `prompts/` references these
contracts; drift breaks every stage at once.

Adding a new tool is fine. Modifying an existing tool's signature is not.

## Sandbox

PoC execution is the highest-risk surface in the system. The model writes attacker-
controlled code; the harness executes it. Treat every PoC as potential malware.

**Mandatory sandbox constraints** (do not weaken these without operator approval):

- One Docker container per `compile_and_run` invocation. Fresh image, no reuse.
- `--network=none` by default. Override is per-attack-class (e.g. SSRF tests need a
  controlled loopback HTTP server) and explicitly opt-in via the attack class config.
- `--read-only` root filesystem. Scratch on tmpfs at `/scratch`.
- Target repo mounted **read-only** at `/repo`.
- Resource caps: `--memory=2g`, `--cpus=2`, `--pids-limit=256`.
- `--cap-drop=ALL`. No added capabilities.
- Wall-clock timeout via `timeout(1)` inside the container. Default 60s, configurable
  per attack class up to 300s.
- Stdout/stderr captured to size cap (10MB each), truncated beyond.
- No host filesystem access except the read-only repo mount.

`compile_and_run` returns a structured result. The agent never gets an interactive
shell or arbitrary `bash` access.

**Firejail fallback** for environments without Docker. Same constraints, different
mechanism. If neither Docker nor Firejail is available, `compile_and_run` returns an
error and the run continues without PoC execution (degrading gracefully).

> **v0.4 scope note (pending implementation):** The first sandbox plumbing
> milestone ships both Docker (primary) and Firejail (fallback) backends,
> enforces the prescriptive constraints above verbatim, and selects between
> backends via auto-detection (Docker → else Firejail → else `sandbox_unavailable`).
> Hunt and Validate do **not** gain the `compile_and_run` tool in v0.4 — wiring
> the tool into their scopes is a follow-on milestone that consumes this layer.
> Deferred to later milestones: libFuzzer/AFL integration, seccomp / AppArmor /
> SELinux profiles, pre-built language images, image-digest pinning, SBOM
> emission, and the SSRF controlled-loopback HTTP fixture. None of these
> weaken the constraints above; all are additive hardening or ergonomics.
> Firejail caveat: per-language filesystem images are a Docker-only feature; on
> Firejail-only hosts, the host must have the required language toolchain
> installed. See `docs/specs/2026-06-02-v0.4-sandbox-design.md`.

## Threat model summary

Full threat model in `docs/threat-model.md`. Key points the implementation must
respect:

1. **The target repo is untrusted.** Files may contain prompt injection. Recon is the
   most exposed stage (it reads README, which often contains the most adversarial
   text). Recon prompts must explicitly instruct the agent to treat repo contents as
   data, not instructions.
2. **PoC code is malicious by assumption.** All execution sandboxed.
3. **The Claude API key is sensitive.** Never log it, never include it in error
   messages, never write it to the state DB. Load from env or OS keychain only.
4. **Findings are sensitive.** A 0-day in a popular OSS project is dual-use. Default
   to local-only storage. No upload, no telemetry, no auto-submission.
5. **FlossWing itself is not a defense.** A repo that passes a FlossWing scan with
   zero findings is not "secure." The report must say so.

## Configuration precedence

Highest to lowest:

1. CLI flags
2. Environment variables (`FLOSSWING_*`)
3. Per-repo config: `<target>/.flosswing/config.toml`
4. User config: `~/.config/flosswing/config.toml`
5. Built-in defaults

Auth credentials (three accepted modes — pick whichever fits your environment):

1. `ANTHROPIC_API_KEY` — direct Anthropic API.
2. `ANTHROPIC_FOUNDRY_API_KEY` — Azure AI Foundry API key. Compatible because Foundry
   hosts Anthropic models on the Messages API; the `claude` CLI handles routing.
3. Microsoft Entra ID via `az login` (or `AZURE_CLIENT_ID` + `AZURE_TENANT_ID` +
   `AZURE_CLIENT_SECRET` for service principals) — Entra ID against Foundry.

Whichever set is present is forwarded verbatim to the spawned `claude` CLI via
`ClaudeAgentOptions.env`. Credentials are env / OS keychain only — never config files,
never the state DB, never logs. See `docs/specs/2026-05-25-v0.2-recon-plumbing-design.md`
§ Authentication for rationale.

## v1 scope summary

**In v1:**

- Stages: Recon, Hunt, Validate, Gapfill, Dedupe, Trace (in-repo), Report
- Languages: C, C++, Rust, Go, Python, JavaScript/TypeScript, Java
- Attack class library as listed under Recon above
- Sandbox: Docker (primary), Firejail (fallback)
- Output: markdown report, JSON report, per-finding directories
- Eval: corpus-based scoring with `flosswing eval`
- BYO `ANTHROPIC_API_KEY`

**Deferred to v2:**

- Feedback stage
- Cross-repo Trace (multi-repo symbol indexing)
- SARIF output (may land in v1.1 if cheap)
- Disclosure draft subcommand (`flosswing disclose`)
- Diff mode (`flosswing diff <run_a> <run_b>` for re-scans after fixes)
- Web UI / local server mode
- Non-Anthropic model providers
- Additional languages (Ruby, PHP, Kotlin, Swift, C#)
- Plugin system for third-party attack classes

**Explicit non-goals (will not be built):**

- Auto-patching, auto-PR generation
- Auto-disclosure
- Cloud/SaaS deployment
- Telemetry of any kind
- Continuous monitoring / daemon mode

## Licensing

Apache-2.0. Required because v1 ships PoC code generation; permissive license with
explicit patent grant matches the dual-use nature of the tool. Do not change without
operator approval.

## When in doubt

Stop and ask the operator. This is a security tool. Wrong defaults are worse than no
progress. Specifically:

- If a tool signature seems wrong, ask — do not edit `docs/tool-contracts.md`.
- If a sandbox constraint seems too tight, ask — do not weaken it.
- If a non-goal seems to be blocking a useful feature, ask — do not build the feature.
- If this document and the code disagree, ask — do not edit the document to match the
  code.
