# FlossWing Tool Contracts

> **Frozen interface.** The tool signatures, parameter names, return shapes, and error
> semantics defined in this document do not change without explicit operator approval.
> Every stage prompt references these contracts; drift breaks every stage at once.
>
> **Adding a tool is fine. Modifying an existing tool's signature is not.**
>
> If a change seems necessary, stop and ask the operator. Do not edit this document
> as part of an implementation task.

## How tools are exposed

Tools are direct Python functions registered with the Claude Agent SDK via the `@tool`
decorator. Each tool:

- Has a Pydantic `BaseModel` for its input, defined in this document.
- Has a Pydantic `BaseModel` for its output payload (the structured object the agent
  receives back), defined in this document.
- Is implemented in `flosswing/tools/<module>.py`.
- Validates its input with `Model.model_validate(args)` at the top of the handler.
- Returns the SDK's expected dict shape: `{"content": [{"type": "text", "text": ...}]}`,
  where the text is the JSON-serialized output model.

Skeleton:

```python
from claude_agent_sdk import tool
from pydantic import BaseModel
from typing import Any

class ReadFileInput(BaseModel):
    path: str
    start_line: int | None = None
    end_line: int | None = None

class ReadFileOutput(BaseModel):
    path: str
    content: str
    total_lines: int
    truncated: bool

@tool("read_file", "Read a file from the target repository (read-only).",
      ReadFileInput.model_json_schema())
async def read_file(args: dict[str, Any]) -> dict[str, Any]:
    inp = ReadFileInput.model_validate(args)
    # ... implementation ...
    out = ReadFileOutput(path=..., content=..., total_lines=..., truncated=...)
    return {"content": [{"type": "text", "text": out.model_dump_json()}]}
```

All input/output models in this document use Pydantic v2 syntax.

## Common conventions

**Paths.** All `path` parameters are **repo-relative POSIX paths** (e.g. `src/main.c`,
not `/abs/path/src/main.c` and not `src\main.c`). Tool implementations resolve them
against the target repo root. Paths that escape the repo root (`../`, absolute paths,
symlinks pointing outside) raise `PathEscapesRepoError`.

**Errors.** Tools never raise to the agent. All errors are caught and returned as a
structured error payload:

```python
class ToolError(BaseModel):
    error: str           # short error code, e.g. "path_escapes_repo"
    message: str         # human-readable detail
    retryable: bool      # whether the agent should reasonably retry

# Returned as:
{"content": [{"type": "text", "text": ToolError(...).model_dump_json()}], "is_error": True}
```

The `is_error: True` flag tells the SDK to surface the result as a tool error to the
model. The model sees the JSON payload regardless.

**Size limits.** Any tool returning textual content caps output at **256 KB** by
default, marked `truncated: True` if exceeded. Configurable via tool-specific limits
where relevant. Agents are instructed (via prompts) to use line-range parameters or
narrower queries rather than fighting the cap.

**Identifiers.** `finding_id`, `task_id`, `cluster_id`, `run_id` are all opaque strings
(currently ULIDs). The agent treats them as opaque — never parses them, never generates
them. Tools that need a new ID generate it server-side.

**Read-only repo.** No tool in this document writes to the target repository. PoC files
written by `compile_and_run` go to scratch space, never to `/repo`.

## Tool registry

Tools are grouped by access scope. Each stage's agent is bound to a specific subset.

### Scope: filesystem (read)

Available to: Recon, Hunt, Validate, Gapfill, Dedupe (agent pass), Trace.

#### `read_file`

Read a file (optionally a line range) from the target repository.

```python
class ReadFileInput(BaseModel):
    path: str                                # repo-relative
    start_line: int | None = None            # 1-indexed, inclusive
    end_line: int | None = None              # 1-indexed, inclusive

class ReadFileOutput(BaseModel):
    path: str
    content: str
    total_lines: int                         # total lines in the full file
    returned_lines: tuple[int, int] | None   # (start, end) actually returned
    truncated: bool                          # True if output hit size cap
    sha256: str                              # of full file, for change detection
```

Errors: `path_escapes_repo`, `file_not_found`, `is_directory`, `binary_file`
(binary detection via null-byte heuristic; agent should not be reading binaries).

#### `list_dir`

List immediate children of a directory.

```python
class ListDirInput(BaseModel):
    path: str = "."                          # repo-relative, default repo root
    include_hidden: bool = False

class DirEntry(BaseModel):
    name: str
    kind: Literal["file", "dir", "symlink"]
    size_bytes: int | None                   # None for dirs
    symlink_target: str | None               # repo-relative if internal, None if external/dangling

class ListDirOutput(BaseModel):
    path: str
    entries: list[DirEntry]
    truncated: bool                          # True if >1000 entries
```

Errors: `path_escapes_repo`, `not_a_directory`, `not_found`.

### Scope: search

Available to: Recon, Hunt, Validate, Gapfill, Trace.

#### `grep`

Search the repository with a regex. Backed by ripgrep.

```python
class GrepInput(BaseModel):
    pattern: str                             # regex (ripgrep syntax)
    path_glob: str | None = None             # restrict to matching paths, e.g. "**/*.go"
    case_insensitive: bool = False
    max_results: int = 50                    # hard ceiling 500
    context_lines: int = 0                   # lines of context around each match

class GrepMatch(BaseModel):
    path: str
    line_number: int
    line: str                                # matched line, truncated to 500 chars
    context_before: list[str]                # if context_lines > 0
    context_after: list[str]

class GrepOutput(BaseModel):
    matches: list[GrepMatch]
    truncated: bool                          # True if hit max_results
    files_searched: int
```

Errors: `invalid_regex`, `pattern_too_broad` (e.g. matching `.*` with no glob — refused
to protect token budget).

### Scope: symbols

Available to: Recon (for entry-point discovery), Hunt, Validate, Trace.

The symbol index is built once by Recon using tree-sitter and cached in SQLite. The
tools below query the cached index. They do not re-parse on every call.

#### `find_definition`

Locate the definition of a symbol.

```python
class FindDefinitionInput(BaseModel):
    symbol: str                              # function/class/method name
    file_hint: str | None = None             # if known, narrows scope
    language: str | None = None              # if known, narrows scope

class SymbolDefinition(BaseModel):
    symbol: str
    fully_qualified_name: str                # e.g. "module.Class.method"
    file: str                                # repo-relative
    line_start: int
    line_end: int
    kind: Literal["function", "method", "class", "struct", "enum", "macro", "type"]
    language: str

class FindDefinitionOutput(BaseModel):
    definitions: list[SymbolDefinition]      # multiple if symbol is overloaded/duplicated
    truncated: bool
```

Errors: `not_indexed` (Recon hasn't run yet — orchestrator-level failure, should never
be visible to agents in normal operation).

#### `find_callers`

Find call sites for a symbol.

```python
class FindCallersInput(BaseModel):
    symbol: str
    file_hint: str | None = None
    language: str | None = None
    max_results: int = 100

class CallSite(BaseModel):
    caller_symbol: str                       # fully-qualified name of the calling function
    file: str
    line: int
    snippet: str                             # the line(s) containing the call, truncated

class FindCallersOutput(BaseModel):
    target: SymbolDefinition | None          # the resolved target, None if ambiguous
    call_sites: list[CallSite]
    truncated: bool
```

Errors: `symbol_not_found`, `ambiguous_symbol` (returned with empty `call_sites` and a
list of candidate definitions in `message` — agent should retry with `file_hint`).

#### `query_entry_points` *(Trace only)*

Return the list of entry points identified by Recon (HTTP handlers, CLI commands,
exported library functions, deserializers, etc.).

```python
class QueryEntryPointsInput(BaseModel):
    kind: Literal["http", "cli", "exported", "deserializer", "ipc", "any"] = "any"

class EntryPoint(BaseModel):
    symbol: str
    file: str
    line: int
    kind: Literal["http", "cli", "exported", "deserializer", "ipc"]
    attacker_controlled_input: bool          # whether external input reaches this symbol
    notes: str                               # Recon's free-text annotation

class QueryEntryPointsOutput(BaseModel):
    entry_points: list[EntryPoint]
```

No errors expected; returns empty list if none match.

### Scope: execution

Available to: Hunt, Validate.

#### `compile_and_run`

Build and execute attacker-supplied PoC code in a sandbox. The single highest-risk tool
in the system. See `ARCHITECTURE.md` § Sandbox for the constraints this enforces.

```python
class SourceFile(BaseModel):
    relative_path: str                       # within /scratch, e.g. "exploit.c"
    content: str

class CompileAndRunInput(BaseModel):
    language: Literal["c", "cpp", "rust", "go", "python", "javascript", "typescript", "java"]
    files: list[SourceFile]                  # source files to write to /scratch
    build_command: str | None = None         # explicit build cmd, else language default
    run_command: str                         # required; what to actually execute
    stdin: str | None = None
    args: list[str] = []
    env: dict[str, str] = {}                 # filtered against an allowlist
    timeout_seconds: int = 60                # hard cap 300
    network: bool = False                    # explicit opt-in, requires attack class to permit
    attack_class: str                        # for sandbox policy lookup and audit

class ExecResult(BaseModel):
    exit_code: int                           # -1 if killed by signal/timeout
    signal: str | None                       # e.g. "SIGSEGV", "SIGKILL"
    stdout: str
    stdout_truncated: bool
    stderr: str
    stderr_truncated: bool
    duration_ms: int
    oom_killed: bool
    timed_out: bool
    network_used: bool                       # observed network attempts (logged even when blocked)
    sandbox_backend: Literal["docker", "firejail"]

class CompileAndRunOutput(BaseModel):
    build: ExecResult | None                 # None if no build step
    run: ExecResult
    scratch_path: str                        # for record_finding to reference
```

Errors:
- `language_not_supported`
- `sandbox_unavailable` (no Docker, no Firejail — `retryable: False`)
- `network_not_permitted` (attack class doesn't allow network even though caller asked)
- `resource_limit_exceeded` (caller asked for >300s timeout, >2g memory, etc.)
- `build_failed` is **not** an error — it returns successfully with `build.exit_code != 0`.
  The agent needs to see build failures to iterate.

**Sandbox policy is enforced by the implementation, not the agent.** If the agent
requests `network=True` for an attack class that doesn't permit it, the tool returns
`network_not_permitted`, not silent network access.

### Scope: findings (Hunt-side)

Available to: Hunt only. **Not available to Validate.** The Validator cannot create
findings.

#### `record_finding`

Record a vulnerability finding.

```python
class RecordFindingInput(BaseModel):
    attack_class: str                        # must match registry; validated server-side
    file: str
    function: str | None = None              # if known
    line_start: int
    line_end: int
    severity: Literal["critical", "high", "medium", "low", "info"]
    confidence: Literal["confirmed", "likely", "speculative"]
    title: str                               # one-line summary, ≤120 chars
    description: str                         # full explanation, markdown
    poc_code: str | None = None              # the PoC source that triggered the bug
    poc_result: CompileAndRunOutput | None = None  # the execution result
    suggested_fix: str | None = None         # markdown
    related_findings: list[str] = []         # finding_ids the agent thinks are related

class RecordFindingOutput(BaseModel):
    finding_id: str
    duplicate_of: str | None                 # set if dedup logic flagged this as a likely duplicate
                                             # (agent is told but the finding is still recorded)
```

Errors:
- `invalid_attack_class` — not in the registry
- `path_not_in_repo`
- `line_range_invalid`
- `description_required_for_confirmed` — `confidence=confirmed` requires non-empty description and either PoC or trace evidence

### Scope: findings (Validate-side)

Available to: Validate only.

#### `query_findings`

Read findings from current run. Also available to Dedupe (agent pass) and Trace.

```python
class QueryFindingsInput(BaseModel):
    finding_id: str | None = None            # exact lookup
    attack_class: str | None = None
    file: str | None = None
    status: Literal["pending_validation", "confirmed", "rejected", "uncertain", "any"] = "any"
    min_severity: Literal["critical", "high", "medium", "low", "info"] | None = None

class Finding(BaseModel):
    finding_id: str
    attack_class: str
    file: str
    function: str | None
    line_start: int
    line_end: int
    severity: Literal["critical", "high", "medium", "low", "info"]
    confidence: Literal["confirmed", "likely", "speculative"]
    status: Literal["pending_validation", "confirmed", "rejected", "uncertain"]
    title: str
    description: str
    poc_code: str | None
    has_poc_result: bool                     # full poc_result available via separate fetch
    suggested_fix: str | None

class QueryFindingsOutput(BaseModel):
    findings: list[Finding]
    truncated: bool
```

#### `validate_finding`

Record an adversarial review verdict for an existing finding.

```python
class ValidateFindingInput(BaseModel):
    finding_id: str
    verdict: Literal["confirmed", "rejected", "uncertain"]
    rationale: str                           # required; markdown
    evidence_files: list[str] = []           # paths the validator examined, for audit

class ValidateFindingOutput(BaseModel):
    finding_id: str
    new_status: Literal["confirmed", "rejected", "uncertain"]
```

Errors:
- `finding_not_found`
- `finding_already_validated` — once a verdict is recorded, the finding is sealed. Re-
  validation requires a new run.
- `rationale_too_short` (<50 chars) — forces actual explanation, not "looks fine"

### Scope: findings (Dedupe-side)

Available to: Dedupe (agent pass) only.

#### `merge_findings`

Collapse multiple findings into a single primary finding.

```python
class MergeFindingsInput(BaseModel):
    primary_finding_id: str                  # the canonical one
    duplicate_finding_ids: list[str]         # to be marked as duplicates
    root_cause_summary: str                  # markdown, required

class MergeFindingsOutput(BaseModel):
    primary_finding_id: str
    merged_count: int
```

#### `link_variant`

Link two findings as variants of a shared root cause without merging them.

```python
class LinkVariantInput(BaseModel):
    finding_id_a: str
    finding_id_b: str
    relationship: Literal["same_root_cause", "exploit_chain", "preconditions"]
    note: str = ""

class LinkVariantOutput(BaseModel):
    link_id: str
```

### Scope: trace

Available to: Trace only.

#### `record_trace`

Record a reachability trace for a finding.

```python
class CallChainStep(BaseModel):
    symbol: str
    file: str
    line: int
    is_entry_point: bool
    notes: str = ""

class RecordTraceInput(BaseModel):
    finding_id: str
    reachable: Literal["reachable", "unreachable", "uncertain"]
    entry_point_symbol: str | None           # required if reachable=="reachable"
    call_chain: list[CallChainStep]          # bug site is the last step; entry point is the first
    rationale: str                           # markdown, required

class RecordTraceOutput(BaseModel):
    trace_id: str
```

Errors: `finding_not_found`, `inconsistent_trace` (e.g. reachable=="reachable" with no entry_point_symbol).

### Scope: task management

Available to: Recon (initial population), Gapfill (additions only).

#### `add_hunt_task`

Enqueue a Hunt task.

```python
class AddHuntTaskInput(BaseModel):
    attack_class: str                        # validated against registry
    scope_hint: str                          # natural-language scope, e.g. "src/cli/exec.go::run_user_cmd"
    rationale: str                           # why this task; helps debugging
    priority: Literal["high", "normal", "low"] = "normal"
    parent_finding_id: str | None = None     # set by Gapfill when re-queueing around a finding

class AddHuntTaskOutput(BaseModel):
    task_id: str
    accepted: bool                           # False if budget is exhausted
    reason: str | None                       # if not accepted, why
```

Errors: `invalid_attack_class`, `budget_exhausted` (returned as `accepted: False`, not an error).

### Scope: recon artifacts

Available to: Recon only.

#### `record_recon_artifact`

Save Recon's architecture analysis.

```python
class TrustBoundary(BaseModel):
    kind: Literal["network", "file", "ipc", "deserialization", "subprocess", "other"]
    description: str
    files: list[str]

class Subsystem(BaseModel):
    name: str
    description: str
    paths: list[str]
    languages: list[str]
    notes: str

class RecordReconArtifactInput(BaseModel):
    languages: list[str]
    build_commands: dict[str, str]           # e.g. {"primary": "make", "test": "make test"}
    entry_points: list[EntryPoint]
    trust_boundaries: list[TrustBoundary]
    subsystems: list[Subsystem]
    notes: str                               # free-text overall description

class RecordReconArtifactOutput(BaseModel):
    artifact_id: str
```

Errors: `recon_already_recorded` — Recon runs once per run; re-running requires a new run.

### Scope: run state (read-only)

Available to: Gapfill.

#### `query_run_state`

Read aggregate information about the current run.

```python
class QueryRunStateInput(BaseModel):
    pass                                     # no parameters; returns current run summary

class HuntTaskSummary(BaseModel):
    task_id: str
    attack_class: str
    scope_hint: str
    status: Literal["pending", "running", "completed", "refused", "budget_exceeded", "errored"]
    findings_count: int

class QueryRunStateOutput(BaseModel):
    run_id: str
    recon_artifact: RecordReconArtifactInput | None  # the recorded architecture, if any
    hunt_tasks: list[HuntTaskSummary]
    budget_used: int                         # token-equivalent units
    budget_remaining: int
```

## Tool scope matrix

| Tool                     | Recon | Hunt | Validate | Gapfill | Dedupe | Trace |
|--------------------------|:-----:|:----:|:--------:|:-------:|:------:|:-----:|
| `read_file`              |   ✓   |  ✓   |    ✓     |   ✓     |   ✓    |   ✓   |
| `list_dir`               |   ✓   |  ✓   |    ✓     |   ✓     |        |   ✓   |
| `grep`                   |   ✓   |  ✓   |    ✓     |   ✓     |        |   ✓   |
| `find_definition`        |   ✓   |  ✓   |    ✓     |         |        |   ✓   |
| `find_callers`           |       |  ✓   |    ✓     |         |        |   ✓   |
| `query_entry_points`     |       |      |          |         |        |   ✓   |
| `compile_and_run`        |       |  ✓   |    ✓     |         |        |       |
| `record_finding`         |       |  ✓   |          |         |        |       |
| `query_findings`         |       |      |    ✓     |   ✓     |   ✓    |   ✓   |
| `validate_finding`       |       |      |    ✓     |         |        |       |
| `merge_findings`         |       |      |          |         |   ✓    |       |
| `link_variant`           |       |      |          |         |   ✓    |       |
| `record_trace`           |       |      |          |         |        |   ✓   |
| `add_hunt_task`          |   ✓   |      |          |   ✓     |        |       |
| `record_recon_artifact`  |   ✓   |      |          |         |        |       |
| `query_run_state`        |       |      |          |   ✓     |        |       |

The orchestrator enforces these scopes by registering only the permitted tools with
each agent's SDK session. Agents cannot import or call tools outside their scope.

## What is deliberately not in this contract

These exist as concepts in `ARCHITECTURE.md` but have no agent-facing tool. They are
operator-facing or implementation-internal:

- **Run lifecycle** (create_run, finalize_run) — orchestrator-only, not exposed to agents.
- **Report generation** — deterministic, not an agent stage; reads SQLite directly.
- **Symbol index construction** — runs inside Recon's pre-agent setup, not as an agent tool.
- **Disclosure drafting** — v2; deliberately operator-driven.
- **Cross-repo trace** — v2.

If during implementation a new operator-facing operation is needed, it goes in
`flosswing/orchestrator.py` or a CLI subcommand, **not** in this document.

## Versioning

This document is v1. Breaking changes increment the major version and require all
prompts in `prompts/` to be reviewed for references to the changed contract. A
breaking change is:

- Removing a tool
- Removing or renaming a field on an existing input/output model
- Changing the type of an existing field
- Tightening a Literal union (broadening is non-breaking)
- Changing error semantics for an existing error code

Non-breaking changes:

- Adding a new tool
- Adding an optional field to an existing input/output model
- Adding a new error code
- Broadening a Literal union
- Adding a new permitted value to an `attack_class` registry
