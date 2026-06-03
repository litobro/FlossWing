"""find_definition / find_callers / query_entry_points — frozen-contract tools.

Per docs/tool-contracts.md § Scope: symbols and
docs/specs/2026-06-02-v0.5-symbol-index-design.md § Component
responsibilities flosswing/tools/symbols.py.

The Pydantic input/output classes are copied verbatim from the contract
— any change here is a contract break and must be approved by the
operator before merge.

All three tools query the per-run symbol index (populated by IndexBuild
between Recon and Hunt). They do not re-parse source files.
"""

from __future__ import annotations

from typing import Final, Literal

from pydantic import BaseModel
from sqlalchemy import func, select

from flosswing.errors import (
    AmbiguousSymbolError,
    NotIndexedError,
    SymbolNotFoundError,
)
from flosswing.state import session as st_session
from flosswing.state.models import CallSite as CallSiteModel
from flosswing.state.models import EntryPoint as EntryPointModel
from flosswing.state.models import Symbol as SymbolModel

# -----------------------------------------------------------------------------
# Frozen-contract Pydantic models (verbatim copy)
# -----------------------------------------------------------------------------

_KIND_LITERAL = Literal[
    "function", "method", "class", "struct", "enum", "macro", "type"
]


class FindDefinitionInput(BaseModel):
    symbol: str
    file_hint: str | None = None
    language: str | None = None


class SymbolDefinition(BaseModel):
    symbol: str
    fully_qualified_name: str
    file: str
    line_start: int
    line_end: int
    kind: _KIND_LITERAL
    language: str


class FindDefinitionOutput(BaseModel):
    definitions: list[SymbolDefinition]
    truncated: bool


class FindCallersInput(BaseModel):
    symbol: str
    file_hint: str | None = None
    language: str | None = None
    max_results: int = 100


class CallSiteOutput(BaseModel):
    caller_symbol: str
    file: str
    line: int
    snippet: str


class FindCallersOutput(BaseModel):
    target: SymbolDefinition | None
    call_sites: list[CallSiteOutput]
    truncated: bool


_ENTRY_KIND_INPUT = Literal[
    "http", "cli", "exported", "deserializer", "ipc", "any"
]
_ENTRY_KIND_OUTPUT = Literal[
    "http", "cli", "exported", "deserializer", "ipc"
]


class QueryEntryPointsInput(BaseModel):
    kind: _ENTRY_KIND_INPUT = "any"


class EntryPointOutput(BaseModel):
    symbol: str
    file: str
    line: int
    kind: _ENTRY_KIND_OUTPUT
    attacker_controlled_input: bool
    notes: str


class QueryEntryPointsOutput(BaseModel):
    entry_points: list[EntryPointOutput]


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------

_FIND_DEFINITION_LIMIT: Final[int] = 50


# -----------------------------------------------------------------------------
# find_definition
# -----------------------------------------------------------------------------


def find_definition(
    inp: FindDefinitionInput,
    *,
    run_id: str,
) -> FindDefinitionOutput:
    """Locate the definition(s) of `inp.symbol`.

    Raises NotIndexedError if the symbols table has zero rows for this
    run_id (orchestrator-level failure; should never be visible to the
    agent in normal operation).
    """
    with st_session.session_scope() as s:
        # not_indexed check: count once. Cheap with the existing index.
        total = s.execute(
            select(func.count()).select_from(SymbolModel).where(
                SymbolModel.run_id == run_id
            )
        ).scalar_one()
        if total == 0:
            raise NotIndexedError(
                f"symbols table empty for run_id={run_id!r}"
            )

        stmt = (
            select(SymbolModel)
            .where(
                SymbolModel.run_id == run_id,
                SymbolModel.symbol == inp.symbol,
            )
            .order_by(SymbolModel.file, SymbolModel.line_start)
            .limit(_FIND_DEFINITION_LIMIT + 1)  # +1 to detect truncation
        )
        if inp.file_hint is not None:
            stmt = stmt.where(SymbolModel.file == inp.file_hint)
        if inp.language is not None:
            stmt = stmt.where(SymbolModel.language == inp.language)

        rows = list(s.execute(stmt).scalars().all())

        truncated = len(rows) > _FIND_DEFINITION_LIMIT
        if truncated:
            rows = rows[:_FIND_DEFINITION_LIMIT]

        # Materialize into Pydantic inside the session scope: session_scope
        # commits on exit which expires loaded attributes, so accessing
        # `r.<col>` after `with` would trigger a refresh against a closed
        # session.
        defs = [
            SymbolDefinition(
                symbol=r.symbol,
                fully_qualified_name=r.fully_qualified_name,
                file=r.file,
                line_start=r.line_start,
                line_end=r.line_end,
                # SQLAlchemy Mapped[str] doesn't narrow to the contract's
                # Literal[...]; insertion-side validation guarantees the value
                # is always one of the seven kind literals from the schema.
                kind=r.kind,  # type: ignore[arg-type]
                language=r.language,
            )
            for r in rows
        ]
    return FindDefinitionOutput(definitions=defs, truncated=truncated)


# -----------------------------------------------------------------------------
# find_callers
# -----------------------------------------------------------------------------


def find_callers(
    inp: FindCallersInput,
    *,
    run_id: str,
) -> FindCallersOutput:
    """Find call sites for the symbol resolved from `inp`.

    Raises SymbolNotFoundError on zero definitions, AmbiguousSymbolError
    on >1 definitions (the agent retries with file_hint per the contract).
    """
    with st_session.session_scope() as s:
        stmt = (
            select(SymbolModel)
            .where(
                SymbolModel.run_id == run_id,
                SymbolModel.symbol == inp.symbol,
            )
            .order_by(SymbolModel.file, SymbolModel.line_start)
        )
        if inp.file_hint is not None:
            stmt = stmt.where(SymbolModel.file == inp.file_hint)
        if inp.language is not None:
            stmt = stmt.where(SymbolModel.language == inp.language)

        targets = list(s.execute(stmt).scalars().all())

        if not targets:
            raise SymbolNotFoundError(
                f"symbol {inp.symbol!r} not found in index"
            )
        if len(targets) > 1:
            candidates = [
                f"{t.file}:{t.line_start}" for t in targets
            ]
            raise AmbiguousSymbolError(
                symbol=inp.symbol, candidates=candidates
            )

        target = targets[0]
        target_def = SymbolDefinition(
            symbol=target.symbol,
            fully_qualified_name=target.fully_qualified_name,
            file=target.file,
            line_start=target.line_start,
            line_end=target.line_end,
            # SQLAlchemy Mapped[str] doesn't narrow to the contract's
            # Literal[...]; insertion-side validation guarantees the value
            # is always one of the seven kind literals from the schema.
            kind=target.kind,  # type: ignore[arg-type]
            language=target.language,
        )

        # JOIN call_sites to symbols on caller_symbol_id for the FQN.
        cs_stmt = (
            select(CallSiteModel, SymbolModel)
            .join(
                SymbolModel,
                SymbolModel.id == CallSiteModel.caller_symbol_id,
            )
            .where(
                CallSiteModel.run_id == run_id,
                CallSiteModel.callee_symbol_id == target.id,
            )
            .order_by(CallSiteModel.file, CallSiteModel.line)
            .limit(inp.max_results + 1)
        )
        joined = list(s.execute(cs_stmt).all())

        truncated = len(joined) > inp.max_results
        if truncated:
            joined = joined[: inp.max_results]

        # Materialize inside the session scope (see find_definition note).
        sites = [
            CallSiteOutput(
                caller_symbol=caller.fully_qualified_name,
                file=cs.file,
                line=cs.line,
                snippet=cs.snippet,
            )
            for cs, caller in joined
        ]
    return FindCallersOutput(
        target=target_def, call_sites=sites, truncated=truncated
    )


# -----------------------------------------------------------------------------
# query_entry_points
# -----------------------------------------------------------------------------


def query_entry_points(
    inp: QueryEntryPointsInput,
    *,
    run_id: str,
) -> QueryEntryPointsOutput:
    """Return all entry points (or those of a specific kind) for the run."""
    with st_session.session_scope() as s:
        stmt = (
            select(EntryPointModel)
            .where(EntryPointModel.run_id == run_id)
            .order_by(
                EntryPointModel.kind,
                EntryPointModel.file,
                EntryPointModel.line,
            )
        )
        if inp.kind != "any":
            stmt = stmt.where(EntryPointModel.kind == inp.kind)
        rows = list(s.execute(stmt).scalars().all())

        # Materialize inside the session scope (see find_definition note).
        out_rows = [
            EntryPointOutput(
                symbol=r.symbol,
                file=r.file,
                line=r.line,
                # SQLAlchemy Mapped[str] doesn't narrow to the contract's
                # Literal[...]; insertion-side validation guarantees the value
                # is always one of the seven kind literals from the schema.
                kind=r.kind,  # type: ignore[arg-type]
                attacker_controlled_input=bool(r.attacker_controlled_input),
                notes=r.notes,
            )
            for r in rows
        ]
    return QueryEntryPointsOutput(entry_points=out_rows)


__all__ = [
    "CallSiteOutput",
    "EntryPointOutput",
    "FindCallersInput",
    "FindCallersOutput",
    "FindDefinitionInput",
    "FindDefinitionOutput",
    "QueryEntryPointsInput",
    "QueryEntryPointsOutput",
    "SymbolDefinition",
    "find_callers",
    "find_definition",
    "query_entry_points",
]
