# FlossWing — local-CLI vulnerability research harness.
# Copyright (C) 2026  FlossWing contributors
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""IndexBuild orchestration — walker + extractor + bulk-insert.

Per docs/specs/2026-06-02-v0.5-symbol-index-design.md § Component
responsibilities flosswing/index/build.py.

The IndexBuild phase runs deterministically between Recon and Hunt.
No agent is involved, no `agent_sessions` row is written. The phase
walks the repo, parses each in-scope file, extracts symbols and call
sites, runs the entry-point post-pass, and bulk-inserts into the three
tables in a single transaction.

Per design decision #7 the build is run-fatal only if zero symbols
emerge. We do NOT raise here — the orchestrator (Task 10) finalizes
the run as `errored` with the `index_build_empty` reason when
result.symbols == 0.
"""

from __future__ import annotations

import contextlib
import logging
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import TextIO

from sqlalchemy.orm import Session as OrmSession
from sqlalchemy.orm import sessionmaker
from ulid import ULID

from flosswing.errors import LanguageGrammarNotLoadedError
from flosswing.index import entry_points as ep_mod
from flosswing.index import walker as walker_mod
from flosswing.index.extractor import (
    CallSiteRow,
    SymbolRow,
    extract,
)
from flosswing.index.grammars import get_parser
from flosswing.state.models import CallSite, EntryPoint, Symbol

logger = logging.getLogger(__name__)

SessionFactory = sessionmaker[OrmSession]


@dataclass
class IndexBuildResult:
    symbols: int = 0
    call_sites: int = 0
    entry_points: int = 0
    files_parsed: int = 0
    files_skipped: int = 0
    duration_ms: int = 0
    languages: list[str] = field(default_factory=list)


async def build_index(
    *,
    run_id: str,
    recon_artifact_id: str,
    repo: Path,
    languages: set[str],
    session_factory: SessionFactory,
    scratch_dir: Path,
) -> IndexBuildResult:
    """Walk → parse → extract → bulk-insert. Returns IndexBuildResult.

    Never raises on per-file failures (parse errors, missing grammar);
    those are logged to `<scratch_dir>/index_build.log` and the file is
    skipped. Returns an empty result if no symbols emerged — the caller
    finalizes the run.
    """
    started = time.monotonic()
    scratch_dir.mkdir(parents=True, exist_ok=True)
    log_path = scratch_dir / "index_build.log"
    log_fh: TextIO = log_path.open("a", encoding="utf-8")
    try:
        _log(log_fh, f"index build started for run_id={run_id} repo={repo}")
        _log(log_fh, f"languages={sorted(languages)}")

        symbol_rows: list[SymbolRow] = []
        call_site_rows: list[CallSiteRow] = []
        file_contents: dict[str, str] = {}
        files_parsed = 0
        files_skipped = 0

        for abs_path, lang in walker_mod.walk(
            repo, languages_allowlist=languages
        ):
            rel = str(abs_path.relative_to(repo))
            try:
                source_bytes = abs_path.read_bytes()
            except OSError as e:
                _log(log_fh, f"skip {rel}: read failed ({e})")
                files_skipped += 1
                continue
            if not source_bytes:
                files_skipped += 1
                continue
            try:
                parser = get_parser(lang)
            except LanguageGrammarNotLoadedError as e:
                _log(log_fh, f"skip {rel}: grammar not loaded ({e.language})")
                files_skipped += 1
                continue
            try:
                tree = parser.parse(source_bytes)
            except Exception as e:
                _log(log_fh, f"skip {rel}: parse raised ({e!r})")
                files_skipped += 1
                continue
            try:
                result = extract(
                    tree=tree,
                    source_bytes=source_bytes,
                    repo_relative_file=rel,
                    language=lang,
                )
            except Exception as e:
                _log(log_fh, f"skip {rel}: extractor raised ({e!r})")
                files_skipped += 1
                continue

            files_parsed += 1
            if result.parse_errors:
                _log(log_fh, f"{rel}: tree-sitter parse_errors=1 (continuing)")
            if result.skipped_rows:
                _log(log_fh, f"{rel}: skipped_rows={result.skipped_rows}")
            symbol_rows.extend(result.symbols)
            call_site_rows.extend(result.call_sites)
            # Keep source text for the entry-point heuristic (Python only).
            if lang == "python":
                with contextlib.suppress(UnicodeDecodeError):
                    file_contents[rel] = source_bytes.decode("utf-8")

        _log(
            log_fh,
            f"extracted symbols={len(symbol_rows)} "
            f"call_sites={len(call_site_rows)}",
        )

        # Detect entry points before writing — runs against the in-memory rows
        # so that `attacker_controlled_input` etc. can be computed without a DB
        # round trip.
        entry_point_rows = ep_mod.detect(
            symbols=symbol_rows,
            call_sites=call_site_rows,
            file_contents=file_contents,
        )
        _log(log_fh, f"detected entry_points={len(entry_point_rows)}")

        # Bulk-insert in a single transaction.
        inserted_symbol_ids: dict[tuple[str, str], str] = {}
        inserted_symbol_ids_by_fqn: dict[str, str] = {}
        sym_objs: list[Symbol] = []
        cs_objs: list[CallSite] = []
        ep_objs: list[EntryPoint] = []
        with session_factory() as s:
            for sr in symbol_rows:
                sid = str(ULID())
                inserted_symbol_ids[(sr.file, sr.fully_qualified_name)] = sid
                # FQN map for callee resolution; collisions keep the first
                # (deterministic insertion order from the walker).
                inserted_symbol_ids_by_fqn.setdefault(
                    sr.fully_qualified_name, sid
                )
                sym_objs.append(Symbol(
                    id=sid,
                    run_id=run_id,
                    symbol=sr.symbol,
                    fully_qualified_name=sr.fully_qualified_name,
                    file=sr.file,
                    line_start=sr.line_start,
                    line_end=sr.line_end,
                    kind=sr.kind,
                    language=sr.language,
                ))
            s.add_all(sym_objs)
            # Flush symbols so call_sites.caller_symbol_id FK resolves at the
            # SQLite level. The transaction is still single — we commit once
            # below — but the rows must be visible to the FK check.
            s.flush()

            # Resolve callers + callees.
            unresolved_callers = 0
            for cs in call_site_rows:
                caller_id = inserted_symbol_ids_by_fqn.get(cs.caller_fqn)
                if caller_id is None:
                    unresolved_callers += 1
                    _log(
                        log_fh,
                        f"drop call site at {cs.file}:{cs.line}: "
                        f"caller_fqn={cs.caller_fqn!r} unresolved",
                    )
                    continue
                # Callee resolution: look up by short callee_text against any
                # Symbol whose short `symbol` matches. NULL if no match.
                #
                # FQN shape varies by language:
                #   - Python:     dotted-module-path.short_name  (e.g. `src.example.cli.greet`)
                #   - Non-Python: <file>::<short_name>           (e.g. `Foo.java::bar`)
                # We match either suffix so callee resolution works for all
                # 8 v1 languages, not just Python. (find_callers regression
                # surfaced in PR #9 code review.)
                callee_id: str | None = None

                def _fqn_matches(fqn: str, short: str) -> bool:
                    return fqn.endswith("." + short) or fqn.endswith("::" + short)

                # Prefer same-file match for stability.
                same_file_match = next(
                    (
                        sid
                        for (file, _fqn), sid in inserted_symbol_ids.items()
                        if file == cs.file
                        and _fqn_matches(_fqn, cs.callee_text)
                    ),
                    None,
                )
                if same_file_match is not None:
                    callee_id = same_file_match
                else:
                    # Cross-file: pick first FQN whose short name matches.
                    cross_file = next(
                        (
                            sid
                            for fqn, sid in inserted_symbol_ids_by_fqn.items()
                            if _fqn_matches(fqn, cs.callee_text)
                        ),
                        None,
                    )
                    callee_id = cross_file
                cs_objs.append(CallSite(
                    id=str(ULID()),
                    run_id=run_id,
                    caller_symbol_id=caller_id,
                    callee_symbol_id=callee_id,
                    callee_text=cs.callee_text,
                    file=cs.file,
                    line=cs.line,
                    snippet=cs.snippet,
                ))
            s.add_all(cs_objs)
            if unresolved_callers:
                _log(
                    log_fh,
                    f"dropped {unresolved_callers} call sites with "
                    f"unresolved callers",
                )

            # Bulk-insert entry points.
            for ep in entry_point_rows:
                ep_objs.append(EntryPoint(
                    id=str(ULID()),
                    recon_artifact_id=recon_artifact_id,
                    run_id=run_id,
                    symbol=ep.symbol,
                    file=ep.file,
                    line=ep.line,
                    kind=ep.kind,
                    attacker_controlled_input=(
                        1 if ep.attacker_controlled_input else 0
                    ),
                    notes=ep.notes,
                ))
            s.add_all(ep_objs)

            s.commit()

        duration_ms = int((time.monotonic() - started) * 1000)
        _log(
            log_fh,
            f"index build complete: symbols={len(sym_objs)} "
            f"call_sites={len(cs_objs)} entry_points={len(ep_objs)} "
            f"files_parsed={files_parsed} files_skipped={files_skipped} "
            f"duration_ms={duration_ms}",
        )
        return IndexBuildResult(
            symbols=len(sym_objs),
            call_sites=len(cs_objs),
            entry_points=len(ep_objs),
            files_parsed=files_parsed,
            files_skipped=files_skipped,
            duration_ms=duration_ms,
            languages=sorted(languages),
        )
    finally:
        log_fh.close()


def _log(fh: TextIO, msg: str) -> None:
    """Write a timestamped line to the build log."""
    ts = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    fh.write(f"{ts} {msg}\n")
    fh.flush()


__all__ = ["IndexBuildResult", "build_index"]
