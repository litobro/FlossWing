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

"""Eval ground-truth manifest registry.

Loads and validates TOML manifests (shipped as package data under
flosswing/eval/ground_truth/) into CorpusEntry objects. Pure file IO +
pydantic validation — no DB, no API. See docs/specs/2026-06-15-eval-design.md.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

from pydantic import BaseModel, Field, ValidationError

from flosswing.errors import EvalConfigError

DEFAULT_TOLERANCE = 10
DEFAULT_MANIFEST_DIR = Path(__file__).resolve().parent / "ground_truth"


class GroundTruthVuln(BaseModel):
    id: str
    file: str
    line_start: int
    line_end: int
    attack_class: str
    tolerance: int = DEFAULT_TOLERANCE
    cve: str | None = None
    severity: str | None = None
    notes: str | None = None


class CorpusEntry(BaseModel):
    model_config = {"populate_by_name": True}

    name: str
    repo: str
    description: str = ""
    vulns: list[GroundTruthVuln] = Field(alias="vuln")


def load_manifest(path: Path) -> CorpusEntry:
    """Parse and validate one manifest file into a CorpusEntry.

    Raises EvalConfigError (naming the path) on any parse or validation
    failure: malformed TOML, missing/invalid fields, name != file stem,
    line_end < line_start, or duplicate vuln ids.
    """
    try:
        with path.open("rb") as fh:
            data = tomllib.load(fh)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise EvalConfigError(f"{path}: cannot read manifest: {exc}") from exc

    try:
        entry = CorpusEntry.model_validate(data)
    except ValidationError as exc:
        raise EvalConfigError(f"{path}: invalid manifest: {exc}") from exc

    if entry.name != path.stem:
        raise EvalConfigError(
            f"{path}: manifest name {entry.name!r} != file stem {path.stem!r}"
        )

    seen: set[str] = set()
    for v in entry.vulns:
        if v.line_end < v.line_start:
            raise EvalConfigError(
                f"{path}: vuln {v.id!r} has line_end {v.line_end} "
                f"< line_start {v.line_start}"
            )
        if v.id in seen:
            raise EvalConfigError(f"{path}: duplicate vuln id {v.id!r}")
        seen.add(v.id)

    return entry


def load_corpus(manifest_dir: Path = DEFAULT_MANIFEST_DIR) -> list[CorpusEntry]:
    """Load every ``*.toml`` manifest in ``manifest_dir``, sorted by name.

    A missing or empty directory yields ``[]`` (not an error).
    """
    if not manifest_dir.is_dir():
        return []
    entries = [load_manifest(p) for p in sorted(manifest_dir.glob("*.toml"))]
    return sorted(entries, key=lambda e: e.name)


def find_entry(
    name: str, manifest_dir: Path = DEFAULT_MANIFEST_DIR
) -> CorpusEntry:
    """Return the corpus entry named ``name`` or raise EvalConfigError."""
    path = manifest_dir / f"{name}.toml"
    if not path.is_file():
        raise EvalConfigError(
            f"no corpus entry named {name!r} in {manifest_dir}"
        )
    return load_manifest(path)
