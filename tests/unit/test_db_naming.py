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
"""Tests that the NAMING_CONVENTION in db.py is idempotent for CHECK constraints."""

from __future__ import annotations

import pytest
from sqlalchemy import CheckConstraint, Column, Integer, MetaData, Table
from sqlalchemy.dialects import sqlite
from sqlalchemy.exc import InvalidRequestError
from sqlalchemy.schema import CreateTable

from flosswing.state.db import NAMING_CONVENTION


def _ddl() -> str:
    md = MetaData(naming_convention=NAMING_CONVENTION)
    t = Table(
        "widgets",
        md,
        Column("n", Integer),
        # Authored with the FULL name (the 001 style that caused doubling):
        CheckConstraint("n >= 0", name="ck_widgets_nonneg"),
        # Authored with a BARE suffix (the recommended style):
        CheckConstraint("n < 100", name="toobig"),
    )
    return str(CreateTable(t).compile(dialect=sqlite.dialect()))


def test_ck_naming_is_idempotent() -> None:
    ddl = _ddl()
    # Both forms resolve to the clean single-prefixed name.
    assert "ck_widgets_nonneg" in ddl
    assert "ck_widgets_toobig" in ddl
    # And nothing is doubled.
    assert "ck_widgets_ck_widgets" not in ddl


def test_unnamed_check_raises() -> None:
    md = MetaData(naming_convention=NAMING_CONVENTION)
    # The convention is applied via an after_parent_attach event, so the raise
    # fires while the Table is being constructed (when the unnamed constraint
    # attaches), not later at CreateTable compile time.
    with pytest.raises(InvalidRequestError):
        Table(
            "widgets",
            md,
            Column("n", Integer),
            # No explicit name: %(constraint_name)s has nothing to resolve.
            CheckConstraint("n >= 0"),
        )


def test_column_attached_check_is_clean() -> None:
    md = MetaData(naming_convention=NAMING_CONVENTION)
    t = Table(
        "widgets",
        md,
        # Constraint attached via the COLUMN, not the table: exercises the
        # column-attached event path.
        Column("n", Integer, CheckConstraint("n >= 0", name="ck_widgets_nonneg")),
    )
    ddl = str(CreateTable(t).compile(dialect=sqlite.dialect()))
    assert "ck_widgets_nonneg" in ddl
    assert "ck_widgets_ck_widgets" not in ddl
