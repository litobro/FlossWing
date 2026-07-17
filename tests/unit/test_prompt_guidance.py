"""Guards that key anti-false-positive guidance stays in the prompts."""

from __future__ import annotations

from pathlib import Path

_PROMPTS = Path(__file__).resolve().parent.parent.parent / "flosswing" / "prompts"


def test_validate_prompt_has_circular_poc_rule() -> None:
    text = (_PROMPTS / "system" / "validate.md").read_text(encoding="utf-8")
    assert "non-probative" in text
    assert "mocks the sink" in text or "re-implements" in text


def test_hunt_prompt_prefers_real_code_pocs() -> None:
    text = (_PROMPTS / "system" / "hunt.md").read_text(encoding="utf-8")
    assert "import" in text.lower() and "real" in text.lower()
