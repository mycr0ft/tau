"""Stage 2: CLI flag surface reaches the runners as ToolApprovalConfig."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from tau_coding import cli


def _invoke(args: list[str], fake: Any, monkeypatch: pytest.MonkeyPatch) -> Any:
    monkeypatch.setattr(cli, "_startup_update_notice", lambda: None)
    if fake is not None:
        monkeypatch.setattr(cli, "run_openai_print_mode", fake)
    return CliRunner().invoke(cli.app, ["--print", *args, "hi"])


@pytest.fixture()
def _capture(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    captured: dict[str, Any] = {}

    async def fake(*positional: Any, **kwargs: Any) -> bool:
        captured["positional"] = positional
        captured["kwargs"] = kwargs
        return True

    monkeypatch.setattr(cli, "run_openai_print_mode", fake)
    monkeypatch.setattr(cli, "_startup_update_notice", lambda: None)
    return captured


def test_jail_flag_reaches_runner(
    tmp_path: Path, _capture: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    result = _invoke(["--jail", str(tmp_path / "a")], None, monkeypatch)
    assert result.exit_code == 0, result.output
    from tau_coding.tool_approval import ToolApprovalConfig

    config = _capture["kwargs"].get("tool_approval")
    assert isinstance(config, ToolApprovalConfig)
    assert config.jail is not None
    assert config.jail.paths == (tmp_path / "a",)
    assert config.run_override is None


def test_jail_flag_repeatable(
    tmp_path: Path, _capture: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    a, b = tmp_path / "a", tmp_path / "b"
    result = CliRunner().invoke(cli.app, ["--print", "--jail", str(a), "--jail", str(b), "hi"])
    assert result.exit_code == 0, result.output
    config = _capture["kwargs"].get("tool_approval")
    assert config is not None and config.jail is not None
    assert config.jail.paths == (a, b)


def test_approve_tools_reaches_runner(
    _capture: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    result = _invoke(["--approve-tools"], None, monkeypatch)
    assert result.exit_code == 0, result.output
    config = _capture["kwargs"].get("tool_approval")
    assert config is not None and config.run_override == "approve"
    assert config.jail is None


def test_no_approve_tools_reaches_runner(
    _capture: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    result = _invoke(["--no-approve-tools"], None, monkeypatch)
    assert result.exit_code == 0, result.output
    config = _capture["kwargs"].get("tool_approval")
    assert config is not None and config.run_override == "decline"


def test_approve_tools_mutually_exclusive(monkeypatch: pytest.MonkeyPatch) -> None:
    result = CliRunner().invoke(cli.app, ["--print", "--approve-tools", "--no-approve-tools", "hi"])
    assert result.exit_code == 2  # typer.BadParameter
    assert "approve-tools" in result.output.replace("\n", " ")


def test_no_flags_no_gate(_capture: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    result = _invoke([], None, monkeypatch)
    assert result.exit_code == 0, result.output
    assert "tool_approval" not in _capture["kwargs"]
