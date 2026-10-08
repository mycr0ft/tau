"""Stage 3: ToolApprovalScreen TUI adapter pilot tests."""

from __future__ import annotations

from pathlib import Path

import pytest
from textual.app import App
from textual.widgets import Static

from tau_coding.tool_approval import ApprovalRequest, ToolRisk
from tau_coding.tui.tool_approval import ToolApprovalScreen


def _request(**risk_kwargs: object) -> ApprovalRequest:
    risk = ToolRisk(
        classification=risk_kwargs.get("classification", "command"),
        sensitive=risk_kwargs.get("sensitive", False),
        reasons=tuple(risk_kwargs.get("reasons", ("reason one",))),
    )
    return ApprovalRequest(
        tool=risk_kwargs.get("tool", "bash"),
        summary=risk_kwargs.get("summary", "command='pkcs11-tool --list-slots'"),
        risk=risk,  # type: ignore[arg-type]
        choices=("allow-once", "deny-once"),
    )


class _Host(App[None]):
    def __init__(self, request: ApprovalRequest) -> None:
        super().__init__()
        self.request = request
        self.results: list[object | None] = []

    def on_mount(self) -> None:
        self.push_screen(ToolApprovalScreen(self.request), self.results.append)


@pytest.mark.anyio
async def test_approval_modal_shows_boundary_and_summary(tmp_path: Path) -> None:
    request = _request()
    host = _Host(request)
    async with host.run_test() as pilot:
        await pilot.pause()
        boundary = str(host.screen.query_one("#tool-approval-boundary", Static).content)
        help_text = str(host.screen.query_one("#tool-approval-help", Static).content)
        tool = str(host.screen.query_one("#tool-approval-tool", Static).content)
        assessment = str(host.screen.query_one("#tool-approval-summary", Static).content)
        assert "not a sandbox" in boundary
        assert "Escape denies this call" in help_text
        assert tool == "bash"
        assert "shell command" in assessment
        await pilot.press("escape")
        await pilot.pause()
    assert host.results == [None]  # cancel = deny-once at the policy layer


@pytest.mark.anyio
async def test_approval_modal_escape_denies_and_dismisses(tmp_path: Path) -> None:
    request = _request()
    host = _Host(request)
    async with host.run_test() as pilot:
        await pilot.pause()
        await pilot.press("escape")
        await pilot.pause()
    assert host.results == [None]


@pytest.mark.anyio
async def test_approval_modal_keyboard_select_allow_once(tmp_path: Path) -> None:
    request = _request()
    host = _Host(request)
    async with host.run_test() as pilot:
        await pilot.pause()
        await pilot.press("enter")  # first item = allow-once
        await pilot.pause()
    assert host.results == ["allow-once"]


@pytest.mark.anyio
async def test_approval_modal_sensitive_choices_only(tmp_path: Path) -> None:
    request = _request(classification="device", sensitive=True, tool="bash")
    host = _Host(request)
    async with host.run_test() as pilot:
        await pilot.pause()
        assessment = str(host.screen.query_one("#tool-approval-summary", Static).content)
        assert "never auto-allowed" in assessment
        items = host.screen.query("#tool-approval-list ListItem")
        names = [item.name for item in items]
        assert names == ["allow-once", "deny-once"]
        await pilot.press("escape")
        await pilot.pause()
    assert host.results == [None]


@pytest.mark.anyio
async def test_approval_modal_lists_all_choices_for_pathbound(tmp_path: Path) -> None:
    request = ApprovalRequest(
        tool="edit",
        summary="path='/tmp/x.py'",
        risk=ToolRisk(
            classification="writes",
            jail_paths=(tmp_path / "x",),
            reasons=("outside jail",),
        ),
        choices=("allow-once", "allow-save", "deny-once", "deny-save"),
    )
    host = _Host(request)
    async with host.run_test() as pilot:
        await pilot.pause()
        names = [item.name for item in host.screen.query("#tool-approval-list ListItem")]
        assert names == ["allow-once", "allow-save", "deny-once", "deny-save"]
        await pilot.press("down")
        await pilot.press("enter")  # select allow-save
        await pilot.pause()
    assert host.results == ["allow-save"]
