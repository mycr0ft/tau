"""Stage 3b: approval decisions land as persistent transcript rows."""

from __future__ import annotations

from typing import Any

import pytest

from tau_coding.tool_approval import ApprovalRequest, ToolRisk
from tau_coding.tui.app import TauTuiApp
from tau_coding.tui.state import ChatItem, TuiState
from test_tui_app import FakeSession


def _request(**risk_kwargs: object) -> ApprovalRequest:
    risk = ToolRisk(
        classification=risk_kwargs.get("classification", "device"),
        sensitive=risk_kwargs.get("sensitive", True),
        reasons=("smart-card/PKCS#11 program access: pkcs11-tool",),
    )
    return ApprovalRequest(
        tool=risk_kwargs.get("tool", "bash"),
        summary=risk_kwargs.get("summary", "command='pkcs11-tool --list-slots'"),
        risk=risk,  # type: ignore[arg-type]
        choices=("allow-once", "deny-once"),
    )


def _status_rows(state: TuiState) -> list[ChatItem]:
    return [item for item in state.items if item.role == "status"]


def _start(app: TauTuiApp, request: ApprovalRequest) -> Any:
    return app.run_worker(app.prompt_tool_approval(request), exclusive=False)


@pytest.mark.anyio
async def test_denied_decision_persists_as_status_row() -> None:
    app = TauTuiApp(FakeSession())
    async with app.run_test() as pilot:
        await pilot.pause()
        worker = _start(app, _request())
        await pilot.pause()
        await pilot.press("escape")  # cancel = deny-once
        result = await worker.wait()
        await pilot.pause()
    assert result is None
    rows = _status_rows(app.state)
    assert rows, "no status row appended"
    text = rows[-1].text
    assert "/approvals" in text
    assert "denied (cancelled)" in text
    assert "Tool: bash" in text
    assert "sensitive" in text
    assert "pkcs11-tool --list-slots" in text


@pytest.mark.anyio
async def test_allowed_decision_persists_as_status_row() -> None:
    app = TauTuiApp(FakeSession())
    async with app.run_test() as pilot:
        await pilot.pause()
        worker = _start(app, _request())
        await pilot.pause()
        await pilot.pause()
        await pilot.press("enter")  # first choice = allow-once
        result = await worker.wait()
        await pilot.pause()
    assert result == "allow-once"
    rows = _status_rows(app.state)
    assert rows and "allow-once" in rows[-1].text
    assert "denied" not in rows[-1].text


@pytest.mark.anyio
async def test_row_survives_across_decisions() -> None:
    app = TauTuiApp(FakeSession())
    async with app.run_test() as pilot:
        await pilot.pause()
        worker_a = _start(app, _request())
        await pilot.pause()
        await pilot.press("escape")
        await worker_a.wait()
        await pilot.pause()
        worker_b = _start(app, _request(summary="command='gpg --card-status'"))
        await pilot.pause()
        await pilot.press("escape")
        await worker_b.wait()
        await pilot.pause()
    texts = [row.text for row in _status_rows(app.state)]
    assert sum("/approvals" in text for text in texts) == 2
    assert any("pkcs11-tool --list-slots" in text for text in texts)
    assert any("gpg --card-status" in text for text in texts)
