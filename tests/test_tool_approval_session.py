"""Stage 2: approval gate wired through CodingSession.load and the live loop."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from pi_event_helpers import assistant_done, assistant_start, tool_call_end
from tau_agent.messages import AssistantMessage, ToolCall
from tau_agent.session import JsonlSessionStorage
from tau_ai import FakeProvider
from tau_coding import CodingSession, CodingSessionConfig
from tau_coding.paths import TauPaths
from tau_coding.tool_approval import (
    ApprovalRequest,
    ApprovalStore,
    PathJail,
    ToolApprovalConfig,
)


def _approval_config(
    tmp_path: Path,
    *,
    jail: PathJail | None = None,
    requester: Any = None,
) -> ToolApprovalConfig:
    home = tmp_path / "tau-home"
    home.mkdir(exist_ok=True)
    return ToolApprovalConfig(
        jail=jail,
        store=ApprovalStore(TauPaths(home=home)),
        requester=requester,
    )


def _assistant_with_call(name: str, arguments: dict[str, object]) -> AssistantMessage:
    from tau_agent.messages import ToolCall

    call = ToolCall(id="call-1", name=name, arguments=arguments)
    return AssistantMessage(content=[call], model="fake")


async def _collect(stream: object) -> list[object]:
    return [event async for event in stream]  # type: ignore[attr-defined]


def _tool_ends(events: list[object], tool: str) -> list[Any]:
    return [
        event
        for event in events
        if getattr(event, "tool_name", None) == tool
        and type(event).__name__ == "ToolExecutionEndEvent"
    ]


def _storage(tmp_path: Path) -> JsonlSessionStorage:
    return JsonlSessionStorage(tmp_path / "session.jsonl")


def _call_stream(name: str, arguments: dict[str, object]) -> list[object]:
    """First provider turn: request `name` and stop cleanly for tool use."""
    call = ToolCall(id="call-1", name=name, arguments=arguments)
    return [
        assistant_start(),
        tool_call_end(call),
        assistant_done(AssistantMessage(content=[call], model="fake"), "toolUse"),
    ]


def _closing_stream(text: str = "done") -> list[object]:
    """Follow-up provider turn with no tool calls."""
    return [assistant_start(), assistant_done({"model": "fake", "content": text})]


@pytest.mark.anyio
async def test_gate_off_keeps_current_behavior(tmp_path: Path) -> None:
    """No tool_approval config => before_tool_call stays None (gate off)."""
    provider = FakeProvider(
        [[assistant_start(), assistant_done({"model": "fake", "content": "hi"})]]
    )
    session = await CodingSession.load(
        CodingSessionConfig(
            provider=provider,
            model="fake",
            storage=_storage(tmp_path),
            cwd=tmp_path,
            system="You are Tau.",
        )
    )
    assert session._harness.config.before_tool_call is None


@pytest.mark.anyio
async def test_sensitive_call_blocked_headless_with_reason_to_model(tmp_path: Path) -> None:
    """Headless + sensitive call: blocked, reason fed back as the tool error."""
    provider = FakeProvider(
        [
            _call_stream("bash", {"command": "pkcs11-tool --list-slots"}),
            _closing_stream("understood"),
        ]
    )
    session = await CodingSession.load(
        CodingSessionConfig(
            provider=provider,
            model="fake",
            storage=_storage(tmp_path),
            cwd=tmp_path,
            system="You are Tau.",
            tool_approval=_approval_config(tmp_path),
        )
    )
    events = await _collect(session.prompt("list slots"))
    ends = _tool_ends(events, "bash")
    assert ends, f"no ToolExecutionEndEvent in {events}"
    assert ends[0].is_error
    assert "Denied by approval gate" in ends[0].result.text
    assert "sensitive" in ends[0].result.text
    # The model saw the denial in its next turn's messages.
    tool_results = [m for m in provider.calls[1][2] if type(m).__name__ == "ToolResultMessage"]
    assert tool_results and tool_results[0].is_error


@pytest.mark.anyio
async def test_requester_decides_interactively(tmp_path: Path) -> None:
    """A wired requester receives the request; allow-once lets the call run."""
    seen: list[ApprovalRequest] = []

    async def requester(request: ApprovalRequest) -> str | None:
        seen.append(request)
        return "allow-once"

    provider = FakeProvider(
        [
            _call_stream("bash", {"command": "gpg --card-status"}),
            _closing_stream(),
        ]
    )
    session = await CodingSession.load(
        CodingSessionConfig(
            provider=provider,
            model="fake",
            storage=_storage(tmp_path),
            cwd=tmp_path,
            system="You are Tau.",
            tool_approval=_approval_config(tmp_path, requester=requester),
        )
    )
    events = await _collect(session.prompt("check card"))
    assert len(seen) == 1
    assert seen[0].tool == "bash"
    assert seen[0].choices == ("allow-once", "deny-once")  # sensitive: no persistence
    ends = _tool_ends(events, "bash")
    assert ends and not ends[0].is_error


@pytest.mark.anyio
async def test_jail_blocks_outside_write(tmp_path: Path) -> None:
    """writesOutside=deny is deterministic even in interactive mode."""

    async def requester(request: ApprovalRequest) -> str | None:
        raise AssertionError("headless-deny must not prompt")

    jail = PathJail(paths=(tmp_path / "proj",), writes_outside="deny")
    (tmp_path / "proj").mkdir()
    provider = FakeProvider(
        [
            _call_stream("write", {"path": "/etc/passwd", "content": "x"}),
            _closing_stream(),
        ]
    )
    session = await CodingSession.load(
        CodingSessionConfig(
            provider=provider,
            model="fake",
            storage=_storage(tmp_path),
            cwd=tmp_path,
            system="You are Tau.",
            tool_approval=_approval_config(tmp_path, jail=jail, requester=requester),
        )
    )
    events = await _collect(session.prompt("write it"))
    ends = _tool_ends(events, "write")
    assert ends and ends[0].is_error
    assert "outside the jail" in ends[0].result.text


@pytest.mark.anyio
async def test_resolver_survives_resume(tmp_path: Path) -> None:
    """Resume threads the same ToolApprovalConfig (one resolver, one audit)."""
    approvals = _approval_config(tmp_path)
    provider = FakeProvider(
        [[assistant_start(), assistant_done({"model": "fake", "content": "hi"})]]
    )
    session = await CodingSession.load(
        CodingSessionConfig(
            provider=provider,
            model="fake",
            storage=_storage(tmp_path),
            cwd=tmp_path,
            system="You are Tau.",
            tool_approval=approvals,
        )
    )
    await _collect(session.prompt("hello"))
    first_gate = session._harness.config.before_tool_call
    assert first_gate is not None

    resumed = await CodingSession.load(
        CodingSessionConfig(
            provider=FakeProvider([]),
            model="fake",
            storage=_storage(tmp_path),
            cwd=tmp_path,
            system="You are Tau.",
            tool_approval=approvals,
        )
    )
    second_gate = resumed._harness.config.before_tool_call
    assert second_gate is not None
    assert second_gate.__self__ is first_gate.__self__


@pytest.mark.anyio
async def test_audit_records_decisions(tmp_path: Path) -> None:
    approvals = _approval_config(tmp_path)
    provider = FakeProvider(
        [
            _call_stream("bash", {"command": "pkcs11-tool -I"}),
            _closing_stream(),
        ]
    )
    session = await CodingSession.load(
        CodingSessionConfig(
            provider=provider,
            model="fake",
            storage=_storage(tmp_path),
            cwd=tmp_path,
            system="You are Tau.",
            tool_approval=approvals,
        )
    )
    await _collect(session.prompt("go"))
    resolver = approvals.resolver
    assert resolver is not None
    assert any("[approval] Denied bash" in row for row in resolver.audit)
