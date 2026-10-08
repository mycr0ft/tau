"""Stage 3c: resume preserves session-scoped policy state (tool policy + gate)."""

from __future__ import annotations

from pathlib import Path

import pytest

from tau_agent.session import JsonlSessionStorage
from tau_ai import FakeProvider
from tau_coding import CodingSession, CodingSessionConfig
from tau_coding.paths import TauPaths
from tau_coding.profiles import ProfileStore, ToolPolicy
from tau_coding.tool_approval import ApprovalStore, ToolApprovalConfig


def _manager(tmp_path: Path):
    from tau_coding.session_manager import SessionManager

    return SessionManager(TauPaths(home=tmp_path / ".tau", agents_home=tmp_path / ".agents"))


@pytest.mark.anyio
async def test_resume_preserves_tool_policy(tmp_path: Path) -> None:
    """resume() builds its replacement config field-by-field; policy must carry."""
    manager = _manager(tmp_path)
    record = manager.create_session(cwd=tmp_path, model="fake", title="A")
    tool_policy = ToolPolicy(deny=("bash",))
    session = await CodingSession.load(
        CodingSessionConfig(
            provider=FakeProvider([]),
            model="fake",
            system="You are Tau.",
            storage=JsonlSessionStorage(record.path),
            cwd=record.cwd,
            session_id=record.id,
            session_manager=manager,
            tool_policy=tool_policy,
        )
    )
    assert session._config.tool_policy is tool_policy or session._config.tool_policy == tool_policy
    await session.resume(record.id)
    assert session._config.tool_policy is not None
    assert session._config.tool_policy.deny == ("bash",)
    # and the policy still applies to the live harness toolset
    tool_names = {tool.name for tool in session._harness.config.tools}
    assert "bash" not in tool_names


@pytest.mark.anyio
async def test_resume_preserves_tool_approval_gate(tmp_path: Path) -> None:
    manager = _manager(tmp_path)
    home = tmp_path / "tau-home"
    home.mkdir()
    approvals = ToolApprovalConfig(store=ApprovalStore(TauPaths(home=home)))
    record = manager.create_session(cwd=tmp_path, model="fake", title="B")
    session = await CodingSession.load(
        CodingSessionConfig(
            provider=FakeProvider([]),
            model="fake",
            system="You are Tau.",
            storage=JsonlSessionStorage(record.path),
            cwd=record.cwd,
            session_id=record.id,
            session_manager=manager,
            tool_approval=approvals,
        )
    )
    gate_before = session._harness.config.before_tool_call
    assert gate_before is not None
    await session.resume(record.id)
    gate_after = session._harness.config.before_tool_call
    assert gate_after is not None
    # Bound methods compare unequal by identity; continuity is the resolver.
    assert gate_after.__self__ is gate_before.__self__


def test_profile_store_rejects_unknown_tool_names(tmp_path: Path) -> None:
    """Policy validation guards the resume thread too (typos fail loudly)."""
    home = tmp_path / "profiles-home"
    home.mkdir()
    store = ProfileStore(TauPaths(home=home))
    with pytest.raises(Exception, match="bashh"):
        store.create("p", tools=ToolPolicy(deny=("bashh",)))
