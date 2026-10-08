"""Hardened profile preset (manifest jail) + /approvals command tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pi_event_helpers import assistant_done, assistant_start
from tau_agent.session import JsonlSessionStorage
from tau_ai import FakeProvider
from tau_coding import CodingSession, CodingSessionConfig
from tau_coding.commands import create_default_command_registry
from tau_coding.paths import TauPaths
from tau_coding.profiles import ProfileStore, ToolPolicy
from tau_coding.tool_approval import ApprovalStore, PathJail, ToolApprovalConfig

# --- manifest preset ----------------------------------------------------------


class TestProfileJailPreset:
    def _store(self, tmp_path: Path) -> ProfileStore:
        return ProfileStore(TauPaths(home=tmp_path / "home"))

    def test_manifest_jail_round_trip(self, tmp_path: Path) -> None:
        store = self._store(tmp_path)
        jail = PathJail(
            paths=(Path("/home/jfox/Projects"), Path("~/.tau")),
            reads_outside="ask",
            writes_outside="deny",
        )
        store.create("hardened", tools=ToolPolicy(deny=("bash",)), tool_approval_jail=jail)
        profile = store.get("hardened")
        assert profile.tool_approval_jail is not None
        expected = (Path(jail.paths[0]), Path("~/").expanduser() / ".tau")
        assert profile.tool_approval_jail.paths == expected
        assert profile.tool_approval_jail.writes_outside == "deny"
        # manifest shape is the documented one
        manifest = json.loads((profile.directory / "profile.json").read_text())
        assert manifest["toolApproval"]["jail"]["writesOutside"] == "deny"
        assert manifest["tools"] == {"deny": ["bash"]}

    def test_manifest_jail_invalid_policy_rejected(self, tmp_path: Path) -> None:
        home = tmp_path / "home"
        (home / "profiles" / "bad").mkdir(parents=True)
        (home / "profiles" / "bad" / "profile.json").write_text(
            json.dumps(
                {
                    "version": 1,
                    "name": "bad",
                    "toolApproval": {"jail": {"paths": ["/w"], "writesOutside": "maybe"}},
                }
            )
        )
        with pytest.raises(Exception, match="ask, allow, or deny"):
            self._store(tmp_path).get("bad")

    def test_empty_jail_paths_rejected(self, tmp_path: Path) -> None:
        home = tmp_path / "home"
        (home / "profiles" / "bad2").mkdir(parents=True)
        (home / "profiles" / "bad2" / "profile.json").write_text(
            json.dumps({"version": 1, "name": "bad2", "toolApproval": {"jail": {"paths": []}}})
        )
        with pytest.raises(Exception, match="non-empty"):
            self._store(tmp_path).get("bad2")

    def test_no_jail_gives_none(self, tmp_path: Path) -> None:
        store = self._store(tmp_path)
        store.create("plain")
        assert store.get("plain").tool_approval_jail is None


# --- gate config from preset (print-mode construction path) --------------------


class TestPresetToGateConfig:
    @pytest.mark.anyio
    async def test_preset_carries_jail_into_gate(self, tmp_path: Path) -> None:
        """ToolApprovalConfig built from a preset jail enforces writesOutside=deny."""
        jail = PathJail(paths=(tmp_path / "proj",), writes_outside="deny")
        (tmp_path / "proj").mkdir()
        home = tmp_path / "tau-home"
        home.mkdir()
        config = ToolApprovalConfig(jail=jail, store=ApprovalStore(TauPaths(home=home)))
        session = await CodingSession.load(
            CodingSessionConfig(
                provider=FakeProvider(
                    [
                        [
                            assistant_start(),
                            assistant_done({"model": "fake", "content": "ok"}),
                        ]
                    ]
                ),
                model="fake",
                system="You are Tau.",
                storage=JsonlSessionStorage(tmp_path / "s.jsonl"),
                cwd=tmp_path,
                tool_approval=config,
            )
        )
        assert session._harness.config.before_tool_call is not None


# --- /approvals command ---------------------------------------------------------


class FakeApprovalsSession:
    """CommandSession-shaped double with a live gate."""

    def __init__(self, tmp_path: Path, with_gate: bool = True) -> None:
        self.cwd = tmp_path
        self.model = "fake"
        self.provider_name = "openai"
        self.session_id = "test"
        if with_gate:
            home = tmp_path / "tau-home"
            home.mkdir(exist_ok=True)
            self._config = ToolApprovalConfig(store=ApprovalStore(TauPaths(home=home)))
            self._resolver = self._config.resolver_for_session()
        else:
            self._config = None
            self._resolver = None

    def approval_resolver(self) -> object | None:
        return self._resolver

    def tool_approval_config(self) -> object | None:
        return self._config

    # CommandSession protocol surface the handler path may touch
    @property
    def resource_diagnostics(self):
        return ()

    @property
    def session_title(self):
        return None


def _run(session: object, text: str) -> str:
    registry = create_default_command_registry()
    result = registry.execute(session, text)  # type: ignore[arg-type]
    assert result.handled, f"command {text!r} not handled"
    return result.message or ""


class TestApprovalsCommand:
    def test_gate_off_message(self, tmp_path: Path) -> None:
        session = FakeApprovalsSession(tmp_path, with_gate=False)
        result = _run(session, "/approvals")
        assert "not active" in result

    def test_lists_saved_rules(self, tmp_path: Path) -> None:
        session = FakeApprovalsSession(tmp_path)
        assert session._config is not None and isinstance(session._config, ToolApprovalConfig)
        session._config.store.add(
            __import__(
                "tau_coding.tool_approval", fromlist=["SavedApprovalRule"]
            ).SavedApprovalRule("allow", "edit", path_prefix=Path("/tmp"))
        )
        out = _run(session, "/approvals")
        assert "Saved rules:" in out
        assert "1. allow edit path=/tmp" in out

    def test_remove_rule(self, tmp_path: Path) -> None:
        session = FakeApprovalsSession(tmp_path)
        assert session._config is not None
        from tau_coding.tool_approval import SavedApprovalRule

        session._config.store.add(SavedApprovalRule("deny", "bash"))
        out = _run(session, "/approvals remove 1")
        assert "Removed rule 1" in out
        assert session._config.store.read() == ()

    def test_run_scoped_decisions_shown(self, tmp_path: Path) -> None:
        session = FakeApprovalsSession(tmp_path)
        assert session._resolver is not None
        session._resolver._session_allow.add("web_upload")
        out = _run(session, "/approvals")
        assert "Allowed for this run: web_upload" in out


@pytest.mark.anyio
async def test_switch_profile_applies_preset_jail(tmp_path: Path) -> None:
    """Live /profile switching carries the new profile's jail into the gate."""
    profiles = ProfileStore(TauPaths(home=tmp_path / "profiles-home"))
    jail = PathJail(paths=(tmp_path / "proj",), writes_outside="deny")
    profiles.create("caged", tool_approval_jail=jail)
    home = tmp_path / "tau-home"
    home.mkdir()
    approvals = ToolApprovalConfig(store=ApprovalStore(TauPaths(home=home)))
    from tau_agent.session import JsonlSessionStorage as J
    from tau_coding.resources import TauResourcePaths

    session_home = tmp_path / "profiles-home"
    session = await CodingSession.load(
        CodingSessionConfig(
            provider=FakeProvider([]),
            model="fake",
            system="You are Tau.",
            storage=J(tmp_path / "s.jsonl"),
            cwd=tmp_path,
            resource_paths=TauResourcePaths(
                root=session_home,
                agents_root=None,
                paths=TauPaths(home=session_home),
            ),
            tool_approval=approvals,
        )
    )
    assert session._config.tool_approval is not None
    assert session._config.tool_approval.jail is None
    await session.switch_profile("caged")
    gate = session._config.tool_approval
    assert gate is not None and gate.jail is not None
    assert gate.jail.writes_outside == "deny"
    # resolver continuity through the switch
    assert gate.resolver is approvals.resolver
    # switching back to no-profile leaves no preset jail
