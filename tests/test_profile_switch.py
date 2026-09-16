"""Tests for profile switching on a live coding session."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from tau_agent.session import JsonlSessionStorage
from tau_coding.paths import TauPaths
from tau_coding.resources import TauResourcePaths
from tau_coding.session import CodingSession, CodingSessionConfig


class _FakeProvider:
    """Minimal provider double: never streams anything."""

    def stream_response(self, **_kwargs: Any) -> Any:
        async def _empty() -> Any:
            return
            yield  # pragma: no cover

        return _empty()

    async def aclose(self) -> None:
        return None


def _write_profile(
    home: Path,
    name: str,
    *,
    tools: dict[str, list[str]] | None = None,
    system_prompt: str | None = None,
) -> Path:
    home = home / ".tau"
    profile_dir = home / "profiles" / name
    profile_dir.mkdir(parents=True, exist_ok=True)
    manifest: dict[str, Any] = {"version": 1, "name": name}
    if tools is not None:
        manifest["tools"] = tools
    (profile_dir / "profile.json").write_text(json.dumps(manifest), encoding="utf-8")
    if system_prompt is not None:
        (profile_dir / "SYSTEM.md").write_text(system_prompt, encoding="utf-8")
    return profile_dir


async def _make_session(tmp_path: Path) -> CodingSession:
    home = tmp_path / ".tau"
    tp = TauPaths(home=home, agents_home=tmp_path / ".agents")
    config = CodingSessionConfig(
        provider=_FakeProvider(),
        model="fake",
        system=None,
        storage=JsonlSessionStorage(tmp_path / "session.jsonl"),
        cwd=tmp_path,
        resource_paths=TauResourcePaths(paths=tp),
    )
    return await CodingSession.load(config)


@pytest.mark.anyio
async def test_switch_profile_applies_tool_policy_and_prompt(
    tmp_path: Path,
) -> None:
    _write_profile(
        tmp_path,
        "work",
        tools={"deny": ["bash"]},
        system_prompt="WORK profile prompt",
    )
    session = await _make_session(tmp_path)

    message = await session.switch_profile("work")

    assert message == "Switched to profile: work"
    assert session.profile_name == "work"
    tool_names = [tool.name for tool in session._harness.config.tools]
    assert "bash" not in tool_names
    assert "WORK profile prompt" in (session._harness.config.system or "")


@pytest.mark.anyio
async def test_switch_profile_rejects_unknown_profile(tmp_path: Path) -> None:
    session = await _make_session(tmp_path)

    with pytest.raises(ValueError, match="work"):
        await session.switch_profile("work")
    assert session.profile_name is None


@pytest.mark.anyio
async def test_list_profiles_reports_available_names(tmp_path: Path) -> None:
    _write_profile(tmp_path, "alpha")
    _write_profile(tmp_path, "beta")
    session = await _make_session(tmp_path)

    assert session.list_profiles() == ("alpha", "beta")


@pytest.mark.anyio
async def test_list_profiles_creates_missing_profiles_dir(tmp_path: Path) -> None:
    session = await _make_session(tmp_path)

    names = session.list_profiles()

    assert names == ()
    assert (tmp_path / ".tau" / "profiles").is_dir()


@pytest.mark.anyio
async def test_create_profile_scaffolds_minimal_profile(tmp_path: Path) -> None:
    session = await _make_session(tmp_path)

    message = session.create_profile("minimal", clone_current=False)

    assert "minimal" in message
    profile_dir = tmp_path / ".tau" / "profiles" / "minimal"
    assert (profile_dir / "profile.json").is_file()
    assert (profile_dir / "SYSTEM.md").is_file()
    manifest = json.loads((profile_dir / "profile.json").read_text(encoding="utf-8"))
    assert manifest["name"] == "minimal"
    assert manifest["version"] == 1
    # A scaffold carries no cloned tool allow-list.
    assert "tools" not in manifest


@pytest.mark.anyio
async def test_create_profile_clone_captures_current_tools(tmp_path: Path) -> None:
    session = await _make_session(tmp_path)

    session.create_profile("clone", clone_current=True)

    profile_dir = tmp_path / ".tau" / "profiles" / "clone"
    manifest = json.loads((profile_dir / "profile.json").read_text(encoding="utf-8"))
    tool_names = [tool.name for tool in session.tools]
    assert manifest["tools"]["allow"] == tool_names


@pytest.mark.anyio
async def test_create_profile_rejects_duplicate(tmp_path: Path) -> None:
    session = await _make_session(tmp_path)

    session.create_profile("dup", clone_current=False)
    with pytest.raises(ValueError, match="already exists"):
        session.create_profile("dup", clone_current=False)


@pytest.mark.anyio
async def test_create_then_switch_round_trip(tmp_path: Path) -> None:
    session = await _make_session(tmp_path)

    session.create_profile("made", clone_current=True)
    message = await session.switch_profile("made")

    assert message == "Switched to profile: made"
    assert session.profile_name == "made"
