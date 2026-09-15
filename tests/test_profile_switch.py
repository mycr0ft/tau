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
