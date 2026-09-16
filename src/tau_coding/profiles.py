"""Named agent-configuration profiles for Tau (v0.4.5 phase, profiles/P1).

A profile is a named bundle under ``~/.tau/profiles/<name>/``:

    profile.json     manifest (provider/model/thinking/tools/auto_compact)
    SYSTEM.md        optional profile system-prompt override
    APPEND_SYSTEM.md optional profile append-prompt
    AGENTS.md        optional profile-level instructions
    skills/          profile-only skills
    prompts/         profile-only prompt templates

Profiles are *tau_coding* configuration: they resolve into an
``AgentHarnessConfig`` (provider, model, system, tools) plus resource
paths.  ``tau_agent`` never learns the word "profile".
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from tau_coding.paths import TauPaths

logger = logging.getLogger(__name__)

PROFILE_MANIFEST = "profile.json"
PROFILE_DIRNAME = "profiles"

_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]*$")
_MAX_NAME_LENGTH = 48

_TOOL_NAMES = frozenset({"read", "write", "edit", "bash"})


class ProfileError(ValueError):
    """A profile is missing, malformed, or conflicts with itself."""


def _require_name(name: str) -> str:
    if not name or not _NAME_RE.fullmatch(name):
        raise ProfileError(
            "Profile name must start with an alphanumeric character and "
            "contain only letters, digits, '-' and '_'"
        )
    if len(name) > _MAX_NAME_LENGTH:
        raise ProfileError(f"Profile name is too long (max {_MAX_NAME_LENGTH})")
    return name


@dataclass(frozen=True, slots=True)
class ToolPolicy:
    """Allow/deny filters applied to the composed toolset.

    ``allow`` is an allow-list (empty = allow everything); ``deny``
    removes named tools after the allow step.  Unknown tool names in
    either list are validated at profile load so typos fail loudly.
    """

    allow: tuple[str, ...] = ()
    deny: tuple[str, ...] = ()

    def apply(self, tools: list[Any]) -> list[Any]:
        allowed = set(self.allow)
        denied = set(self.deny)
        if not allowed and not denied:
            return tools
        return [
            tool
            for tool in tools
            if (not allowed or tool.name in allowed) and tool.name not in denied
        ]

    def to_json(self) -> dict[str, Any]:
        data: dict[str, Any] = {}
        if self.allow:
            data["allow"] = list(self.allow)
        if self.deny:
            data["deny"] = list(self.deny)
        return data

    @staticmethod
    def from_json(data: Any) -> ToolPolicy:
        if data is None:
            return ToolPolicy()
        if not isinstance(data, dict):
            raise ProfileError("profile tools must be an object")
        allow = data.get("allow", [])
        deny = data.get("deny", [])
        if not isinstance(allow, list) or not isinstance(deny, list):
            raise ProfileError("profile tools allow/deny must be lists")
        for name in allow + deny:
            if name not in _TOOL_NAMES:
                raise ProfileError(f"unknown tool in profile: {name!r}")
        return ToolPolicy(allow=tuple(allow), deny=tuple(deny))


@dataclass(frozen=True, slots=True)
class Profile:
    """A validated profile manifest plus its directory."""

    name: str
    directory: Path
    provider: str | None = None
    model: str | None = None
    thinking_level: str | None = None
    tools: ToolPolicy = field(default_factory=ToolPolicy)
    auto_compact_enabled: bool | None = None

    @property
    def system_prompt_path(self) -> Path:
        return self.directory / "SYSTEM.md"

    @property
    def append_system_prompt_path(self) -> Path:
        return self.directory / "APPEND_SYSTEM.md"

    @property
    def agents_path(self) -> Path:
        return self.directory / "AGENTS.md"

    @property
    def skills_dir(self) -> Path:
        return self.directory / "skills"

    @property
    def prompts_dir(self) -> Path:
        return self.directory / "prompts"


@dataclass(frozen=True, slots=True)
class ProfileStorePaths:
    """Resolved profile-store paths for one session."""

    profiles_dir: Path

    @classmethod
    def from_tau_paths(cls, paths: TauPaths | None = None) -> ProfileStorePaths:
        tau_paths = paths or TauPaths()
        return cls(profiles_dir=tau_paths.home / PROFILE_DIRNAME)


class ProfileStore:
    """List, read, and validate profiles under ``~/.tau/profiles/``."""

    def __init__(self, paths: TauPaths | None = None) -> None:
        self._paths = ProfileStorePaths.from_tau_paths(paths)

    @property
    def profiles_dir(self) -> Path:
        return self._paths.profiles_dir

    def ensure_profiles_dir(self) -> Path:
        """Create ``~/.tau/profiles/`` when missing; return it."""
        self.profiles_dir.mkdir(parents=True, exist_ok=True)
        return self.profiles_dir

    def list_profiles(self) -> tuple[str, ...]:
        """Profile names in sorted order (directories with profile.json)."""
        if not self.profiles_dir.is_dir():
            # First contact with profiles: create the folder so `/profile`
            # never dead-ends on a missing directory.
            self.ensure_profiles_dir()
            return ()
        names = []
        for entry in sorted(self.profiles_dir.iterdir(), key=lambda p: p.name):
            if entry.is_dir() and (entry / PROFILE_MANIFEST).is_file():
                names.append(entry.name)
        return tuple(names)

    def exists(self, name: str) -> bool:
        return (self.profiles_dir / name / PROFILE_MANIFEST).is_file()

    def get(self, name: str) -> Profile:
        """Load and validate one profile by name."""
        _require_name(name)
        directory = self.profiles_dir / name
        manifest = directory / PROFILE_MANIFEST
        if not manifest.is_file():
            raise ProfileError(f"Unknown profile: {name}")
        try:
            data = json.loads(manifest.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ProfileError(
                f"Profile {name!r} has a malformed {PROFILE_MANIFEST}: {exc}"
            ) from exc
        if not isinstance(data, dict):
            raise ProfileError(f"Profile {name!r} manifest must be a JSON object")

        version = data.get("version")
        if version != 1:
            raise ProfileError(f"Profile {name!r} manifest version must be 1 (got {version!r})")
        stored_name = data.get("name")
        if stored_name is not None and stored_name != name:
            raise ProfileError(f"Profile {name!r} manifest declares name {stored_name!r}")

        provider = _optional_str(data, "provider", name)
        model = _optional_str(data, "model", name)
        thinking = _optional_str(data, "thinking_level", name)
        auto_compact = data.get("auto_compact_enabled")
        if auto_compact is not None and not isinstance(auto_compact, bool):
            raise ProfileError(f"Profile {name!r} auto_compact_enabled must be a boolean")
        tools = ToolPolicy.from_json(data.get("tools"))

        if tools.deny and tools.allow:
            overlap = set(tools.allow) & set(tools.deny)
            if overlap:
                raise ProfileError(f"Profile {name!r} both allows and denies: {sorted(overlap)}")

        return Profile(
            name=name,
            directory=directory,
            provider=provider,
            model=model,
            thinking_level=thinking,
            tools=tools,
            auto_compact_enabled=auto_compact,
        )

    def create(self, name: str, **values: Any) -> Profile:
        """Create a profile directory with a manifest; refuses to overwrite."""
        _require_name(name)
        directory = self.profiles_dir / name
        if directory.exists():
            raise ProfileError(f"Profile already exists: {name}")
        manifest_data = {"version": 1, "name": name}
        for key in ("provider", "model", "thinking_level", "auto_compact_enabled"):
            if key in values and values[key] is not None:
                manifest_data[key] = values[key]
        if "tools" in values and values["tools"] is not None:
            manifest_data["tools"] = _tool_policy_json(values["tools"])

        directory.mkdir(parents=True, exist_ok=False)
        (directory / PROFILE_MANIFEST).write_text(
            json.dumps(manifest_data, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        scaffold = bool(values.get("scaffold"))
        if scaffold:
            system_template = values.get("system_prompt")
            if isinstance(system_template, str) and system_template:
                (directory / "SYSTEM.md").write_text(system_template, encoding="utf-8")
        return self.get(name)


def _tool_policy_json(value: Any) -> Any:
    if isinstance(value, ToolPolicy):
        return value.to_json()
    if isinstance(value, dict):
        return {k: list(v) if isinstance(v, (list, tuple)) else v for k, v in value.items()}
    raise ProfileError("profile tools must be a ToolPolicy or dict")


def _optional_str(data: dict[str, Any], key: str, profile: str) -> str | None:
    value = data.get(key)
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise ProfileError(f"Profile {profile!r} {key} must be a string")
    return value
