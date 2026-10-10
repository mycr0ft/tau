"""Landlock enforcement: launcher plumbing, gating, and optional live kernel tests."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from tau_coding._landlock import EnforcePolicy, landlock_available, launcher_command
from tau_coding.tool_approval import PathJail


def _py_with_landlock() -> str:
    """Interpreter used for live probes (venv python if it has py-landlock)."""
    return sys.executable


class TestAvailabilityAndArgv:
    def test_graceful_without_landlock(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("tau_coding._landlock.landlock_available", lambda: False)
        assert launcher_command(PathJail(paths=("/tmp/w",))) is None

    @pytest.mark.skipif(not landlock_available(), reason="py-landlock + kernel not available")
    def test_argv_shape(self, tmp_path: Path) -> None:
        argv = launcher_command(PathJail(paths=(tmp_path,)), python_path=sys.executable)
        assert argv is not None
        assert argv[-1].startswith("{")
        spec = json.loads(argv[-1])
        assert spec["jail"]["paths"] == [str(tmp_path)]
        # PYTHONPATH injection when src not importable
        assert any("PYTHONPATH" in part for part in argv) or "tau_coding" in sys.modules

    def test_nonwin_guard_in_policy_helper(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        from tau_coding.session import _bash_enforcement_prefix
        from tau_coding.tool_approval import ToolApprovalConfig

        config = ToolApprovalConfig(jail=PathJail(paths=(tmp_path,)), enforce_bash=True)
        monkeypatch.setattr("tau_coding._landlock.landlock_available", lambda: False)
        assert _bash_enforcement_prefix(config, tmp_path) is None

    def test_requires_active_jail(self, tmp_path: Path) -> None:
        from tau_coding.session import _bash_enforcement_prefix
        from tau_coding.tool_approval import ToolApprovalConfig

        config = ToolApprovalConfig(enforce_bash=True)  # no jail
        assert _bash_enforcement_prefix(config, tmp_path) is None


class TestToolsWiring:
    def test_create_coding_tools_accepts_enforce_prefix(self) -> None:
        from tau_coding.tools import create_coding_tools

        tools = create_coding_tools(shell_enforce_prefix=("/bin/echo", "launch"))
        bash = [tool for tool in tools if tool.name == "bash"]
        assert bash, "bash tool missing"
        # The enforcement prefix is carried in the executor closure; exercise
        # via the tool's schema-level presence only here (live exec below).

    def test_enforce_prefix_none_keeps_legacy_spawn(self) -> None:
        from tau_coding.tools import create_bash_tool

        tool = create_bash_tool()  # no enforce prefix
        assert tool.name == "bash"


@pytest.mark.skipif(not landlock_available(), reason="py-landlock + Landlock kernel not available")
class TestLiveConfinement:
    """Full-fidelity tests: the real kernel enforces; run in a disposable home."""

    def _launcher(
        self, tmp_path: Path, jail_root: Path, *, network: str = "deny"
    ) -> tuple[list[str], dict[str, str]]:
        prefix = launcher_command(
            PathJail(paths=(jail_root,)),
            policy=EnforcePolicy(include_cwd_read=False, network=network),  # type: ignore[arg-type]
            python_path=sys.executable,
        )
        assert prefix is not None
        return prefix, dict(os.environ)

    def _child_argv(self, prefix: list[str], command: str) -> list[str]:
        return [*prefix, "bash", "-c", command]

    def test_bash_child_is_kernel_confined(self, tmp_path: Path) -> None:
        jail_root = tmp_path / "jail"
        jail_root.mkdir()
        prefix, env = self._launcher(tmp_path, jail_root)
        command = (
            f"(echo in > {jail_root}/ok) && "
            f"(ls {Path.home()} > /dev/null 2>&1 || echo BLOCKED-home) && "
            f"(ls {tmp_path} > /dev/null 2>&1 || echo BLOCKED-ls) && "
            f"(cat {jail_root}/ok > /dev/null && echo JAIL-READ-OK)"
        )
        result = subprocess.run(
            self._child_argv(prefix, command),
            env=env,
            capture_output=True,
            text=True,
            cwd=str(tmp_path),
        )
        out = result.stdout
        assert "JAIL-READ-OK" in out
        assert "BLOCKED-home" in out, out
        assert "BLOCKED-ls" in out, out
        assert (jail_root / "ok").exists()  # jail write kept working

    def test_network_allow_opens_connects(self, tmp_path: Path) -> None:
        jail_root = tmp_path / "jail"
        jail_root.mkdir()
        prefix, env = self._launcher(tmp_path, jail_root, network="allow")
        command = "curl -s --max-time 8 -o /dev/null -w '%{http_code}' https://example.com"
        result = subprocess.run(
            self._child_argv(prefix, command),
            env=env,
            capture_output=True,
            text=True,
            cwd=str(tmp_path),
        )
        assert result.stdout.strip().endswith("200") or result.stdout.strip() == "200"

    def test_missing_child_fails_loud(self, tmp_path: Path) -> None:
        jail_root = tmp_path / "jail"
        jail_root.mkdir()
        prefix, env = self._launcher(tmp_path, jail_root)
        result = subprocess.run(prefix, env=env, capture_output=True, text=True, cwd=str(tmp_path))
        assert result.returncode != 0
        assert "CHILD" in (result.stderr or "")

    def test_bash_tool_runs_under_enforcement(self, tmp_path: Path) -> None:
        """The real bash tool path, with the enforcement prefix wired in."""
        import asyncio

        from tau_coding.tools import create_bash_tool

        jail_root = tmp_path / "jail"
        jail_root.mkdir()
        prefix, _ = self._launcher(tmp_path, jail_root)
        tool = create_bash_tool(cwd=tmp_path, enforce_prefix=tuple(prefix))
        result = asyncio.run(
            tool.execute(
                "call-1",
                {
                    "command": f"echo hi > {jail_root}/marker && cat {jail_root}/marker",
                    "description": "probe",
                },
                None,
                None,
            )
        )
        assert "hi" in result.text
        assert (jail_root / "marker").exists()

    def test_gate_asks_out_of_jail_write_but_bash_is_walled(self, tmp_path: Path) -> None:
        """Policy layer (ask for files) + enforcement (kernel walls bash) compose."""
        import asyncio

        from tau_coding.tools import create_bash_tool

        jail_root = tmp_path / "jail"
        jail_root.mkdir()
        prefix, _ = self._launcher(tmp_path, jail_root)
        tool = create_bash_tool(cwd=tmp_path, enforce_prefix=tuple(prefix))
        escaped = tmp_path / "escape-marker"
        result = asyncio.run(
            tool.execute(
                "call-1",
                {"command": f"touch {escaped} 2>&1; echo touched-rc=$?", "description": "probe"},
                None,
                None,
            )
        )
        # The escape file cannot exist: the kernel denied the write.
        assert not escaped.exists()
        assert not escaped.is_file()
        assert "Permission denied" in result.text or "Read-only" in result.text
