"""Seatbelt (macOS) enforcement: profile building, dispatch, live confinement.

Unit tests run on every OS (the profile compiler is pure). The live class
exercises real ``sandbox-exec`` confinement and is skipped on non-macOS
hosts — run it on a Mac with ``uv run pytest tests/test_seatbelt_enforcement.py``.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

import tau_coding._seatbelt as seatbelt_module
from tau_coding._landlock import EnforcePolicy
from tau_coding._seatbelt import (
    SANDBOX_EXEC_BANNER_LINES,
    build_seatbelt_profile,
    launcher_command,
    seatbelt_available,
    strip_sandbox_exec_banner,
)
from tau_coding.tool_approval import PathJail


def _profile(jail: PathJail, **kwargs: object) -> str:
    return build_seatbelt_profile(jail, **kwargs)  # type: ignore[arg-type]


class TestProfileContent:
    def test_deny_default_shape(self) -> None:
        text = _profile(PathJail(paths=(Path("/Users/jon/work"),)))
        assert text.startswith("(version 1)")
        assert "(deny default)" in text
        assert "(allow process-exec*)" in text
        assert "(allow process-fork)" in text
        assert "(allow sysctl-read)" in text

    def test_system_read_tier(self) -> None:
        text = _profile(PathJail(paths=(Path("/work/test"),)))
        for target in ("/usr", "/System", "/Library", "/private/etc", "/dev"):
            assert f'(subpath "{target}")' in text

    def test_jail_grants_read_and_write(self) -> None:
        text = _profile(PathJail(paths=(Path("/work/test"), Path("/Users/jon/other"))))
        assert text.count('(allow file-write* (subpath "/work/test"))') == 1
        assert text.count('(allow file-write* (subpath "/Users/jon/other"))') == 1
        assert text.count('(allow file-read* (subpath "/work/test"))') == 1

    def test_tmp_and_dev_write(self) -> None:
        text = _profile(PathJail(paths=(Path("/work/test"),)))
        assert '(allow file-write* (subpath "/tmp"))' in text
        assert '(allow file-write* (subpath "/private/tmp"))' in text
        assert '(allow file-write* (subpath "/dev"))' in text

    def test_home_read_denied(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("HOME", "/Users/jon")
        text = _profile(PathJail(paths=(Path("/work/test"),)))
        assert '(deny file-read* (subpath "/Users/jon"))' in text
        for denied in (
            "/Users/jon/.ssh",
            "/Users/jon/.aws",
            "/Users/jon/.tau",
            "/Users/jon/Library/Keychains",
        ):
            assert f'(deny file-read* (subpath "{denied}"))' in text

    def test_interpreter_prefix_overrides_home_deny(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("HOME", "/Users/jon")
        text = _profile(
            PathJail(paths=(Path("/work/test"),)),
            python_path="/Users/jon/.local/share/uv/tools/tau-ai/bin/python",
        )
        assert '(allow file-read* (subpath "/Users/jon/.local/share/uv/tools/tau-ai"))' in text
        # Ordering: the override appears after the deny (Seatbelt honours
        # rule order, later rules win).
        deny_index = text.index('(deny file-read* (subpath "/Users/jon"))')
        override_index = text.index('/uv/tools/tau-ai"))')
        assert override_index > deny_index

    def test_cwd_read_option(self) -> None:
        text_on = build_seatbelt_profile(
            PathJail(paths=(Path("/work/test"),)), policy=EnforcePolicy(include_cwd_read=True)
        )
        text_off = build_seatbelt_profile(
            PathJail(paths=(Path("/work/test"),)), policy=EnforcePolicy(include_cwd_read=False)
        )
        cwd_line = f'(allow file-read* (subpath "{Path.cwd()}"))'
        assert cwd_line in text_on
        assert cwd_line not in text_off
        # Exactly one grant difference, so the flag only touches cwd reads.
        assert text_off.count("file-read*") == text_on.count("file-read*") - 1

    def test_network_denied_by_default(self) -> None:
        text = _profile(PathJail(paths=(Path("/work/test"),)), policy=EnforcePolicy(network="deny"))
        assert "network-outbound" not in text
        assert "mach-lookup" not in text

    def test_network_allow_ports(self) -> None:
        text = _profile(
            PathJail(paths=(Path("/work/test"),)),
            policy=EnforcePolicy(network="allow", network_connect_ports=(443,)),
        )
        assert "(allow network-outbound (remote tcp-* :443))" in text
        assert "udp-* :53" in text
        assert "(allow mach-lookup)" in text
        assert "(allow system-socket)" in text

    def test_custom_ports(self) -> None:
        text = _profile(
            PathJail(paths=(Path("/work/test"),)),
            policy=EnforcePolicy(network="allow", network_connect_ports=(8080,)),
        )
        assert "tcp-* :8080" in text
        assert "tcp-* :443" not in text

    def test_paths_with_spaces_are_quoted(self) -> None:
        text = _profile(PathJail(paths=(Path("/Users/jo n/work"),)))
        assert '(allow file-write* (subpath "/Users/jo n/work"))' in text

    def test_tilde_jail_expanded(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("HOME", "/Users/jon")
        text = _profile(PathJail(paths=(Path("~/work"),)))
        assert '(allow file-write* (subpath "/Users/jon/work"))' in text


class TestLauncher:
    def test_unavailable_off_macos(self) -> None:
        if sys.platform == "darwin":
            pytest.skip("host is macOS")
        assert launcher_command(PathJail(paths=(Path("/work/test"),))) is None

    def test_available_argv_and_cached_profile(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        # Simulate macOS availability regardless of the host platform: the
        # module reads sys.platform and the SANDBOX_EXEC path at call time.
        monkeypatch.setattr(sys, "platform", "darwin")
        monkeypatch.setattr(seatbelt_module, "SANDBOX_EXEC", "/bin/true")
        argv_one = launcher_command(PathJail(paths=(tmp_path,)), python_path=None)
        if argv_one is None:  # pragma: no cover - only on broken platforms
            pytest.fail("launcher unexpectedly unavailable")
        assert argv_one[0] == "/bin/true"
        assert argv_one[1] == "-f"
        profile_path = Path(argv_one[2])
        try:
            assert profile_path.exists()
            assert oct(profile_path.stat().st_mode & 0o777) == "0o600"
            argv_again = launcher_command(PathJail(paths=(tmp_path,)), python_path=None)
            assert argv_again == argv_one
        finally:
            import tempfile

            cache_dir = Path(tempfile.gettempdir())
            for stale in cache_dir.glob("tau-seatbelt-*.sb"):
                if argv_one and str(stale) in argv_one:
                    stale.unlink()

    def test_degrade_semantics_pin(self) -> None:
        # seatbelt_available is platform-gated; off-macOS it must be False,
        # pinning the approval-only degrade the design promises.
        expected = str(sys.platform) == "darwin"
        assert seatbelt_available() == expected


class TestBannerFilter:
    def test_exact_banner_removed(self) -> None:
        noisy = "\n".join([*SANDBOX_EXEC_BANNER_LINES, "hello", "world", ""])
        assert strip_sandbox_exec_banner(noisy).strip() == "hello\nworld"

    def test_other_content_untouched(self) -> None:
        output = "WARNING: sandbox-exec is deprecated-ish\nhello\n"
        assert strip_sandbox_exec_banner(output) == output

    def test_noop_without_banner(self) -> None:
        assert strip_sandbox_exec_banner("plain\n") == "plain\n"


@pytest.mark.skipif(
    sys.platform != "darwin" or not seatbelt_available(),
    reason="live sandbox-exec confinement requires macOS",
)
class TestLiveConfinement:
    """In-vivo verification on a Mac: the wall is the kernel's."""

    @staticmethod
    def _argv(tmp_path: Path) -> list[str]:
        argv = launcher_command(PathJail(paths=(tmp_path,)), python_path=sys.executable)
        assert argv is not None
        return argv

    @staticmethod
    def _run(
        argv: list[str], command: str, cwd: Path | None = None
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [*argv, "bash", "-c", command],
            capture_output=True,
            text=True,
            timeout=60,
            cwd=str(cwd or Path.cwd()),
        )

    def test_home_listing_blocked(self, tmp_path: Path) -> None:
        argv = self._argv(tmp_path)
        result = self._run(argv, "ls ~")
        assert result.returncode != 0
        combined = result.stdout + result.stderr
        assert "Operation not permitted" in combined or "Permission denied" in combined

    def test_home_write_blocked(self, tmp_path: Path) -> None:
        argv = self._argv(tmp_path)
        result = self._run(argv, "echo secret > ~/tau-seatbelt-test")
        assert result.returncode != 0

    def test_jail_write_allowed(self, tmp_path: Path) -> None:
        argv = self._argv(tmp_path)
        marker = tmp_path / "ok.txt"
        result = self._run(argv, f"echo in > {marker}")
        assert result.returncode == 0
        assert marker.read_text().startswith("in")

    def test_network_blocked(self, tmp_path: Path) -> None:
        argv = self._argv(tmp_path)
        result = self._run(argv, "curl -sS -m 5 https://example.com -o /dev/null")
        assert result.returncode != 0

    def test_confines_descendants(self, tmp_path: Path) -> None:
        argv = self._argv(tmp_path)
        result = self._run(argv, "sh -c 'sh -c \"ls ~\"'")
        assert result.returncode != 0

    def test_system_python_runs(self, tmp_path: Path) -> None:
        argv = self._argv(tmp_path)
        result = self._run(argv, "python3 -c 'print(\"alive\")'")
        assert result.returncode == 0
        assert "alive" in result.stdout

    def test_banner_absent_from_output(self, tmp_path: Path) -> None:
        argv = self._argv(tmp_path)
        result = self._run(argv, "echo hello")
        stripped = strip_sandbox_exec_banner(result.stdout)
        assert stripped.count("sandbox-exec is deprecated") == 0
        assert "hello" in stripped
