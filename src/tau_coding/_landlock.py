"""Kernel-enforced confinement for bash children via Linux Landlock.

This module is the *enforcement* half of the approval-gate design. The gate
(policy) asks and records decisions; when the profile/config opts into
enforcement, every bash child runs inside a Landlock ruleset so the kernel —
not policy — blocks filesystem and network access outside the granted set.
``py-landlock`` is imported lazily; without it (or on unsupported kernels)
enforcement degrades to approval-only with a one-time diagnostic, never a
hard failure.

Shape verified against kernel ABI 7 (6.19): a ruleset carrying ONLY
``allow_execute(system paths) + allow_read(system paths) +
allow_read_write(jail, tmp)`` blocks ``ls $HOME`` and network connects in
spawned shells while exec and jail writes keep working. Grants
double as traversal rights on Linux Landlock, so no separate Refer rule is
needed. Rules apply to the applying thread and everything it spawns; they
cannot be relaxed afterwards, so the process-wide launcher runs a tiny
child: apply, then ``os.execv`` the user's shell.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path

from tau_coding.tool_approval import JailOutsidePolicy, PathJail

# /dev is granted read+write so shell idioms (`> /dev/null`, process
# substitution fifos, /dev/urandom) keep working inside the ruleset.
_SYSTEM_DEV = "/dev"


def landlock_available() -> bool:
    """True when py-landlock imports and the running kernel supports it."""
    try:
        from py_landlock import get_abi_version
    except ImportError:
        return False
    try:
        get_abi_version()
    except Exception:
        # LandlockNotAvailableError / LandlockDisabledError: unusable here.
        return False
    return True


class LandlockUnavailable(RuntimeError):
    """Landlock could not be used; the caller should degrade or refuse."""


@dataclass(frozen=True, slots=True)
class EnforcePolicy:
    """What the launcher may grant: jail + system read/exec + optional net."""

    include_cwd_read: bool = True
    network: JailOutsidePolicy = "deny"
    network_connect_ports: tuple[int, ...] = (443,)


def launcher_command(
    jail: PathJail,
    *,
    policy: EnforcePolicy | None = None,
    python_path: str | None = None,
) -> list[str] | None:
    """Return the argv prefix that confines a bash child, or None.

    ``None`` means enforcement unavailable in this environment; callers
    degrade to approval-only. Callers append their child argv
    (``bash -c <command>``); the spawned interpreter applies the ruleset in
    the spec (embedded JSON) then execs the child — an exec-bridge, so the
    confinement is in force before any user code runs.
    """
    import json as _json

    if not landlock_available():
        return None
    effective = policy or EnforcePolicy()
    spec: dict[str, object] = {
        "jail": jail.to_json(),
        "network": effective.network,
        "ports": list(effective.network_connect_ports),
        "include_cwd_read": effective.include_cwd_read,
    }
    python = python_path or sys.executable
    argv = [python, "-m", "tau_coding._landlock", _json.dumps(spec)]
    # The child python may be a bare interpreter without tau_coding importable;
    # point its PYTHONPATH at this module's package root so "-m" resolves.
    module_root = str(Path(__file__).resolve().parent.parent)
    existing = os.environ.get("PYTHONPATH", "")
    if module_root not in existing.split(os.pathsep):
        pythonpath = f"{module_root}{os.pathsep}{existing}" if existing else module_root
        argv = ["/usr/bin/env", f"PYTHONPATH={pythonpath}", *argv]
    return argv


def _apply_ruleset(spec_json: str) -> None:
    import json

    from py_landlock import Landlock, get_abi_version

    spec = json.loads(spec_json)
    jail = PathJail.from_json(spec["jail"])
    abi = get_abi_version()
    ll = Landlock()
    ll.allow_execute("/usr", "/bin")
    # /etc read: resolver config (resolv.conf, nsswitch), CA bundle paths.
    # Secrets typically live in $HOME, not /etc; /etc is system config.
    ll.allow_read("/usr", "/etc", _SYSTEM_DEV, "/proc")
    ll.allow_read_write(_SYSTEM_DEV, "/tmp")
    if spec.get("include_cwd_read"):
        cwd = Path.cwd()
        ll.allow_read(str(cwd))
    for path in jail.paths:
        resolved = path.expanduser()
        ll.allow_read_write(str(resolved), str(resolved))
    # Network: "deny" grants nothing (all TCP connect becomes EPERM on ABI>=4).
    # "ask"/"allow" open the ruleset; the ask-flow was already decided by the
    # gate before this launcher ran.
    if str(spec.get("network", "deny")) in ("allow", "ask") and abi >= 4:
        ll.allow_all_network()
    ll.apply()


def _maybe_reexec(spec_json: str, child_argv: list[str]) -> None:
    """Apply the ruleset then exec the caller's argv (never returns)."""
    if not child_argv:
        print("no child command after the launcher spec", file=sys.stderr)
        raise SystemExit(2)
    _apply_ruleset(spec_json)
    os.execvp(child_argv[0], child_argv)


if __name__ == "__main__":
    import sys

    # Usage: python -m tau_coding._landlock SPEC_JSON CHILD [ARGS...]
    # Applies the ruleset, then execs CHILD — a standard exec-bridge.
    if len(sys.argv) < 3:
        print(
            "usage: python -m tau_coding._landlock SPEC_JSON CHILD [ARGS...] (internal)",
            file=sys.stderr,
        )
        raise SystemExit(2)
    _maybe_reexec(sys.argv[1], sys.argv[2:])
