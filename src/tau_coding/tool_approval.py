"""Per-call tool approval policy: classification, path jail, rules, resolution.

Layered on the existing project-trust input guard, this module decides what
Tau may *do* once a session runs. It is an application-layer choke point
wired through the agent loop's ``before_tool_call`` seam — deliberately not a
sandbox. bash commands read whatever the user can read and can exfiltrate
without any Tau tool; real isolation requires an OS/container/VM boundary.

Invariants (see ``dev-notes/design/tool-approval.md``):

- Sensitive classes — ``device`` (smart card / PIV / PKCS#11 access) and
  ``exfil-capable`` (upload-shaped transfers) — are always-ask, evaluated
  BEFORE any saved rule, and are never persistable.
- The path jail is user-level policy; resolved paths are compared with
  ``realpath`` semantics so symlinks cannot walk around it.
- Unknown tools ask; nothing is allowed by default outside an active jail.
- Headless sessions never prompt: deterministic allow (in-jail, harmless)
  or deny with a reason the model sees as its tool error.
"""

from __future__ import annotations

import os
import shlex
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from tau_coding._durable_store import DurableJsonStore, DurableStoreError
from tau_coding.paths import TauPaths

ToolClass = Literal[
    "readonly",
    "writes",
    "command",
    "network",
    "device",
    "exfil-capable",
    "unknown",
]

ApprovalChoice = Literal[
    "allow-once",
    "allow-run",
    "allow-save",
    "deny-once",
    "deny-save",
]

ApprovalSource = Literal[
    "in-jail",
    "jail-policy",
    "rule",
    "user",
    "run-only-override",
    "headless-default",
    "denied",
]

RunOverride = Literal["approve", "decline"]

JailOutsidePolicy = Literal["ask", "allow", "deny"]


class ToolApprovalError(DurableStoreError):
    """An approval policy, store, or resolution operation failed safely."""


Requester = Callable[["ApprovalRequest"], Awaitable[ApprovalChoice | None]]
"""Ask a frontend for one decision. Returning None means cancel = deny-once."""


@dataclass(frozen=True, slots=True)
class ToolRisk:
    """Static, content-free risk assessment of one requested tool call."""

    classification: ToolClass
    jail_paths: tuple[Path, ...] = ()
    sensitive: bool = False
    reasons: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ApprovalRequest:
    """Frontend-neutral request for one interactive approval decision."""

    tool: str
    summary: str
    risk: ToolRisk
    choices: tuple[ApprovalChoice, ...]
    call_id: str | None = None


@dataclass(frozen=True, slots=True)
class ApprovalResolution:
    """Completed decision for one tool call."""

    allowed: bool
    source: ApprovalSource
    reason: str


@dataclass(frozen=True, slots=True)
class SavedApprovalRule:
    """One narrow persisted rule; deny rules win over allow rules."""

    kind: Literal["allow", "deny"]
    tool: str
    path_prefix: Path | None = None
    created: str | None = None


# --- classification tables -------------------------------------------------
#
# Deliberately incomplete-by-design: unrecognized programs fall through to
# ask, and the deny-not-allow default covers the rest. Word matching is
# program-name based because content/command rules are trivially bypassable.

_DEVICE_PROGRAMS: frozenset[str] = frozenset(
    {
        "pkcs11-tool",
        "pkcs15-tool",
        "pkcs15-init",
        "opensc-tool",
        "opensc-explorer",
        "piv-tool",
        "cardos-tool",
        "ykman",
        "pcscd",
        "scctrl",
    }
)

# OpenSC/PC-SC wrapper entry points whose *arguments* decide sensitivity.
_DEVICE_FLAG_PROGRAMS: Mapping[str, tuple[str, ...]] = {
    "gpg": ("--card-status", "--card-edit", "--change-pin", "--card-attr"),
    "ssh": ("-I",),
    "ssh-add": ("-s",),
}

_EXFIL_TRANSFER_PROGRAMS: frozenset[str] = frozenset(
    {
        "scp",
        "sftp",
        "rsync",
        "rclone",
        "gsutil",
        "gcloud",
    }
)

# aws is exfil-capable only in its s3/storage transfer shapes.
_EXFIL_AWS_SUBCOMMANDS: tuple[str, ...] = ("s3", "s3api", "s3control")

# curl/wget option shapes that move local data toward a destination.
_EXFIL_UPLOAD_FLAGS: tuple[str, ...] = (
    "-T",
    "--upload-file",
    "-F",
    "--form",
    "--form-string",
    "-d",
    "--data",
    "--data-raw",
    "--data-binary",
    "--data-urlencode",
    "--post-file",
)

_FETCH_PROGRAMS: frozenset[str] = frozenset({"curl", "wget", "http", "https", "ftp"})

_NETWORK_SUBCOMMAND_PROGRAMS: Mapping[str, frozenset[str]] = {
    "git": frozenset({"push", "remote", "fetch", "pull", "clone", "ls-remote"}),
    "gh": frozenset({"pr", "issue", "release", "repo", "gist", "api"}),
}

# Path-taking built-in tools, per argument name.
_PATH_BOUND_ARGUMENTS: Mapping[str, tuple[str, ...]] = {
    "read": ("path",),
    "write": ("path",),
    "edit": ("path",),
}

_MAX_SUMMARY_LENGTH = 160
_MAX_AUDIT_ENTRIES = 1000


def _summary_for(tool: str, arguments: Mapping[str, object]) -> str:
    """Render a bounded, human-facing summary of the call's key arguments."""
    path_keys = _PATH_BOUND_ARGUMENTS.get(tool, ())
    parts: list[str] = [tool]
    for key in ("command", *path_keys):
        value = arguments.get(key)
        if isinstance(value, str) and value:
            text = value if len(value) <= _MAX_SUMMARY_LENGTH else value[:_MAX_SUMMARY_LENGTH] + "…"
            parts.append(f"{key}={text!r}")
    return " ".join(parts)


def _bashlex_available() -> bool:
    try:
        import bashlex  # type: ignore[import-not-found]  # noqa: F401

        return True
    except ImportError:
        return False


_HAS_BASHLEX = _bashlex_available()


def _bash_words_via_bashlex(command: str) -> list[str]:
    import bashlex

    words: list[str] = []

    def walk(node: object) -> None:
        kind = getattr(node, "kind", None)
        if kind == "word":
            words.append(str(getattr(node, "word", "")))
        for part in getattr(node, "parts", ()) or ():
            walk(part)

    for node in bashlex.parse(command):
        walk(node)
    return words


def _bash_words_conservative(command: str) -> list[str]:
    """Tokenize without bashlex; command substitutions fail closed upstream."""
    lexer = shlex.shlex(command, posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    return list(lexer)


def classify_bash_command(command: str) -> ToolRisk:
    """Classify one bash tool command string by the programs it would run."""
    words: list[str]
    if _HAS_BASHLEX:
        try:
            words = _bash_words_via_bashlex(command)
        except Exception:
            return ToolRisk(
                classification="command",
                sensitive=True,
                reasons=("command did not parse; failing closed as sensitive",),
            )
    else:
        if any(marker in command for marker in ("$(", "`", "${", " <(", ">(")):
            return ToolRisk(
                classification="command",
                sensitive=True,
                reasons=(
                    "command substitution or process substitution present; "
                    "unsupported without a bash parser and always-ask",
                ),
            )
        try:
            words = _bash_words_conservative(command)
        except ValueError:
            return ToolRisk(
                classification="command",
                sensitive=True,
                reasons=("command did not tokenize; failing closed as sensitive",),
            )

    reasons: list[str] = []
    classification: ToolClass = "command"
    sensitive = False

    for index, word in enumerate(words):
        lowered = word.lower()
        base = Path(lowered).name
        if base in _DEVICE_PROGRAMS:
            return ToolRisk(
                classification="device",
                sensitive=True,
                reasons=(f"smart-card/PKCS#11 program access: {base}",),
            )
        flag_targets = _DEVICE_FLAG_PROGRAMS.get(base)
        if flag_targets is not None:
            window = words[index + 1 : index + 12]
            if any(flag in window for flag in flag_targets):
                return ToolRisk(
                    classification="device",
                    sensitive=True,
                    reasons=(f"{base} invoked with security-token/device flags",),
                )
        if base in _EXFIL_TRANSFER_PROGRAMS:
            return ToolRisk(
                classification="exfil-capable",
                sensitive=True,
                reasons=(f"remote transfer program: {base}",),
            )
        if base == "aws" and any(
            sub in words[index + 1 : index + 3] for sub in _EXFIL_AWS_SUBCOMMANDS
        ):
            return ToolRisk(
                classification="exfil-capable",
                sensitive=True,
                reasons=("aws storage transfer (s3)",),
            )
        if base in _FETCH_PROGRAMS:
            upload_shaped = any(
                flag in _EXFIL_UPLOAD_FLAGS or flag.startswith("--data")
                for flag in words[index + 1 : index + 25]
            )
            if upload_shaped:
                return ToolRisk(
                    classification="exfil-capable",
                    sensitive=True,
                    reasons=(f"upload-shaped {base} invocation",),
                )
            if classification == "command":
                classification = "network"
                reasons.append(f"{base} fetch to a model-chosen destination")
            continue
        subcommands = _NETWORK_SUBCOMMAND_PROGRAMS.get(base)
        if subcommands is not None and any(
            sub in words[index + 1 : index + 3] for sub in subcommands
        ):
            if classification == "command":
                classification = "network"
            reasons.append(f"{base} network subcommand")

    if reasons and classification == "network":
        return ToolRisk(classification=classification, sensitive=False, reasons=tuple(reasons))
    return ToolRisk(classification=classification, sensitive=sensitive, reasons=tuple(reasons))


def classify_tool_call(tool: str, arguments: Mapping[str, object]) -> ToolRisk:
    """Classify any tool call. Unknown tools classify as ask-rememberable."""
    if tool == "bash":
        command = arguments.get("command")
        if isinstance(command, str):
            return classify_bash_command(command)
        return ToolRisk(
            classification="command",
            sensitive=True,
            reasons=("bash call without a command string; failing closed",),
        )
    path_keys = _PATH_BOUND_ARGUMENTS.get(tool)
    if path_keys is not None:
        paths = tuple(
            Path(str(arguments[key])) for key in path_keys if isinstance(arguments.get(key), str)
        )
        default_class: ToolClass = "writes" if tool in {"write", "edit"} else "readonly"
        return ToolRisk(classification=default_class, jail_paths=paths)
    return ToolRisk(classification="unknown")


# --- path jail -------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class PathJail:
    """User-level path containment for the path-bound built-in tools."""

    paths: tuple[Path, ...] = ()
    reads_outside: JailOutsidePolicy = "ask"
    writes_outside: JailOutsidePolicy = "ask"

    @property
    def active(self) -> bool:
        return bool(self.paths)

    def contains(self, target: Path) -> bool:
        """True when ``target`` (resolved) is inside the jail."""
        if not self.active:
            return True
        resolved = target.resolve()
        for root in self.paths:
            try:
                if resolved == root.resolve() or resolved.is_relative_to(root.resolve()):
                    return True
            except OSError:
                continue
        return False

    def resolve_target(self, raw: str | Path, *, base: Path | None = None) -> Path:
        """Canonicalize one jail candidate; nonexistent write targets use parents.

        Relative arguments resolve against ``base`` (the session cwd, injected
        by the wiring layer) or the process cwd when unset.
        """
        path = Path(raw).expanduser()
        if not path.is_absolute():
            path = (base or Path.cwd()) / path
        return path.resolve()

    def outside_policy(self, classification: ToolClass) -> JailOutsidePolicy:
        if classification == "readonly":
            return self.reads_outside
        return self.writes_outside


# --- approvals store -------------------------------------------------------


def _parse_approval_payload(payload: object, store_path: Path) -> tuple[SavedApprovalRule, ...]:
    if not isinstance(payload, dict) or set(payload) != {"version", "rules"}:
        raise ToolApprovalError(f"Malformed approvals store {store_path}: unknown schema")
    if payload["version"] != 1 or not isinstance(payload["rules"], list):
        raise ToolApprovalError(f"Unsupported or malformed approvals store {store_path}")
    rules: list[SavedApprovalRule] = []
    seen: set[tuple[str, str, str]] = set()
    for raw in payload["rules"]:
        if not isinstance(raw, dict):
            raise ToolApprovalError(f"Malformed rule in approvals store {store_path}")
        allowed_keys = {"kind", "tool", "path_prefix", "created"}
        if set(raw) - allowed_keys or not {"kind", "tool"} <= set(raw):
            raise ToolApprovalError(f"Malformed rule in approvals store {store_path}")
        kind = raw["kind"]
        tool = raw["tool"]
        if kind not in {"allow", "deny"} or not isinstance(tool, str) or not tool:
            raise ToolApprovalError(f"Malformed rule in approvals store {store_path}")
        path_prefix: Path | None = None
        if "path_prefix" in raw and raw["path_prefix"] is not None:
            value = raw["path_prefix"]
            if not isinstance(value, str):
                raise ToolApprovalError(f"Malformed rule in approvals store {store_path}")
            candidate = Path(value)
            if not candidate.is_absolute() or Path(os.path.normpath(value)) != candidate:
                raise ToolApprovalError(f"Noncanonical path in approvals store {store_path}")
            path_prefix = candidate
        created = raw.get("created")
        if created is not None and not isinstance(created, str):
            raise ToolApprovalError(f"Malformed rule in approvals store {store_path}")
        key = (str(kind), tool, str(path_prefix))
        if key in seen:
            raise ToolApprovalError(f"Duplicate rule in approvals store {store_path}")
        seen.add(key)
        rules.append(
            SavedApprovalRule(
                kind=kind,
                tool=tool,
                path_prefix=path_prefix,
                created=created if isinstance(created, str) else None,
            )
        )
    return tuple(rules)


def _serialize_approval_rules(rules: Sequence[SavedApprovalRule]) -> Mapping[str, object]:
    return {
        "version": 1,
        "rules": [
            entry
            for entry in (
                {
                    "kind": rule.kind,
                    "tool": rule.tool,
                    **({"path_prefix": str(rule.path_prefix)} if rule.path_prefix else {}),
                    **({"created": rule.created} if rule.created else {}),
                }
                for rule in sorted(
                    rules, key=lambda item: (item.tool, str(item.path_prefix), item.kind)
                )
            )
        ],
    }


class ApprovalStore:
    """Versioned, locked, atomically replaced store of narrow approval rules."""

    def __init__(self, paths: TauPaths | None = None) -> None:
        self.paths = paths or TauPaths()
        self.path = self.paths.home / "approvals.json"
        self._store: DurableJsonStore[tuple[SavedApprovalRule, ...]] = DurableJsonStore(
            self.path,
            parse=lambda payload: _parse_approval_payload(payload, self.path),
            serialize=_serialize_approval_rules,
            empty_factory=tuple,
            error_factory=ToolApprovalError,
            label="approvals store",
        )

    @property
    def pending_path(self) -> Path:
        return self._store.pending_path

    def read(self) -> tuple[SavedApprovalRule, ...]:
        return self._store.read()

    def add(self, rule: SavedApprovalRule) -> None:
        def mutate(
            rules: tuple[SavedApprovalRule, ...],
        ) -> tuple[SavedApprovalRule, ...] | None:
            key = (rule.kind, rule.tool, str(rule.path_prefix))
            if any(
                (existing.kind, existing.tool, str(existing.path_prefix)) == key
                for existing in rules
            ):
                return None
            return (*rules, rule)

        self._store.update(mutate)

    def remove(self, rule: SavedApprovalRule) -> None:
        def mutate(rules: tuple[SavedApprovalRule, ...]) -> tuple[SavedApprovalRule, ...]:
            key = (rule.kind, rule.tool, str(rule.path_prefix))
            return tuple(
                existing
                for existing in rules
                if (existing.kind, existing.tool, str(existing.path_prefix)) != key
            )

        self._store.update(mutate)


# --- resolver --------------------------------------------------------------


@dataclass(slots=True)
class ToolApprovalConfig:
    """Everything the resolver needs besides runtime state.

    Carry one instance across session replacement/reload: the cached
    ``resolver`` (session rules + audit trail) then survives, mirroring the
    project-trust coordinator's per-process continuity.
    """

    jail: PathJail | None = None
    store: ApprovalStore | None = None
    requester: Requester | None = None
    run_override: RunOverride | None = None
    resolver: ApprovalDecisionResolver | None = None

    def resolver_for_session(self) -> ApprovalDecisionResolver:
        if self.resolver is None:
            self.resolver = ApprovalDecisionResolver(self)
        return self.resolver


class ApprovalDecisionResolver:
    """Decide every tool call; wired as the agent loop's ``before_tool_call``.

    Precedence: run-only override, sensitive always-ask (before any rule),
    jail evaluation, stored rules (deny wins), session rules, then the
    interactive requester — or the deterministic headless table when no UI
    exists. Repeated identical calls within one session reuse the earlier
    decision, so a model cannot spam the user with duplicate modals.
    """

    def __init__(self, config: ToolApprovalConfig, *, store: ApprovalStore | None = None) -> None:
        self._config = config
        self._store = store or config.store or ApprovalStore()
        self._session_allow: set[str] = set()
        self._session_deny: set[str] = set()
        self._seen: dict[str, ApprovalResolution] = {}
        self.audit: list[str] = []

    async def dispatch(self, call: object) -> tuple[bool, str | None]:
        """Return ``(blocked, block_reason)`` for one agent-loop tool call."""
        tool = str(getattr(call, "name", ""))
        arguments = getattr(call, "arguments", {}) or {}
        resolution = await self._decide(tool, arguments)
        self._record(tool, resolution)
        if resolution.allowed:
            return False, None
        return True, f"Denied by approval gate: {resolution.reason}"

    async def _decide(self, tool: str, arguments: Mapping[str, object]) -> ApprovalResolution:
        risk = classify_tool_call(tool, arguments)
        signature = self._signature(tool, arguments)

        cached = self._seen.get(signature)
        if cached is not None:
            return cached

        resolution = await self._resolve(tool, arguments, risk)
        self._seen[signature] = resolution
        return resolution

    async def _resolve(
        self, tool: str, arguments: Mapping[str, object], risk: ToolRisk
    ) -> ApprovalResolution:
        override = self._config.run_override
        if override == "approve":
            return self._audit_resolution(
                True,
                "run-only-override",
                f"allowed {tool} by run-only --approve-tools",
            )
        if override == "decline" and not (
            risk.classification in {"readonly"} and self._in_jail(risk)
        ):
            return self._audit_resolution(
                False, "denied", f"{tool} denied by run-only --no-approve-tools"
            )

        if risk.sensitive:
            return await self._ask(
                tool,
                arguments,
                risk,
                choices=("allow-once", "deny-once"),
                headless_reason="sensitive tool call requires interactive approval",
            )

        jail = self._config.jail
        if jail is not None and jail.active and risk.jail_paths:
            inside = all(jail.contains(jail.resolve_target(path)) for path in risk.jail_paths)
            if not inside:
                policy = jail.outside_policy(risk.classification)
                if policy == "deny":
                    return self._audit_resolution(
                        False, "denied", f"{tool} targets paths outside the jail"
                    )
                if policy == "ask":
                    return await self._ask(
                        tool,
                        arguments,
                        risk,
                        choices=self._choices_for(tool, risk),
                        headless_reason="path outside the jail requires interactive approval",
                    )
                return self._audit_resolution(
                    True,
                    "jail-policy",
                    f"{tool} outside the jail allowed by jail policy",
                )
            return self._audit_resolution(True, "in-jail", f"{tool} stays inside the jail")

        ruled = self._by_rules(tool, risk)
        if ruled is not None:
            return ruled

        if tool in self._session_deny:
            return self._audit_resolution(False, "denied", f"{tool} denied for this session")
        if tool in self._session_allow:
            return self._audit_resolution(True, "user", f"{tool} allowed for this session")

        return await self._ask(
            tool,
            arguments,
            risk,
            choices=self._choices_for(tool, risk),
            headless_reason="unrecognized call requires interactive approval",
        )

    def _in_jail(self, risk: ToolRisk) -> bool:
        jail = self._config.jail
        if jail is None or not jail.active or not risk.jail_paths:
            return False
        return all(jail.contains(jail.resolve_target(path)) for path in risk.jail_paths)

    def _by_rules(self, tool: str, risk: ToolRisk) -> ApprovalResolution | None:
        try:
            rules = self._store.read()
        except ToolApprovalError as exc:
            return self._audit_resolution(
                False, "denied", f"approvals store unreadable (fail closed): {exc}"
            )
        resolved_risk_paths = [
            self._config.jail.resolve_target(path) if self._config.jail else Path(path).resolve()
            for path in risk.jail_paths
        ]
        for rule in rules:
            matches = rule.tool == tool
            if matches and rule.path_prefix is not None:
                matches = any(
                    path == rule.path_prefix or path.is_relative_to(rule.path_prefix)
                    for path in resolved_risk_paths
                )
            if not matches:
                continue
            if rule.kind == "deny":
                return self._audit_resolution(False, "denied", f"{tool} denied by saved rule")
            return self._audit_resolution(True, "rule", f"{tool} allowed by saved rule")
        return None

    def _choices_for(self, tool: str, risk: ToolRisk) -> tuple[ApprovalChoice, ...]:
        persistable = risk.classification not in ("device", "exfil-capable")
        if not persistable:
            return ("allow-once", "deny-once")
        choices: list[ApprovalChoice] = ["allow-once", "deny-once"]
        if risk.jail_paths:
            choices = ["allow-once", "allow-save", "deny-once", "deny-save"]
        else:
            choices = ["allow-once", "allow-run", "deny-once"]
        return tuple(choices)

    async def _ask(
        self,
        tool: str,
        arguments: Mapping[str, object],
        risk: ToolRisk,
        *,
        choices: tuple[ApprovalChoice, ...],
        headless_reason: str,
    ) -> ApprovalResolution:
        requester = self._config.requester
        if requester is None:
            return self._audit_resolution(False, "headless-default", f"{tool}: {headless_reason}")
        request = ApprovalRequest(
            tool=tool,
            summary=_summary_for(tool, arguments),
            risk=risk,
            choices=choices,
        )
        try:
            choice = await requester(request)
        except Exception as exc:  # noqa: BLE001 - requester failure denies safely
            return self._audit_resolution(
                False, "denied", f"{tool} approval request failed: {type(exc).__name__}"
            )
        if choice is None or choice == "deny-once":
            return self._audit_resolution(False, "denied", f"{tool} denied for this call")
        if choice == "allow-once":
            return self._audit_resolution(True, "user", f"{tool} allowed for this call")
        if choice == "allow-run":
            self._session_allow.add(tool)
            self._session_deny.discard(tool)
            return self._audit_resolution(True, "user", f"{tool} allowed for this session")
        if choice == "allow-save":
            rule = SavedApprovalRule(kind="allow", tool=tool, path_prefix=self._rule_path(risk))
            self._persist_rule(rule)
            return self._audit_resolution(True, "rule", f"{tool} allowed by new saved rule")
        if choice == "deny-save":
            rule = SavedApprovalRule(kind="deny", tool=tool, path_prefix=self._rule_path(risk))
            self._persist_rule(rule)
            return self._audit_resolution(False, "denied", f"{tool} denied by new saved rule")
        return self._audit_resolution(False, "denied", f"{tool} denied (unknown choice)")

    def _rule_path(self, risk: ToolRisk) -> Path | None:
        if not risk.jail_paths:
            return None
        path = risk.jail_paths[0]
        return self._config.jail.resolve_target(path) if self._config.jail else Path(path).resolve()

    def _persist_rule(self, rule: SavedApprovalRule) -> None:
        try:
            self._store.add(rule)
        except ToolApprovalError:
            # Fail closed: a rule that could not be written must not grant.
            # The deny direction also keeps its decision; only persistence failed.
            self._session_deny.add(rule.tool)

    def _signature(self, tool: str, arguments: Mapping[str, object]) -> str:
        path_keys = _PATH_BOUND_ARGUMENTS.get(tool)
        keys = ("command", *(path_keys or ()))
        values = tuple(str(arguments.get(key, "")) for key in keys if key in arguments)
        return tool + "|" + "\x1f".join(values)

    def _audit_resolution(
        self, allowed: bool, source: ApprovalSource, reason: str
    ) -> ApprovalResolution:
        return ApprovalResolution(allowed=allowed, source=source, reason=reason)

    def _record(self, tool: str, resolution: ApprovalResolution) -> None:
        self.audit.append(
            f"[approval] {'Allowed' if resolution.allowed else 'Denied'} "
            f"{tool} ({resolution.source}): {resolution.reason}"
        )
        if len(self.audit) > _MAX_AUDIT_ENTRIES:
            del self.audit[: len(self.audit) - _MAX_AUDIT_ENTRIES]

    def reset_session_rules(self) -> None:
        """Forget session-scoped allowances and denials (not stored rules)."""
        self._session_allow.clear()
        self._session_deny.clear()
