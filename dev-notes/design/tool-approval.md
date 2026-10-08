# Per-call tool approval and the path jail: compatibility research and Tau design

Status: **stages 1-3 implemented** on the `profiles` branch (shared durable
store, policy module, session/CLI/TUI wiring, published docs); the optional
stage 4 items (hardened profile preset, Landlock enforcement reference,
container recipe) remain future work. The implementation follows this note.

This note is the implementation plan for a per-tool-call approval gate layered on
the existing project-trust system. Project trust decides which project *inputs*
may load before a session starts; this design decides what Tau may *do* with the
user's machine once the session is running. It was written after auditing the
current runtime on the `profiles` branch.

## Why this phase

Tau's own docs state the boundary plainly (`data/docs/security.md`): tools run
with the user's permissions. `read`/`write`/`edit` accept absolute paths
anywhere, and `bash` executes arbitrary shell commands. The core harness already
ships the right seam — `before_tool_call` / `after_tool_call` on
`AgentHarnessConfig` (src/tau_agent/harness.py:47), honored per call in
`run_agent_loop` (src/tau_agent/loop.py:308) — but nothing in `tau_coding` wires
them. The approval policy is therefore an application layer that can land
without touching `tau_agent` at all.

Special-attention classes drive the requirements:

- **Device access (smart cards / PIV / CAC).** Commands that reach OpenSC,
  PKCS#11, PC/SC, or a security token can export credentials or sign data as
  the user. These must require fresh interactive approval every run; they are
  never eligible for a persisted allow rule.
- **Web uploads and exfil-capable calls.** Any tool call that moves local data
  toward a destination the model chose (upload flags on curl/wget, POST bodies,
  s3/rclone-style clients, future web tool arguments carrying URLs with bodies)
  gets the same always-ask treatment.
- **Path jail.** File tools default to a configurable set of directories.
  Reads and writes outside the jail seek approval instead of executing
  silently.

## Reuse assessment (build vs borrow)

Audited 2026-10-08. Verdict: the policy layer is new code; three borrowable
components, all optional and none load-bearing for stages 1–3.

- **bashlex** (PyPI; Python port of GNU bash's parser, transliterated, no
  execution, full AST) replaces a hand-rolled `shlex` classifier for bash. It
  sees what `shlex.split` cannot: `$(...)`/backtick command substitutions,
  process substitution `<(...)`, heredocs, `&&`/`||` chains and pipelines as
  separate command words — exactly the places a sensitive program hides from a
  naive split. Usage is parse-only, so a vendored-style pinned dependency with
  a small surface is acceptable. Rule: wrap parsing in try/except and treat a
  parse failure as sensitive (always ask) — fail closed, never fall back to
  the naive split. Re-verify release health at implementation time.
- **py-landlock** (PyPI, MIT; Linux Landlock bindings) is the candidate for a
  later enforcement stage beyond approval: kernel-enforced per-bash-child
  filesystem/network restriction after an allow decision. Integration shape is
  restrict-then-exec (a tiny launcher restricts its own thread and
  `os.execv`s bash, so the child inherits rules without touching Tau's asyncio
  threads; `preexec_fn` is thread-unsafe and must not be used). Linux 5.13+
  only (TCP net rules need ABI 4/6.7+, IPC scoping ABI 6/6.12+); macOS falls
  back to a Seatbelt `shell_command_prefix` recipe, Windows to nothing. Ship
  as an optional extra with `supported()` probing and graceful degradation to
  approval-only — never silently require it.
- **bubblewrap-bin** ships a prebuilt `bwrap` binary for environments where
  namespace-based sandboxing is preferred to Landlock; likely unnecessary if
  Landlock fits, kept as the alternative anchor.

Everything else is build-new: the sensitive-class policy, precedence order,
headless tables, approvals store, and TUI modal have no importable equivalent
— agent products (Claude Code PreToolUse hooks, Codex approval modes) are
prior art, not libraries. Internal reuse does the rest: the durable-store
plumbing factors out of `project_trust.py`, the modal clones
`ProjectTrustScreen`, and `ToolPolicy` composes as-is. Landlock's known gaps
(`/proc/*/fd`, UDP, pre-5.13 kernels) reinforce the non-sandbox sentence:
it narrows the blast radius; it is not isolation.

## Compatibility baseline

Pi was not consulted for a per-call gate at the pinned revision used by
`dev-notes/design/project-trust.md` (2026-08-03, `fa07e7bd`): its project trust
is an input-loading guard and its tool layer relies on human review plus OS
isolation, like Tau today. This design is therefore Tau-original, but reuses
Pi-verified durability patterns already ported for the trust store.

## Related, existing layers (kept, not replaced)

- **Profile `ToolPolicy`** (src/tau_coding/profiles.py:55) filters the toolset
  once per session. That is a coarse switch ("no bash in this profile"); this
  layer is per-call. They compose: policy filtering runs first, the gate runs
  second on every surviving call.
- **Project trust** (src/tau_coding/project_trust.py) gates ambient project
  inputs before loading. A trusted project still gets the approval gate: inputs
  being approved says nothing about subsequent actions.
- **`shell_command_prefix`** (src/tau_coding/shell_config.py) remains a manual
  wrapper hook; the gate is independent of it and composes with it (a prefix
  can wrap every command in a sandbox wrapper if the user has one).

## Non-goals and honest boundary

This gate is an **application-layer choke point, not a sandbox**. bash can read
anything the user can and an unconfined command can exfiltrate without any Tau
tool; a trusted malicious project can bypass this gate the moment it runs a
command. What the gate genuinely buys:

- accidents and common prompt-injection chains (a read of `~/.ssh` followed by
  an upload) become visible decisions instead of silent actions;
- default-deny headless runs get deterministic, auditable behavior;
- sensitive classes (smart card, uploads) get a human in the loop by design.

Real isolation remains OS/container/VM territory, exactly as
`data/docs/security.md` already states for project trust. Nothing in this
design changes that sentence. Do not market this as a sandbox.

## Deployment modes

The gate is the policy, prompt, and audit layer; it composes with whatever
enforcement boundary hosts the session. Two named modes:

- **Workstation mode (default; personal machines).** No CUI processing. The
  gate is the only active layer: prompts, jail, rules, audit rows. Its honest
  limits are the ones stated above.
- **Container mode (FedRAMP/CUI target world).** Tau runs inside a container
  (or VM) and the container boundary is the enforcement layer; the gate keeps
  running inside it as the UX/audit layer and defense-in-depth, but the
  security claim rests on the boundary, not on the gate. What that changes in
  practice:

  - **Egress is enforced by network policy, not by the classifier.** The
    `exfil-capable` still-ask behavior remains useful as an audit signal, but
    denial-by-network-policy (no route, or proxy-allowlisted domains) is the
    enforceable control. Egress control is a stated criterion for this
    deployment, so the reference recipe treats it as a first-class knob.
  - **Sensitive hardware is absent by default.** Smart-card/PC-SC readers are
    unreachable unless explicitly passed through. Absence is a stronger
    control than any classifier rule; the `device` always-ask class still
    applies to the passthrough case.
  - **Jail paths map to mounts.** The jail configuration and the container
    mount list derive from one source (a profile preset) so they cannot
    drift; inside the container the OS enforces what the jail asks about.
  - **Durable state stays deployment-scoped.** `~/.tau` (approvals, trust)
    lives on a volume scoped to that deployment and must not silently share
    the workstation store whose decisions were made under a weaker boundary.
  - **Headless default is deny.** Recommended container preset: allowlist-style
    profile with `jail` on and `writesOutside: "deny"`, `readsOutside: "ask"`,
    no `--approve-tools`.

  A reference container recipe (podman/docker invocations, mount and device
  policy, egress pattern) belongs to the optional later stage and to published
  docs only when it ships — never as a substitute for the deployment's own
  accreditation posture.

## Architecture

```text
tau_coding/tool_approval.py   pure policy: types, classifier, jail, store, resolver
tau_coding/session.py         wires gate.before_tool_call into AgentHarnessConfig
tau_coding/cli.py             run-only overrides + jail flag
tau_coding/tui/app.py         ToolApprovalScreen via existing UI-bridge pattern
tau_agent                     NO changes (seams already exist)
```

The policy module accepts `(tool_name, arguments_dict)` plain values, mirrors
`project_trust.py`'s import discipline (no Textual, no CLI), and contains no
provider assumptions.

## Types

```python
ToolClass = Literal["readonly", "writes", "command", "network", "device", "exfil-capable"]

@dataclass(frozen=True, slots=True)
class ToolRisk:
    classification: ToolClass
    jail_paths: tuple[Path, ...]        # empty = call is not path-bound
    sensitive: bool                     # device / exfil-capable / broad-scope
    reasons: tuple[str, ...]            # bounded, human-facing, content-free

@dataclass(frozen=True, slots=True)
class ApprovalRequest:
    call_id: str
    tool: str
    summary: str                        # redacted, length-capped argument rendering
    risk: ToolRisk
    choices: tuple[ApprovalChoice, ...] # persistent choices omitted when sensitive

ApprovalChoice = Literal[
    "allow-once", "allow-run", "allow-save",   # save = path-scoped rule
    "deny-once", "deny-save",
]

@dataclass(frozen=True, slots=True)
class ApprovalResolution:
    allowed: bool
    source: Literal["in-jail", "rule", "user", "run-only-override", "headless-default", "denied"]
    saved_rule: "SavedApprovalRule | None" = None
```

## Decision pipeline

`before_tool_call(call) -> (bool, reason)` is implemented as one resolver with
this precedence, evaluated per call:

1. **Classification.** Map `(tool, arguments)` to `ToolRisk` using static
   tables and a small `shlex`-based command parser for bash. Classification
   never parses file contents — file names and the command string only.
2. **In-jail allow.** Path-bound tools (`read`, `write`, `edit`) whose paths
   resolve inside the jail are allowed by policy when `sensitive` is false.
   Reads outside the jail: `jail.readsOutside` (`ask` default). Writes outside:
   `jail.writesOutside` (`ask` default).
3. **Sensitive override — check rules AFTER this.** `classification in
   {"device", "exfil-capable"}` or tool `bash` targeting a sensitive program is
   **always ask**, interactive-only, and immune to every persisted and
   session-scoped rule. This ordering rule is what makes "smart card and
   uploads always need fresh approval" enforceable rather than a hope.
4. **Saved rules.** `~/.tau/approvals.json` consulted after the sensitive
   override: exact `(tool, path_prefix)` allow rules for path-bound tools;
   whole-tool allow/deny for others; deny rules win over allow.
5. **Session rules.** Choices like "allow this run for `<tool>`" live in memory
   only and die with the process, and an in-turn dedupe table collapses
   repeated identical calls (same tool + normalized key) so the model cannot
   spam the user with repeated modals — a denied signature stays denied for the
   turn, an allowed signature stays allowed.
6. **Run-only CLI override.** `--approve-tools` makes steps 2–5 moot for the
   invocation (still logged); `--no-approve-tools` denies everything not
   in-jail. Mutually exclusive, never persisted, mirroring
   `--approve`/`--no-approve`.
7. **Headless default.** No UI ⇒ `allow` only for in-jail non-sensitive calls;
   everything else is denied with a reason string the model sees as the tool
   error result, plus one diagnostic. Deterministic table, no prompting ever.

The `before_tool_call` hook may be `await`ed inside the loop, so step 3's
interactive ask resolves by awaiting the UI bridge (TUI) or by the headless
table (all other frontends).

## Path jail mechanics

Stored as user-level settings (never project-level; a project must not define
its own cage), activated either by settings or by `--jail PATH`:

```json
{"jail": {
  "paths": ["~/Projects", "~/.tau"],
  "readsOutside": "ask",
  "writesOutside": "ask"
}}
```

- Default when unset: **jail off** — existing behavior is unchanged, matching
  the repo's minimalist-migration instinct. Sandboxed profiles are the intended
  vehicle ("a CUI profile").
- Containment is resolved-path based: `realpath` both sides
  (`Path.resolve()`), then strict `Path.is_relative_to`. Relative arguments,
  `..` spelling, and empty strings canonicalize before comparison; symlink
  spellings collapse to one target; a nonexistent write target resolves via its
  nearest existing parent.
- Jail applies to path-bound tools at the gate. bash is not path-contained by
  the gate — honesty requirement above — it gets program classification
  instead. (A later phase may add a `shell-jail` wrapper recipe documented
  under `shell_command_prefix`.)

## Classification tables (v1)

- `readonly`: `read` (in-jail only by step 2).
- `writes`: `write`, `edit`.
- `command`: `bash`.
- `device` (always ask, unruleable): bash program or arguments matching —
  `pkcs11-tool`, `pkcs15-tool`, `pkcs15-init`, `opensc-tool`, `opensc-explorer`,
  `piv-tool`, `cardos-tool`, `pkcs11-provider` usage in ssh, `gpg --card-*`,
  `ykman`, `pcscd` control via systemctl/launchctl, `scctrl`-style helpers.
- `exfil-capable` (always ask, unruleable): curl/wget with upload or POST
  flags (`-T`, `--upload-file`, `-F`, `-d`, `--data*`, `-G` to non-standard
  host), `s3`/`aws s3`/`gsutil`/`rclone` transfers, `scp`/`rsync` to remote
  hosts, plus future web-tool calls whose arguments carry a request body.
- `network` (ask, session-rememberable): `git push`, `gh` writes, plain fetches
  of URLs.
- Unknown future tools default to *ask, rememberable*, never to allow.

The lists are data (module-level tuples), unit-tested with vector fixtures, and
explicitly incomplete-by-design; the deny-not-allow default covers the rest.

## Persistence: the approvals store

`~/.tau/approvals.json` copies the ProjectTrustStore contract verbatim:
`version: 1`, strict schema (unknown fields, duplicate canonical paths, and
noncanonical spellings are store errors), flock'd read-modify-write, same-dir
tempfile + fsync + `os.replace`, and a fail-closed undo journal so a torn write
can never resurrect a revoked deny or manufacture an allow. Implement by
factoring the journal/atomic/fsync plumbing out of `project_trust.py` into a
private `_durable_store.py` shared by both stores — behavior-identical for the
trust store, its existing tests prove it.

Rule atoms, deliberately narrow:

```json
{"version": 1, "rules": [
  {"kind": "allow", "tool": "edit", "path_prefix": "/home/jfox/tau",
   "created": "2026-10-08T00:00:00Z"},
  {"kind": "deny", "tool": "bash", "created": "..."}
]}
```

No content-based command rules ("allow bash matching `git`")—they are trivially
bypassable with `git; curl …`. Command-level rules are limited to exact program
names recorded session-only from "allow this run" choices.

## Interactive UX (TUI)

- `ToolApprovalScreen(ModalScreen[ApprovalChoice | None])`, a structural clone
  of `ProjectTrustScreen`: keyboard-first list, escape = deny-once (fail-closed
  cancel semantics, mirrors trust), title states tool + bounded summary, body
  states classification and reason lines.
- The modal opens while the agent is streaming; the existing activity timer and
  busy state already cover this (the loop is awaiting the gate). Escape inside
  the modal denies the one call and returns control; it must not be confused
  with agent-interrupt Escape, which stays bound outside the modal.
- **Decisions land in the transcript as persistent rows** (`[approval] Allowed
  edit /path (in-jail)`, `[approval] Denied bash (headless default)`), rendered
  like `/reload`'s command row — the user reviewing a session later must be
  able to reconstruct what ran. A toast is additionally acceptable; a toast
  alone is not.
- Persistent choices are omitted (with a short reason) for `device` and
  `exfil-capable` requests and for out-of-jail writes when
  `writesOutside: "deny"`.

`/approvals` (future command) lists saved rules and session rules, deletes
persisted rules, and states that changes apply to new calls immediately but
store edits of deny rules follow the same never-resurrect-by-accident rule as
trust edits.

## Integration points (exact)

- `CodingSession.load()` (src/tau_coding/session.py:765) builds the gate from
  config and passes `before_tool_call=gate.dispatch` into `AgentHarnessConfig`;
  the `reload()` staging path rebuilds through the same code — one wiring site
  shared by both, per the two-call-site rule.
- `CodingSessionConfig` gains `tool_approval: ToolApprovalConfig | None` and a
  requester callback; profile loading can supply a preset.
- CLI: `--approve-tools` / `--no-approve-tools` (mutually exclusive), `--jail
  PATH` (repeatable), both documented in `configuration.md` and `cli.md`.
- Frontends other than TUI never see a prompt; the resolver branches on
  `requester is None`.

## Migration and rollout

1. **Pure policy + store.** Types, classifier tables, jail evaluation, durable
   store (with the shared plumbing refactor), full unit tests. No wiring.
2. **Headless determinism + wiring.** Gate wired into load/reload, run-only
   flags, headless table, diagnostics, print-mode FakeProvider tests proving
   blocked calls reach the model as error results and stdout contracts hold.
3. **TUI.** Modal, transcript rows, escape semantics, pilot tests, doc surfaces
   (`security.md` gets an "Approval gate" section whose last sentence repeats
   the non-sandbox boundary; `configuration.md`, `cli.md`, `tui.md`,
   slash-commands reference when `/approvals` lands).
4. **Optional later.** `after_tool_call` result redaction/audit, profile
   presets shipping a `sandboxed` profile, shell-jail wrapper recipe.

No release-notes entry until a runtime stage ships; docs describe only landed
behavior.

## Deterministic test plan

- Tables: every classification fixture, including opensc/pkcs11 vectors, upload
  flag vectors, and near-miss programs that must NOT classify sensitive.
- Jail: relative paths, `..`, empty string, symlinks, nonexistent write
  targets, jail-off default, parent-less root containment.
- Store: torn-write fail-closed mirrors of the trust tests; deny-rule never
  resurrects; malformed store denies rather than allows.
- Precedence: sensitive beats every rule; run-only override beats rules; rule
  beats ask; headless table per frontend; cancel = deny-once.
- Loop integration: FakeProvider streams a call, gate blocks by policy, model
  sees the denied error result and continues; dedupe collapses repeated
  identical denied calls; no prompt attempted in print/JSON/RPC modes.
- TUI pilots: modal renders bounded summary, escape deny, allow-run session
  rule applied to a later identical call, persistent choices absent for device
  vectors, transcript rows persist after dismissal, busy spinner remains live.