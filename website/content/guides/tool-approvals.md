---
title: "Tool approvals and the path jail"
weight: 60
---

Tau can ask before individual tool calls run. This page walks you through
turning that on, living with it for a day, and hardening it into a preset you
can reuse — the reference details follow at the end.

## 1. Turn the gate on

The gate is off by default; a normal `tau` session behaves exactly as before.
Turn it on for one session by giving the file tools a jail:

```bash
cd my-project
tau --jail .
```

`--jail` is repeatable, so a session that legitimately touches two trees can
carry both:

```bash
tau --jail ~/Projects/my-project --jail ~/Projects/shared-lib
```

While the gate is active, `read`, `write`, and `edit` are confined to those
directories: inside them they run without asking, outside them Tau asks
before acting (see [Jail behavior](#jail-behavior) for changing that).

## 2. Watch it ask

Ask for something that reaches outside the jail:

```text
show me what's in ~/.config
```

A modal appears instead of the call running:

```text
Tool call requires approval
Tool      bash
Assessment shell command
Call      command='ls ~/.config/toml'

 This gate asks before acting; it is not a sandbox.

  Allow this call          ← ↑/↓ choose
  Allow this tool for this run
  Deny this call
```

Pick with **↑/↓** and **Enter**. **Esc** denies the one call — canceling
never allows anything.

## 3. Understand the two speeds

Most calls ask and can be remembered. Two classes *always* ask, in every
session, and can never be saved as rules:

- **Smart-card / security-token access** — `pkcs11-tool`, `opensc-tool`,
  `piv-tool`, `ykman`, `gpg --card-status`, `ssh -I` with a PKCS#11 provider.
  Anything that can sign or export as you gets a human every time.
- **Upload-shaped transfers** — `curl -T/-F/-d`, `wget --post-file`, `scp`,
  `rsync` to a remote, `rclone`, `aws s3`. Any call that moves your local
  data toward a destination the model chose always asks.

Plain fetches (`curl https://…` with no upload) and pushes (`git push`) are
the ordinary ask-and-optionally-remember kind.

{{% tip title="Why sensitive calls have no \"save\" option" %}}
A saved rule is permanent permission. These call classes sign, export, or
upload — the three things a prompt-injection chain most wants to do — so a
stale allow-all rule must never be able to cover them.
{{% /tip %}}

## 4. Save a rule (and un-save it)

When a path-bound call asks, the choices include persistence:

```text
  Allow this call
  Allow and save rule for this path
  Deny this call
  Deny and save rule for this path
```

"Allow and save" records one narrow rule — this tool on this path prefix,
nothing more — to `~/.tau/approvals.json`. After permitting edits under
`~/Projects/my-project` once, later edits there run silently; edits elsewhere
still ask.

See and prune your rules any time:

```text
/approvals
/approvals remove 2
```

`/approvals` lists saved rules and any run-scoped decisions this session has
already made. If the gate is off it says so instead of failing silently.

## 5. Run one-shot commands safely

Print, JSON, transcript, and RPC modes never prompt — there is no UI to ask
in. With the gate active they use a deterministic rule: harmless in-jail
calls run, everything else is denied, and the model receives the denial
reason as its tool error so it can adjust.

Two overrides exist for scripts:

```bash
tau -p --approve-tools "…"   # allow every call this run (still audited)
tau -p --no-approve-tools "…" # deny everything outside the jail this run
```

Neither writes the approvals store — they are one-invocation decisions.
`--approve-tools` and `--no-approve-tools` are mutually exclusive.

## 6. Make it your daily driver: the preset profile

Repeating `--jail` every session gets old. Put it in a profile instead and
switch with `/profile`:

```bash
mkdir -p ~/.tau/profiles/cui
```

`~/.tau/profiles/cui/profile.json`:

```json
{
  "version": 1,
  "name": "cui",
  "tools": { "deny": ["bash"] },
  "toolApproval": {
    "jail": {
      "paths": ["~/work/cui-root"],
      "readsOutside": "ask",
      "writesOutside": "deny"
    }
  }
}
```

Then inside Tau:

```text
/profile cui
```

That profile asks before reads outside `~/work/cui-root`, denies all writes
outside it, and removes `bash` entirely — a reasonable shape for CUI work on
a workstation. Explicit CLI flags win over the preset
per-field: `tau --profile cui --jail ~/other-tree` re-points the jail for
that run, and switching profiles mid-session applies the new profile's jail
to the live gate while keeping your run-only overrides.

{{% tip title="Container mode" %}}
For accredited or CUI environments, run Tau inside a container whose mounts
mirror the jail's paths and whose network policy does the egress control.
The gate is the asking/audit layer inside that boundary; the boundary is what
enforces. Keep the container's `TAU_HOME` separate from your workstation's so
decisions made under different rules never share one store.
{{% /tip %}}

## What you will see in the transcript

Every decision lands as a persistent transcript row (search them later, as
with `/reload` output):

```text
/approvals
 Decision: allow-once
 Tool: bash
 Assessment: device — sensitive
 Call: command='pkcs11-tool --list-slots'
```

Denied calls also surface in the tool result the model sees, so the model can
tell you it was blocked rather than appearing to lose your request.

## Reference

### What always asks

- Smart-card and security-token access: `pkcs11-tool`, `opensc-tool`,
  `opensc-explorer`, `piv-tool`, `cardos-tool`, `ykman`, `pcscd`, `gpg` card
  subcommands; `ssh`/`ssh-add` with a PKCS#11 provider.
- Upload-shaped transfers: `curl -T/--upload-file`, `curl -F/--form`,
  `curl -d/--data*`, `wget --post-file`, `scp`, `sftp`, `rsync` to a remote,
  `rclone`, `gsutil`, and `aws s3` transfers.

Each run requires fresh approval. A rule saved earlier never covers these.
Unknown tools also ask; nothing is allowed by default outside an active jail.

### Jail behavior

`readsOutside` and `writesOutside` each accept `ask` (default), `allow`, or
`deny` — set per jail in a profile preset. Paths are compared after symlink
resolution, so shortcuts and aliases do not escape; a not-yet-existing write
target is judged by its nearest existing parent. A project can never define
its own jail — the preset comes from your profile, and a project's files are
exactly what the jail is against.

### Rules

Rules are narrow by design: a tool name plus, for path-bound tools, a path
prefix. Deny rules win over allow rules. There are no content-matching
command rules — `curl https://x` may be ruleable, but "allow curl with these
arguments" is not, because commands can be chained past any matcher. The
store is locked, atomically replaced, and fails closed: a torn or malformed
store denies rather than allows, and says why in `/approvals`.

### Headless behavior

Print, JSON, transcript, and RPC modes never prompt. Harmless in-jail calls
run; everything else is denied and the denial reason is delivered to the
model as the tool error. The run-only overrides above never write the
approvals store.

### Boundary

The gate is an application-layer choke point, not a sandbox. bash commands
read whatever you can read and can reach the network directly; a trusted
malicious project can bypass the gate once a command runs. Real isolation
requires an OS sandbox, container, or VM — for accredited or CUI work, run
Tau inside such a boundary and treat the gate as the asking, audit, and
defense-in-depth layer inside it.