# Profiles (named agent configurations)

Date: 2026-09-13
Status: Design — Phase P1 (foundations) targets this branch

## What a profile is

A **profile** is a named bundle of agent-configuration values that can be
selected at startup (`--profile NAME`) and switched in-session (`/profile`).
Conceptually it is a saved answer to "what agent am I running right now":

```text
~/.tau/profiles/<name>/
├── profile.json        # profile manifest (see below)
├── SYSTEM.md           # optional profile system-prompt override
├── APPEND_SYSTEM.md    # optional profile append-prompt
├── AGENTS.md           # optional profile-level instructions
├── skills/             # profile-only skills
├── prompts/            # profile-only prompt templates
└── lessons/            # profile-scoped learned memory (P2)
```

`profile.json` (initial fields):

```json
{
  "version": 1,
  "name": "work",
  "provider": "openai",
  "model": "gpt-5.4",
  "thinking_level": "high",
  "tools": {"allow": ["read", "edit", "bash", "write"]},
  "auto_compact_enabled": true
}
```

The default profile (no `--profile` flag) behaves exactly as today and owns
no profile directory — `profiles/` being empty or absent is the normal
state, and every profile path below resolves to the existing defaults when
no profile is active.

## Why it maps onto AgentHarness

`AgentHarnessConfig` is already profile-shaped:

```python
provider, model, system, tools, max_turns, queue_mode, hooks
```

A profile is a *construction-time recipe* for those values plus the resource
directories that feed prompt assembly. The harness itself never mutates its
config; Tau's existing reload machinery (staged replacement snapshot) is the
mechanism for switching — so `/profile NAME` reuses the `/reload` pattern:
stage a new `CodingSession` built from the profile's paths/values, publish
atomically, refuse while an agent turn is active.

## Layer mapping

| Profile value | Harness/session config | Assembled by |
|---|---|---|
| `provider`, `model` | `AgentHarnessConfig.provider/.model` | provider selection (exists) |
| system override / append | `system` / append sections | `build_system_prompt` + provenance (exists) |
| `tools.allow` / `tools.deny` | `AgentHarnessConfig.tools` | filter after `compose_tools` (new, small) |
| skills / prompts / append dirs | prompt + `/skills`, `/prompts` | `TauResourcePaths` with profile root (new) |
| learned memory scope | `learned_context` | learning loop (P2: per-profile stores) |
| `max_turns`, `auto_compact` | harness / session config | exists |

## How it maps to Pi's design

- `tau_agent` stays profile-free: a profile is *tau_coding* configuration
  that produces an `AgentHarnessConfig`. The reusable brain never learns
  the word "profile".
- `CodingSessionConfig` gains `profile_name: str | None` and carries the
  resolved resource paths; nothing else in the harness changes.
- Delegation (P3) is N harnesses: a subagent spawns
  `AgentHarness(AgentHarnessConfig(...from delegatee profile...))` — the
  architecture already supports multiple harness instances; the TUI
  renders one today, and the `skills_enabled=False` subagent seam is the
  precursor.

## Phasing

- **P1 — Foundations (this branch)**
  - `ProfileStore` (`tau_coding/profiles.py`): list/create/read/validate
    profiles under `~/.tau/profiles/`; strict JSON schema validation
  - `TauResourcePaths` gains an optional `profile_root` — when set, the
    profile dir's `SYSTEM.md`, `APPEND_SYSTEM.md`, `AGENTS.md`, `skills/`,
    `prompts/` take precedence over the user-level defaults (profile
    overrides global, project overrides profile)
  - `--profile NAME` CLI flag wiring the resource paths + `profile.json`
    provider/model/thinking defaults into startup
  - `/profile` command: no args lists profiles with the active marker;
    `NAME` switches via the staged-replacement reload path
  - `--tools-allow` / `--tools-deny` filters applied in `compose_tools`
- **P2 — Per-profile learning + settings**
  - learned memory under the profile dir; global store consulted
    read-only underneath (frozen snapshot composes both)
  - profile-scoped provider settings, tui themes
- **P3 — Delegation**
  - `/delegate @<profile> <prompt>`: spawns a second harness with the
    delegatee profile; transcript rendered as a nested block; tool
    permission checks enforced per profile
  - extension API: `session.delegate(profile=..., prompt=...)`

## Invariants

- No profile configured → bit-for-bit the current behavior (all paths
  resolve to today's defaults; `profile.json` optional per profile).
- The active profile name is visible in the sidebar and `/session`.
- Profile switching is atomic and idle-guarded, like reload.
- A profile never mutates the global `~/.tau` stores (P2 scoping aside).

## Testing strategy

- `ProfileStore` round-trip, validation, precedence (unit)
- resource-path override composition (profile > global, project > profile)
- tool allow/deny filtering through `compose_tools`
- prompt assembly: profile SYSTEM.md appears in the provenance map
- `/profile` switching reuses the reload test matrix
- `--profile` end-to-end with `FakeProvider`