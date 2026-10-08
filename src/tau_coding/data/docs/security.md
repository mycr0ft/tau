# Project trust and security

Tau resolves trust for the canonical destination cwd before reading ambient
project Markdown/JSON or importing project extensions. Protected inputs include
project skills, prompts, themes, system-prompt files, `AGENTS.md` context,
extension candidates, and reserved project settings.

Interactive users can save exact or displayed-parent decisions or choose a
run-only result. Headless `ask`/`never` decisions decline project inputs;
`--approve` and `--no-approve` are run-only overrides. Cancelling an interactive
trust decision exits startup or preserves the current session during reload and
replacement. Trust is committed only after the staged session is adopted.

## Built-in local-backend boundary

The bundled llama.cpp backend is trusted Tau package code. It loads before the
project-trust decision, remains available with `--no-extensions`, and never
creates a project trust prompt. Its provider/backend definitions are owned by
the active extension-runtime generation. Endpoint settings and allowlisted model
snapshots are user-level integration state, not project inputs; they live under
`~/.tau/state/extensions/llama.cpp.json`.

After the user confirms a backend, `/local` probes only the endpoint they
entered, saved, supplied through `LLAMA_BASE_URL`, or accepted as the default. It
does not scan processes, ports, or the local network. Tau does not install,
start, or stop llama.cpp and never writes or deletes model files. On a compatible
router, an explicit confirmed action can ask the independent llama.cpp server to
download a selected model.

## Credentials and safe state

API keys are collected through secret fields. A stored key is kept in Tau's
private credential store and referenced by an opaque integration-owned name.
`LLAMA_API_KEY` is an environment fallback. If neither is present, Tau omits
`Authorization`; it never synthesizes a fake local key. Stored credentials win
over the environment value.

The llama.cpp state file contains only the normalized endpoint, exact
server-reported model IDs, allowlisted display/context/modality metadata, the
selected reference, and a timestamp. It does not contain keys, arbitrary
headers, server PIDs, project-local overrides, or raw server payloads. Secrets
are excluded from provider representations, diagnostics, sessions, and exports.
State and credential writes are separate transactions: a failed state commit
leaves the prior configuration active and an unreferenced credential is cleaned
up or reported for recovery; old-credential cleanup failure does not invalidate
the committed new configuration. Reset removes safe settings first and deletes a
stored credential only after separate confirmation.

## Per-call approval gate

Sessions may run with an approval gate that asks before individual tool calls:
smart-card/security-token programs (`pkcs11-tool`, `opensc-tool`, `piv-tool`,
`ykman`, `gpg --card-*`) and upload-shaped transfers (`curl -T/-F/-d`,
`scp`, `rsync`, `aws s3`, `rclone`) always require fresh interactive approval
and can never be persisted as rules. Path-taking tools are confined by an
optional user-level path jail; reads and writes outside it ask by default.
Saved rules are narrow (`tool` plus optional path prefix); deny rules win, the
store is versioned, locked, atomically replaced, and fails closed. Headless
runs never prompt: in-jail harmless calls run, everything else is denied with
the reason delivered to the model. `--approve-tools` and `--no-approve-tools`
are run-only overrides. The gate is an application-layer choke point, not a
filesystem, process, network, or exfiltration sandbox.

## General boundary

Project trust is an input-loading guard, not a filesystem, process, shell,
network, tool, credential, provider, model, package-install, prompt-injection,
or exfiltration sandbox. Extensions execute arbitrary Python. Use an OS
sandbox, container, VM, remote environment, and restricted credentials/network
when isolation is required.

For endpoint, auth, cached-downtime, Doctor, and model-selection troubleshooting,
see `local-inference.md`.

## Migration boundary

The built-in `llama.cpp` integration does not import or rewrite an existing
`llama-cpp` catalog entry. Configure it separately through `/local`, verify the
exact model ID returned by `/v1/models`, and remove the old entry only when it
is no longer needed. Ollama, gateways, and other local servers remain on the
manual custom-provider path. No Phase 6 operation starts, stops, downloads, or
deletes an external server or model file.
