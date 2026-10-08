---
title: "Tool approvals and the path jail"
weight: 60
---

Tau can ask before individual tool calls run. The approval gate sits between
the model and Tau's tools: every call is classified, and sensitive calls stop
for a decision instead of executing.

## What always asks

Some call shapes are never auto-allowed and can never be saved as rules:

- Smart-card and security-token access: `pkcs11-tool`, `opensc-tool`,
  `opensc-explorer`, `piv-tool`, `cardos-tool`, `ykman`, `pcscd`, and `gpg`
  card subcommands; `ssh`/`ssh-add` with a PKCS#11 provider.
- Upload-shaped transfers: `curl -T/--upload-file`, `curl -F/--form`,
  `curl -d/--data*`, `wget --post-file`, `scp`, `sftp`, `rsync` to a remote,
  `rclone`, `gsutil`, and `aws s3` transfers.

Each run requires fresh approval. A rule saved earlier never covers these.

## The path jail

`--jail PATH` (repeatable) confines the path-taking tools (`read`, `write`,
`edit`) to trusted directories. Paths are compared after symlink resolution,
so spelling tricks do not escape the jail. By default, reads and writes
outside the jail ask; a user-level settings file can set them to allow or
deny instead. A project can never define its own jail.

## Rules

When a call asks and you choose "allow and save", Tau stores one narrow rule
in `~/.tau/approvals.json`: a tool name plus, for path-bound tools, a path
prefix. Deny rules win. The store is locked, atomically replaced, and fails
closed: a torn or malformed store denies rather than allows.

## Headless behavior

Print, JSON, transcript, and RPC modes never prompt. Harmless in-jail calls
run; everything else is denied and the denial reason is delivered to the
model as the tool error. `--approve-tools` allows every call for one
invocation; `--no-approve-tools` denies every call outside the jail. Neither
writes the approvals store.

## Boundary

The gate is an application-layer choke point, not a sandbox. bash commands
read whatever you can read and can reach the network directly; a trusted
malicious project can bypass the gate once a command runs. Real isolation
requires an OS sandbox, container, or VM — for accredited or CUI work, run
Tau inside such a boundary and treat the gate as the asking, audit, and
defense-in-depth layer inside it.
