"""``x-opencode-session`` — OpenCode relay session-affinity header.

OpenCode (opencode.ai Zen/Go relay) pins requests that share an
``x-opencode-session`` value to the same upstream backend, which keeps the
relay's prompt cache warm across the turns of one conversation. The value is
the ambient Tau session id: opaque, stable per conversation, and carrying no
personal data.

Every OpenCode request — main turns on any transport plus auxiliary calls
(renaming, summaries, curation) — goes through
:func:`merge_opencode_session_headers` so the header cannot drift per code
path. Non-OpenCode targets are left untouched.
"""

from __future__ import annotations

from urllib.parse import urlsplit

OPENCODE_SESSION_HEADER = "x-opencode-session"
_OPENCODE_HOST = "opencode.ai"


def is_opencode_target(provider_name: str | None, base_url: str | None) -> bool:
    """True when *provider_name* or *base_url* addresses the OpenCode relay.

    Matches the catalog provider ids (``opencode``, ``opencode-go``, and any
    future ``opencode-*`` provider) plus any base URL hosted on opencode.ai,
    so custom providers pointed at the relay are also recognized.
    """

    name = (provider_name or "").strip().lower()
    if name.startswith("opencode"):
        return True
    host = (urlsplit(base_url or "").hostname or "").lower()
    return host == _OPENCODE_HOST or host.endswith(f".{_OPENCODE_HOST}")


def opencode_session_headers(
    provider_name: str | None,
    base_url: str | None,
    session_id: str | None = None,
) -> dict[str, str]:
    """Return ``{"x-opencode-session": <id>}`` for OpenCode targets, else ``{}``."""

    if not session_id or not is_opencode_target(provider_name, base_url):
        return {}
    key = str(session_id).strip()
    if not key:
        return {}
    return {OPENCODE_SESSION_HEADER: key}


def merge_opencode_session_headers(
    headers: dict[str, str],
    provider_name: str | None,
    base_url: str | None,
    session_id: str | None = None,
) -> dict[str, str]:
    """Merge the affinity header into *headers* (in place).

    Existing per-request headers win, so a caller-pinned value is preserved.
    Non-OpenCode targets are left untouched.
    """

    for name, value in opencode_session_headers(provider_name, base_url, session_id).items():
        headers.setdefault(name, value)
    return headers
