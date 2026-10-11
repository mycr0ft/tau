"""Helpers for surfacing safe provider HTTP error details."""

from __future__ import annotations

from collections.abc import Mapping
from json import JSONDecodeError, loads
from typing import Any

_MAX_ERROR_DETAIL_LENGTH = 1000


def provider_http_error_message(
    *,
    provider_name: str,
    status_code: int,
    body: str,
    model: str | None = None,
) -> str:
    """Return an actionable, secret-free HTTP error message for a provider response."""
    prefix = f"{provider_name} request failed with status {status_code}"
    if model:
        prefix = f"{prefix} for model {model}"
    detail = provider_http_error_detail(body)
    if detail:
        return f"{prefix}: {detail}{opencode_free_tier_hint(detail)}"
    return f"{prefix}{opencode_free_tier_hint(body)}"


def provider_http_error_detail(body: str) -> str:
    """Extract a concise provider-supplied error detail from an HTTP body."""
    parsed = _loads_object(body)
    if parsed is not None:
        detail = provider_error_detail_from_mapping(parsed)
        if detail:
            return detail
    return body.strip()[:_MAX_ERROR_DETAIL_LENGTH]


_FREE_TIER_MESSAGE_FRAGMENT = "free tier can only be used from within opencode"


def opencode_free_tier_hint(detail: str) -> str:
    """Return Tau's guidance appended to OpenCode free-tier gate rejections.

    The relay 403s free-tier models from third-party clients on a header
    fingerprint (opencode issue 49433); the raw message alone reads like a
    bug. The hint stays factual and points at sanctioned alternatives.
    """
    if _FREE_TIER_MESSAGE_FRAGMENT not in detail.casefold():
        return ""
    return (
        " Tau note: this model is on OpenCode's free tier, which the relay "
        "currently gates to the official OpenCode client (their issue 49433); "
        "Tau requests are refused by policy, not a header bug. Pick a paid "
        "model on the same provider, or another provider."
    )


def provider_error_detail_from_mapping(value: Mapping[str, Any]) -> str:
    """Return the most useful message/code from a provider error object."""
    error = value.get("error")
    if isinstance(error, Mapping):
        message = error.get("message")
        if isinstance(message, str) and message:
            return message
        code = error.get("code")
        if isinstance(code, str) and code:
            return code
    for key in ("message", "detail", "error"):
        detail = value.get(key)
        if isinstance(detail, str) and detail:
            return detail
        if isinstance(detail, Mapping):
            nested = provider_error_detail_from_mapping(detail)
            if nested:
                return nested
    return ""


def _loads_object(value: str) -> Mapping[str, Any] | None:
    try:
        parsed = loads(value)
    except JSONDecodeError:
        return None
    return parsed if isinstance(parsed, Mapping) else None
