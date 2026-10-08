"""x-opencode-session rides on every OpenCode relay request, on every transport."""

from __future__ import annotations

from collections.abc import AsyncIterator

import httpx
import pytest

from tau_agent import UserMessage
from tau_ai import (
    AnthropicConfig,
    AnthropicProvider,
    OpenAICompatibleConfig,
    OpenAICompatibleProvider,
)
from tau_ai.http import create_async_client, tau_user_agent
from tau_ai.opencode_affinity import (
    OPENCODE_SESSION_HEADER,
    is_opencode_target,
    merge_opencode_session_headers,
    opencode_session_headers,
)

_CHAT_SSE = (
    'data: {"choices":[{"delta":{"content":"ok"},"finish_reason":"stop"}]}\n\ndata: [DONE]\n\n'
)
_RESPONSES_SSE = (
    'data: {"type":"response.output_text.delta","delta":"ok"}\n\n'
    'data: {"type":"response.completed","response":{"status":"completed"}}\n\n'
)
_ANTHROPIC_SSE = (
    'data: {"type":"message_start","message":{"usage":{"input_tokens":1,"output_tokens":0}}}\n\n'
    'data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}\n\n'
    'data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"ok"}}\n\n'
    'data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},'
    '"usage":{"output_tokens":2}}\n\n'
    'data: {"type":"message_stop"}\n\n'
)


async def _collect(stream: AsyncIterator[object]) -> list[object]:
    return [event async for event in stream]


def _sse_handler(
    requests: list[httpx.Request],
) -> httpx.Response:
    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        path = request.url.path
        if path.endswith("/messages"):
            text = _ANTHROPIC_SSE
        elif path.endswith("/responses") or path.endswith("/codex/responses"):
            text = _RESPONSES_SSE
        else:
            text = _CHAT_SSE
        return httpx.Response(200, text=text, headers={"content-type": "text/event-stream"})

    return handler


@pytest.mark.anyio
@pytest.mark.parametrize(
    "provider_name, base_url, api",
    [
        ("opencode-go", "https://opencode.ai/zen/go/v1", "openai-completions"),
        ("opencode-go", "https://opencode.ai/zen/go/v1", "openai-responses"),
        ("opencode", "https://opencode.ai/zen/v1", "openai-completions"),
        ("custom", "https://opencode.ai/zen/go/v1", "openai-completions"),
    ],
)
async def test_main_turn_sends_stable_session_header_on_every_transport(
    provider_name: str, base_url: str, api: str
) -> None:
    requests: list[httpx.Request] = []

    async with httpx.AsyncClient(transport=httpx.MockTransport(_sse_handler(requests))) as client:
        provider = OpenAICompatibleProvider(
            OpenAICompatibleConfig(
                api_key="test-key",
                base_url=base_url,
                api=api,
                provider_name=provider_name,
            ),
            client=client,
        )
        for _ in range(2):
            events = await _collect(
                provider.stream_response(
                    model="glm-5",
                    system="You are Tau.",
                    messages=[UserMessage(content="hi")],
                    tools=[],
                    session_id="sess-affinity-1",
                )
            )
            assert events[-1].type == "done"  # type: ignore[attr-defined]

    for request in requests:
        assert request.headers[OPENCODE_SESSION_HEADER] == "sess-affinity-1"


@pytest.mark.anyio
async def test_anthropic_transport_sends_stable_session_header_for_opencode() -> None:
    requests: list[httpx.Request] = []

    async with httpx.AsyncClient(transport=httpx.MockTransport(_sse_handler(requests))) as client:
        provider = AnthropicProvider(
            AnthropicConfig(
                api_key="test-key",
                base_url="https://opencode.ai/anthropic/v1",
                bearer_auth=True,
                provider_name="opencode-go",
            ),
            client=client,
        )
        await _collect(
            provider.stream_response(
                model="glm-5",
                system="You are Tau.",
                messages=[UserMessage(content="hi")],
                tools=[],
                session_id="sess-affinity-1",
            )
        )

    assert requests[0].headers[OPENCODE_SESSION_HEADER] == "sess-affinity-1"


@pytest.mark.anyio
@pytest.mark.parametrize("provider_name", ["openai", "openai-codex", "custom"])
async def test_non_opencode_targets_do_not_send_the_header(provider_name: str) -> None:
    requests: list[httpx.Request] = []

    async with httpx.AsyncClient(transport=httpx.MockTransport(_sse_handler(requests))) as client:
        provider = OpenAICompatibleProvider(
            OpenAICompatibleConfig(
                api_key="test-key",
                base_url="https://example.test/v1",
                provider_name=provider_name,
            ),
            client=client,
        )
        await _collect(
            provider.stream_response(
                model="x",
                system="You are Tau.",
                messages=[UserMessage(content="hi")],
                tools=[],
                session_id="sess-affinity-1",
            )
        )

    for request in requests:
        assert OPENCODE_SESSION_HEADER not in request.headers


def test_caller_pinned_header_wins() -> None:
    headers = merge_opencode_session_headers(
        {OPENCODE_SESSION_HEADER: "pinned"},
        "opencode-go",
        "https://opencode.ai/zen/go/v1",
        "sess-affinity-1",
    )
    assert headers[OPENCODE_SESSION_HEADER] == "pinned"


def test_opencode_target_detection() -> None:
    assert is_opencode_target("opencode-go", None)
    assert is_opencode_target("opencode", None)
    assert is_opencode_target("custom", "https://opencode.ai/zen/v1")
    assert is_opencode_target("custom", "https://sub.opencode.ai/v1")
    assert not is_opencode_target("openai-codex", "https://chatgpt.com/backend-api")
    assert not is_opencode_target("antiopencode", None)
    assert not is_opencode_target("custom", "https://opencode.example.com/v1")
    assert not is_opencode_target(None, None)


def test_no_session_id_yields_no_header() -> None:
    assert opencode_session_headers("opencode-go", "https://opencode.ai/zen/go/v1", None) == {}
    assert opencode_session_headers("opencode-go", "https://opencode.ai/zen/go/v1", "   ") == {}


def test_tau_user_agent_self_identifies() -> None:
    agent = tau_user_agent()
    assert agent.startswith("tau/")
    assert "python" not in agent
    assert "httpx" not in agent


@pytest.mark.anyio
async def test_shared_client_sets_tau_user_agent() -> None:
    async with create_async_client() as client:
        assert client.headers["user-agent"] == tau_user_agent()
