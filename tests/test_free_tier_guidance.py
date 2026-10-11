"""Free-tier guidance: picker marking, selection refusal, and 403 mapping."""

from __future__ import annotations

from tau_ai.http_errors import provider_http_error_detail, provider_http_error_message
from tau_coding import ModelChoice
from tau_coding.tui.app import _is_opencode_free_tier_model, _model_picker_label


class TestFreeTierPredicate:
    def test_zen_free_suffix_models(self) -> None:
        assert _is_opencode_free_tier_model("opencode", "mimo-v2.5-free")
        assert _is_opencode_free_tier_model("opencode", "deepseek-v4-flash-free")
        assert _is_opencode_free_tier_model("opencode", "nemotron-3-ultra-free")

    def test_go_free_models(self) -> None:
        assert _is_opencode_free_tier_model("opencode-go", "longcat-2.5-preview-free")

    def test_paid_models_not_marked(self) -> None:
        assert not _is_opencode_free_tier_model("opencode-go", "glm-5.3-flash")
        assert not _is_opencode_free_tier_model("opencode-go", "kimi-k2.7-code")
        assert not _is_opencode_free_tier_model("opencode", "big-pickle")

    def test_free_marker_on_other_providers_is_not_opencode_gated(self) -> None:
        # OpenRouter's :free suffix is a different mechanism (usually works).
        assert not _is_opencode_free_tier_model("openrouter", "openai/gpt-oss-120b:free")
        assert not _is_opencode_free_tier_model("openai", "anything-free")

    def test_case_insensitive_provider(self) -> None:
        assert _is_opencode_free_tier_model("OpenCode-Go", "x-free")


class TestPickerLabel:
    def test_free_tier_models_are_marked(self) -> None:
        choice = ModelChoice(provider_name="opencode", model="mimo-v2.5-free")
        label = _model_picker_label(choice, current_model="x", current_provider="opencode")
        assert "[free tier: official OpenCode client required]" in label
        assert "[unavailable]" not in label

    def test_paid_models_are_unmarked(self) -> None:
        choice = ModelChoice(provider_name="opencode-go", model="glm-5.3-flash")
        label = _model_picker_label(choice, current_model="x", current_provider="opencode-go")
        assert "free tier" not in label


_FREE_TIER_BODY = (
    '{"type":"FreeTierError","message":"Error from provider (Console): '
    "OpenCode's free tier can only be used from within OpenCode\"}"
)


class TestErrorHint:
    def test_403_carries_guidance(self) -> None:
        message = provider_http_error_message(
            provider_name="opencode-go",
            status_code=403,
            body=_FREE_TIER_BODY,
            model="mimo-v2.5-free",
        )
        assert "Tau note" in message
        assert "49433" in message
        assert "paid" in message

    def test_unrelated_errors_untouched(self) -> None:
        message = provider_http_error_message(
            provider_name="opencode-go",
            status_code=429,
            body='{"error":{"message":"rate limited"}}',
        )
        assert "Tau note" not in message

    def test_detail_extraction_still_exact(self) -> None:
        detail = provider_http_error_detail(_FREE_TIER_BODY)
        assert "free tier" in detail
