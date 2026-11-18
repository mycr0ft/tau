"""Auto-compaction defaults: threshold from usable context, retention from the threshold.

The behaviour these pin, and why it is not `window - 16k`:

- a 1M-token model must not wait until ~1M tokens to compact (the old rule did);
- a small window must still leave the summarisation reserve;
- retention must scale with the threshold, or a 24k threshold retaining 20k recompacts
  after 4k of new work.
"""

from __future__ import annotations

import pytest

from tau_coding.context_window import (
    DEFAULT_COMPACTION_KEEP_RECENT_CAP,
    DEFAULT_COMPACTION_KEEP_RECENT_FLOOR,
    DEFAULT_COMPACTION_RESERVE_TOKENS,
    DEFAULT_COMPACTION_THRESHOLD_CAP,
    DEFAULT_COMPACTION_THRESHOLD_FLOOR,
    auto_compaction_threshold_for_context_window,
    default_auto_compact_threshold,
    default_compaction_keep_recent_tokens,
)


@pytest.mark.parametrize(
    ("window", "expected"),
    [
        (128_000, 76_800),  # 60% of the window
        (200_000, DEFAULT_COMPACTION_THRESHOLD_CAP),  # capped
        (1_000_000, DEFAULT_COMPACTION_THRESHOLD_CAP),  # a big window must not push it up
        (32_000, 15_616),  # window - reserve, because 60% would eat the reserve
        (16_384, 8_192),  # degenerate: half the window rather than nothing
    ],
)
def test_threshold_tracks_usable_context(window: int, expected: int) -> None:
    assert default_auto_compact_threshold(window) == expected


def test_threshold_never_eats_the_summarisation_reserve() -> None:
    for window in (9_000, 16_384, 32_000, 65_536, 131_072, 1_048_576):
        threshold = default_auto_compact_threshold(window)
        assert threshold is not None
        if window > DEFAULT_COMPACTION_RESERVE_TOKENS:
            assert window - threshold >= DEFAULT_COMPACTION_RESERVE_TOKENS or (
                threshold == window // 2
            ), window


def test_threshold_stays_above_the_floor_for_mid_sized_windows() -> None:
    for window in (32_000, 64_000, 100_000, 128_000):
        threshold = default_auto_compact_threshold(window)
        assert threshold is not None
        assert threshold >= DEFAULT_COMPACTION_THRESHOLD_FLOOR


def test_zero_or_negative_window_has_no_threshold() -> None:
    assert default_auto_compact_threshold(0) is None
    assert default_auto_compact_threshold(-5) is None


def test_the_old_rule_is_still_available_for_callers_that_want_it() -> None:
    """Pi-style `window - reserve` remains, so nothing silently changes meaning."""
    assert auto_compaction_threshold_for_context_window(128_000) == (
        128_000 - DEFAULT_COMPACTION_RESERVE_TOKENS
    )


@pytest.mark.parametrize(
    ("threshold", "expected"),
    [
        (76_800, 20_000),  # capped: a third would be 25.6k
        (24_000, 8_000),
        (9_000, 4_000),  # floored
        (120_000, 20_000),
    ],
)
def test_retention_scales_with_the_threshold(threshold: int, expected: int) -> None:
    assert default_compaction_keep_recent_tokens(threshold) == expected


def test_retention_always_leaves_room_to_work() -> None:
    """Whatever the threshold, at least half of it must be new work, not retained history."""
    for threshold in (8_000, 9_000, 16_000, 24_000, 76_800, 120_000):
        keep = default_compaction_keep_recent_tokens(threshold)
        assert keep <= max(DEFAULT_COMPACTION_KEEP_RECENT_FLOOR, threshold // 2)
        assert keep <= DEFAULT_COMPACTION_KEEP_RECENT_CAP


def test_retention_is_defined_for_a_degenerate_threshold() -> None:
    assert default_compaction_keep_recent_tokens(0) == DEFAULT_COMPACTION_KEEP_RECENT_FLOOR
