"""Byte metering and bounded JSON prefix cutting for snapshot evidence."""

from __future__ import annotations

import json


def _json_bytes(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _json_text_prefix(text: str, maximum_bytes: int) -> tuple[str, int, int]:
    encoded_length = len(_json_bytes(text))
    if encoded_length <= maximum_bytes:
        return text, 0, encoded_length
    low = 0
    high = len(text)
    while low < high:
        middle = (low + high + 1) // 2
        if len(_json_bytes(text[:middle])) <= maximum_bytes:
            low = middle
        else:
            high = middle - 1
    accepted = text[:low]
    omitted = len(text[low:].encode("utf-8"))
    return accepted, omitted, len(_json_bytes(accepted))
