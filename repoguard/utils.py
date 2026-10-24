"""Small shared utilities for RepoGuard AI."""

from __future__ import annotations

import asyncio
import concurrent.futures
import re
from typing import Any


def run_async(coro):
    """Run a coroutine from sync code (Streamlit buttons run synchronously).

    Handles both "no running loop" (normal CLI/thread) and "loop already
    running" (notebook/Jupyter) contexts without crashing.
    """
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(asyncio.run, coro).result()


_FENCE_RE = re.compile(r"```[a-zA-Z0-9_-]*\n(.*?)```", re.S)


def extract_fenced_code(text: str) -> str | None:
    """Pull the first fenced code block out of an LLM response."""
    match = _FENCE_RE.search(text)
    return match.group(1).strip() if match else None


def extract_ai_text(response: Any) -> str:
    """Best-effort extraction of reply text across SDK/shape variations.

    The DNotifier SDK (and OpenAI-compatible servers) may return a plain
    string, a dict, or a pydantic-ish object — normalise all of them.
    """
    if response is None:
        return ""
    if isinstance(response, str):
        return response
    if isinstance(response, dict):
        # DNotifier wraps the AI reply under `data` (verified live):
        #   {"data": {"type": "openai", "content": "...", "usage": {...}}}
        #   {"data": {"type": "error", "message": "..."}}
        data = response.get("data")
        if isinstance(data, dict):
            if data.get("type") == "error":
                return f"DNotifier AI error: {data.get('message', 'unknown error')}"
            content = data.get("content")
            if isinstance(content, str) and content.strip():
                return content
        for key in ("text", "content", "message", "reply", "answer", "output"):
            value = response.get(key)
            if isinstance(value, str) and value.strip():
                return value
        # Nested OpenAI-style: choices[0].message.content
        choices = response.get("choices")
        if isinstance(choices, list) and choices:
            first = choices[0]
            if isinstance(first, dict):
                msg = first.get("message", {})
                if isinstance(msg, dict) and isinstance(msg.get("content"), str):
                    return msg["content"]
        return str(response)
    # Object with an attribute-style payload
    for attr in ("text", "content", "message"):
        value = getattr(response, attr, None)
        if isinstance(value, str) and value.strip():
            return value
    return str(response)
