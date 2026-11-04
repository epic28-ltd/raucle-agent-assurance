# SPDX-License-Identifier: Apache-2.0
"""Local runtime protocol mirroring LangGraph's middleware surface.

The adapter must be testable and installable without langgraph/langchain
present. This module mirrors the shapes it depends on:

- ``langgraph.prebuilt.tool_node.ToolCallRequest`` (as ``ToolCallRequest``)
- ``langchain.agents.middleware.AgentMiddleware`` (as ``MiddlewareBase``)

When langchain **is** importable, ``MIDDLEWARE_BASE`` is the real
``AgentMiddleware`` subclass so the middleware registers as a first-class
langchain middleware; otherwise a minimal local base class with the same
``wrap_tool_call`` hook is used. Attribute shape is identical either way.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, Protocol, TypedDict

try:  # pragma: no cover - depends on environment
    from langchain.agents.middleware import AgentMiddleware

    MIDDLEWARE_BASE: type = AgentMiddleware
    _USES_LANGCHAIN = True
except Exception:  # pragma: no cover - exercised by default test runs
    MIDDLEWARE_BASE = object
    _USES_LANGCHAIN = False

USES_LANGCHAIN_MIDDLEWARE = _USES_LANGCHAIN


class ToolCall(TypedDict):
    """A single model-issued tool call (mirrors langchain.core ToolCall)."""

    name: str
    args: dict[str, Any]
    id: str


class ToolCallRequest(TypedDict, total=False):
    """Mirror of ``langgraph.prebuilt.tool_node.ToolCallRequest``.

    Only the fields this adapter touches are declared; extra keys forwarded
    by the real runtime pass through untouched because we treat the request
    as an opaque mapping.
    """

    tool_call: ToolCall
    state: Any
    runtime: Any


ToolExecutor = Callable[[ToolCallRequest], Any]
"""Executable that runs the tool body. Middleware vetoes by NOT calling it."""


class SpanAttributeSink(Protocol):
    """Callback interface for span attributes (keeps otel out of this package)."""

    def set_tool_attributes(self, call_id: str, attributes: dict[str, Any]) -> None:
        """Attach ``attributes`` to the span covering tool call ``call_id``."""
        ...
