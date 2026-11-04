# SPDX-License-Identifier: Apache-2.0
"""Gate clients: the enforcement boundary to Raucle Agent Trust.

The adapter CALLS the gate through one of these clients; it is never the gate
itself (monitoring never enforcement-authority). Every client returns the same
``GateDecision`` result so the middleware is transport-agnostic.

Both implementations are lazy: ``raucle`` (the pinned v0.23.5 / git 63edacd
worktree) and ``urllib``-level HTTP are only touched when the corresponding
client is actually constructed.
"""

from __future__ import annotations

import importlib
import json
import os
import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

#: Distro pin keyed by the raucle distribution, NOT ``raucle.__version__``
#: (which is stale) — see packages/raucle-adapter/evidence_plane.py.
RAUCLE_DISTRIBUTION_PIN = "raucle 0.23.5 (git 63edacd)"

#: Default location of the pinned raucle worktree used by local tests.
DEFAULT_RAUCLE_WORKTREE = Path.home() / "Projects" / "oaa-spike-4nov" / "evd" / "raucle-63edacd"

_ALLOW = "allow"
_DENY = "deny"
_ESCALATE = "escalate"


@dataclass(frozen=True)
class GateDecision:
    """Normalised gate outcome.

    ``error`` is set when the gate itself failed (transport/exception). In
    that case ``decision`` mirrors the middleware's fail mode (``fail_closed``
    callers see ``deny``), and ``receipt_hash`` is always empty — no receipt
    means no verification state to attach.
    """

    decision: str  # "allow" | "deny" | "error"
    reason: str = ""
    receipt_hash: str | None = None
    latency_us: int = 0
    error: str | None = None
    raw: Mapping[str, Any] = field(default_factory=dict)


class GateClient(Protocol):
    """Anything the middleware can enforce against."""

    def check_tool_call(
        self,
        *,
        tool: str,
        args: dict[str, Any],
        call_id: str,
        trace_id: str,
        agent_id: str,
        source: str,
    ) -> GateDecision:
        """Gate one tool call. Must not retry; must return promptly."""
        ...  # pragma: no cover - protocol


def _ensure_raucle_importable() -> tuple[Any, Any, Any]:
    """Import the pinned raucle, adding the default worktree to sys.path first.

    Returns (raucle module, RaucleGateway, GatewayConfig) or raises
    ``ImportError`` naming the pin so operators know exactly what to fix.
    """
    try:
        raucle = importlib.import_module("raucle")
        importlib.import_module("raucle.gateway")
    except ImportError:
        if DEFAULT_RAUCLE_WORKTREE.is_dir():
            import sys  # noqa: PLC0415 (lazy, only when the worktree fallback runs)

            worktree = str(DEFAULT_RAUCLE_WORKTREE)
            if worktree not in sys.path:
                sys.path.insert(0, worktree)
            raucle = importlib.import_module("raucle")
            importlib.import_module("raucle.gateway")
        else:
            raise
    return raucle, raucle.gateway.RaucleGateway, raucle.gateway.GatewayConfig


class InProcessRaucleGate:
    """Wrap a real ``RaucleGateway`` in-process (same interpreter as the agent).

    Enforcement authority stays entirely with the gateway: this wrapper is a
    transport shim, not a policy evaluator.
    """

    def __init__(
        self,
        gateway: Any | None = None,
        *,
        gateway_config: Any | None = None,
        agent_id: str = "",
        source: str = "langgraph",
    ) -> None:
        if gateway is None:
            _, RaucleGateway, GatewayConfig = _ensure_raucle_importable()
            gateway = RaucleGateway(
                gateway_config if gateway_config is not None else GatewayConfig()
            )
        self._gateway = gateway
        self._agent_id = agent_id
        self._source = source

    def check_tool_call(
        self,
        *,
        tool: str,
        args: dict[str, Any],
        call_id: str,
        trace_id: str,
        agent_id: str,
        source: str,
    ) -> GateDecision:
        # Correlation: the caller's id travels as the gate's trace_id (call_id
        # as fallback), so the signed receipt is keyed by the call it covers.
        result = self._gateway.check_tool_call(
            tool,
            args,
            agent_id=agent_id or self._agent_id,
            source=source or self._source,
            trace_id=trace_id or call_id,
        )
        decision = str(result.get("decision", _DENY))
        if decision == _ALLOW:
            receipt_hash = result.get("receipt_id")
            return GateDecision(
                decision=_ALLOW,
                reason=str(result.get("reason", "")),
                receipt_hash=receipt_hash if receipt_hash else None,
                latency_us=int(result.get("latency_us", 0)),
                raw=result,
            )
        if decision == _ESCALATE:
            # Escalate is not authority to run. Until an approval workflow is
            # wired through the adapter, escalation resolves to deny.
            return GateDecision(
                decision=_DENY,
                reason=str(result.get("reason", "")) or "escalation unresolved",
                latency_us=int(result.get("latency_us", 0)),
                raw=result,
            )
        return GateDecision(
            decision=_DENY,
            reason=str(result.get("reason", "denied")),
            latency_us=int(result.get("latency_us", 0)),
            raw=result,
        )


class HttpGateClient:
    """POST the gate request to a Raucle gateway HTTP endpoint as JSON.

    One request per call, no retries inside the enforcement path. ``timeout_s``
    defaults to 80 ms (the latency budget agreed in EPIC M).
    """

    def __init__(
        self,
        endpoint: str,
        *,
        timeout_s: float = 0.080,
        agent_id: str = "",
        source: str = "langgraph",
        fail_open: bool = False,
        extra_body: Mapping[str, Any] | None = None,
    ) -> None:
        self._endpoint = endpoint
        self._timeout_s = timeout_s
        self._agent_id = agent_id
        self._source = source
        self._fail_open = fail_open
        self._extra_body = dict(extra_body or {})

    def check_tool_call(
        self,
        *,
        tool: str,
        args: dict[str, Any],
        call_id: str,
        trace_id: str,
        agent_id: str,
        source: str,
    ) -> GateDecision:
        body = {
            "tool": tool,
            "args": args,
            "call_id": call_id,
            "trace_id": trace_id or call_id,
            "agent_id": agent_id or self._agent_id,
            "source": source or self._source,
            "distribution_pin": RAUCLE_DISTRIBUTION_PIN,
            **self._extra_body,
        }
        req = urllib.request.Request(
            self._endpoint,
            data=json.dumps(body).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self._timeout_s) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
        except Exception as exc:  # gate failure — resolution is the caller's job
            return GateDecision(
                decision=_ALLOW if self._fail_open else _DENY,
                reason=f"gate unreachable: {exc}",
                error=str(exc),
                raw={},
            )
        decision = str(payload.get("decision", _DENY))
        return GateDecision(
            decision=_ALLOW if decision == _ALLOW else _DENY,
            reason=str(payload.get("reason", "")),
            receipt_hash=payload.get("receipt_hash"),
            latency_us=int(payload.get("latency_us", 0)),
            raw=payload,
        )


def ensure_pinned_raucle_worktree(worktree: str | os.PathLike[str] | None = None) -> Path:
    """Return the worktree path, registering it on sys.path if present.

    Used by tests and operators running from a checkout; production users
    install raucle normally.
    """
    path = Path(worktree) if worktree else DEFAULT_RAUCLE_WORKTREE
    if not path.is_dir():
        raise FileNotFoundError(f"pinned raucle worktree missing: {path}")
    os.environ.setdefault("RAUCLE_WORKTREE", str(path))
    return path
