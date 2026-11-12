"""Hosted-surface sessions: short-lived receipted bearer sessions (R2 slice 1).

Mirrors the gateway's admin session idiom (raucle X3 slice 1) so operators
recognise one shape across the suite:

- a successful login issues 256 bits of entropy, prefixed ``oas_``; only the
  token's SHA-256 digest is stored - the session store is not a credential
  file.
- sessions expire (default 1 hour, operator-configurable); expiry is
  enforced on every resolve; an unknown, expired, malformed or already-
  closed token resolves to NO principal and fails like a missing header.
- the session table is bounded; opening one more session beyond the cap
  refuses fail-closed (503 to the caller) instead of silently evicting.
- open / refresh / close are RECEIPTED lifecycle events in the hashed
  ledger, binding the session's public handle (hash-derived, never the
  token), the subject and the expiry. The console holds no in-process
  gateway signer, so the receipt of record is the surface's own hashed
  ledger; wiring a JWS signer is the follow-up named in the PR.

Role resolution happens at request time against the CURRENT role registry,
so a receipted role change takes effect on the next request without
waiting for session expiry. ``open()`` still records the principal's
identifier strings, which the registry later matches against env grants
and receipted changes.
"""
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import hashlib
import logging
import secrets
import time

logger = logging.getLogger(__name__)

SESSION_TOKEN_PREFIX = "oas_"
DEFAULT_SESSION_TTL_SECONDS = 3600
DEFAULT_MAX_SESSIONS = 64


class SessionOpenError(Exception):
    """A session could not be opened, with the HTTP status to answer."""

    def __init__(self, reason: str, status: int = 401) -> None:
        super().__init__(reason)
        self.reason = reason
        self.status = status


def hash_session_token(token: str) -> str:
    """The digest we store - never the token."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def derive_session_id(token_hash: str) -> str:
    """Stable public handle for receipts (never the token, never its digest)."""
    return "osn-" + token_hash[:12]


def principal_ids(claims: dict) -> list[str]:
    """Identity strings a registry can match for a verified principal."""
    ordered = ["sub", "email", "preferred_username", "name"]
    return [c for c in (str(claims.get(k) or "") for k in ordered) if c]


class HostedSessionManager:
    """Registry-backed sessions for the hosted operator surface."""

    def __init__(
        self,
        *,
        ttl_seconds: int = DEFAULT_SESSION_TTL_SECONDS,
        max_sessions: int = DEFAULT_MAX_SESSIONS,
        ledger=None,
        clock=time.time,
    ) -> None:
        if ttl_seconds < 60:
            raise ValueError("hosted session ttl_seconds must be at least 60")
        if max_sessions <= 0:
            raise ValueError("hosted session max_sessions must be positive")
        self._ttl = int(ttl_seconds)
        self._max_sessions = int(max_sessions)
        self._ledger = ledger
        self._clock = clock if clock is not None else time.time
        self._sessions: dict[str, dict] = {}

    # ----------------------------------------------------------- lifecycle
    def open(self, principal) -> dict:
        """Issue a receipted session for an ALREADY-authenticated principal.

        The caller is the OIDC exchange path: the id_token verification has
        already succeeded fail-closed when this runs.
        """
        now = self._clock()
        if len(self._sessions) >= self._max_sessions:
            self._sweep_expired()
        if len(self._sessions) >= self._max_sessions:
            raise SessionOpenError(
                "session limit reached; close a session or wait for expiry",
                status=503,
            )
        token = SESSION_TOKEN_PREFIX + secrets.token_hex(32)
        digest = hash_session_token(token)
        expires_at = now + self._ttl
        subject = principal.subject
        self._sessions[digest] = {
            "ids": list(principal_ids(principal.claims)),
            "opened_at": now,
            "expires_at": expires_at,
        }
        self._receipt(
            "open",
            {
                "session_id": derive_session_id(digest),
                "subject": subject,
                "expires_at": int(expires_at),
            },
            required=False,
        )
        logger.info("hosted session opened for %s", subject)
        return {"token": token, "expires_at": expires_at, "subject": subject}

    def resolve_token(self, token) -> dict | None:
        """The session record for a presented bearer token, or None.

        Fail-closed on every failure shape: unknown, malformed prefix,
        expired or already-closed tokens all resolve to None.
        """
        record = self._record_for(token)
        return dict(record) if record is not None else None

    def refresh(self, token) -> float | None:
        """Extend the session to now + ttl. Receipted; None fails closed."""
        record = self._record_for(token)
        if record is None:
            return None
        digest = hash_session_token(token)
        record["expires_at"] = self._clock() + self._ttl
        self._sessions[digest]["expires_at"] = record["expires_at"]
        self._receipt(
            "refresh",
            {
                "session_id": derive_session_id(digest),
                "subject": record["ids"][0] if record["ids"] else "",
                "expires_at": int(record["expires_at"]),
            },
            required=False,
        )
        return record["expires_at"]

    def close(self, token) -> bool:
        """Receipt BEFORE the record is dropped: the ledger never loses it."""
        record = self._record_for(token)
        if record is None:
            return False
        digest = hash_session_token(token)
        self._receipt(
            "close",
            {
                "session_id": derive_session_id(digest),
                "subject": record["ids"][0] if record["ids"] else "",
                "expires_at": int(record["expires_at"]),
            },
            required=False,
        )
        self._sessions.pop(digest, None)
        logger.info("hosted session closed")
        return True

    def active_count(self) -> int:
        self._sweep_expired()
        return len(self._sessions)

    @property
    def ttl_seconds(self) -> int:
        """The configured session ttl (seconds); exposed for /session/config."""
        return self._ttl

    # ------------------------------------------------------------ internals
    def _record_for(self, token) -> dict | None:
        if not isinstance(token, str) or not token.startswith(SESSION_TOKEN_PREFIX):
            return None
        digest = hash_session_token(token)
        record = self._sessions.get(digest)
        if record is None:
            return None
        if self._clock() > record["expires_at"]:
            self._sessions.pop(digest, None)
            return None
        return dict(record, session_id=derive_session_id(digest))

    def _sweep_expired(self) -> None:
        now = self._clock()
        for digest in [d for d, rec in self._sessions.items() if rec["expires_at"] <= now]:
            self._sessions.pop(digest, None)

    def _receipt(self, action: str, payload: dict, *, required: bool) -> None:
        if self._ledger is None:
            return
        try:
            self._ledger.append("session_" + action, payload)
        except Exception:
            # Degradation mirrors the gateway manager's: a receipt emission
            # failure is logged and visible, and never silent in data. Role
            # changes (required=True) fail the change instead.
            logger.exception("hosted receipt emission failed for %s", action)
            if required:
                raise


def subject_of(claims: dict) -> str:
    return claims.get("sub") or ""
