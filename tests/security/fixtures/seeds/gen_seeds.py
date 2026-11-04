# SPDX-License-Identifier: Apache-2.0
"""Deterministic PRIV-01 seeded-secret generator.

Regenerate with: python gen_seeds.py  (rewrites seeds.json byte-identical —
the RNG is fixed-seed and the PEM blocks are deterministic base64 of the
keyed stream). Every value carries an obvious synthetic prefix
(`oaa-priv01-` / synthetic PEM header) — these are NOT real credentials, but
they structurally match what the redaction patterns must catch.
"""

from __future__ import annotations

import base64
import hashlib
import json
import pathlib
import random

RNG = random.Random(0x5052493031)  # fixed seed: "PRI01"

ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"


def _hex(rng: random.Random, n: int) -> str:
    return "".join(rng.choice("0123456789abcdef") for _ in range(n))


def _alnum(rng: random.Random, n: int) -> str:
    return "".join(rng.choice(ALPHABET) for _ in range(n))


def _pem_block(rng: random.Random, label: str = "RSA PRIVATE KEY") -> str:
    der = bytes(rng.getrandbits(8) for _ in range(256))
    b64 = base64.b64encode(der).decode()
    lines = "\n".join(b64[i : i + 64] for i in range(0, len(b64), 64))
    return f"-----BEGIN {label}-----\n{lines}\n-----END {label}-----"


def main() -> list[dict]:
    seeds = [
        {
            "id": "seed-aws-access-key",
            "class": "aws_access_key",
            "value": "AKIA"
            + "".join(
                RNG.choice(ALPHABET[:36] and "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
                for _ in range(16)
            ),
            "shape": "OTel span attribute `aws.access_key`",
        },
        {
            "id": "seed-aws-secret",
            "class": "aws_access_key",
            "value": _alnum(RNG, 40),
            "shape": "OTel span attribute `aws.secret` (40-char key)",
        },
        {
            "id": "seed-bearer-token",
            "class": "bearer_token",
            "value": "Bearer " + _hex(RNG, 32),
            "shape": "authorization header echo in `http.request.header.authorization`",
        },
        {
            "id": "seed-jwt",
            "class": "jwt",
            "payload": _alnum(RNG, 40),
            "value": None,
            "shape": "span attribute `oidc.token`",
        },
        {
            "id": "seed-private-key-pem",
            "class": "private_key_pem",
            "value": None,
            "shape": "span attribute `tls.client_key_pem`",
        },
        {
            "id": "seed-email",
            "class": "email",
            "value": "oaa-priv01-" + _alnum(RNG, 8).lower() + "@example.invalid",
            "shape": "span attribute `user.email`",
        },
        {
            "id": "seed-api-key-kv",
            "class": "credential_kv",
            "value": "api_key=" + _alnum(RNG, 24),
            "shape": "LLM input message echo in `llm.input_messages`",
        },
        {
            "id": "seed-high-entropy",
            "class": "high_entropy",
            "value": _alnum(RNG, 48) + _hex(RNG, 8) + "+/=",
            "shape": "span attribute `client.hmac_key` (no key-name hint: entropy heuristic)",
        },
        {
            "id": "seed-allowlisted-metadata",
            "class": "allowlisted",
            "value": "run-note: oaa.metadata passthrough probe " + _alnum(RNG, 12),
            "shape": "span attribute `oaa.metadata.run_note` (MUST pass through unredacted)",
        },
    ]
    for s in seeds:
        if s["id"] == "seed-jwt":
            b64 = lambda t: base64.urlsafe_b64encode(t).decode().rstrip("=")
            s["value"] = (
                b64(b'{"alg":"RS256","typ":"JWT"}')
                + "."
                + b64(s.pop("payload").encode())  # type: ignore[typeddict-item]
                + "."
                + _alnum(RNG, 42)
            )
        if s["id"] == "seed-private-key-pem":
            s["value"] = _pem_block(RNG)
        s["sha256"] = hashlib.sha256(s["value"].encode()).hexdigest()
    out = pathlib.Path(__file__).resolve().parent / "seeds.json"
    out.write_text(
        json.dumps({"purpose": "PRIV-01 seeded synthetic secrets", "seeds": seeds}, indent=2) + "\n"
    )
    print(f"wrote {out} with {len(seeds)} seeds")


if __name__ == "__main__":
    main()
