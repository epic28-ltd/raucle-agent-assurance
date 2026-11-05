# SPDX-License-Identifier: Apache-2.0

# Independent Assurance Agent (OV-13)

A reference implementation of the AAS dual-agent pattern: a verifier agent
that is **structurally isolated** from the builder agent that produced the
assurance artefacts.

## Pattern mapping

| AAS role | Implementation |
| --- | --- |
| Builder agent | The repo's gate, pack builders and the prebind module (`oaa_prebind`). |
| Independent verifier agent | `python -m oaa_iaa` — a separate process entry point. |
| Handoff artefact | Any published JSON evidence document on stdin (assurance packet, prebind indicator set, run records). |
| Return artefact | `oaa.independent-review-opinion/v1` JSON on stdout: verdict (`pass`/`concern`/`fail`), cited positives and concerns. |

## Isolation guarantees

1. **Process isolation** — the verifier runs as its own process
   (`python -m oaa_iaa` with `services/independent-assurance/src` on
   `PYTHONPATH`). It is never imported by builder code.
2. **No builder context** — the module imports only the standard library.
   The verifier cannot reach the gate, fixtures, or builder state; it cites
   only what the handed artefact itself carries.
3. **Fail-visible** — malformed input exits non-zero with an explicit
   stderr error; the agent never fabricates an opinion from partial input.

## Usage

    PYTHONPATH=services/independent-assurance/src \
      python -m oaa_iaa < published-evidence.json > review-opinion.json

Tests: `tests/independent-assurance/`.
