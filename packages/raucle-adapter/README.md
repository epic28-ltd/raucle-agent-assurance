# oaa-raucle-adapter

Evidence-plane adapter between the raucle policy gate and the Open Agent
Assurance companion core module set. SPDX Apache-2.0.

## What it provides

- `oaa_raucle_adapter.evidence_plane.EvidenceStore` — byte-verbatim
  `{receipt_hash, jws}` JSONL store with sha256 integrity on read-back.
- `oaa_raucle_adapter.evidence_plane.TrustRootRegistry` — versioned trust
  roots keyed `(key_id, valid_from, valid_until)`; retire = archive, never
  delete; keys selected by event time (the receipt's signed `iat`), so
  rotation never silently degrades historic receipts (ADR-0001 §2).
- `oaa_raucle_adapter.evidence_plane.classify()` — runs raucle's own
  `ProvenanceVerifier` and maps the outcome onto the ADR-0001 state space:
  valid | invalid | unknown_key | unsupported_schema | pending | unavailable |
  not_applicable.
- `oaa_raucle_adapter.fixture_gen` — deterministic conformance fixture
  generator built on raucle's real signing path (never hand-constructed JWS).

## raucle dependency — PIN AND INSTALL STATUS

raucle is an OPTIONAL dependency, imported lazily. Signature-verification
paths (classify, fixture generation) require it; the store/registry semantics
run without it (hence the raucle-free test suite in `tests/conformance`).

**Pin: raucle v0.23.5, git commit `63edacd`** — the version the fixtures,
findings and behaviour were verified against.

Install from ONE of, and document which you used when reporting results:

1. **Pinned git worktree** (preferred; this is what the 4 Nov spikes used):
   ```bash
   git -C ~/Projects/raucle worktree add ../raucle-63edacd 63edacd
   pip install -e ~/Projects/raucle-63edacd   # or PYTHONPATH it
   ```
   Do NOT point at a drifting main checkout — code-level findings were made at
   the pin and main has demonstrably drifted past `63edacd`.
2. **PyPI**: `pip install raucle==0.23.5` (verify the released tag matches the
   pin before use).

## Version provenance caveat

`raucle.__version__` is STALE (reported 0.22.0 at the 0.23.5 pin). Anything
recording `verifier_version` must key on this package's
`RAUCLE_DISTRIBUTION_PIN` constant ("raucle 0.23.5 (git 63edacd)"), not the
package constant.

## Usage

```python
import oaa_raucle_adapter as ep

store = ep.EvidenceStore(path)  # byte-verbatim canonical storage
reg = ep.TrustRootRegistry()
reg.add(ep.TrustRoot(...))
result = ep.classify(envelope_line, reg)  # raucle required
```

Fixture generation / full harness (raucle required):
`fixtures/` dir output:

```bash
python packages/raucle-adapter/examples/run_evd.py ./fixtures
```

## Tests

`tests/conformance/test_evidence_plane.py` needs no raucle (envelope shape,
digest integrity, event-time selection, rotation semantics from the committed
corpus). `tests/conformance/test_fixture_conformance.py` needs raucle and
SKIPs without it (recorded skip reason), so CI without the signed-key
environment stays green.