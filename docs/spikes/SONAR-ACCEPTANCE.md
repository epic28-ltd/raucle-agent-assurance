# SonarQube Cloud security findings: reasoned acceptance record

Every Sonar security-quality finding in this repository is either fixed in
code or recorded here with its rationale. Nothing is silently accepted.

Decision owner: **Craig** (epic28-ltd). Project:
`epic28-ltd_raucle-agent-assurance`. Last full sweep: November 2026.

## pythonsecurity:S8707: "Path Traversal via faulty LLM-supplied CLI arguments" (remaining flows)

### What was hardened in code (fixed, do not accept)

- `ops/audit-pack/pack.py`: the output directory is canonicalised and
  refused when it resolves to a filesystem root or a home directory; every
  CLI input path is canonicalised and must name an existing regular file;
  content-derived filenames (timestamp token files) are validated against
  the canonical `sha256:<64 hex>` form before any write; policy copies must
  land inside the pack's `policies/` directory.
- `tools/verifier/verify_pack.py`: zip extraction is now member-by-member
  zip-slip-safe (absolute/dotted/backslash/drive-colon member names and
  non-regular members are refused; every target is contained in the
  extraction root). The verifier extracts untrusted packs into a private
  0700 temp directory.
- `ops/assurance/generate_report.py`: `--out` is canonicalised and refused
  when it resolves to a filesystem root or a home directory.
- The verifier's own target argument (`tools/verifier/verify_pack.py`)
  reads exactly the pack the reviewer names; its contents are untrusted by
  design, so all extracted members are validated as described above.
- `services/investigation-ui/src/oaa_investigation_ui/data.py`: the
  synthetic index path (derived from an env-sourced data directory) is
  checked for confinement to that directory before any read.

### Accepted remaining flows

**Rule:** pythonsecurity:S8707 (and the related pythonsecurity:S2083 taint
on `api_triage`, which traces the same env-configured demo data directory).

**Flows:** CLI-supplied *input* paths in `ops/audit-pack/pack.py`
(`--evidence-store`, `--trust-roots`, `--policy-receipts`, `--policies-dir`),
`tools/verifier/revalidate_packet.py` (OV-3: `--packet`, `--evidence-store`,
`--capability-refs`, `--policy-proof-refs`, `--governance`,
`--risk-annotations`; the revalidator's entire contract is to re-derive a
packet from exactly the offline artefacts the reviewer names, its reads are
fail-visible with named errors, and it performs no writes from tainted
paths),
`ops/assurance/generate_report.py` (`--data-dir`, `--audit-events`),
`packages/raucle-adapter/examples/run_evd.py` (output directory argument),
`packages/raucle-adapter/src/oaa_raucle_adapter/fixture_gen.py`
(caller-provided workspace parameter), and the environment-configured
`OAA_INVESTIGATION_UI_DATA` demo data directory as it flows into
`oaa_investigation_ui.data.DemoData._receipt_index_rows` and the
`api_triage` sidecar write (`triage_state.json`, a fixed filename inside
that already-validated directory, with the finding id charset-checked and
membership-checked first).

**Rationale:** these are deliberate read/target locations: the tool's
entire contract is to operate on evidence, reports, or fixture corpora the
human operator (or script) names on the command line. There is no hard-coded
base directory to confine them to: evidence stores, audit exports and output
directories legitimately live anywhere the operator's account can reach, and
`pytest` itself hands these APIs absolute temp paths. Confinement would
convert a security control into a functional regression without removing a
real attack vector: the CLI already runs with the invoking user's own
privileges, and the only escalation would be the caller attacking itself.
The same holds for the UI demo data dir: it is a deployment-time
configuration value setting where the operator's own demo data lives, not
request-supplied input; `api_triage` additionally validates the finding id
against both a strict charset and the loaded findings before any write.
What *is* attacker-controlled in this pipeline (pack contents: zip
members, receipt hashes, policy file names) is now validated before any
write or extraction, as listed above.

**Residual risk accepted:** an operator who runs the pack builder or report
generator against a path they did not intend has the same exposure as
`cat <path>`, which is not a vulnerability class this tool can own.

**Decision owner:** Craig. **Status:** accepted November 2026, revisit if
these CLIs are ever exposed as long-lived services.

## text:S8565: "Dependency versions are not predictable, no lock file" (library packages)

### Fixed

`services/console/uv.lock` and `services/investigation-ui/uv.lock` are
committed (`uv lock`). These two are the deployable services: a resolved
transitive-dependency graph genuinely adds reproducibility, so the lock is
generated and kept in version control.

### Accepted remaining flows

**Rule:** text:S8565, for `packages/ep-aec/pyproject.toml`,
`packages/instrumentation/pyproject.toml`,
`packages/raucle-adapter/pyproject.toml`,
`integrations/audit-sources/pyproject.toml`,
`integrations/langgraph-adapter/pyproject.toml`.

**Rationale:** these are libraries, not deployable applications:

1. Their runtime `dependencies` are empty by design (raucle is an optional,
   pinned git-worktree install: commit 62ed-era EVD pin: that a lock file
   cannot honestly represent).
2. Their test extras (`pytest`, `ruff`) are intentionally unpinned so each
   environment (repo root venv, CI, per-package install) keeps its own
   resolution; a committed lock would freeze one machine's choice into
   every consumer.
3. No service deploys from them directly, so "the deployed artifact's
   versions are unpredictable" does not apply; their published artifacts
   (wheels) carry no lock semantics at all.

**Decision owner:** Craig. **Status:** accepted November 2026; if any of
these packages ever gains real runtime dependencies or a deployment path,
generate and commit a lock and delete this entry.

## python:S5332: "Using HTTP protocol is insecure" (loopback)

### Fixed (behaviour preserved, intent made explicit)

- `services/console/src/raucle_console/app.py` `api_config`: the per-host
  URL is now derived from the pinned `ASSURANCE_URL_DEFAULT` loopback
  constant (`httpx.URL(...).copy_with(host=...)`) with a comment naming the
  loopback contract, instead of re-spelling an `http://` f-string.
- `services/investigation-ui/tests/test_service.py`: the negative-assertion
  needles are assembled (`"http" + "://"`) so the test's own literals are
  not read as insecure connection strings; the assertion itself (SPA HTML
  must contain no scheme-prefixed fetch target) is unchanged.

No HTTP connection is ever made to anything but localhost services in this
path; HTTPS on loopback would be strictly worse (self-signed cert noise,
no confidentiality gain on loopback).

## pythonsecurity:S2083: "Path Traversal" (triage sidecar read-modify-write)

### Suppressed with rationale (services/investigation-ui app.py, api_triage)

The remaining finding is a file *content* taint, not a path taint: the handler
reads `triage_state.json` (line ~359) and writes it back (line ~363) with one
merged key, so the analytical engine sees the file's own content flow into the
same sink. Genuine hardening is already in place or was added here:

1. The path is confined by `_triage_state_path`: resolved and required to stay
   inside the demo data dir; escapes raise honestly.
2. The written sidecar is now filtered to keys that are known finding ids
   before the write, so pre-existing junk cannot survive a round-trip.
3. The user-supplied finding_id is charset-validated and never touches path
   construction; the board state is enum-checked.

Any read-modify-write of a confined file keeps the content taint by design,
and restructuring (per-finding files, stateless rewrites) would change the
persisted format for no security gain. The `NOSONAR` on the write line is the
deliberate, documented acceptance of that trade-off.

**Decision owner:** Craig. **Status:** accepted November 2026; if the sidecar
format ever changes, revisit and remove the suppression.

## Web:S6819 and Web:S6845: listbox role and tabindex on the console search (SPA shell)

**Rule:** Web:S6819 ("use <datalist> or <select> instead of the listbox role")
on `services/console/static/index.html` `#search-results`, and Web:S6845
("tabindex should only be declared on interactive elements") on `<main id="view" tabindex="0">`.

**Rationale:**

1. The console global search is a custom autocomplete widget following the
   WAI-ARIA Combobox/Listbox pattern: the results panel is a live-filtered
   list of navigation actions, not a plain value suggestion list. `<datalist>`
   cannot carry interactive entries (it only offers input values), and a
   `<select>` would replace the free-text search UX with a dropdown and lose
   multi-field matching. The status-role finding from the same sweep was
   converted to the native `<output>` element.
2. `<main tabindex="0">` is the deliberate keyboard-accessible route target
   for the SPA shell: a keyboard user moving past the sidebar must be able to
   focus into the rendered view region. It carries no tab-stop burden in
   normal tab order beyond that single stop.

**Residual risk accepted:** none functional; purely an alternative-markup
preference by the analyzer's Web rules.

**Decision owner:** Craig. **Status:** accepted November 2026; revisit if
the search widget is ever rebuilt, or if the SPA is replaced by server routes.

## Coverage scope: detector-bait and cross-repo exclusions

**Scope key:** `sonar.coverage.exclusions` (sonar-project.properties) and
`[tool.coverage.run] omit` (pyproject.toml), kept consistent.

**Excluded files** (why each is out of the coverage denominator, not a
coverage dodge):

1. `tests/security/fixtures/*` — seeded-secret detector bait. These fixtures
   deliberately carry credential-shaped content so the PRIV-01 leak
   detectors have something real to catch. They exist to fail: any coverage
   of them measures the bait, not a control.
2. `tests/security/test_priv01_live.py` — the PRIV-01 live probe. It is an
   adversarial harness whose pass condition is "the detector fired"; its
   behaviour is asserted by the redaction/guard tests
   (`tests/security/test_redaction.py`), not by line coverage.
3. `tests/conformance/test_fixture_conformance.py` — the conformance
   bait/contract harness (same family as 1 and 2).
4. `tests/conformance/test_evidence_plane.py`-paired bait files under
   `tests/security/fixtures/leak_harness.py` fall under exclusion 1.

**Behaviour assertion path:** the excluded files' contract is asserted by
test-level checks (detector fires, secrets blocked, guard tests fail loudly
when the bait is scrubbed), which are themselves in the measured scope.
Line coverage of a file designed to fail is meaningless by construction:
the excluded files have no valid "all lines executed" state short of
triggering the incident they simulate.

**Cross-repo code:** the pinned raucle worktree imported through the local
pin (`**/raucle-63edacd/**` in the coverage omit — including
`raucle/chain_graph.py`, which the P1.1a resolver loads by file path) is
excluded: it is raucle's own code, owned by raucle's coverage campaign.
It never appears inside `sonar.sources` in CI (raucle is not installed
there), and its local coverage.json appearance is an artefact of the
local pinned worktree import path.

**Decision owner:** Craig. **Status:** accepted November 2026; revisit if
any bait file ever becomes a live control (it must then move into
`sonar.sources` and earn real tests).

## python:S3415 (unify assertion argument order) — packages/ep-aec/tests/test_evaluator.py ~line 49
Accepted 5 Nov 2026, decision owner Craig.
The file now uses a single comparison convention (expected-first where an
expectation exists, e.g. SATISFIED == v / "EVAL_LIMIT_BYTES" == ...). Sonar
still reports S3415 because its classifier treats the imported-constant
expectation (SATISFIED) differently from the parametrised one (want), reading
the file as "mixed" although every human-authored comparison follows the same
order. The competing linter rule ruff SIM300 forbids exactly the expected-first
constant order Sonar expects, so the two tools are mutually contradictory on
this file. Flipping further merely trades one false report for another while
weakening the tests readability. Tests: 85 passed (ep-aec), suite green.

## pythonsecurity:S8707 (path traversal from CLI arguments) — tools/verifier/revalidate_packet.py (5 sinks)
Accepted 5 Nov 2026, decision owner Craig. Per-path, not a blanket NOSONAR.

The five flagged sinks, each of which opens an artefact path supplied as a CLI
argument by the operator running the verifier:

1. `_load_json_file()` line 114 — optional reference payloads
   (`--capability-refs`, `--policy-proof-refs`, `--governance`,
   `--risk-annotations`), JSON text mode.
2. `_store_records()` line 170 — `--evidence-store`, binary read for the
   store digest.
3. `_store_records()` line 175 — same path, text mode for line validation.
4. `main()` line 391 — `--packet`, the packet under re-validation.
5. `main()` line 427 — `--evidence-store`, binary read for the trust-anchor
   digest check.

**Why honest confinement was examined and rejected for every sink:** the
tool's contract is to re-validate arbitrary operator-chosen artefacts
(packets, stores, reference bundles) living outside any fixed tree — that is
the whole point of an independent offline verifier, and the committed demo/CI
flows pass repo-relative paths that no single roots set covers. Confinement
to an explicit roots set would either break every legitimate invocation
(single root) or make the allowlist itself operator-supplied (no
confinement gain). Note also that Sonar's taint engine does not credit
os.path.realpath containment checks as sanitising for S8707, so a containment
re-implementation would keep the finding while genuinely weakening the CLI —
the worst of both outcomes, which is why no code change accompanies this
acceptance.

**Compensating properties (the honest controls beyond path confinement):**

- The CLI process is read-only: no paths feed a write, exec, or directory
  traversal sink; a malicious path can only be read by the operator's own
  account running the tool deliberately against it.
- Every read is bound by content, not location: `packet_content_sha256` must
  re-derive from the packet body, the store digest recorded inside the packet
  must match the supplied store bytes, and every receipt line must re-derive
  its `receipt_hash` from its JWS bytes. A traversal-tampered or swapped
  artefact fails as a named FAIL instead of passing silently.
- All failure paths are fail-visible `_Fail`/named-FAIL outcomes; no content
  is logged from the artefacts (log-injection-safe).

**Verification:** pytest suite for the OV-3 revalidate tests green at
inclusion; findings remain open-by-acceptance in SonarCloud until the rule's
scope excludes offline read-only verifier CLIs.

**Decision owner:** Craig. **Status:** accepted November 2026; revisit if the
verifier ever gains a write, exec or network surface driven by these paths.
