# Canonical Finding Correlation and Aggregation

RedForge correlates normalized `FindingRecord` values through a pure,
provider-neutral domain service. Correlation is offline and deterministic. It
does not execute providers, publish runtime state, persist results, or change
the accepted `VULNERABILITIES` contract.

## Four identity layers

The domain keeps four concepts deliberately separate:

1. `FindingIdentity` identifies one normalized source finding using its
   classification and affected asset, endpoint, and technology.
2. `FindingFingerprint` is the exact SHA-256 fingerprint of that identity and
   detects exact semantic duplicates.
3. `FindingCorrelationKey` adds typed concrete and weakness references plus a
   normalized descriptive title for conservative pairwise comparison. It is
   not an alias of `FindingIdentity`.
4. `CanonicalFindingId` is the SHA-256 identity of an explicit canonical
   anchor. It never uses provider order, source record IDs, severity,
   confidence, evidence, provenance, or observation order.

## Concrete vulnerabilities and weakness classes

CVE, GHSA, and OSV references are concrete vulnerability identifiers in the
current policy. A shared concrete identifier can anchor correlation when the
affected subject is compatible.

RedForge does not yet resolve aliases between CVE, GHSA, and OSV. Each record
selects one deterministic primary concrete anchor using the documented scheme
priority. Automatic merging requires the same selected anchor on both records;
a shared secondary identifier is only `POSSIBLE`. This prevents a newly added
source from silently changing an established canonical ID.

CWE is a weakness classification, not a vulnerability instance identifier.
The same CWE may describe independent findings on one asset or across several
endpoints. CWE alone never creates a concrete anchor and never widens a match
to `STRONG`. Vendor and research URLs remain generic references; RedForge does
not assume that every advisory URL identifies exactly one vulnerability.

## Subject hierarchy and conflicts

The affected subject hierarchy is asset, then endpoint, then technology.
Correlation fails closed:

- different assets are `NO_MATCH`;
- conflicting explicit endpoints are `NO_MATCH`;
- conflicting explicit technologies are `NO_MATCH`;
- disjoint concrete identifier sets, or contradictory same-kind concrete
  identifiers, are `NO_MATCH`;
- incompatible classifications are blocking without a shared concrete
  identifier.

A shared concrete identifier may tolerate a missing endpoint or technology on
one side and produce `STRONG`, provided no explicit subject conflict exists.
Without that anchor, missing context produces at most `POSSIBLE`. Titles are
descriptive only: identical or normalized-equal titles cannot trigger an
automatic merge and no fuzzy title matching is performed.

## Match strengths and automatic merge

- `EXACT` means the fingerprint is identical, or a shared concrete identifier
  has the same asset and complete compatible subject.
- `STRONG` means a shared concrete identifier has compatible subject data with
  controlled missing context.
- `POSSIBLE` records a meaningful but insufficient signal and remains
  unmerged.
- `NO_MATCH` records unsafe, contradictory, or insufficient identity.

Only `EXACT` and conflict-free `STRONG` decisions merge automatically.
`POSSIBLE` never merges. When a missing-context record could bridge two
otherwise conflicting groups, it remains separate rather than joining them.

## Canonical anchors and stable IDs

Concrete groups use a common concrete identifier plus the canonical affected
subject as their anchor. Exact generic groups use normalized classification
plus the exact subject. Explicit endpoint and technology values are retained
when unambiguous; they are never dropped merely to widen correlation.

The canonical ID hashes an explicitly ordered JSON tuple of the anchor.
Input permutation, exact duplicate addition, provider changes, source record
IDs, severity, confidence, evidence summaries, evidence quality, and
provenance do not alter it. Adding another correlated source leaves the ID
unchanged while the common anchor remains unchanged.

## Aggregation and traceability

`CanonicalFinding` retains every distinct normalized source record. Exact
record duplicates collapse deterministically, while correlated non-identical
records remain individually traceable. Aggregates contain deterministically
ordered generic references, sanitized evidence summaries, detection methods,
provenance sources, observed severities, strongest categorical confidence,
strongest categorical evidence quality, and typed non-blocking conflicts.

`CanonicalFindingCollection` also retains deterministic unmerged pairwise
decisions so blocking conflicts and possible correlations remain visible.
Normal disagreements are typed domain values rather than broad exceptions.

## Runtime boundary

The provider-neutral `finding_correlation` capability consumes the existing
typed `VULNERABILITIES` state and delegates once to `FindingCorrelator`. It
atomically publishes a `CanonicalFindingCollection` as `CANONICAL_FINDINGS`.
Empty input is a successful empty publication; ordinary `POSSIBLE` and
`NO_MATCH` decisions remain domain results rather than runtime failures.

The capability contains no correlation policy, provider knowledge, I/O, or
Nuclei behavior. Planning derives the dependency from the default capability
definition rather than hard-coded application ordering.

CVSS, EPSS, and KEV are modeled by the separate downstream
[Vulnerability Enrichment](vulnerability-enrichment.md) architecture. Those
signals never affect correlation or canonical identity. Exploit intelligence,
Knowledge Graph integration, Risk
Intelligence integration, remediation, persistence, cross-scan storage,
cross-scheme alias resolution, distributed correlation, and AI reasoning
remain outside this boundary.
