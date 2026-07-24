# Security Knowledge Graph

TASK-0014 constructs an immutable, deterministic graph snapshot from RedForge's
existing intelligence read models. It performs no external I/O and requires no
adapter.

## Current graph

The graph represents only relationships already established by previous
capabilities:

```text
Asset
  |
  | observed_technology
  v
Technology observation
  |
  | matches_vulnerability
  v
Vulnerability
```

Asset nodes retain the original snapshot-local `Asset` identity. Technology
nodes represent exact immutable observations, including their source and
evidence. Vulnerability nodes retain canonical vulnerability knowledge.

Technology-to-vulnerability edges preserve the `ProductIdentifier`, match
method, identity-match confidence, and evidence created by Vulnerability
Intelligence. CVSS and match confidence remain provider metadata; neither is
RedForge risk.

## Identity semantics

Graph node identifiers are deterministic within the knowledge snapshot:

- Asset node identity derives from the existing snapshot-local Asset identifier.
- Technology observation identity is a SHA-256 digest of the complete immutable
  observation. It is not a durable product identity.
- Vulnerability identity derives from its canonical vulnerability identifier.

The graph does not create persistent cross-scan identity. Graph persistence and
cross-scan reconciliation require a separate, explicitly designed milestone.

## Conservative relationship policy

The capability never infers ownership:

- An Asset-to-Technology edge requires an existing `AssetAssociation`.
- A Technology-to-Vulnerability edge requires an existing
  `VulnerabilityAssociation` and referenced Vulnerability.
- A vulnerability relationship without an Asset relationship remains valid but
  unowned.
- Dangling or invalid relationships are skipped and produce a `PARTIAL` result.

Hosts and endpoints remain part of Asset identity. Services, findings, and
evidence remain independent because no explicit ownership relationships exist
for them yet.

## Non-goals

TASK-0014 does not implement:

- a graph database or persistence;
- query or traversal frameworks;
- graph mutation;
- risk scoring;
- attack paths;
- service or finding ownership inference;
- durable Technology or cross-scan Asset identity;
- reporting or visualization.

The read model is intended as the input to the next Risk Intelligence
capability while remaining suitable for later persistence through an adapter.
