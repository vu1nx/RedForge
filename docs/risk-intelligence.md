# Risk Intelligence

TASK-0015A transforms explicit Security Knowledge Graph paths into deterministic,
explainable investigation priorities. It is a read model: it does not infer
compromise, reachability, exploitability, or missing graph relationships.

## Input and graph behavior

The capability consumes `PipelineStateKey.KNOWLEDGE_GRAPH` and assesses only
correctly directed `Asset -> Technology -> Vulnerability` paths. Invalid or
dangling relationships are skipped, valid assessments are preserved, and the
capability returns `PARTIAL`.

Input outcomes are intentionally distinct:

- a missing Knowledge Graph state key is `FAILURE` with empty output;
- a value of the wrong type is `ERROR` with empty output;
- a legitimate empty `KnowledgeGraph` is `SUCCESS` with empty output.

Each unique graph path produces one immutable assessment. Its SHA-256 identifier
depends only on the three graph node identifiers. Results sort by descending
priority and then stable graph identifiers; confidence is not a tie-breaker.

## Priority, confidence, and completeness

These are separate measures:

- `priority_score` is vulnerability investigation magnitude from provider
  evidence only. A valid CVSS base score maps linearly from 0.0–10.0 to 0–70.
  If CVSS is unavailable or invalid, qualitative severity is the fallback:
  `LOW=15`, `MEDIUM=35`, `HIGH=55`, `CRITICAL=70`, `UNKNOWN=0`.
  CVSS and severity are never added together.
- `confidence_score` describes correlation evidence, not risk probability.
  Identity confidence maps `HIGH=100` and `MEDIUM=60`; valid technology
  detection confidence retains its 0–100 value. Two available components are
  integer-averaged, one is used directly, and no components produce zero.
- `data_completeness` gives 25 points for each available component: usable CVSS
  or severity, identity-match confidence, technology-detection confidence, and
  the explicit Asset-to-Technology relationship. A valid assessment therefore
  has 25, 50, 75, or 100 percent completeness.

No confidence, completeness, endpoint, or data-quality factor changes priority.
Missing data never subtracts priority points. `DATA_QUALITY` factors contribute
zero and name the absent explicit fields.

Endpoint presence is contextual evidence only. It contributes zero and does not
establish internet exposure, attacker reachability, external availability,
network-zone placement, or current reachability. RedForge does not inspect
endpoint details to infer those properties.

Risk levels for known vulnerability-magnitude evidence are:

| Priority score | Level |
| ---: | --- |
| 0–19 | `LOW` |
| 20–39 | `MEDIUM` |
| 40–59 | `HIGH` |
| 60–100 | `CRITICAL` |

`UNKNOWN` does not mean numerically low priority. It means neither a valid CVSS
score nor known qualitative severity is available. Confidence, completeness,
and endpoint presence or absence do not determine `UNKNOWN`.

## Determinism and limitations

Providers are not called during scoring. Input ordering and duplicate edges do
not change output. Factors and evidence are immutable. The current maximum
priority is 70 and is not normalized to 100.

The capability owns validation of its Knowledge Graph prerequisite. The
pipeline publishes `SUCCESS` and `PARTIAL` output, preserves capability results
in execution history, aggregates `PARTIAL`, `FAILURE`, and `ERROR` globally, and
stops on `FAILURE` or `ERROR`. See the
[Execution Contract](execution-contract.md).

EPSS, KEV, threat intelligence, attack paths, exploit prediction, remediation,
persistence, reporting, workflow orchestration, and durable cross-scan identity
are outside this milestone.
