# Kali Reconnaissance Smoke Validation

## Official phase result

```text
Reconnaissance infrastructure:
VALIDATED ON KALI

Controlled real-tool execution:
COMPLETED

Final result:
PARTIAL WITH SAFE, EXPLAINABLE MALFORMED-EVIDENCE SKIPS
```

This is a sanitized validation record for one explicitly authorized controlled
run. It intentionally retains no target, discovered hostname, address,
endpoint, technology name, raw process output, command line, environment
value, executable path, credential, or temporary-file path.

## Validation environment

- platform: Kali Linux rolling; the exact release/build identifier was not
  retained in the sanitized result;
- Python: a repository-supported CPython runtime (`>=3.12`); the exact
  interpreter version was not retained in the sanitized result;
- Subfinder: canonical tool identity `subfinder`; exact version not retained;
- HTTPX: canonical tool identity `httpx`, resolved to the ProjectDiscovery
  `httpx-toolkit` candidate after target-free identity validation; exact
  version not retained;
- Katana: canonical tool identity `katana`; the validated startup and adapter
  contract is Katana v1.6.1;
- WhatWeb: canonical tool identity `whatweb`; WhatWeb 0.6.4.

Versions not present in the sanitized execution summary are recorded as
unknown rather than inferred. RedForge still does not claim general version
compatibility ranges.

## Execution-chain verification

Readiness completed successfully before runtime. The planner produced, and the
runtime history preserved, this exact capability order:

| Order | Capability | Observed status | Execution boundary |
| --- | --- | --- | --- |
| 1 | `subdomain_discovery` | `SUCCESS` | Subfinder through `ToolRunner` |
| 2 | `host_resolution` | `SUCCESS` | injected resolver port |
| 3 | `http_probe` | `SUCCESS` | HTTPX through `ToolRunner` |
| 4 | `web_crawl` | `SUCCESS` | Katana through `ToolRunner` |
| 5 | `technology_detection` | `PARTIAL` | WhatWeb through `ToolRunner` |

All five planned capabilities executed once. The four external reconnaissance
tools used the production `ToolRunner` boundary; host resolution remained a
separate provider port. Tool identities did not become planner steps.

HTTPX executable resolution selected `httpx-toolkit` and rejected the
unrelated Python HTTPX command identity. Katana started successfully with the
minimal child environment retaining `HOME` and `USERPROFILE`. WhatWeb 0.6.4
numeric version values crossed the corrected bounded scalar-normalization path.

## Result interpretation

Technology detection returned usable evidence together with the typed safe
reason:

```text
malformed_records_skipped
```

This is legitimate partial evidence, not an infrastructure failure and not a
reason to weaken parsing. Malformed or unsupported records remained rejected;
valid evidence remained available for atomic `TECHNOLOGIES` publication. No
raw record was retained in the diagnostic event.

The aggregate runtime status was therefore `PARTIAL`. Because
`allow_partial_results` was disabled, application acceptance was `false`.
This is the intended separation: runtime reports execution truth, while the
application policy decides whether that result is accepted.

## Infrastructure corrections validated

The controlled validation cycle found and verified these narrow
infrastructure corrections:

1. Kali's ProjectDiscovery executable is commonly `httpx-toolkit`; ordered
   candidate resolution and bounded version-output identity validation now
   prevent collision with the unrelated `httpx` command.
2. Katana v1.6.1 requires a usable process home during startup; the minimal
   environment now retains `HOME` and `USERPROFILE`.
3. WhatWeb 0.6.4 may serialize versions as native JSON integers or finite
   floats; bounded numeric values now normalize deterministically without
   accepting booleans, non-finite values, collections, controls, or oversized
   evidence.
4. Typed PARTIAL reasons now cross the closed observability boundary as an
   explicit JSON string array without arbitrary metadata passthrough.

None of these corrections changed the dependency graph, capability status
precedence, publication rules, parser scope checks, or acceptance policy.
Parser strictness was not weakened to manufacture `SUCCESS`.

## Security assessment

The diagnostic event exposed only stable capability identity, typed runtime
status, and the allowlisted reason code. It did not expose target evidence,
URLs, technologies, stdout, stderr, argv, executable paths, environment,
temporary paths, provider exceptions, or object representations.

The final human/JSON result contract remained separate from diagnostics.
Diagnostics remained stderr-only, and their failure policy remained
non-semantic.

## Remaining limitations

- exact Kali, Python, Subfinder, and HTTPX version strings were not retained in
  the sanitized result;
- supported external-tool version ranges are not yet enforced;
- WhatWeb may legitimately remain PARTIAL when usable evidence coexists with
  malformed records;
- external execution is synchronous and sequential;
- subprocess output capture is bounded after process completion rather than
  streamed;
- there are no retries, resume, persistence, parallel execution, dynamic
  replanning, or report export.

## Future revalidation criteria

Repeat a controlled authorized Kali validation when any of these change:

- Kali distribution baseline or supported Python minor version;
- Subfinder, HTTPX, Katana, or WhatWeb major/minor version;
- executable-candidate or identity-validation policy;
- minimal child-environment policy;
- tool argv, output schema, parsing, scope, or status mapping;
- planner order, runtime publication, diagnostics, or acceptance semantics.

A future record should retain sanitized platform, Python, and tool versions
when available; pass readiness; execute the same five-capability closure in
planner order; preserve strict parsing; and confirm that diagnostics contain
only approved bounded fields.
