# Minimal CLI

RedForge provides a deliberately small application-facing command line:

```text
redforge --help
redforge scan --help
redforge scan authorized.example
redforge scan authorized.example --preset reconnaissance
redforge scan authorized.example --preset full --allow-partial-results
redforge scan authorized.example --output json
python -m redforge.cli scan authorized.example
```

Only scan systems you are explicitly authorized to assess.

The CLI is an adapter over the application API. It validates the target through
the canonical `ScanConfig` model, selects requested output presets, runs
readiness preflight, and renders the immutable `ScanResult`.

It does not contain scan-planning or execution business logic. It does not
plan, build pipelines, execute capabilities, or inspect Context directly.

## Presets and safety defaults

`reconnaissance` is the default preset and requests canonical technology
evidence. `full` requests canonical risk intelligence. Full execution also
requires the separately configured vulnerability provider and all tools in its
dependency closure; the default local composition reports missing provider
readiness honestly rather than fabricating one.

Built-in `ScanLimits` defaults are always applied. This first CLI exposes no
flags for increasing limits, timeouts, concurrency, tool arguments, providers,
credentials, proxies, executable paths, retries, reports, or configuration
files. Targets containing URL syntax, paths, credentials, wildcards, or IP
literals are rejected by the canonical DNS-target validator.

`--allow-partial-results` changes acceptance only. It does not alter runtime
status, dependencies, limits, or stop behavior.

## Output and exit codes

`--output human|json` selects the representation explicitly; human is the
default. Human mode retains its stdout/stderr split. JSON mode writes one
versioned document to stdout for every handled outcome and leaves stderr empty;
the exit code remains authoritative. Its schema version is independent from
the package version. See [Deterministic JSON Output](json-output.md).

Neither mode contains raw evidence, subprocess output, environment values,
credentials, temporary paths, or exception details.

| Code | Meaning |
| ---: | --- |
| 0 | Scan result accepted |
| 2 | Invalid command or scan configuration |
| 3 | Composition or readiness requirement unavailable |
| 4 | Scan completed but its result was not accepted |
| 5 | Unexpected internal invariant failure |
| 130 | Interrupted by the operator |

The CLI currently provides no JSON file output, evidence report export,
interactive prompts, configuration-file loading, environment-driven
configuration, persistence, retry, parallel execution, dynamic replanning, or
cancellation of work already running inside a capability. It does not verify
target ownership.
