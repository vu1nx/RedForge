# Minimal CLI

RedForge provides a deliberately small application-facing command line:

```text
redforge --help
redforge scan --help
redforge scan authorized.example
redforge scan authorized.example --preset reconnaissance
redforge scan authorized.example --preset full --allow-partial-results
redforge scan authorized.example --output json
redforge scan authorized.example --config redforge.toml
redforge scan authorized.example --log-level info
python -m redforge.cli scan authorized.example
```

Only scan systems you are explicitly authorized to assess.

The CLI is an adapter over the application API. It validates the target through
the canonical `ScanConfig` model, selects an explicit
[composition profile](application-composition.md), delegates construction, and
renders the immutable `ScanResult`.

It does not contain scan-planning or execution business logic. It does not
plan, build pipelines, execute capabilities, or inspect Context directly.

## Presets and safety defaults

`reconnaissance` is the default preset and requests canonical technology
evidence through the reconnaissance composition profile. `full` requests
canonical risk intelligence through `full_assessment`. Full execution also
requires a separately supplied vulnerability provider; the composition
framework reports missing provider readiness honestly rather than fabricating
one.

The CLI constructs no ToolRunner, tool or capability registry, readiness
registry, probe, provider, or capability factory. Its lazy default factory asks
`ApplicationComposition` for one profile-scoped `ScanOrchestrator`.

Without a configuration file, built-in `ScanLimits` defaults are applied.
One explicit schema-versioned TOML document may supply the scan preset,
partial-result policy, limits, composition profile, and output format:

```text
redforge scan authorized.example --config redforge.toml
```

Only explicitly supplied `--preset`, `--allow-partial-results`, `--output`,
and `--log-level` values override the file. Omitted parser options do not mask
file values.
`--config` may appear once; stdin, URLs, directories, discovery, environment
overrides, and multi-file merging are unsupported. The target remains a
required positional argument and is never read from configuration. See
[Typed Configuration](configuration.md).

The CLI exposes no flags for increasing limits, concurrency, tool arguments,
providers, credentials, proxies, executable paths, retries, or reports.
Targets containing URL syntax, paths, credentials, wildcards, or IP literals
are rejected by the canonical DNS-target validator.

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

## Structured diagnostics

Diagnostics are off by default. `--log-level
debug|info|warning|error|off` selects the minimum typed severity and overrides
the TOML `[observability]` level. There is no `-v`, progress mode, log file,
environment override, root-logger configuration, or remote telemetry.

When enabled, each bounded diagnostic event is one compact JSON record on
stderr. Human scan summaries remain on stdout. With `--output json`, stdout
still contains exactly one final machine-outcome document; diagnostic records
never mix into it. Repeated in-process `main()` calls create isolated dedicated
loggers without accumulating handlers. See
[Structured Observability](observability.md).

| Code | Meaning |
| ---: | --- |
| 0 | Scan result accepted |
| 2 | Invalid command or scan configuration |
| 3 | Composition or readiness requirement unavailable |
| 4 | Scan completed but its result was not accepted |
| 5 | Unexpected internal invariant failure |
| 130 | Interrupted by the operator |

Typed configuration failures use exit 2. Human mode emits a concise sanitized
stderr message; explicitly selected JSON mode emits one error document to
stdout with a stable `configuration_*` reason code. Argparse failures remain
command-line usage errors.

The CLI currently provides no JSON file output, evidence report export,
interactive prompts, environment-driven or implicit configuration,
persistence, retry, parallel execution, dynamic replanning, or cancellation
of work already running inside a capability. It does not verify target
ownership.

## Dry run

`redforge scan authorized.example --dry-run` uses the same target,
configuration, preset, profile, output-precedence, and readiness contracts as a
scan, but stops before pipeline construction. It creates no `Context`, executes
no capability or external tool, performs no DNS resolution or target network
access, and publishes no state.

Human output lists only the canonical target, selected preset/profile, planned
capability IDs, required tool/provider IDs, and sanitized readiness results.
`--dry-run --output json` emits one `dry_run` document on stdout with the same
bounded fields. Ready inspection exits 0; non-ready inspection exits 3.
Commands, executable paths, environment values, evidence, and raw process
output are never rendered. See [Dry Run](dry-run.md).

## Controlled local smoke profile

The `local_smoke` composition accepts a complete, explicit origin such as
`http://lab.redforge.test:8080` and requires
`composition.expected_ip = "127.0.0.1"`. It preserves the scheme and port
through discovery, probing, crawling, and technology detection. See
[Controlled Local Smoke Test](local-smoke-test.md). This profile never invokes
Subfinder; it does not bypass readiness inspection for HTTPX, Katana, or
WhatWeb.

## Doctor

`redforge doctor` accepts no target and inspects static platform, runtime,
registry, composition, configuration, and executable-availability metadata.
It supports `--profile reconnaissance`, `--profile full_assessment`, and
`--output human|json`. Exit 0 means ready, 3 not ready, 5 internal failure, and
130 interrupted; parser errors remain 2. It creates no scan state and performs
no DNS, network, scan, installation, or remediation. See
[RedForge Doctor](doctor.md).
