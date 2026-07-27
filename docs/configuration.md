# Typed Configuration

RedForge accepts one explicitly named UTF-8 TOML document:

```bash
redforge scan authorized.example --config redforge.toml
```

The target is intentionally CLI-only. Configuration files are reusable and
cannot silently select an authorization-sensitive scan target.

## Boundary and flow

```text
explicit TOML path
        |
        v
tomllib parser
        |
        v
strict internal mapping validation
        |
        v
RedForgeConfiguration
        |
        +-- ScanConfig
        +-- CompositionProfile
        +-- OutputFormat
        +-- ObservabilityLevel
```

`redforge.configuration` owns parsing, typed models, validation, and pure
translation. It does not construct registries, providers, adapters, runners,
or an orchestrator. `ApplicationComposition` continues to own wiring, and the
CLI consumes typed values without inspecting TOML dictionaries.

There is no default-file search, working-directory discovery, home-directory
lookup, environment override, stdin input, URL loading, include, merge,
interpolation, templating, or remote configuration.

## Schema version 1

`schema_version` is a mandatory integer:

```toml
schema_version = 1

[scan]
preset = "reconnaissance"
allow_partial_results = false

[scan.limits]
max_subdomains = 1000
max_hosts = 1000
max_alive_hosts = 500
max_http_endpoints = 1000
max_crawl_endpoints = 5000
max_technologies = 500
overall_timeout_seconds = 900

[composition]
profile = "reconnaissance"

[output]
format = "human"

[observability]
level = "off"
```

The five sections are optional and use typed defaults; the schema version is
not optional. Unknown keys at every supported level, duplicate TOML keys,
wrong primitive types, aliases, and unsupported versions are rejected.
Strings are not coerced to numbers or booleans.

This configuration schema version is independent from both the package version
and the JSON output schema version. RedForge performs no automatic schema
migration.

## Values and defaults

Supported scan presets are `reconnaissance` and `full`. Supported composition
profiles are `reconnaissance` and `full_assessment`. Supported output formats
are `human` and `json`. Supported observability levels are `debug`, `info`,
`warning`, `error`, and `off`.

The defaults preserve the no-file CLI contract:

- reconnaissance scan and composition profiles;
- partial-result acceptance disabled;
- human output;
- observability off;
- the existing validated `ScanLimits` defaults.

Limits reuse `ScanLimits` validation and bounds. They are application
publication and deadline policy—not arbitrary tool arguments. Provider
credentials, provider class names, executable paths, tool IDs, retry counts,
concurrency, rate limits, report paths, and persistence options are not part of
schema version 1.

The composition profile must support the scan preset. A full composition can
run reconnaissance, but reconnaissance composition cannot run a full scan.
Selecting a valid full configuration does not invent a vulnerability provider:
composition succeeds and preflight reports that provider as unavailable.

## CLI precedence

Resolution is deterministic:

```text
explicit CLI option > configuration value > application default
```

Only supplied `--preset`, `--allow-partial-results`, `--output`, and
`--log-level` options
override the document. Omitted argparse options remain unset and therefore do
not mask file values. Limits currently have no CLI flags.

`--config` may appear once and requires a normal filesystem path. `-`, URLs,
directories, and multiple configuration files are rejected; there is no
multi-file merge.

## Errors and safety

Expected file, TOML, version, unknown-field, value, and profile failures use
typed errors with stable `configuration_*` reason codes. Human mode writes a
concise message to stderr and exits 2. If `--output json` was explicitly
selected before loading, the same failure becomes one schema-versioned JSON
document on stdout with empty stderr.

Messages do not contain file contents, absolute paths, tracebacks, exception
reprs, or environment values. Unknown-field messages may include only the
sanitized field path. Parser-level failures, such as a missing `--config`
value, remain command-line usage errors.

Loading reads only the requested file as UTF-8 and performs no writes, network
access, PATH inspection, environment expansion, argv parsing, composition,
preflight, or provider construction. This narrow behavior is not a claim that
the loader protects against every malicious filesystem condition.

See the safe reusable example at
[`examples/redforge.toml`](../examples/redforge.toml).

`--dry-run` does not alter configuration precedence or schema. The CLI first
loads and resolves the same typed configuration, validates the canonical
target, and only then asks composition for an execution-free inspection.
Configuration failure therefore occurs before PATH inspection, planning
readiness, runtime state, or tool work. See [Dry Run](dry-run.md).
