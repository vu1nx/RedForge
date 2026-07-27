# Dry Run

Use dry run to validate configuration, derive the actual plan, and inspect
static readiness without executing a scan:

```text
redforge scan authorized.example --dry-run
```

Dry run performs only:

1. command parsing;
2. explicit TOML loading and precedence resolution;
3. canonical target validation;
4. composition-profile selection;
5. deterministic planning;
6. plan-derived toolchain-manifest creation;
7. non-executing readiness checks.

It does not construct a pipeline, create a runtime `Context`, instantiate a
capability, execute an external tool, resolve a hostname, access a network
target, or publish state. Executable readiness uses static resolution only.

The immutable `ToolchainManifest` contains capability IDs in plan order and
deduplicated tool/provider requirements in first-required order. It contains
no executable paths, command arguments, adapter classes, environment details,
or target evidence.

## Output and exit status

Human output lists the canonical target, preset, composition profile, planned
capabilities, required tools/providers, and sanitized readiness failures.
Ready inspection exits `0`; non-ready inspection exits `3`. Configuration and
target errors retain the existing CLI exit contract.

Versioned JSON is available through:

```text
redforge scan authorized.example --dry-run --output json
```

The one stdout document uses `outcome: "dry_run"` and includes only:

- schema version and exit code;
- canonical target;
- preset and composition profile;
- planned capability IDs;
- required tool and provider IDs;
- bounded preflight summary.

It excludes executable paths, commands, environment values, credentials,
working directories, evidence, `Context`, and raw process output. Dry run does
not emit runtime lifecycle diagnostics because no runtime lifecycle exists.
Configuration errors and optional logging behavior retain normal stdout/stderr
isolation.

Dry run is not proof that a later external process or network service will
succeed. It checks availability, not tool-version compatibility, provider
credentials, DNS behavior, or target reachability.
