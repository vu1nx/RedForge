# RedForge Doctor

`redforge doctor` performs deterministic, target-free local readiness
diagnostics:

```text
redforge doctor
redforge doctor --profile reconnaissance
redforge doctor --profile full_assessment
redforge doctor --output json
python -m redforge.cli doctor
```

The default profile is `reconnaissance`. `local_smoke` is intentionally not a
doctor option because that composition requires an explicitly authorized exact
target, while doctor never accepts or constructs target data.

Doctor checks bounded platform classification, current Python implementation
and version, package import, registry integrity, selected composition,
registry-derived executable availability, typed default configuration, and
readiness metadata alignment. Required checks may be `ready`, `warning`,
`unavailable`, `incompatible`, `misconfigured`, or `error`. Required `ready`
and `warning` checks permit an overall ready result; any other required status
makes the environment not ready.

Windows and unvalidated Linux distributions are warnings; missing required
tools still make reconnaissance not ready. Full assessment currently reports
the missing vulnerability provider as expected readiness debt.

The reconnaissance inventory is derived from canonical factory requirements
and ToolRegistry definitions. It currently resolves to Subfinder, HTTPX,
Katana, and WhatWeb. Host resolution is a provider port, not an executable.
Future canonical tool requirements appear without doctor-specific branches.

Availability checks use the existing static readiness boundary without
executing tools. Production doctor currently does not run version commands.
The provider-neutral version-probe contract supports injected bounded,
target-free probes, but verified compatibility ranges do not yet exist, so
compatibility remains `unverified`; an unknown exact version alone does not
fail doctor.

Doctor performs no user configuration discovery. It never creates
`ScanConfig`, Context, an execution plan, a pipeline, or a scan result. It does
not resolve DNS, contact a target or network service, execute reconnaissance
tools, inspect environment secrets, install software, modify `PATH`, or perform
automatic remediation.

Human output is the default. JSON uses independent
`DOCTOR_JSON_SCHEMA_VERSION = 1`, one newline-terminated document, fixed key
order, explicit DTOs, and null fields for unavailable error data. It contains
no target, path, environment value, command, raw output, exception text,
Context, or ScanResult.

| Exit code | Meaning |
|---:|---|
| 0 | Environment ready |
| 2 | Invalid command |
| 3 | Environment not ready |
| 5 | Unexpected internal failure |
| 130 | Interrupted |

Doctor performs no installation and prints no automatic installation commands.
