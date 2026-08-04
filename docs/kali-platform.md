# Kali Linux Platform Policy

Kali Linux is RedForge's primary supported execution platform and the official
target for external-tool integration. The five-capability reconnaissance chain
has completed controlled real-tool validation after correcting the HTTPX
executable-name collision, Katana startup environment, and WhatWeb numeric
version compatibility. The sanitized result is recorded in
[Kali Reconnaissance Smoke Validation](kali-smoke-validation.md).

Other Linux distributions may be compatible, but remain best effort until
explicitly validated. Windows remains supported for development, unit tests,
offline integration tests, and compatibility validation; it is not the primary
offensive-security execution platform. macOS currently has library-level
compatibility only.

Platform policy is confined to environment diagnostics and composition wiring.
Domain models, planning, capabilities, and runtime execution contain no
Kali-specific branches.

`redforge doctor` reads only bounded operating-system metadata. On Linux, its
platform adapter may read `/etc/os-release` directly with the standard library.
It does not execute a shell, inspect packages, read environment variables, or
expose file contents. Kali is `primary`; other Linux is `best_effort`; Windows
is `development`; macOS is `library_only`; unknown systems are `unsupported`.

External tools remain separately installed and maintained by the operator from
trusted upstream sources. RedForge does not install software, invoke package
managers, modify `PATH`, edit shell profiles, download releases, or elevate
privileges.

Kali may expose ProjectDiscovery HTTPX as `/usr/bin/httpx-toolkit`;
`/usr/bin/httpx` may instead be the unrelated Python HTTPX command-line client.
RedForge's canonical identity remains `httpx`. Infrastructure metadata declares
the ordered candidates `httpx-toolkit`, then `httpx`, and a bounded
ProjectDiscovery version-output identity check rejects name collisions. No
symlink, executable rename, wrapper, or `PATH` modification is required.
Detected versions remain compatibility-unverified until explicit supported
version constraints are defined.

The validated run resolved canonical `httpx` through `httpx-toolkit`, executed
all four external tools through `ToolRunner`, and completed with an honest
technology-detection `PARTIAL` carrying only
`malformed_records_skipped`. This validates the reconnaissance infrastructure,
not every future Kali or tool version.
