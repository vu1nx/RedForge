# Kali Linux Platform Policy

Kali Linux is RedForge's primary supported execution platform and the official
target for external-tool integration and future controlled real-tool smoke
validation. This is a support policy, not a claim that the current release has
already completed real Kali smoke validation.

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
