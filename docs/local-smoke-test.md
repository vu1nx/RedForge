# Controlled Local Smoke Test

RedForge provides an explicit `local_smoke` composition profile for one
authorized loopback HTTP origin. It is deliberately separate from production
reconnaissance composition: discovery and host resolution are static,
network-free providers, while HTTPX, Katana, and WhatWeb remain behind their
normal `ToolRunner` ports.

The profile requires a complete URL with an explicit port and a loopback
address:

```toml
schema_version = 1

[scan]
preset = "reconnaissance"
allow_partial_results = false

[scan.limits]
max_subdomains = 1
max_hosts = 1
max_alive_hosts = 1
max_http_endpoints = 1
max_crawl_endpoints = 10
max_technologies = 100
overall_timeout_seconds = 120

[composition]
profile = "local_smoke"
expected_ip = "127.0.0.1"
```

For the controlled lab, add this explicit hosts-file mapping:

```text
127.0.0.1 lab.redforge.test
```

Start the local server from the directory containing `page.html`:

```text
python -m http.server 8080 --bind 127.0.0.1
```

The proposed inspection and smoke commands are:

```text
python -m redforge.cli scan http://lab.redforge.test:8080 --config redforge-local-smoke.toml --dry-run
python -m redforge.cli scan http://lab.redforge.test:8080 --config redforge-local-smoke.toml
```

The first command performs readiness inspection and the second performs the
controlled execution. Neither is run as part of implementation validation.

The four capability stages are discovery, HTTP probing, crawling, and
technology detection; static host resolution is an internal prerequisite.
Discovery performs no subprocess, DNS, or network operation. The only external
tool targets are:

```text
HTTPX stdin:   http://lab.redforge.test:8080
Katana stdin:  http://lab.redforge.test:8080
WhatWeb argv:  http://lab.redforge.test:8080
```

Subfinder is not invoked by this profile. Production reconnaissance continues
to select the existing Subfinder adapter.

Before each external-tool invocation, the adapter verifies the exact hostname,
resolved address, scheme, and port. Only `lab.redforge.test`,
`127.0.0.1`, `http`, and `8080` are valid for this configuration. Output
evidence from another origin, including a redirect, is rejected. HTTPX is
configured not to follow redirects, Katana receives one exact seed, and WhatWeb
receives one exact base target. No port 80, port 443, HTTPS URL, additional
hostname, or additional address is synthesized.

This profile does not weaken the normal authorization and preflight gates. It
does not install tools, start the server, edit the hosts file, perform DNS
lookups, or execute a scan automatically.
