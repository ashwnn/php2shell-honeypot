# Validation status

Version 0.3.0, 2026-10-21.

## Successful user-run Docker verification

The user ran `sh scripts/check-docker.sh` on Docker Desktop's Linux engine and supplied its completed build/runtime output. This is user-provided execution evidence; the agent did not independently run the successful checks through its restricted Docker socket.

The run completed:

- Rust compilation, unit tests and process integration tests through `cargo test --locked`.
- Clippy through `cargo clippy --locked --all-targets`. Successful completion does not imply zero warnings; the build does not promote warnings to errors.
- The synthetic TLS smoke test: certificate verification, HTTP/1.1 ALPN, decrypted raw request capture, evidence digest and read-only database health.
- Production image compilation through `cargo build --release --locked`.
- A healthy network guard, plus HTTP and Cowrie container startup.
- Synthetic HTTP capture, SSH and Telnet password login and emulated commands.
- Persistence of those sessions/commands in the combined timeline.
- Denial of an outbound connection to a local synthetic test container.
- Cleanup of the isolated test containers, network and synthetic evidence volumes.

The smoke script reported:

```text
PASS: Rust HTTP, SSH + Telnet login/commands, persisted combined timeline, outbound connection denied
```

The tested dependency resolution was exported to the repository as `Cargo.lock`. The successful test image was `php2shell-tests:local`, manifest list digest `sha256:8e6f6d53f52279fea5707a7a5bc26da012cd82cd1c164c03f31b8628cdbc3848`. The production sensor image manifest list digest was `sha256:2e07b2be672285998b97d3ebec5a8196066c95fa3e14fb40d0b0d9a0339f29fb`. These identify that run's images, not future builds of the mutable local tags.

The preceding run compiled successfully but failed three fixtures that used temporary directories without guaranteed 0700 permissions. Fixtures now use collector-created evidence directories, including the process integration test. A regression test verifies private directory creation and rejection of an existing 0755 directory. The subsequent complete run above passed after that correction; runtime permission enforcement was preserved.

## Additional checks executed by the agent

- Static review of the Rust capture, evidence, timeline and terminal-display paths; a Luna agent independently reviewed code and researched operator documentation.
- Compose parsing for private, public and optional HTTPS configurations, including intended port mappings, shared guard networking and offline read-only tools.
- Python smoke-script syntax, shell-script syntax, manifest parsing and `git diff --check`.
- Synthetic in-memory SQLite checks for report/timeline SQL, legacy/new UTC timestamp ordering and oversized metadata handling. These check query semantics, not the Rust executable.
- Provider documentation lookup for Cowrie, T-Pot, SNARE and Shodan; see `docs/RESEARCH.md`.

GitHub Actions workflows remain removed. All verification is manual; no CI/CD job was triggered.

## Remaining deployment checks and limits

No VPS deployment, provider firewall configuration, external reachability check, packet capture, Shodan scan or indexing verification has occurred. Docker Desktop success does not replace verification on the target Linux VPS. The optional Compose HTTPS service was configuration-checked; the separate Rust TLS listener was runtime-tested. Production certificate provisioning and public TLS ingress remain deployment work.

The shell is Cowrie emulation, a separate upstream Python service. Captured commands show client input, not real execution on the VPS or successful PHP exploitation. The guard blocks initiated outbound connections but does not establish protection against kernel/container vulnerabilities. HTTP storage budgets are estimates rather than filesystem quotas. Cowrie logs, recordings and artifacts require an operator retention policy and dedicated disk quota.

Reports are bounded snapshots. Follow mode can miss intervening events or repeat events after rotation; missing close events do not prove a session is still connected. Raw captures intentionally retain credentials and hostile content. Terminal replay renders hostile terminal bytes. Keep evidence restricted and treat original logs/captures as authoritative.
