# PHP2Shell Honeypot

Version 0.3.0 combines a custom Rust HTTP evidence sensor and offline timeline reporter with the official Cowrie SSH/Telnet emulated shell. The HTTP sensor records PHP2Shell-related probes and general HTTP attack traffic. Cowrie records login attempts and shell interaction. Neither service gives visitors a real host shell or executes captured HTTP uploads.

## Run the HTTP sensor locally

Rust 1.90 or newer and Cargo are required:

```sh
cargo run -- serve
# In another terminal
curl -F 'file=@README.md' http://127.0.0.1:8080/upload.php
cargo run -- report --data data --recent 10
```

The default listener is `127.0.0.1:8080`; the default evidence directory is `data/`. Give the sensor a dedicated ordinary directory with mode `0700`; do not point `--data` at a symlink or a directory containing unrelated files. Configuration options are available with `cargo run -- serve --help`.

## Full SSH and Telnet stack

For login, command, and terminal-session evidence, use Docker Compose on a dedicated Linux VM with Docker Engine and Compose v2:

```sh
docker compose up -d --build
docker compose ps
```

The private defaults publish HTTP on `127.0.0.1:8080`, SSH on `127.0.0.1:2222`, and Telnet on `127.0.0.1:2323`. Try the decoys locally with fabricated credentials:

```sh
curl -F 'file=@README.md' http://127.0.0.1:8080/upload.php
ssh -p 2222 root@127.0.0.1
# Enter a fabricated password; try: id, pwd, ls /, exit
telnet 127.0.0.1 2323
```

Cowrie is the official Python-based service inside the pinned Cowrie container. Its medium-interaction mode emulates a Unix shell and filesystem. Commands and terminal activity are evidence of what the client sent to the emulator; they do not show commands running on the VPS.

To publish on a disposable public VPS, first set up and test a separate administrator SSH management port through the provider console. The real SSH service must not share public TCP 22 with the decoy. Then follow [the VPS guide](docs/VPS.md), which uses `.env.vps` and the public Compose override. Public reachability can make a service eligible for scanning, but does not guarantee discovery or Shodan indexing.

## Watch and trace activity

Follow container logs and use the offline Rust reporter:

```sh
docker compose logs -f sensor ssh
docker compose run --rm -T tools --summary --format text
docker compose run --rm -T tools --follow --format text
docker compose run --rm -T tools --session SESSION_ID --summary --format text
docker compose run --rm -T tools --ip SOURCE_IP --indicators
```

The Rust `trace` command reads the HTTP database and Cowrie JSON logs without network access. Locally, point `--cowrie` at Cowrie's `var` directory (the one containing `log/cowrie`):

```sh
cargo run -- trace --http data --cowrie /path/to/cowrie/var --summary
cargo run -- trace --http data --cowrie /path/to/cowrie/var --follow
```

Use `--format text` for readable, line-oriented activity; it escapes attacker-supplied control characters, newlines and Unicode formatting characters before printing. The default format remains JSON for automation. `--follow --format text --session SESSION_ID` watches a selected session. Reports link events within observed Cowrie sessions, summarize logins and commands, filter by source IP/session/time, and optionally extract URL strings and IPv4 literals as passive indicators. The reporter never visits URLs or fetches payloads. IP/time correlation is a lead, not attribution or proof of successful PHP exploitation. Missing logs, malformed records, truncation, or event limits are surfaced as coverage warnings. Each Cowrie snapshot reads at most 64 MiB across all files, indexes at most 10,000 sessions, and retains at most 16 MiB of raw log records; parsed JSON and session summaries need extra memory. HTTP timelines independently cap retained output at 16 MiB. These are bounded views, not complete historical searches.

Cowrie terminal recordings can be replayed with Cowrie's packaged utility:

```sh
docker compose exec ssh /cowrie/cowrie-env/bin/python3 -m cowrie.scripts.playlog \
  /cowrie/cowrie-git/var/lib/cowrie/tty/RECORDING
```

Replace `RECORDING` with a file from Cowrie's TTY directory. Treat terminal output and uploaded/downloaded artifacts as hostile evidence. `docker compose down` retains named volumes; `docker compose down -v` deletes them.

## Evidence and privacy

Each accepted HTTP connection creates one byte-preserving `.raw` file and an indexed SQLite event. The raw capture includes request headers (including cookies and authorization values), body bytes, and HTTP chunk framing when present, within configured limits. The SQLite metadata retains duplicate-preserving headers. Routine `report` output omits headers, and the combined `trace` output redacts common credential fields and Cowrie messages by default. Original evidence remains unchanged.

Credential redaction cannot identify secrets embedded in arbitrary command text, URLs, or uploaded content. Use `--show-credentials` only when needed and restrict access to all reports and evidence. Store evidence on a restricted or encrypted volume, establish a retention policy, and archive the database and raw files together. SHA-256 hashes help detect changes against a trusted index copy; they are not a signed chain of custody.

The HTTP collector's default limits are 16 MiB per connection, 64 KiB of request headers, 30 seconds per request, four concurrent connections, and an estimated 4 GiB storage budget. The configured `max-bytes * max-connections` must fit a fixed 64 MiB aggregate raw-buffer budget; JSON, TLS and runtime allocations require additional memory. The budget is not a filesystem quota. Automatic deletion is disabled. Cowrie's logs, recordings, and artifacts need their own storage quota and retention policy. The guard drops newly initiated outbound connections, including DNS and payload downloads, while allowing replies to inbound connections. This does not protect against a host or container escape; use a disposable VM with no sensitive data.

The Cowrie emulation has a finite command set and fake filesystem. Download URLs can appear in recorded commands, but the sensor does not retrieve their content. HTTP, SSH, and Telnet are separate decoys; the HTTP service does not execute PHP or hand a web shell into Cowrie. The project does not prove exploitation or identify the person behind an address.

The CLI also supports HTTPS with user-provided certificate and key via `serve --cert ... --key ...`. TLS terminates in the sensor, which captures decrypted HTTP/1.1 bytes. Use a separate evidence directory for an HTTPS instance. The optional `compose.https.yaml` adds ports 443/8443 using operator-provided TLS files; see the VPS guide. Failed TLS handshakes are not application captures.

## Existing data and release checks

The v0.3 Rust collector uses the same `events` table column layout as the earlier HTTP collector, but the project has no general schema migration framework. Back up the SQLite database together with its `.raw` files before upgrading, and do not reuse an unknown or incompatible schema. Read-only reports do not create a missing database.

GitHub Actions has been removed; verification is manual to avoid consuming Actions credits. The user's Docker run passed Rust unit/process tests, Clippy, synthetic TLS verification, production image compilation and the HTTP/SSH/Telnet/egress smoke check. `Cargo.lock` contains the dependency resolution exported from that run. See [VALIDATION.md](VALIDATION.md) for evidence and remaining VPS deployment checks. Include the lockfile when committing or copying this project.

For the systemd HTTP-only option, see [deploy/README.md](deploy/README.md). For Cowrie/Docker source references and honeypot comparisons, see [docs/RESEARCH.md](docs/RESEARCH.md).

## Test and export

Use Docker for compilation, Rust unit/process tests and the TLS check, then exercise the local HTTP/SSH/Telnet stack:

```sh
sh scripts/check-docker.sh
```

No host Rust or `sshpass` installation is needed. The host needs Docker Engine/Compose and Python 3. Tests use an isolated Compose project and loopback ports; synthetic test volumes are removed afterward. A missing `Cargo.lock` is copied out of the tested image for review. This script requires access to the Docker daemon. The dedicated `Dockerfile.test` runs Rust/TLS tests during its build; the production image keeps those test dependencies out.


Run all checks manually on a network-enabled Linux machine with Rust 1.90+, Docker, Python 3, OpenSSL and `sshpass`:

```sh
sh scripts/check-local.sh
```

This uses an isolated Compose project on loopback ports 18080/12222/12323 and removes only that test project's synthetic volumes afterward. The script formats the Rust source and creates a missing lockfile; review those changes before committing. Individual checks:

```sh
cargo test
python3 scripts/smoke-tls.py target/debug/php2shell
docker compose --profile test up -d --build
python3 scripts/smoke-compose.py
docker compose --profile test stop probe
```

The Compose smoke check requires host Python 3 and uses local synthetic services only. It uses host `sshpass` when available and otherwise uses the test-only SSH client container. The full Docker check passed in the user's local run. See [VALIDATION.md](VALIDATION.md) for execution evidence and remaining deployment checks.

Stop active sessions before a consistent export; use the same Compose files and env file as the deployed stack:

```sh
mkdir -p exports
chmod 700 exports
docker compose stop sensor ssh
docker compose cp sensor:/data exports/http
docker compose cp ssh:/cowrie/cowrie-git/var exports/cowrie
docker compose start sensor ssh
```

For a TLS-enabled stack also stop/export/start `https` and include `--https /https` when invoking its `tools` reporter. A live SQLite copy needs the database and WAL together; copying a stopped collector is preferable. Keep exported credentials, recordings and payloads out of version control.
