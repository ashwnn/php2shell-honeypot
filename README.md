# PHP2Shell Honeypot

Version 0.2.0. A dependency-free Python 3.12+ HTTP/1.x decoy for collecting PHP2Shell-related probes and general PHP attack traffic. No PHP interpreter or uploaded code is executed. All paths return a generic upload page with Apache/PHP-looking headers.

## Start

```sh
python3 honeypot.py serve
# In another terminal:
curl -F 'file=@README.md' http://127.0.0.1:8080/upload.php
python3 honeypot.py report --recent 10
```

Default listener: localhost:8080. Default evidence directory: `data/`. Live events are JSON on stdout; send stdout to your existing log collector. No external telemetry, callbacks, DNS enrichment, URL fetching, or webhook delivery is implemented.

To monitor repeatedly on Linux:

```sh
watch -n 5 'python3 honeypot.py report --recent 5'
```

The report shows a bounded sample (latest 10,000 by default), signal counts, full observed headers, errors, and source endpoints. Report errors fail visibly instead of reporting an empty healthy dataset. A process supervisor must alert on `storage_failure`, `connection_rejected`, process exit, and absence of expected health checks. A rejected connection is printed to stdout, not inserted into the evidence database.

## Capture and evidence

Each accepted TCP connection gets one `.raw` file and an indexed SQLite record with UTC time, actual TCP peer/local endpoint, request target, duplicate-preserving headers, framing offsets when available, observed bytes, duration, signals, and SHA-256 of the raw file. Raw includes request headers, body, and HTTP chunk framing exactly as received by the application, up to configured limits. Uploaded files remain inert bytes inside the capture; filenames never become filesystem paths. No multipart parser rewrites evidence.

`complete` means the supported HTTP framing was fully read. It does not mean an exploit succeeded. The digest detects later byte changes when compared against a trusted index copy; it is not a signed chain of custody. Copy the database and raw files together using a SQLite-safe backup or while the collector is stopped.

Limits: 16 MiB per connection, 64 KiB request headers, 30 seconds total read time, 4 concurrent connections, 4 GiB conservative storage budget. Partial data is retained on parse failure, timeout, size limit or disconnect. Storage failure closes the listener, emits an error and stops new capture. Already active connections may still fail to save; full-disk capture cannot be lossless. The storage budget reserves 16 KiB per event for index overhead and is deliberately conservative. This is not a filesystem hard quota; apply a dedicated volume quota as well. Automatic deletion is disabled. Stop collection, archive evidence to restricted storage, then start with a new `--data` directory.

```sh
python3 honeypot.py serve --host 0.0.0.0 --port 8080 \
  --max-bytes 16777216 --timeout 30 --max-connections 4 --quota-mib 4096
```

Increasing concurrency and capture size increases memory demand. Capture uses bounded in-memory buffers; plan approximately several times `max-bytes * max-connections` plus runtime and socket overhead. The Docker resource cap can terminate an overcommitted sensor, losing in-flight evidence.

## HTTPS

Provide your own certificate and private key; no certificate issuance is automated.

```sh
python3 honeypot.py serve --host 0.0.0.0 --port 8443 \
  --cert /secure/fullchain.pem --key /secure/privkey.pem
```

TLS terminates at the sensor, so application evidence contains decrypted HTTP bytes. It negotiates HTTP/1.1 only. Failed TLS handshakes do not create application evidence; use packet capture for them. Run separate instances with separate data directories for HTTP and HTTPS. TLS client fingerprints and full handshake metadata are not extracted.

## Packet capture

On a Linux host with tcpdump installed:

```sh
sudo sh scripts/capture.sh eth0 /secure/pcap
```

The script records TCP ports 8080/8443 with full snap length and a 32 x 100 MB rotating ring. Adapt the filter to the actual public ports and interface, including 80/443 if forwarded there. PCAP records retransmissions, rejected connections, and TLS handshake traffic; HTTPS application content is encrypted there. Monitor tcpdump's dropped-packet counters. Rotation overwrites old packets. Check the capture service account can write the destination before use. Packet capture requires host privileges; the application does not.

## Docker Compose: HTTP + SSH

Run on a dedicated Linux Docker Engine VM with Compose v2. No host-directory ownership setup is required; evidence lives in persistent named volumes.

```sh
git clone https://github.com/ashwnn/php2shell-pot.git
cd php2shell-pot
docker compose up -d --build
```

This starts a PHP-looking HTTP decoy on `127.0.0.1:8080` and a Cowrie SSH decoy on `127.0.0.1:2222`. Cowrie accepts any attempted password and provides an emulated shell/filesystem; the visitor never receives a host shell. Try locally:

```sh
curl -F 'file=@README.md' http://127.0.0.1:8080/upload.php
ssh -p 2222 root@127.0.0.1
# Enter any made-up password, then: id, pwd, ls /, exit
```

For public exposure on the isolated VM, use:

```sh
BIND_ADDRESS=0.0.0.0 docker compose up -d --build
```

For persistent configuration, copy `.env.example` to `.env` and edit its address/ports. Keep the host's real SSH management port separate and limited to your management address or private network. `SSH_PORT` is the attacker-facing honeypot, not administrator SSH. Do not map it to the port currently used to administer your VM. No public deployment was performed by this change.

The guard service installs an outbound firewall inside a shared container network namespace. The decoys have no NET_ADMIN capability; only the guard has it. New outbound connections are dropped, including DNS, downloads, reverse connections and loopback requests; established replies to inbound sessions remain allowed. IPv6 is disabled in that namespace. Cowrie SSH forwarding is disabled. Failures installing the guard rules prevent the decoys from starting. This does not protect the host from a container/kernel escape; use a disposable VM and a dedicated evidence disk. Linux Docker Engine is the supported target; rootless Docker, Desktop networking, and restrictive managed runtimes may need adaptation. If the guard is recreated, recreate the decoys together with `docker compose up -d --force-recreate`.

The SSH service records login attempts, accepted credentials, source addresses, session IDs, commands, terminal recordings and supported file-transfer artifacts. Referenced download URLs remain in command logs, but outbound payload fetching is blocked. Upload artifacts are retained without being executed by a host shell. Cowrie shell emulation has finite command support. HTTP and SSH are separate decoys on the same address; the PHP endpoint does not execute an exploit or automatically hand a web shell into SSH.

### Inspect and trace activity

```sh
docker compose ps
docker compose logs -f sensor ssh
docker compose run --rm -T tools --indicators
docker compose run --rm -T tools --ip 198.51.100.7 --indicators
docker compose run --rm -T tools --session SESSION_ID
docker compose run --rm -T tools --since 2026-10-21T00:00:00Z
docker compose run --rm -T tools --follow
```

`tools` reads both volumes without network access or write access to evidence. It produces one UTC timeline, links SSH events within an observed session, and filters source IPs across HTTP and SSH. It extracts observed HTTP/FTP URL strings and IPv4 literals from request targets and SSH commands as passive indicators. It never visits them. This is not exhaustive payload IOC extraction, network-path tracing, geolocation, or identifying a real person behind a VPN/NAT. Matching source IP/time is a correlation lead, not proof of the same actor or successful PHP exploitation.

Credentials are redacted in reports by default; use `--show-credentials` only when needed. Original Cowrie evidence intentionally keeps the attempted credentials. HTTP raw captures retain headers/body even though the combined summary omits arbitrary headers. Coverage warnings report absent sources, truncated log tails, malformed lines and event limits. No events can mean no activity; missing files mean unknown coverage. Follow mode scans bounded recent snapshots and can miss events between scans or repeat events after rotation; raw logs remain authoritative.

### Export and replay

```sh
mkdir -p evidence
chmod 700 evidence
docker compose run --rm -T tools --indicators > evidence/timeline.json
# Run after stopping sessions when a consistent evidence snapshot is required:
docker compose cp sensor:/data evidence/http
docker compose cp ssh:/cowrie/cowrie-git/var/log/cowrie evidence/ssh-logs
docker compose cp ssh:/cowrie/cowrie-git/var/lib/cowrie/tty evidence/tty
docker compose cp ssh:/cowrie/cowrie-git/var/lib/cowrie/downloads evidence/artifacts
# Replay a captured terminal recording using Cowrie's packaged tool:
docker compose exec ssh /cowrie/cowrie-env/bin/python3 /cowrie/cowrie-git/bin/playlog /cowrie/cowrie-git/var/lib/cowrie/tty/RECORDING
```

`docker compose down` keeps volumes. `docker compose down -v` deletes the evidence. Compose stdout logs rotate separately from persistent evidence. The HTTP sensor has a conservative storage budget; Cowrie log/TTY/artifact storage needs a dedicated volume quota and an operator retention policy. Neither the guard nor reporter adds a hard Cowrie disk quota. Read-only SQLite reports need the live database/WAL files together.

### Test the stack

```sh
docker compose --profile test up -d --build
# Host test dependency on Debian/Ubuntu: sudo apt-get install sshpass
python3 scripts/smoke-compose.py
docker compose --profile test stop probe
```

The smoke check makes a synthetic HTTP request, logs into Cowrie, runs harmless exploration commands, confirms their persisted timeline, and checks outbound denial against a local test container. No internet target is used. The `probe` service is test-only and publishes no ports.

Source references: [Cowrie Docker configuration](https://docs.cowrie.org/en/latest/docker/README.html), [Cowrie configuration defaults](https://github.com/cowrie/cowrie/blob/main/src/cowrie/data/etc/cowrie.cfg.dist), [official Cowrie image](https://hub.docker.com/r/cowrie/cowrie). Cowrie is pinned to the inspected 3.1.3 image digest; review/re-pin for updates. The Python/Alpine base tags remain mutable.

## Detection basis and limits

Vendor advisories, reviewed 2026-10-21:

- [CVE-2026-109618 / GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w): OOM corruption; multipart header multiplication, empty file controls, nested names and content-length handling can contribute to memory exhaustion.
- [CVE-2026-109619 / GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp): stale request-owned global state; exploitation requires a producer and later consumer in the same PHP worker. Upload progress is one relevant consumer path.

Signals flag multipart requests, missing multipart content length, at least 16 empty filenames, at least 64 `[` bytes, at least 128 header-like body lines, the default upload progress marker, and simple code/command markers. These thresholds are project heuristics, not vendor signatures. Ordinary uploads can trigger them. Absence of signals is not evidence of benign traffic. Marker matching examines raw body bytes, so chunk boundaries, compression, encoding, or renamed settings can hide markers. No claimed reliable exploit classifier is included.

This low-interaction decoy cannot reproduce PHP heap behavior, prove exploitation, capture executed commands, or emulate a persistent PHP worker. It closes after one request per connection; pipelined bytes already read are retained with an extra-byte count, but later requests are not processed. HTTP/2, HTTP/3, WebSockets and arbitrary protocols are not supported. Missing-length multipart streams are read until EOF or deadline and recorded as unframed. Attackers may fingerprint the simple response. Pair it with packet capture for transport-level visibility.

Raw evidence intentionally retains attacker-supplied cookies, authorization headers, and uploaded content to support the stated capture goal. Restrict access, use encrypted storage, establish a retention period, and treat files and terminal output as hostile evidence. No raw payload is rendered as HTML or executed. JSON output escapes control characters.

## Verification

```sh
python3 -m unittest discover -s tests -v
```

Tests use synthetic requests against ephemeral localhost listeners. They do not replay exploits or contact external targets. See `VALIDATION.md` for executed checks and deployment limitations.
