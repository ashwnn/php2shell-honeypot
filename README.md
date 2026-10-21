# PHP2Shell Honeypot

Version 0.1.0. A dependency-free Python 3.12+ HTTP/1.x decoy for collecting PHP2Shell-related probes and general PHP attack traffic. No PHP interpreter or uploaded code is executed. All paths return a generic upload page with Apache/PHP-looking headers.

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

## Container

```sh
mkdir -p data
sudo chown 65532:65532 data
chmod 700 data
docker compose up --build -d
docker compose logs -f
```

Compose binds localhost by default. Change the published address deliberately for an isolated sensor VM. Use a dedicated disposable VM outside production networks, deny outbound initiation and private-network access at the host/network boundary, and allow only inbound sensor ports plus established reply traffic. Container capability restrictions do not themselves enforce network egress isolation. Do not mount credentials, Docker sockets, or production files. The supplied image tag is mutable; pin the built image/base digest before repeatable deployment. Docker packaging was prepared but not executed in the build environment.

A reverse proxy/CDN can normalize malformed requests, block uploads, change chunking, and hide the real TCP source. Prefer direct termination for evidence fidelity. Forwarded headers are recorded as untrusted bytes and never replace the actual peer. No public deployment, firewall changes, or cloud resources have been created.

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
