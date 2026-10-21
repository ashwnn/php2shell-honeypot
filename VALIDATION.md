# Validation

Executed 2026-10-21, Python 3.12.14, localhost only.

- 14 asynchronous integration tests passed: ordinary GET, binary multipart upload, chunked body with trailers, duplicate headers, conflicting framing, truncated upload, read timeout, malformed chunk size, malformed request line, capture byte limit, quota shutdown, Expect: 100-continue, unframed multipart, and capacity rejection.
- Real CLI process tested with a temporary self-signed TLS certificate: HTTPS response received, plaintext HTTP raw evidence persisted, SQLite event stored, and read-only report CLI returned the event with TLS=true.
- SHA-256 and raw-byte equality checked for synthetic request captures.
- Docker and tcpdump were unavailable; container startup, packet capture and public ingress were not executed.
- No vulnerable PHP runtime, exploit replay, cloud deployment, or external active scan was used.

This is a functional initial collector, not a load-tested production deployment. Load testing, service supervision, alerts, dedicated disk quota, ingress/egress firewalling, certificate provisioning, retention operations and capture-drop monitoring remain deployment work. No claim of lossless capture, exploit confirmation, or post-exploitation visibility is made.
