# Systemd deployment: HTTP only

This systemd unit runs the custom Rust HTTP sensor on a dedicated Linux VM. It does not run Cowrie, provide SSH/Telnet honeypots, or install an egress firewall. For the full SSH/Telnet collection stack, use Docker Compose and [the VPS guide](../docs/VPS.md). Keep real administrator SSH restricted to a trusted address or private network.

Use a disposable VM without production data or credentials. Install Rust 1.90 or newer and Cargo on the VM, or build on a compatible Linux system. Building on macOS produces a macOS binary that will not run on Linux.

## Build and install

From the repository root:

```sh
rustc --version
cargo --version
cargo build --release
sudo useradd --system --no-create-home --shell /usr/sbin/nologin php2shell
sudo install -d -o root -g root -m 0755 /opt/php2shell-honeypot
sudo install -o root -g root -m 0755 target/release/php2shell /opt/php2shell-honeypot/php2shell
sudo install -m 0644 deploy/php2shell-honeypot.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now php2shell-honeypot
sudo systemctl status php2shell-honeypot
curl --fail http://127.0.0.1:8080/upload.php
```

Create the `php2shell` account only on first installation; reuse it for updates. The unit's `StateDirectory` creates `/var/lib/php2shell-honeypot` with mode `0700`, and `UMask=0077` restricts new files. Use a dedicated ordinary directory for evidence, never a symlink. The unit binds HTTP on all IPv4 interfaces at port 8080; allow inbound access through the VM/provider firewall only when intended. This unit does not expose port 22 or change the host's SSH configuration.

For a reproducible release build, generate and review `Cargo.lock`, commit it, then build with `cargo build --release --locked`. The repository includes the lockfile exported from the successful Docker test run; keep it with the source when deploying.

## Read and correlate evidence

```sh
sudo -u php2shell /opt/php2shell-honeypot/php2shell report \
  --data /var/lib/php2shell-honeypot --recent 10
sudo journalctl -u php2shell-honeypot -f
```

The `report` command opens SQLite read-only and never creates a missing database. For a local Cowrie installation, `trace --http /var/lib/php2shell-honeypot --cowrie /path/to/cowrie/var --summary` reads the Cowrie JSON logs under `var/log/cowrie`. This unit alone has no Cowrie source to correlate.

HTTP evidence consists of SQLite metadata and one `.raw` file per accepted connection. Preserve the database and raw files together. Raw captures may contain credentials, cookies, authorization headers, and uploaded content. Reports omit HTTP headers, while `trace` redacts common credential fields and Cowrie messages by default; arbitrary commands and URLs may still contain secrets. Restrict report access and set a retention period. A SHA-256 digest detects byte changes when checked against a trusted index copy, but does not create a signed chain of custody.

For HTTPS, the Rust CLI accepts `serve --cert /secure/fullchain.pem --key /secure/privkey.pem`; provide a separate `--data` directory for the HTTPS process. TLS terminates in the sensor and application evidence contains decrypted HTTP/1.1 bytes. The systemd unit does not configure HTTPS or obtain certificates. Docker users can add `compose.https.yaml` after provisioning TLS files; see the VPS guide.

## Limits and shutdown

The sensor does not execute uploaded PHP or visit URLs. Its default limits are 16 MiB per connection, 64 KiB headers, 30 seconds per request, four concurrent connections, and an estimated 4 GiB storage budget; the estimate is not a filesystem quota. The unit itself does not block outbound connections, so apply host/network egress controls separately if required. Public reachability may attract scanners but does not guarantee traffic or Shodan indexing.

Stop collection while preserving evidence:

```sh
sudo systemctl disable --now php2shell-honeypot
```

Remove public ingress rules separately. Before upgrades, stop the service and archive the database with its `.raw` files. The Rust collector retains the earlier HTTP `events` table layout but has no general schema migration framework; do not reuse an unknown or incompatible database. Never commit captured traffic, credentials, or private keys.
