# Public VPS deployment

Use a disposable Linux VPS with Docker Engine and Compose v2.24.4 or newer, a dedicated evidence disk if practical, and no production data or credentials. This guide publishes the honeypot on the VPS's public IPv4 address. Provider firewall rules must allow the intended public TCP ports; compose port mappings alone do not override provider firewalls.

## Protect management access first

The public compose override publishes TCP 22 for the SSH honeypot. Before starting it, arrange a separate administrator SSH port, for example TCP 64295, using the VPS provider console and the provider's documented procedure. Add and test the new management firewall rule and an administrator login in a second session before closing the existing session. Keep provider console access available. This project does not edit `sshd`, firewall rules, or provider settings automatically. Ensure public port 22 can safely be assigned to the decoy before proceeding.

## Configure and start

From the repository root on the VPS:

```sh
cp .env.vps.example .env.vps
${EDITOR:-vi} .env.vps
docker compose --env-file .env.vps -f compose.yaml -f compose.public.yaml config
docker compose --env-file .env.vps -f compose.yaml -f compose.public.yaml up -d --build
docker compose --env-file .env.vps -f compose.yaml -f compose.public.yaml ps
```

Review `.env.vps.example` and set the required public bind address and port values before launch. The public override defaults to TCP 80 and 8080 for HTTP, 22 and 2222 for SSH, and 23 for Telnet. Keep the internal application ports and guard networking as defined by Compose. The private base configuration defaults to host loopback bindings `127.0.0.1:8080`, `127.0.0.1:2222`, and `127.0.0.1:2323`; use the public override only on the isolated VPS.

Open only the needed ports in the provider firewall. Keep the actual management SSH port restricted to your trusted source address or private network. Confirm HTTP and SSH honeypot reachability from a separate network. Telnet sends credentials in clear text by protocol design; keep the VPS disposable and use unique fabricated credentials when testing.

## Optional HTTPS coverage

To add TCP 443 and 8443, provision `fullchain.pem` and `privkey.pem` in `./tls` (or set `TLS_DIRECTORY` in `.env.vps`). The unprivileged sensor runs as uid/gid 65532: that identity must be able to traverse the mounted directory and read both files. Keep the private key restricted to that identity; do not make it world-readable. Use a certificate for your decoy domain if you have one. A self-signed certificate also offers a TLS service but will not be trusted by browsers. No certificate issuance is automated.

Append the TLS file to **every** subsequent Compose command for that stack:

```sh
docker compose --env-file .env.vps -f compose.yaml -f compose.public.yaml -f compose.https.yaml config --quiet
docker compose --env-file .env.vps -f compose.yaml -f compose.public.yaml -f compose.https.yaml up -d --build
docker compose --env-file .env.vps -f compose.yaml -f compose.public.yaml -f compose.https.yaml run --rm -T tools --https /https --summary
```

Allow those TLS ports in the provider firewall and verify from another network. This is a separate HTTP/1.1 sensor with its own persistent evidence volume and the same egress guard. TLS evidence is decrypted application bytes; failed TLS handshakes appear only in diagnostic logs/packet capture. Restart `https` after changing its certificate files.

If the guard network container is recreated, recreate all decoys together with `up -d --force-recreate` using the same Compose file set. Stop and archive data before an upgrade. Health checks verify database readability, not public listener reachability: verify ingress from a second network and monitor process exits, quota errors, evidence disk use, and guard health separately. Cowrie needs a dedicated evidence filesystem quota; Compose memory limits do not limit its disk use.

## Observe and inspect

```sh
docker compose --env-file .env.vps -f compose.yaml -f compose.public.yaml logs -f sensor ssh
docker compose --env-file .env.vps -f compose.yaml -f compose.public.yaml run --rm -T tools --summary --format text
docker compose --env-file .env.vps -f compose.yaml -f compose.public.yaml run --rm -T tools --follow --format text
docker compose --env-file .env.vps -f compose.yaml -f compose.public.yaml run --rm -T tools --session SESSION_ID --summary --format text
docker compose --env-file .env.vps -f compose.yaml -f compose.public.yaml run --rm -T tools --ip SOURCE_IP
docker compose --env-file .env.vps -f compose.yaml -f compose.public.yaml run --rm -T tools --indicators
```

The text view shows `LOGIN`, `COMMAND`, `CONNECTED`, `DISCONNECTED`, recording paths and passive file-transfer references. To focus the live view, combine `--follow --format text --session SESSION_ID`. Text output escapes terminal control sequences from hostile input; JSON remains the default for exports.

Add `--show-credentials` only when credential values are needed for a specific investigation. Treat the output and persistent Cowrie evidence as sensitive. The reporter correlates recorded events and displays attacker-supplied activity; it does not run captured commands or visit extracted URLs.

Cowrie's terminal recordings can be replayed with its packaged `playlog` command:

```sh
docker compose --env-file .env.vps -f compose.yaml -f compose.public.yaml exec ssh \
  /cowrie/cowrie-env/bin/python3 -m cowrie.scripts.playlog \
  /cowrie/cowrie-git/var/lib/cowrie/tty/RECORDING
```

Replace `RECORDING` with a recording filename from Cowrie's persistent TTY directory. Replay output is hostile terminal content; do not paste it into a shell. For evidence export, first stop the services to get a consistent copy, then copy the named volumes using the commands in the project README and store the export in access-controlled storage.

## Discovery and limits

Publicly reachable services may be found by Internet scanners. Shodan indexing is asynchronous and not guaranteed. If desired, and if the account has scan credits, an operator can request a scan of their own public address using Shodan's CLI: `shodan scan submit <your-public-ip>`. Shodan documents one scan credit per IP and asynchronous results. Verify the address belongs to your VPS before submitting; a scan request is optional and does not itself prove that the honeypot is functioning.

SSH and Telnet use Cowrie's finite emulated shell and fake filesystem. The host shell is never exposed to visitors, and outbound connections are blocked, including payload downloads. Commands shown in reports are observed input, not proof of execution or compromise. IP/time matches across protocols do not prove common identity. No VPS address was supplied for this documentation task, so no deployment, scan, or live exposure check was performed.

Stop containers while retaining evidence:

```sh
docker compose --env-file .env.vps -f compose.yaml -f compose.public.yaml down
```

Do not add `-v` unless you intend to delete the evidence volumes. Remove public provider firewall rules separately when taking the VPS offline.

For crawler visibility, use the VPS's directly reachable public address and allow the intended service ports. An HTTP CDN, web challenge, or reverse proxy can hide the decoy banner or client address. A domain with a DNS A record is optional for IP-based service scanning. Do not publish real credentials, expose evidence volumes, or open a public analyst dashboard. These services can collect automated traffic, but cannot establish whether a remote client was controlled by an AI agent or a person.
