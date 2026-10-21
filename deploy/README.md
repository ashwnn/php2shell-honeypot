# Deploy to a dedicated Linux VM

Target: a disposable, isolated VM with systemd and Python 3.12 or newer. No VM is provisioned by this project. Review resource billing with your provider. Do not run the sensor on the production application server.

Copy this repository to `/opt/php2shell-honeypot`, then run on the VM:

```sh
python3 --version
sudo useradd --system --no-create-home --shell /usr/sbin/nologin php2shell
sudo chown -R root:root /opt/php2shell-honeypot
sudo chmod -R go-w /opt/php2shell-honeypot
sudo install -m 0644 /opt/php2shell-honeypot/deploy/php2shell-honeypot.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now php2shell-honeypot
sudo systemctl status php2shell-honeypot
curl --fail http://127.0.0.1:8080/index.php
sudo journalctl -u php2shell-honeypot -f
```

The `useradd` command is for first installation only; reuse the existing service account for updates. Source is owned by root and evidence by the restricted service account. The service binds all IPv4 interfaces on port 8080. Expose it deliberately using the VM's network firewall. Keep SSH limited to your management IP or private management network. Deny outbound initiated connections and private-network destinations using the VM/network firewall while allowing established replies. The unit itself does not enforce egress filtering. Place evidence on a dedicated volume with a filesystem quota.

Public verification: make one synthetic request from a separate network to the VM's public address, then inspect the event and exact `.raw` file on the VM. A local curl response alone does not prove public reachability or persistence. Begin PCAP separately using the repository's capture script and monitor its loss counters.

For HTTPS, adapt ExecStart using the main README's `--cert`/`--key` options, port 8443, and readable certificate/key files provisioned for the service account. No automatic TLS provisioning, DNS setup or firewall mutation is included.

Read the evidence report:

```sh
sudo -u php2shell python3 /opt/php2shell-honeypot/honeypot.py report --data /var/lib/php2shell-honeypot
```

Stop and rollback:

```sh
sudo systemctl disable --now php2shell-honeypot
```

This preserves all evidence. Remove the public ingress rule separately. For a code update, stop the service, copy the reviewed source to `/opt/php2shell-honeypot`, run tests, then start it again. Archive evidence before changing its schema. Never commit captured traffic, private keys, or credentials to GitHub.
