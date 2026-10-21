# Honeypot design notes

Research reviewed 2026-10-21. This project combines an HTTP decoy with Cowrie's SSH/Telnet emulation and a local evidence reporter. The references below informed the boundaries and operator workflow; this is not a claim of equivalence with a full honeypot platform.

## Relevant projects

- [Cowrie documentation](https://docs.cowrie.org/en/stable/README.html) describes an SSH and Telnet honeypot that logs brute-force attempts and shell interaction. Its default medium-interaction mode emulates a Unix shell and filesystem. It retains downloaded/uploaded artifacts, JSON audit events, and replayable terminal sessions under `var/lib/cowrie/tty` using `playlog`. This matches the need to record command activity and inspect sessions while keeping attackers away from a real host shell. Cowrie's optional proxy/high-interaction and LLM modes have different risk and resource properties; this deployment uses the emulated shell.
- [T-Pot](https://github.com/telekom-security/tpotce) is a broad Docker-based platform with many honeypots, Elastic Stack, dashboards, and network-monitoring tools. Its documentation calls for substantial disk and memory, and its installer changes host settings including the SSH port. It is useful when an operator wants a full multi-sensor analysis stack; this smaller deployment keeps management-port changes manual and focuses on the PHP2Shell HTTP sensor plus SSH/Telnet evidence.
- [SNARE](https://github.com/mushorg/snare) is a web-application honeypot focused on generating an attack surface, with lightweight SNARE sensors and a TANNER decision-making service. It provides useful context for HTTP deception, but does not address the SSH command-session workflow this project emphasizes.

## Discovery and interpretation

An Internet-facing address and reachable ports make a sensor eligible to be observed by scanners; they do not guarantee that Shodan or another crawler will index it, when it will be crawled, or which service banner it will retain. The [Shodan on-demand scanning guide](https://help.shodan.io/the-basics/on-demand-scanning) says crawling is asynchronous and a scan request consumes one scan credit per IP. Operators can optionally request a scan of their own address with `shodan scan submit <your-public-ip>` after confirming the address and account credits. This asks Shodan to crawl; it is not a deployment check and does not guarantee a search result.

Treat recorded credentials, commands, uploaded files, and indicators as attacker-supplied evidence. A captured command shows what the client sent to the emulator, not that it ran on the VPS. The emulated filesystem and command set are finite, and outbound connections are dropped so payload-fetching commands will not retrieve remote content. A username, password, source IP, or command pattern cannot establish the attacker's identity. Correlating HTTP and SSH by IP/time is a lead, not proof that the same actor made both requests or that PHP exploitation succeeded.

## Primary references

- Cowrie project documentation, including features and file locations: <https://docs.cowrie.org/en/stable/README.html>
- Cowrie JSON event reference: <https://docs.cowrie.org/en/latest/OUTPUT.html>
- T-Pot project documentation and requirements: <https://github.com/telekom-security/tpotce>
- SNARE project documentation: <https://github.com/mushorg/snare>
- Shodan on-demand scan behavior and credits: <https://help.shodan.io/the-basics/on-demand-scanning>
- Shodan scan API requirements: <https://developer.shodan.io/api>
