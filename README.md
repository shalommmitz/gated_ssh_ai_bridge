# gated_ssh_ai_bridge

A human-gated SSH bridge for AI-driven command execution.

Motivation: Allow OpenAi Codex (or another locally-run agents) to remotely (using SSH) debug issues, with step-by-step human approval.

The tool keeps a persistent SSH connection open, accepts structured JSON command requests from a local TCP socket, displays every command in a Textual TUI, and executes only after explicit human approval.

## Install

Use Python 3.11+.

```bash
python -m pip install paramiko textual
```

## Run

Password authentication:

```bash
python ssh_bridge.py --host 1.2.3.4 --user ubuntu --password-auth
```

Key authentication:

```bash
python ssh_bridge.py --host 1.2.3.4 --user ubuntu --key ~/.ssh/id_ed25519
```

Encrypted key:

```bash
python ssh_bridge.py --host 1.2.3.4 --user ubuntu --key ~/.ssh/id_ed25519 --key-passphrase
```

Startup authentication behavior:

- If the host or SSH service cannot be reached, the tool prints a short connection error and exits.
- If password authentication fails, the tool offers a retry and exits after 3 failed password attempts.
- If the server does not accept password authentication, the tool asks for a private key file.

By default the bridge listens on `127.0.0.1:8765`. The TUI owns the terminal, so agent messages are sent over TCP instead of stdin.

## Codex From Docker

When Codex runs inside Docker and the bridge runs on the Docker host, the container must be able to resolve a stable host name for the host gateway. Add this line to the `docker run` command in the `run_docker` script:

```bash
--add-host=host.docker.internal:host-gateway \
```

Codex can then reach the bridge at:

```text
host.docker.internal:8765
```

The bridge must also listen on an address reachable from Docker. `run_ssh_bridge` starts the bridge on the Docker bridge gateway address:

```bash
python ssh_bridge.py --host 1.1.1.1 --bridge-host 172.17.0.1 --bridge-port 8765
```

Replace `1.1.1.1` with the SSH target host.

## `run_ssh_bridge`

`run_ssh_bridge` is the host-side launcher for this setup. It does three things:

1. Removes any existing matching `docker0` firewall rules for port `8765` and the general `docker0` drop rule.
2. Inserts a rule that allows containers to connect only to TCP port `8765` on the host.
3. Inserts a following rule that drops other inbound traffic from `docker0`, then starts the SSH bridge bound to `172.17.0.1:8765`.

Current script:

```bash
#!/usr/bin/env bash
set -euo pipefail

while sudo iptables -D INPUT -i docker0 -p tcp --dport 8765 -j ACCEPT 2>/dev/null; do
  :
done

while sudo iptables -D INPUT -i docker0 -j DROP 2>/dev/null; do
  :
done

sudo iptables -I INPUT 1 -i docker0 -p tcp --dport 8765 -j ACCEPT
sudo iptables -I INPUT 2 -i docker0 -j DROP

python ssh_bridge.py --host 1.1.1.1 --bridge-host 172.17.0.1 --bridge-port 8765
```

Run it on the Docker host:

```bash
bash run_ssh_bridge
```

Check that it is listening:

```bash
ss -ltnp | grep 8765
```

Expected listener:

```text
172.17.0.1:8765
```

Environment changes used for this solution:

- Docker run includes `--add-host=host.docker.internal:host-gateway \`.
- The bridge is started with `--bridge-host 172.17.0.1 --bridge-port 8765`.
- Host firewall rules on `docker0` allow TCP `8765` and drop other inbound `docker0` traffic.
- The raw bridge port is not exposed to the public internet.

## Request Protocol

Send one JSON object per line:

```json
{"command":"pwd","purpose":"show the current directory","risk":"low"}
```

Valid risk values are `low`, `medium`, and `high`.

Health check without approval or SSH execution:

```json
{"type":"ping"}
```

Ping response:

```json
{"ok":true,"pong":true}
```

The raw line `ping` is also accepted.

Example with `nc`:

```bash
printf '%s\n' '{"command":"pwd","purpose":"show the current directory","risk":"low"}' | nc 127.0.0.1 8765
```

Example with Python:

```bash
python - <<'PY'
import json
import socket

request = {"command": "pwd", "purpose": "show the current directory", "risk": "low"}
with socket.create_connection(("127.0.0.1", 8765)) as sock:
    sock.sendall((json.dumps(request) + "\n").encode())
    print(sock.recv(65535).decode(), end="")
PY
```

Approved execution response:

```json
{"approved":true,"stdout":"...","stderr":"...","exit_code":0}
```

Rejected response:

```json
{"approved":false,"comment":"..."}
```

## Human Approval

For each request, the TUI displays:

```text
Command: <command>
Purpose: <purpose>
Risk: <risk>
```

Actions:

- `y` approves the command.
- `n` rejects it and prompts for feedback returned to the agent.
- `edit` lets the human edit the command, then approve or reject the edited command.

When editing, `USER` is treated as a placeholder for the real SSH username.

## Safety

The bridge never executes a command without explicit human approval.

It rejects malformed requests, overlong commands, multiline commands, and commands containing non-printable or non-ASCII characters.

It requires a second confirmation for:

- `rm -rf` / `rm -fr`
- `dd`
- `mkfs`
- `reboot`, `shutdown`, `poweroff`, `halt`
- `modprobe -r`
- unquoted command chaining operators: `&&`, `;`, `|`

The second confirmation requires typing `CONFIRM` exactly.

## Username Redaction

The SSH username is collected during login and retained only for the SSH connection. Responses and logs replace the username with `USER`.

Passwords are requested with `getpass`, are not logged, and are discarded after the SSH connection attempt.

## Logging

Audit logs are written to:

```text
ssh_bridge_log.jsonl
```

The log includes received requests, approvals, rejections, command results, stdout, stderr, exit codes, and shutdown events. Passwords and passphrases are never logged.

Use `--log-file` to choose another path.

## Useful Options

```bash
python ssh_bridge.py --help
```

Common options:

- `--bridge-host 127.0.0.1`
- `--bridge-port 8765`
- `--timeout 60`
- `--max-command-length 1000`
- `--no-agent`
- `--no-look-for-keys`

## Self Test

Run lightweight validation checks without connecting to SSH:

```bash
python ssh_bridge.py --self-test
```

## Design Note

This project uses a small JSON-lines bridge instead of full MCP JSON-RPC. That keeps the TUI cleanly in control of the terminal while still providing structured request and response messages for an AI agent.

## Author

Architecture: Shalom Mitz
Code: OpenAi Codex, using ChatGPT 5.4

## Licence

MIT
