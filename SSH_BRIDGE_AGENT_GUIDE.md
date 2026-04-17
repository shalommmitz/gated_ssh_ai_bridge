# SSH Bridge Agent Guide

Use this file when an AI agent needs to work on a remote computer through
`gated_ssh_ai_bridge`.

The bridge is a human-gated SSH command service. You send one JSON request to a
local TCP socket. A human sees the command in the bridge TUI and must approve,
edit, or reject it before anything runs over SSH.

## Non-Negotiable Rules

- Use the SSH bridge for remote work. Do not bypass it with direct `ssh`, `scp`,
  `rsync`, cloud consoles, or other remote execution paths unless the human
  explicitly tells you to.
- Never assume a command ran until you receive an approved response from the
  bridge.
- Send one command at a time and wait for the response before planning the next
  remote action.
- Every request must include a clear `purpose` and an honest `risk` value.
- Do not include passwords, passphrases, tokens, private keys, cookies, or other
  secrets in command text, purposes, logs, comments, or summaries.
- Treat the username placeholder `USER` as redacted. Do not try to recover or
  reveal the real SSH username.
- Prefer inspection commands before write commands. Avoid destructive commands
  unless they are necessary and clearly explained.
- If the human rejects or edits a command, respect that decision and continue
  from the returned result or comment.

## Connection

The bridge should already be running before you use it.

Default local endpoint:

```text
127.0.0.1:8765
```

When you are running inside Docker and the bridge is on the Docker host, use:

```text
host.docker.internal:8765
```

If connection fails, try a health check first. If that also fails, ask the human
which bridge host and port to use. Do not debug or restart the bridge unless the
human explicitly asks you to.

## Health Check

Send either raw `ping` or a JSON ping request. Ping does not require human
approval and does not execute SSH.

```bash
python3 -c 'import socket; s=socket.create_connection(("127.0.0.1",8765),timeout=5); s.sendall(b"{\"type\":\"ping\"}\n"); print(s.recv(65535).decode(), end=""); s.close()'
```

Expected response:

```json
{"ok": true, "pong": true}
```

If you are inside Docker, replace `127.0.0.1` with
`host.docker.internal`.

## Request Protocol

Send exactly one JSON object per line.

Required fields:

- `command`: the exact single-line shell command to run on the remote host.
- `purpose`: why this command is needed.
- `risk`: one of `low`, `medium`, or `high`.

Example request:

```json
{"command":"pwd","purpose":"Show the current remote working directory before making changes.","risk":"low"}
```

Example sender:

```bash
python3 -c 'import json,socket; req={"command":"pwd","purpose":"Show the current remote working directory before making changes.","risk":"low"}; s=socket.create_connection(("127.0.0.1",8765),timeout=5); s.sendall((json.dumps(req)+"\n").encode()); print(s.recv(65535).decode(), end=""); s.close()'
```

Inside Docker:

```bash
python3 -c 'import json,socket; req={"command":"pwd","purpose":"Show the current remote working directory before making changes.","risk":"low"}; s=socket.create_connection(("host.docker.internal",8765),timeout=5); s.sendall((json.dumps(req)+"\n").encode()); print(s.recv(65535).decode(), end=""); s.close()'
```

## Responses

Approved command:

```json
{"approved": true, "stdout": "...", "stderr": "...", "exit_code": 0}
```

Rejected command:

```json
{"approved": false, "comment": "..."}
```

How to handle responses:

- If `approved` is `true`, use `stdout`, `stderr`, and `exit_code` as the result
  of the remote command.
- If `exit_code` is nonzero, inspect the output and decide the next safe command.
- If `approved` is `false`, read `comment`, adjust your approach, and send a new
  request only if appropriate.
- Do not claim a remote change was made unless the approved response confirms the
  command ran successfully.

## Command Constraints

The bridge validates commands before showing them for approval.

Commands must be:

- Non-empty.
- A single line.
- Printable ASCII only.
- Within the bridge command length limit, commonly 1000 characters.

The bridge rejects malformed JSON, missing fields, invalid risk values, overlong
commands, multiline commands, and commands containing non-printable or non-ASCII
characters.

## Risk Levels

Use `low` for read-only inspection:

```text
pwd
ls -la
cat /etc/os-release
systemctl status nginx
```

Use `medium` for ordinary writes or service-impacting checks:

```text
mkdir -p /tmp/diagnostics
python3 -c 'from pathlib import Path; Path("/tmp/example.txt").write_text("ok\n")'
sudo systemctl reload nginx
```

Use `high` for destructive, security-sensitive, or availability-impacting work:

```text
sudo systemctl restart production-service
sudo apt-get upgrade
rm -rf /tmp/some-directory
sudo reboot
```

When in doubt, choose the higher risk and explain why.

## Extra Human Confirmation

Some commands require the human to type an additional confirmation in the TUI.
Expect extra scrutiny for:

- `rm -rf` or `rm -fr`
- `dd`
- `mkfs`
- `reboot`, `shutdown`, `poweroff`, or `halt`
- `modprobe -r`
- Unquoted command chaining operators such as `&&`, `;`, or `|`

Avoid command chaining when possible. Prefer separate requests with a clear
purpose for each step.

## Practical Workflow

1. Ping the bridge if you are not sure it is reachable.
2. Establish context with safe read-only commands such as `pwd`, `hostname`,
   `whoami`, `ls`, and targeted status checks.
3. Explain each next command in `purpose` using concrete intent, not generic text.
4. Prefer small, reversible changes.
5. Verify every change with a follow-up read-only command.
6. Summarize only what was actually approved and observed.

## File Editing On The Remote Host

Commands are single-line only. Do not send heredocs or multiline shell scripts.

For small edits, prefer single-line tools such as:

```text
python3 -c 'from pathlib import Path; p=Path("/tmp/example.txt"); p.write_text("hello\n")'
```

For larger edits, break the work into small approved steps or ask the human for a
safer file transfer/editing approach. Keep each command under the bridge command
length limit.

Before changing files:

- Inspect the current file.
- Preserve permissions and ownership when relevant.
- Create backups only when appropriate and explain where they are placed.
- Verify the resulting content with a read-only command.

## Good Request Examples

Read-only inspection:

```json
{"command":"systemctl status nginx --no-pager","purpose":"Check nginx health before making any configuration changes.","risk":"low"}
```

Targeted log inspection:

```json
{"command":"journalctl -u nginx -n 80 --no-pager","purpose":"Read recent nginx logs to identify the current failure mode.","risk":"low"}
```

Small write:

```json
{"command":"mkdir -p /tmp/ssh-bridge-diagnostics","purpose":"Create a temporary diagnostics directory for approved troubleshooting output.","risk":"medium"}
```

Verification:

```json
{"command":"test -d /tmp/ssh-bridge-diagnostics && ls -ld /tmp/ssh-bridge-diagnostics","purpose":"Verify the diagnostics directory exists after the approved create command.","risk":"low"}
```

## Bad Request Patterns

Do not send vague purposes:

```json
{"command":"sudo systemctl restart app","purpose":"fix it","risk":"medium"}
```

Do not hide multiple unrelated actions in one command:

```json
{"command":"cd /srv/app && git pull && npm install && sudo systemctl restart app","purpose":"Update the app.","risk":"high"}
```

Do not request secrets:

```json
{"command":"cat ~/.ssh/id_rsa","purpose":"Check private key contents.","risk":"high"}
```

Do not send multiline commands. They will be rejected.

## Minimal Python Helper

Use this helper shape in your own local commands if you need to send multiple
bridge requests from the agent environment. Keep the request content specific to
the task.

```python
import json
import socket


def bridge_request(command, purpose, risk="low", host="127.0.0.1", port=8765):
    request = {"command": command, "purpose": purpose, "risk": risk}
    with socket.create_connection((host, port), timeout=5) as sock:
        sock.sendall((json.dumps(request) + "\n").encode())
        return json.loads(sock.recv(65535).decode())


result = bridge_request(
    "pwd",
    "Show the current remote working directory before making changes.",
    "low",
)
print(json.dumps(result, indent=2))
```

If running inside Docker, call the helper with `host="host.docker.internal"`.

## Final Reporting

When reporting back to the human, include:

- Commands that were approved and their outcomes.
- Commands that were rejected, if relevant.
- Files or services changed.
- Verification commands and results.
- Any remaining risk or follow-up that still needs human approval.

Do not include secrets. Preserve `USER` redaction.
