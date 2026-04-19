# gated_ssh_ai_bridge

A human approval gate for AI-assisted SSH work.

AI coding agents are useful for remote diagnostics, maintenance, and repair.
The risky part is giving an agent a direct SSH path to a machine you care
about. `gated_ssh_ai_bridge` puts a human-controlled checkpoint in the middle:
the agent can request commands, but the human sees every command, purpose, and
risk level before anything runs.

The result is a practical workflow for letting an AI agent help on a remote
computer without handing it unchecked shell access.

## Why It Exists

Remote work with an AI agent usually has a bad tradeoff:

- Give the agent direct SSH access, and mistakes can run immediately.
- Keep SSH fully manual, and the poor human have to do constant copy/paste.

This bridge is the middle path. It keeps the agent productive while preserving a
hard, deterministic and auditable human approval boundary.

## What You Get

- Human approval for every remote command.
- A Textual TUI where the human can approve, reject, or edit requests.
- Structured request and response messages for AI agents.
- A persistent SSH connection managed by the bridge.
- Username redaction in responses, logs, and display.
- Audit logging for requested commands, decisions, and results.
- Docker-friendly local connectivity for containerized agents.
- A small Python implementation that is easy to inspect.
- A tiny agent-side helper, `bridge_request.py`, for sending requests.

## How The Workflow Feels

1. The human starts the bridge and connects it to a target SSH host.
2. The AI agent sends a command request through the local bridge socket, usually
   with `bridge_request.py`.
3. The bridge displays the command, purpose, and risk in the TUI.
4. The human approves, edits, or rejects the request.
5. Only approved commands run over SSH.
6. The agent receives structured JSON with the result or rejection comment.

The human stays in control, and the agent still gets enough feedback to continue
the task intelligently.

## Quick Start

Install the runtime dependencies:

```bash
python3 -m pip install paramiko textual
```

Start the bridge for a target host:

```bash
python3 ssh_bridge.py --host 1.2.3.4 --user ubuntu --key ~/.ssh/id_ed25519
```

By default the bridge listens on `127.0.0.1:8765`.

For Docker-based agents, the included `run_ssh_bridge` launcher shows the
intended host-side pattern: bind the bridge to the Docker gateway address,
allow only the bridge port from `docker0`, and keep the raw bridge port off the
public internet.

From an agent environment that can resolve `host.docker.internal`, send a
request with:

```bash
python3 bridge_request.py "pwd" "Show the current remote working directory before making changes." low
```

`bridge_request.py` is intentionally small. It sends one request, waits for the
human-gated result, and prints the bridge JSON response.

## Companion Project

This project is a natural extension of
[`codex_in_a_docker`](https://github.com/shalommmitz/codex_in_a_docker).

`codex_in_a_docker` gives Codex a contained local environment: the agent can
work freely inside Docker while the host remains protected. `gated_ssh_ai_bridge`
extends the same idea to remote machines. The agent still runs in the controlled
Docker workflow, but remote SSH actions pass through an explicit human approval
gate before they reach the target host.

Together, the two projects support a practical operating model: let the agent do
real work in an isolated container, then let it request remote commands without
granting unchecked SSH access.

## Documentation Map

- `SSH_BRIDGE_AGENT_GUIDE.md` is the file to give an AI agent in another
  project. It explains how to use the bridge safely and how to report results.
- `bridge_request.py` is the preferred helper for agents that need to send
  command requests to the bridge.
- `AGENTS.md` is for agents maintaining this repository.
- `python3 ssh_bridge.py --help` lists runtime options for the bridge itself.

The README is intentionally high-level. The agent guide is the operational
handoff document.

## Good Fit

This project is useful when:

- You want an AI agent to help debug or maintain a remote Linux machine.
- You want the agent to inspect logs, services, files, and configuration over
  SSH.
- You want every remote command reviewed by a human before execution.
- You run agents in Docker and need a simple local bridge to the host.
- You prefer a transparent JSON-lines protocol over a larger service stack.

## Safety Model

The bridge is not an autonomous security boundary for hostile users. It is a
human approval gate for trusted local agent workflows.

The expected deployment is local: bind the bridge to `127.0.0.1` by default, or
to a Docker host-gateway address when a containerized agent needs access. Do not
expose the bridge port to the public internet.

The bridge validates requests, rejects malformed command payloads, requires
extra confirmation for dangerous command patterns, redacts the SSH username, and
does not log passwords or key passphrases.

## Design Philosophy

Keep it small, explicit, and auditable.

The core bridge lives in `ssh_bridge.py`. The agent helper lives in
`bridge_request.py`. The protocol is plain JSON over a local TCP socket so an
agent can use it from almost any environment.

## Credits

Architecture and testing: Shalom Mitz

Code: OpenAI Codex / ChatGPT 5.4 xhigh

## License

[MIT](LICENSE)
