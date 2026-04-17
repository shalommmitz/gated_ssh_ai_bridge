# AGENTS.md

## Project

`gated_ssh_ai_bridge` is a Python tool that lets an AI agent request SSH commands while a human approves, edits, or rejects every command in a Textual TUI.

## Local Instructions

- Keep deployment simple. Prefer a single-file implementation in `ssh_bridge.py`.
- Do not execute remote commands without an explicit human approval path.
- Do not log passwords, passphrases, tokens, or private keys.
- Keep the local bridge bound to `127.0.0.1` by default.
- Preserve username redaction in responses, logs, and TUI display.
- Maintain structured JSON responses:
  - Approved: `{"approved": true, "stdout": "...", "stderr": "...", "exit_code": 0}`
  - Rejected: `{"approved": false, "comment": "..."}`
- Keep `SSH_BRIDGE_AGENT_GUIDE.md` current. It is the single-file handoff guide for agents that only use the SSH bridge from other projects and do not maintain or debug this repo.
- Update `SSH_BRIDGE_AGENT_GUIDE.md` whenever request protocol, bridge endpoint behavior, safety rules, response schemas, risk guidance, or agent-facing usage workflow changes.
- If adding dependencies, document them in `README.md` and keep them minimal.
- Prefer focused validation and self-tests for safety helpers.

## Commands

Run syntax checks:

```bash
python -m py_compile ssh_bridge.py
```

Run lightweight self-tests:

```bash
python ssh_bridge.py --self-test
```
