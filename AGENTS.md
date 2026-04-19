# AGENTS.md

## Project

`gated_ssh_ai_bridge` is a Python tool that lets an AI agent request SSH commands while a human approves, edits, or rejects every command in a Textual TUI.

## Local Instructions

- Keep deployment simple. Prefer a single-file implementation in `ssh_bridge.py`.
- Keep `bridge_request.py` as a small dependency-free agent client for submitting one bridge request and printing the JSON response.
- Do not execute remote commands without an explicit human approval path.
- Do not log passwords, passphrases, tokens, or private keys.
- Keep the local bridge bound to `127.0.0.1` by default.
- Preserve username redaction in responses, logs, and TUI display.
- Maintain structured JSON responses:
  - Approved: `{"approved": true, "stdout": "...", "stderr": "...", "exit_code": 0}`
  - Rejected: `{"approved": false, "comment": "..."}`
- Keep `SSH_BRIDGE_AGENT_GUIDE.md` current. It is the single-file handoff guide for agents that only use the SSH bridge from other projects and do not maintain or debug this repo.
- Update `SSH_BRIDGE_AGENT_GUIDE.md` whenever request protocol, bridge endpoint behavior, safety rules, response schemas, risk guidance, or agent-facing usage workflow changes.
- Keep README.md high-level and human-facing. Do not duplicate the full protocol there; point humans to `SSH_BRIDGE_AGENT_GUIDE.md` for agent handoff details.
- Update all three documentation surfaces when `bridge_request.py` behavior changes: README.md, AGENTS.md, and `SSH_BRIDGE_AGENT_GUIDE.md`.
- If adding dependencies, document them in `README.md` and keep them minimal.
- Prefer focused validation and self-tests for safety helpers.

## Commands

Run syntax checks:

```bash
python3 -m py_compile ssh_bridge.py bridge_request.py
```

Run lightweight self-tests:

```bash
python3 ssh_bridge.py --self-test
```
