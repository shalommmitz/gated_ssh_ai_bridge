#!/usr/bin/env python3
"""TUI-gated SSH command bridge for AI agents.

The bridge accepts one JSON object per line on a local TCP socket. Every valid
command is shown in the Textual TUI and is executed over SSH only after human
approval.
"""

from __future__ import annotations

import argparse
import asyncio
import dataclasses
import getpass
import json
import re
import shlex
import sys
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    import paramiko
except ImportError:  # pragma: no cover - exercised on systems without deps
    paramiko = None

try:
    from rich.panel import Panel
    from rich.syntax import Syntax
    from rich.table import Table
    from rich.text import Text
    from textual.app import App, ComposeResult
    from textual.containers import Horizontal
    from textual.widgets import Footer, Header, Input, RichLog, Static
except ImportError:  # pragma: no cover - exercised on systems without deps
    Panel = None
    Syntax = None
    Table = None
    Text = None
    App = object
    ComposeResult = object
    Container = None
    Horizontal = None
    Footer = None
    Header = None
    Input = None
    RichLog = None
    Static = None


RISK_LEVELS = {"low", "medium", "high"}
DEFAULT_MAX_COMMAND_LENGTH = 1000
DEFAULT_MAX_PURPOSE_LENGTH = 2000
DEFAULT_DISPLAY_OUTPUT_LIMIT = 4000
LOG_FILE = "ssh_bridge_log.jsonl"

DANGEROUS_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(r"(^|[;&|]\s*)rm\s+[^#\n]*-(?:[A-Za-z]*r[A-Za-z]*f|[A-Za-z]*f[A-Za-z]*r)\b"),
        "recursive forced removal: rm -rf / rm -fr",
    ),
    (re.compile(r"(^|[;&|]\s*)dd(\s|$)"), "raw block copy: dd"),
    (re.compile(r"(^|[;&|]\s*)mkfs(?:\.[A-Za-z0-9_+-]+)?(\s|$)"), "filesystem creation: mkfs"),
    (re.compile(r"(^|[;&|]\s*)(reboot|shutdown|poweroff|halt)(\s|$)"), "machine power control"),
    (re.compile(r"(^|[;&|]\s*)modprobe\s+-r(\s|$)"), "kernel module removal: modprobe -r"),
]


#1. Data classes keep JSON parsing, TUI state, and SSH execution boundaries clear.
@dataclasses.dataclass
class CommandRequest:
    command: str
    purpose: str
    risk: str
    request_id: str
    source: str = "agent"


@dataclasses.dataclass
class PendingRequest:
    request: CommandRequest
    response_future: asyncio.Future[dict[str, Any]]


@dataclasses.dataclass
class ExecutionResult:
    stdout: str
    stderr: str
    exit_code: int
    timed_out: bool = False


@dataclasses.dataclass
class HistoryEntry:
    request_id: str
    command: str
    purpose: str
    risk: str
    approved: bool
    exit_code: int | None
    comment: str | None
    timestamp: str


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def redact_username(value: Any, username: str) -> Any:
    """Replace the SSH username in text returned to the agent or shown in logs."""
    if isinstance(value, str):
        return value.replace(username, "USER") if username else value
    if isinstance(value, list):
        return [redact_username(item, username) for item in value]
    if isinstance(value, dict):
        return {key: redact_username(item, username) for key, item in value.items()}
    return value


def printable_ascii_only(value: str) -> bool:
    return all(32 <= ord(char) <= 126 for char in value)


def validate_command_text(command: str, max_length: int) -> str | None:
    if not command.strip():
        return "command must not be empty"
    if len(command) > max_length:
        return f"command length exceeds {max_length} characters"
    if "\n" in command or "\r" in command:
        return "command must be a single line"
    if not printable_ascii_only(command):
        return "command contains non-printable or non-ASCII characters"
    return None


def validate_request_payload(
    payload: Any,
    *,
    max_command_length: int,
    max_purpose_length: int = DEFAULT_MAX_PURPOSE_LENGTH,
) -> tuple[CommandRequest | None, str | None]:
    if not isinstance(payload, dict):
        return None, "request must be a JSON object"

    missing = [field for field in ("command", "purpose", "risk") if field not in payload]
    if missing:
        return None, f"missing required field(s): {', '.join(missing)}"

    command = payload["command"]
    purpose = payload["purpose"]
    risk = payload["risk"]

    if not isinstance(command, str):
        return None, "command must be a string"
    if not isinstance(purpose, str):
        return None, "purpose must be a string"
    if not isinstance(risk, str):
        return None, "risk must be a string"
    if risk not in RISK_LEVELS:
        return None, "risk must be one of: low, medium, high"
    if len(purpose) > max_purpose_length:
        return None, f"purpose length exceeds {max_purpose_length} characters"

    command_error = validate_command_text(command, max_command_length)
    if command_error:
        return None, command_error

    return CommandRequest(
        command=command,
        purpose=purpose,
        risk=risk,
        request_id=uuid.uuid4().hex,
    ), None


#2. The shell scanner warns on chaining operators outside basic quotes.
def find_unquoted_chaining(command: str) -> list[str]:
    operators: list[str] = []
    in_single = False
    in_double = False
    escaped = False
    index = 0

    while index < len(command):
        char = command[index]

        if escaped:
            escaped = False
            index += 1
            continue

        if char == "\\":
            escaped = True
            index += 1
            continue

        if char == "'" and not in_double:
            in_single = not in_single
            index += 1
            continue

        if char == '"' and not in_single:
            in_double = not in_double
            index += 1
            continue

        if not in_single and not in_double:
            if command.startswith("&&", index):
                operators.append("&&")
                index += 2
                continue
            if char == ";":
                operators.append(";")
            elif char == "|":
                operators.append("|")

        index += 1

    return sorted(set(operators))


def find_dangerous_patterns(command: str) -> list[str]:
    return [reason for pattern, reason in DANGEROUS_PATTERNS if pattern.search(command)]


def safety_warnings(command: str) -> list[str]:
    warnings = find_dangerous_patterns(command)
    chaining = find_unquoted_chaining(command)
    if chaining:
        warnings.append(f"command chaining/operator use: {', '.join(chaining)}")
    return warnings


def response_rejected(comment: str, username: str) -> dict[str, Any]:
    return {"approved": False, "comment": redact_username(comment, username)}


def response_ping() -> dict[str, Any]:
    return {"ok": True, "pong": True}


def is_ping_payload(payload: Any) -> bool:
    if not isinstance(payload, dict):
        return False
    return payload.get("type") == "ping" or payload.get("ping") is True


def response_executed(result: ExecutionResult, username: str) -> dict[str, Any]:
    stderr = result.stderr
    if result.timed_out:
        suffix = "Command timed out before completion."
        stderr = f"{stderr.rstrip()}\n{suffix}" if stderr else suffix
    return {
        "approved": True,
        "stdout": redact_username(result.stdout, username),
        "stderr": redact_username(stderr, username),
        "exit_code": result.exit_code,
    }


def compact_for_display(value: str, limit: int = DEFAULT_DISPLAY_OUTPUT_LIMIT) -> str:
    if len(value) <= limit:
        return value
    remaining = len(value) - limit
    return f"{value[:limit]}\n... truncated {remaining} characters for display ..."


class JsonlLogger:
    def __init__(self, path: Path, username: str) -> None:
        self.path = path
        self.username = username
        self._lock = threading.Lock()

    def log(self, event: str, **fields: Any) -> None:
        record = {"timestamp": utc_now(), "event": event}
        record.update(fields)
        record = redact_username(record, self.username)
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(record, ensure_ascii=True, sort_keys=True) + "\n")


#3. SSHSession reuses one SSHClient while each command receives its own channel.
class SSHSession:
    def __init__(
        self,
        *,
        host: str,
        port: int,
        username: str,
        key_filename: str | None,
        allow_agent: bool,
        look_for_keys: bool,
    ) -> None:
        self.host = host
        self.port = port
        self.username = username
        self.key_filename = key_filename
        self.allow_agent = allow_agent
        self.look_for_keys = look_for_keys
        self.client: Any = None
        self.cwd = ""

    def connect(
        self,
        *,
        password: str | None,
        passphrase: str | None,
        timeout: float,
    ) -> None:
        if paramiko is None:
            raise RuntimeError("Missing dependency: install paramiko with `python -m pip install paramiko textual`")

        client = paramiko.SSHClient()
        client.load_system_host_keys()
        client.set_missing_host_key_policy(paramiko.WarningPolicy())
        client.connect(
            hostname=self.host,
            port=self.port,
            username=self.username,
            password=password,
            passphrase=passphrase,
            key_filename=self.key_filename,
            allow_agent=self.allow_agent,
            look_for_keys=self.look_for_keys,
            timeout=timeout,
            banner_timeout=timeout,
            auth_timeout=timeout,
        )
        transport = client.get_transport()
        if transport is not None:
            transport.set_keepalive(30)
        self.client = client
        self.cwd = self._initial_cwd(timeout=timeout)

    def _initial_cwd(self, timeout: float) -> str:
        result = self.execute("pwd", timeout=timeout, update_cwd=False)
        return result.stdout.strip().splitlines()[-1] if result.stdout.strip() else "~"

    def close(self) -> None:
        if self.client is not None:
            self.client.close()
            self.client = None

    def execute(self, command: str, *, timeout: float, update_cwd: bool = True) -> ExecutionResult:
        if self.client is None:
            raise RuntimeError("SSH session is not connected")

        transport = self.client.get_transport()
        if transport is None or not transport.is_active():
            raise RuntimeError("SSH transport is not active")

        cwd_marker = f"__GATED_SSH_CWD_{uuid.uuid4().hex}__"
        cd_command = "cd" if self.cwd in {"", "~"} else f"cd {shlex.quote(self.cwd)}"
        script = (
            f"{cd_command} || exit $?\n"
            f"{command}\n"
            "__gated_status=$?\n"
            f"printf '\\n{cwd_marker}%s\\n' \"$PWD\"\n"
            "exit $__gated_status\n"
        )

        channel = transport.open_session()
        channel.settimeout(1.0)
        channel.exec_command(script)

        stdout_parts: list[bytes] = []
        stderr_parts: list[bytes] = []
        start = time.monotonic()
        timed_out = False

        while True:
            while channel.recv_ready():
                stdout_parts.append(channel.recv(4096))
            while channel.recv_stderr_ready():
                stderr_parts.append(channel.recv_stderr(4096))

            if channel.exit_status_ready():
                break

            if time.monotonic() - start > timeout:
                timed_out = True
                channel.close()
                break

            time.sleep(0.05)

        while channel.recv_ready():
            stdout_parts.append(channel.recv(4096))
        while channel.recv_stderr_ready():
            stderr_parts.append(channel.recv_stderr(4096))

        if timed_out:
            exit_code = -1
        else:
            exit_code = channel.recv_exit_status()

        stdout = b"".join(stdout_parts).decode("utf-8", errors="replace")
        stderr = b"".join(stderr_parts).decode("utf-8", errors="replace")
        stdout, discovered_cwd = self._strip_cwd_marker(stdout, cwd_marker)
        if update_cwd and discovered_cwd:
            self.cwd = discovered_cwd

        return ExecutionResult(stdout=stdout, stderr=stderr, exit_code=exit_code, timed_out=timed_out)

    @staticmethod
    def _strip_cwd_marker(stdout: str, marker: str) -> tuple[str, str | None]:
        discovered_cwd: str | None = None
        kept_lines: list[str] = []

        for line in stdout.splitlines(keepends=True):
            stripped = line.rstrip("\r\n")
            if stripped.startswith(marker):
                discovered_cwd = stripped[len(marker) :]
                continue
            kept_lines.append(line)

        return "".join(kept_lines), discovered_cwd


class BridgeApp(App):  # type: ignore[misc]
    CSS = """
    Screen {
        background: #101418;
        color: #d7dde5;
    }

    #topline {
        height: auto;
        padding: 1 2;
        background: #1d252d;
        color: #d7dde5;
    }

    #status_bar {
        height: auto;
        padding: 0 2 1 2;
        background: #1d252d;
    }

    .status_box {
        width: 1fr;
        padding: 0 1;
        color: #9fd3c7;
    }

    #log {
        height: 1fr;
        padding: 1 2;
        background: #101418;
        border: solid #31414f;
    }

    #command_input {
        height: 3;
        margin: 0 1 1 1;
        border: solid #67b7dc;
    }
    """

    BINDINGS = [
        ("ctrl+c", "quit", "Quit"),
        ("ctrl+q", "quit", "Quit"),
    ]

    def __init__(
        self,
        *,
        session: SSHSession,
        logger: JsonlLogger,
        bridge_host: str,
        bridge_port: int,
        command_timeout: float,
        max_command_length: int,
        display_output_limit: int,
    ) -> None:
        super().__init__()
        self.session = session
        self.logger = logger
        self.bridge_host = bridge_host
        self.bridge_port = bridge_port
        self.command_timeout = command_timeout
        self.max_command_length = max_command_length
        self.display_output_limit = display_output_limit

        self.pending_queue: asyncio.Queue[PendingRequest] = asyncio.Queue()
        self.current: PendingRequest | None = None
        self.current_command: str | None = None
        self.mode = "idle"
        self.server: asyncio.AbstractServer | None = None
        self.server_task: asyncio.Task[None] | None = None
        self.approval_task: asyncio.Task[None] | None = None
        self.history: list[HistoryEntry] = []

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static("Gated SSH AI Bridge", id="topline")
        with Horizontal(id="status_bar"):
            yield Static("", id="ssh_status", classes="status_box")
            yield Static("", id="bridge_status", classes="status_box")
            yield Static("", id="cwd_status", classes="status_box")
        yield RichLog(id="log", wrap=True, markup=True, highlight=True)
        yield Input(placeholder="Type a local command, or wait for agent requests.", id="command_input")
        yield Footer()

    async def on_mount(self) -> None:
        self._refresh_status()
        self.server_task = asyncio.create_task(self._start_server())
        self.approval_task = asyncio.create_task(self._approval_loop())
        self._write_intro()
        self.query_one("#command_input", Input).focus()

    async def on_unmount(self) -> None:
        if self.server is not None:
            self.server.close()
            await self.server.wait_closed()
        for task in (self.server_task, self.approval_task):
            if task is not None:
                task.cancel()
        self.session.close()

    async def _start_server(self) -> None:
        try:
            self.server = await asyncio.start_server(self._handle_client, self.bridge_host, self.bridge_port)
            self._refresh_status()
            async with self.server:
                await self.server.serve_forever()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self.logger.log("bridge_start_failed", error=str(exc), host=self.bridge_host, port=self.bridge_port)
            self._log_widget().write(f"[red]Bridge listener failed:[/red] {exc}")

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        self._log_widget().write(f"[dim]client connected: {peer}[/dim]")

        try:
            while not reader.at_eof():
                try:
                    raw = await reader.readline()
                except ValueError:
                    await self._write_socket_response(
                        writer,
                        response_rejected("request line is too large", self.session.username),
                    )
                    continue

                if not raw:
                    break
                if not raw.strip():
                    continue

                request, response = self._parse_socket_request(raw)
                if response is not None:
                    await self._write_socket_response(writer, response)
                    continue

                assert request is not None
                future: asyncio.Future[dict[str, Any]] = asyncio.get_running_loop().create_future()
                await self.pending_queue.put(PendingRequest(request=request, response_future=future))
                self.logger.log(
                    "request_received",
                    request_id=request.request_id,
                    source=request.source,
                    command=request.command,
                    purpose=request.purpose,
                    risk=request.risk,
                    peer=str(peer),
                )
                result = await future
                await self._write_socket_response(writer, result)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self._log_widget().write(f"[red]client error:[/red] {exc}")
        finally:
            writer.close()
            await writer.wait_closed()
            self._log_widget().write(f"[dim]client disconnected: {peer}[/dim]")

    def _parse_socket_request(self, raw: bytes) -> tuple[CommandRequest | None, dict[str, Any] | None]:
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            response = response_rejected("request must be valid UTF-8", self.session.username)
            self.logger.log("request_invalid", reason=response["comment"])
            return None, response

        if text.strip().lower() == "ping":
            self.logger.log("ping")
            return None, response_ping()

        try:
            payload = json.loads(text)
        except json.JSONDecodeError as exc:
            response = response_rejected(f"invalid JSON: {exc.msg}", self.session.username)
            self.logger.log("request_invalid", reason=response["comment"])
            return None, response

        if is_ping_payload(payload):
            self.logger.log("ping")
            return None, response_ping()

        request, error = validate_request_payload(payload, max_command_length=self.max_command_length)
        if error:
            response = response_rejected(error, self.session.username)
            self.logger.log("request_invalid", reason=response["comment"], payload=payload)
            return None, response

        return request, None

    async def _write_socket_response(self, writer: asyncio.StreamWriter, response: dict[str, Any]) -> None:
        writer.write((json.dumps(response, ensure_ascii=True) + "\n").encode("utf-8"))
        await writer.drain()

    async def _approval_loop(self) -> None:
        while True:
            pending = await self.pending_queue.get()
            self.current = pending
            self.current_command = pending.request.command
            self.mode = "await_action"
            self._display_request(pending.request)
            self._set_input_prompt("Approve? y / n / edit")
            await pending.response_future
            self.current = None
            self.current_command = None
            self.mode = "idle"
            self._set_input_prompt("Type a local command, `history`, or wait for agent requests.")
            self._refresh_status()

    def on_input_submitted(self, event: Any) -> None:
        value = event.value.strip()
        event.input.value = ""
        asyncio.create_task(self._handle_input(value))

    async def _handle_input(self, value: str) -> None:
        if not value:
            return

        if self.current is None:
            await self._handle_idle_input(value)
            return

        if self.mode == "await_action":
            await self._handle_approval_action(value)
        elif self.mode == "await_rejection_feedback":
            await self._reject_current(value)
        elif self.mode == "await_edit":
            await self._apply_edit(value)
        elif self.mode == "await_second_confirm":
            await self._handle_second_confirmation(value)

    async def _handle_idle_input(self, value: str) -> None:
        if value.lower() == "history":
            self._display_history()
            return

        error = validate_command_text(value, self.max_command_length)
        if error:
            self._log_widget().write(f"[red]Local command rejected:[/red] {error}")
            return

        request = CommandRequest(
            command=value,
            purpose="Manual command entered in the TUI",
            risk="medium",
            request_id=uuid.uuid4().hex,
            source="human",
        )
        future: asyncio.Future[dict[str, Any]] = asyncio.get_running_loop().create_future()
        await self.pending_queue.put(PendingRequest(request=request, response_future=future))
        self.logger.log(
            "request_received",
            request_id=request.request_id,
            source=request.source,
            command=request.command,
            purpose=request.purpose,
            risk=request.risk,
        )

    async def _handle_approval_action(self, value: str) -> None:
        action = value.lower()
        if action == "y":
            await self._approve_current()
        elif action == "n":
            self.mode = "await_rejection_feedback"
            self._set_input_prompt("Reject feedback for the agent")
            self._log_widget().write("[yellow]Rejected. Enter feedback to return to the agent.[/yellow]")
        elif action in {"edit", "e"}:
            self.mode = "await_edit"
            current = self.current_command or ""
            input_widget = self.query_one("#command_input", Input)
            input_widget.value = redact_username(current, self.session.username)
            input_widget.cursor_position = len(input_widget.value)
            self._set_input_prompt("Edit command, then press Enter")
        elif action.startswith("edit "):
            await self._apply_edit(value[5:].strip())
        else:
            self._log_widget().write("[yellow]Use `y`, `n`, or `edit`.[/yellow]")

    async def _handle_second_confirmation(self, value: str) -> None:
        action = value.strip()
        lower = action.lower()
        if action == "CONFIRM":
            await self._execute_current()
        elif lower == "n":
            self.mode = "await_rejection_feedback"
            self._set_input_prompt("Reject feedback for the agent")
            self._log_widget().write("[yellow]Enter feedback to return to the agent.[/yellow]")
        elif lower in {"edit", "e"}:
            self.mode = "await_edit"
            input_widget = self.query_one("#command_input", Input)
            input_widget.value = redact_username(self.current_command or "", self.session.username)
            input_widget.cursor_position = len(input_widget.value)
            self._set_input_prompt("Edit command, then press Enter")
        else:
            self._log_widget().write("[red]Type CONFIRM exactly, or use n/edit.[/red]")

    async def _apply_edit(self, edited: str) -> None:
        if self.current is None:
            return

        edited = edited.replace("USER", self.session.username)
        error = validate_command_text(edited, self.max_command_length)
        if error:
            self._log_widget().write(f"[red]Edited command rejected:[/red] {error}")
            self.mode = "await_edit"
            self._set_input_prompt("Edit command, then press Enter")
            return

        self.current_command = edited
        self.mode = "await_action"
        self._display_request(self.current.request, edited_command=edited)
        self._set_input_prompt("Edited. Approve? y / n / edit")

    async def _approve_current(self) -> None:
        if self.current is None or self.current_command is None:
            return

        error = validate_command_text(self.current_command, self.max_command_length)
        if error:
            self._log_widget().write(f"[red]Cannot execute:[/red] {error}. Use edit or n.")
            return

        warnings = safety_warnings(self.current_command)
        if warnings:
            self.mode = "await_second_confirm"
            table = Table.grid(padding=(0, 1))
            table.add_column(style="bold red")
            table.add_column()
            for warning in warnings:
                table.add_row("Warning", warning)
            self._log_widget().write(Panel(table, title="Second Confirmation Required", border_style="red"))
            self._set_input_prompt("Type CONFIRM exactly to execute, or n/edit")
            return

        await self._execute_current()

    async def _execute_current(self) -> None:
        if self.current is None or self.current_command is None:
            return

        pending = self.current
        command = self.current_command
        request = pending.request
        edited = command != request.command
        self.mode = "executing"
        self._set_input_prompt("Executing approved command...")
        self._log_widget().write("[green]Approved. Executing over SSH...[/green]")
        self.logger.log(
            "command_approved",
            request_id=request.request_id,
            source=request.source,
            original_command=request.command,
            executed_command=command,
            edited=edited,
            purpose=request.purpose,
            risk=request.risk,
        )

        try:
            result = await asyncio.to_thread(self.session.execute, command, timeout=self.command_timeout)
            response = response_executed(result, self.session.username)
            pending.response_future.set_result(response)
            self._record_history(request, command, approved=True, exit_code=result.exit_code, comment=None)
            self.logger.log(
                "command_result",
                request_id=request.request_id,
                command=command,
                approved=True,
                stdout=result.stdout,
                stderr=result.stderr,
                exit_code=result.exit_code,
                timed_out=result.timed_out,
                cwd=self.session.cwd,
            )
            self._display_result(result)
        except Exception as exc:
            comment = f"execution failed: {exc}"
            response = response_rejected(comment, self.session.username)
            pending.response_future.set_result(response)
            self._record_history(request, command, approved=False, exit_code=None, comment=comment)
            self.logger.log(
                "command_error",
                request_id=request.request_id,
                command=command,
                approved=False,
                error=comment,
            )
            self._log_widget().write(f"[red]{comment}[/red]")

    async def _reject_current(self, comment: str) -> None:
        if self.current is None:
            return

        if not comment.strip():
            comment = "Rejected by human reviewer."

        request = self.current.request
        command = self.current_command or request.command
        response = response_rejected(comment, self.session.username)
        self.current.response_future.set_result(response)
        self._record_history(request, command, approved=False, exit_code=None, comment=comment)
        self.logger.log(
            "command_rejected",
            request_id=request.request_id,
            source=request.source,
            command=command,
            purpose=request.purpose,
            risk=request.risk,
            comment=comment,
        )
        self._log_widget().write(f"[yellow]Rejected:[/yellow] {redact_username(comment, self.session.username)}")

    def _display_request(self, request: CommandRequest, *, edited_command: str | None = None) -> None:
        command = edited_command if edited_command is not None else request.command
        table = Table.grid(padding=(0, 1))
        table.add_column(style="bold cyan", no_wrap=True)
        table.add_column()
        table.add_row("Source", request.source)
        table.add_row("Command", redact_username(command, self.session.username))
        table.add_row("Purpose", redact_username(request.purpose, self.session.username))
        table.add_row("Risk", self._risk_text(request.risk))
        if edited_command is not None:
            table.add_row("Edited", "yes")
        self._log_widget().write(Panel(table, title=f"Approval Request {request.request_id[:8]}", border_style="cyan"))

    def _display_result(self, result: ExecutionResult) -> None:
        title = f"Result exit_code={result.exit_code}"
        if result.timed_out:
            title += " timed_out=true"

        table = Table.grid(expand=True)
        table.add_column()
        stdout = compact_for_display(redact_username(result.stdout, self.session.username), self.display_output_limit)
        stderr = compact_for_display(redact_username(result.stderr, self.session.username), self.display_output_limit)

        if stdout:
            table.add_row(Text("stdout", style="bold green"))
            table.add_row(Syntax(stdout.rstrip("\n"), "text", word_wrap=True))
        else:
            table.add_row(Text("stdout: <empty>", style="dim"))

        if stderr:
            table.add_row(Text("stderr", style="bold red"))
            table.add_row(Syntax(stderr.rstrip("\n"), "text", word_wrap=True))
        else:
            table.add_row(Text("stderr: <empty>", style="dim"))

        self._log_widget().write(Panel(table, title=title, border_style="green" if result.exit_code == 0 else "yellow"))
        self._refresh_status()

    def _display_history(self) -> None:
        if not self.history:
            self._log_widget().write("[dim]No command history yet.[/dim]")
            return

        table = Table(title="Recent Commands")
        table.add_column("Time")
        table.add_column("Decision")
        table.add_column("Exit")
        table.add_column("Risk")
        table.add_column("Command")

        for entry in self.history[-12:]:
            decision = "approved" if entry.approved else "rejected"
            table.add_row(
                entry.timestamp,
                decision,
                "" if entry.exit_code is None else str(entry.exit_code),
                entry.risk,
                redact_username(entry.command, self.session.username),
            )

        self._log_widget().write(table)

    def _record_history(
        self,
        request: CommandRequest,
        command: str,
        *,
        approved: bool,
        exit_code: int | None,
        comment: str | None,
    ) -> None:
        self.history.append(
            HistoryEntry(
                request_id=request.request_id,
                command=command,
                purpose=request.purpose,
                risk=request.risk,
                approved=approved,
                exit_code=exit_code,
                comment=comment,
                timestamp=utc_now(),
            )
        )

    def _risk_text(self, risk: str) -> Text:
        styles = {"low": "green", "medium": "yellow", "high": "bold red"}
        return Text(risk, style=styles.get(risk, "white"))

    def _write_intro(self) -> None:
        message = (
            f"Listening on [bold]{self.bridge_host}:{self.bridge_port}[/bold]. "
            "Send one JSON request per line. Every command needs approval."
        )
        self._log_widget().write(Panel(message, title="Ready", border_style="green"))

    def _refresh_status(self) -> None:
        username = redact_username(self.session.username, self.session.username)
        self.query_one("#ssh_status", Static).update(f"SSH: {username}@{self.session.host}:{self.session.port}")
        self.query_one("#bridge_status", Static).update(f"Bridge: {self.bridge_host}:{self.bridge_port}")
        self.query_one("#cwd_status", Static).update(f"CWD: {redact_username(self.session.cwd, self.session.username)}")

    def _set_input_prompt(self, prompt: str) -> None:
        self.query_one("#command_input", Input).placeholder = prompt

    def _log_widget(self) -> Any:
        return self.query_one("#log", RichLog)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Human-gated SSH bridge for AI command execution.",
    )
    parser.add_argument("--host", help="Remote SSH host")
    parser.add_argument("--port", type=int, default=22, help="Remote SSH port")
    parser.add_argument("--user", help="Remote SSH username; prompted if omitted")
    parser.add_argument("--key", help="Path to SSH private key")
    parser.add_argument(
        "--password-auth",
        action="store_true",
        help="Prompt for an SSH password. If --key is omitted, password auth is prompted by default.",
    )
    parser.add_argument(
        "--key-passphrase",
        action="store_true",
        help="Prompt for the private key passphrase.",
    )
    parser.add_argument(
        "--no-agent",
        action="store_true",
        help="Disable SSH agent authentication.",
    )
    parser.add_argument(
        "--no-look-for-keys",
        action="store_true",
        help="Disable Paramiko's default private-key discovery.",
    )
    parser.add_argument(
        "--bridge-host",
        default="127.0.0.1",
        help="Local host/interface for agent JSON-lines connections.",
    )
    parser.add_argument(
        "--bridge-port",
        type=int,
        default=8765,
        help="Local TCP port for agent JSON-lines connections.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=60.0,
        help="Per-command timeout in seconds.",
    )
    parser.add_argument(
        "--connect-timeout",
        type=float,
        default=20.0,
        help="SSH connection timeout in seconds.",
    )
    parser.add_argument(
        "--max-command-length",
        type=int,
        default=DEFAULT_MAX_COMMAND_LENGTH,
        help="Maximum command length accepted from the agent.",
    )
    parser.add_argument(
        "--display-output-limit",
        type=int,
        default=DEFAULT_DISPLAY_OUTPUT_LIMIT,
        help="Maximum stdout/stderr characters shown in the TUI per stream.",
    )
    parser.add_argument(
        "--log-file",
        default=LOG_FILE,
        help="JSONL audit log file.",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Run lightweight validation tests without connecting to SSH.",
    )
    return parser.parse_args(argv)


def ensure_runtime_dependencies() -> None:
    missing: list[str] = []
    if paramiko is None:
        missing.append("paramiko")
    if App is object:
        missing.append("textual")
    if missing:
        names = " ".join(missing)
        raise RuntimeError(f"Missing dependencies. Install with: python -m pip install {names}")


def normalize_key_filename(key_filename: str | None) -> str | None:
    if not key_filename:
        return None
    return str(Path(key_filename).expanduser())


def validate_key_filename(key_filename: str | None) -> str | None:
    if key_filename is None:
        return None
    path = Path(key_filename).expanduser()
    if not path.is_file():
        print(f"Key file not found: {path}", file=sys.stderr)
        return None
    return str(path)


def prompt_key_filename(username: str, host: str) -> str | None:
    while True:
        value = input(f"SSH private key file for {username}@{host} (blank to exit): ").strip()
        if not value:
            print("No key file supplied; exiting.", file=sys.stderr)
            return None
        key_filename = validate_key_filename(value)
        if key_filename is not None:
            return key_filename


def prompt_password(username: str, host: str) -> str:
    return getpass.getpass(f"SSH password for {username}@{host}: ")


def prompt_key_passphrase(key_filename: str) -> str | None:
    passphrase = getpass.getpass(f"Private key passphrase for {key_filename}: ")
    return passphrase if passphrase else None


def paramiko_exception_type(name: str) -> type[BaseException] | tuple[()]:
    if paramiko is None:
        return ()
    return getattr(paramiko.ssh_exception, name, ())


def is_connection_failure(exc: BaseException) -> bool:
    no_valid_connections = paramiko_exception_type("NoValidConnectionsError")
    if no_valid_connections and isinstance(exc, no_valid_connections):
        return True
    if isinstance(exc, (ConnectionError, TimeoutError)):
        return True
    if exc.__class__.__name__ in {"gaierror", "timeout"}:
        return True
    return False


def allowed_auth_types(exc: BaseException) -> set[str]:
    allowed = getattr(exc, "allowed_types", None)
    if not allowed:
        return set()
    return {str(item) for item in allowed}


def server_requires_key_auth(exc: BaseException) -> bool:
    bad_auth_type = paramiko_exception_type("BadAuthenticationType")
    if not bad_auth_type or not isinstance(exc, bad_auth_type):
        return False
    allowed = allowed_auth_types(exc)
    return "publickey" in allowed and "password" not in allowed


def is_key_passphrase_required(exc: BaseException) -> bool:
    password_required = paramiko_exception_type("PasswordRequiredException")
    return bool(password_required and isinstance(exc, password_required))


def is_authentication_failure(exc: BaseException) -> bool:
    auth_exception = paramiko_exception_type("AuthenticationException")
    return bool(auth_exception and isinstance(exc, auth_exception))


def short_exception_message(exc: BaseException) -> str:
    message = str(exc).strip()
    return message if message else exc.__class__.__name__


def ask_yes_no(prompt: str) -> bool:
    return input(prompt).strip().lower() in {"y", "yes"}


def build_ssh_session(args: argparse.Namespace, username: str, key_filename: str | None) -> SSHSession:
    return SSHSession(
        host=args.host,
        port=args.port,
        username=username,
        key_filename=key_filename,
        allow_agent=not args.no_agent,
        look_for_keys=not args.no_look_for_keys,
    )


#4. Connection setup keeps credentials short-lived and gives common failures clear paths.
def connect_ssh_with_guidance(args: argparse.Namespace, username: str) -> tuple[SSHSession, str | None] | None:
    key_filename = normalize_key_filename(args.key)
    if args.key:
        key_filename = validate_key_filename(key_filename)
        if key_filename is None:
            return None

    password_failures = 0
    force_key_only = False
    force_key_passphrase = False

    while True:
        password: str | None = None
        passphrase: str | None = None
        prompt_for_password = (args.password_auth or not key_filename) and not force_key_only

        try:
            if key_filename and (args.key_passphrase or force_key_passphrase):
                passphrase = prompt_key_passphrase(key_filename)
            if prompt_for_password:
                password = prompt_password(username, args.host)

            session = build_ssh_session(args, username, key_filename)
            try:
                session.connect(password=password, passphrase=passphrase, timeout=args.connect_timeout)
                return session, key_filename
            except Exception as exc:
                session.close()

                if is_connection_failure(exc):
                    print(
                        f"Cannot connect to {args.host}:{args.port}. Check host, port, network, and SSH service.",
                        file=sys.stderr,
                    )
                    return None

                if prompt_for_password and server_requires_key_auth(exc):
                    print(
                        "Server does not accept password authentication; a private key is required.",
                        file=sys.stderr,
                    )
                    key_filename = prompt_key_filename(username, args.host)
                    if key_filename is None:
                        return None
                    force_key_only = True
                    force_key_passphrase = False
                    password_failures = 0
                    continue

                if is_key_passphrase_required(exc):
                    print("Private key is encrypted; a passphrase is required.", file=sys.stderr)
                    force_key_passphrase = True
                    continue

                if is_authentication_failure(exc):
                    if prompt_for_password:
                        password_failures += 1
                        if password_failures >= 3:
                            print("Wrong password. Exiting after 3 failed attempts.", file=sys.stderr)
                            return None
                        if ask_yes_no("Wrong password. Retry? [y/N]: "):
                            continue
                        print("Authentication cancelled.", file=sys.stderr)
                        return None

                    print("SSH authentication failed. Check username, key, or passphrase.", file=sys.stderr)
                    return None

                print(f"SSH connection failed: {short_exception_message(exc)}", file=sys.stderr)
                return None
        finally:
            password = None
            passphrase = None


def run_self_tests() -> int:
    cases = [
        (
            {"command": "pwd", "purpose": "show cwd", "risk": "low"},
            True,
            None,
        ),
        (
            {"command": "echo hi && whoami", "purpose": "test chaining", "risk": "medium"},
            True,
            "&&",
        ),
        (
            {"command": "rm -rf /tmp/example", "purpose": "danger", "risk": "high"},
            True,
            "rm -rf",
        ),
        (
            {"command": "echo snowman \u2603", "purpose": "unicode", "risk": "low"},
            False,
            None,
        ),
        (
            {"command": "pwd", "purpose": "bad risk", "risk": "urgent"},
            False,
            None,
        ),
    ]

    for payload, should_validate, expected_warning in cases:
        request, error = validate_request_payload(payload, max_command_length=DEFAULT_MAX_COMMAND_LENGTH)
        if should_validate and error:
            print(f"self-test failed: expected valid payload, got {error}: {payload}", file=sys.stderr)
            return 1
        if not should_validate and not error:
            print(f"self-test failed: expected invalid payload: {payload}", file=sys.stderr)
            return 1
        if request and expected_warning:
            warnings = " ".join(safety_warnings(request.command))
            if expected_warning not in warnings:
                print(f"self-test failed: expected warning {expected_warning!r}, got {warnings!r}", file=sys.stderr)
                return 1

    if redact_username("/home/alice", "alice") != "/home/USER":
        print("self-test failed: username redaction", file=sys.stderr)
        return 1
    if not is_ping_payload({"type": "ping"}) or not is_ping_payload({"ping": True}):
        print("self-test failed: ping payload detection", file=sys.stderr)
        return 1
    if response_ping() != {"ok": True, "pong": True}:
        print("self-test failed: ping response", file=sys.stderr)
        return 1
    if datetime.fromisoformat(utc_now()).tzinfo is None:
        print("self-test failed: UTC timestamp must include timezone", file=sys.stderr)
        return 1

    print("self-tests passed")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)

    if args.self_test:
        return run_self_tests()

    if not args.host:
        print("--host is required unless --self-test is used", file=sys.stderr)
        return 2

    try:
        ensure_runtime_dependencies()
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    username = args.user or input("SSH username: ").strip()
    if not username:
        print("SSH username is required", file=sys.stderr)
        return 2

    connected = connect_ssh_with_guidance(args, username)
    if connected is None:
        return 2
    session, key_filename = connected

    logger = JsonlLogger(Path(args.log_file), username)
    logger.log(
        "ssh_connected",
        host=args.host,
        port=args.port,
        username=username,
        key_filename=key_filename,
        allow_agent=not args.no_agent,
        look_for_keys=not args.no_look_for_keys,
        cwd=session.cwd,
    )

    app = BridgeApp(
        session=session,
        logger=logger,
        bridge_host=args.bridge_host,
        bridge_port=args.bridge_port,
        command_timeout=args.timeout,
        max_command_length=args.max_command_length,
        display_output_limit=args.display_output_limit,
    )

    try:
        app.run()
    except KeyboardInterrupt:
        pass
    finally:
        logger.log("shutdown")
        session.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
