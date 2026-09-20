"""Drive the W10 MCP stdio host with raw JSON-RPC and record every frame.

Deliberately raw rather than an SDK client: the transcript this writes is the
literal protocol on the wire, so a reader can see the ``initialize`` handshake,
the ``tools/list`` result and the ``tools/call`` result without trusting a
library to render them.

Writes ``--transcript`` as a chronological log of
``>>> <request frame>`` / ``<<< <response frame>`` lines with arrival times, and
``--results`` as the decoded tool payloads for human reading.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="w10-mcp-stdio-client")
    parser.add_argument("--host-script", required=True)
    parser.add_argument("--mcp-src", required=True)
    parser.add_argument("--home", required=True)
    parser.add_argument("--calls", required=True, help="JSON file: {label, calls:[...]}")
    parser.add_argument("--transcript", required=True)
    parser.add_argument("--results", required=True)
    parser.add_argument("--pretty-results", required=True)
    parser.add_argument("--protocol", default="2025-11-25")
    parser.add_argument("--timeout-s", type=float, default=180.0)
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    plan = json.loads(Path(args.calls).read_text(encoding="utf-8"))
    # The registry rejects a relative axiom_home, so resolve once here and pass
    # the same absolute path to both the host and the transcript.
    args.home = str(Path(args.home).resolve())

    env = dict(os.environ)
    env["AXIOM_HOME"] = args.home
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUNBUFFERED"] = "1"

    proc = subprocess.Popen(
        [
            sys.executable,
            args.host_script,
            "--home",
            args.home,
            "--mcp-src",
            args.mcp_src,
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        bufsize=1,
        env=env,
    )

    frames: list[tuple[float, str, str]] = []
    lock = threading.Lock()
    responses: dict[int, dict] = {}
    stderr_lines: list[str] = []
    started = time.perf_counter()

    def now() -> float:
        return round((time.perf_counter() - started) * 1000, 1)

    def record(direction: str, text: str) -> None:
        with lock:
            frames.append((now(), direction, text.rstrip("\n")))

    def read_stdout() -> None:
        assert proc.stdout is not None
        for line in proc.stdout:
            if not line.strip():
                continue
            record("<<<", line)
            try:
                document = json.loads(line)
            except ValueError:
                continue
            if isinstance(document, dict) and isinstance(document.get("id"), int):
                with lock:
                    responses[document["id"]] = document

    def read_stderr() -> None:
        assert proc.stderr is not None
        for line in proc.stderr:
            with lock:
                stderr_lines.append(f"[{now()} ms] {line.rstrip()}")

    out_thread = threading.Thread(target=read_stdout, daemon=True)
    err_thread = threading.Thread(target=read_stderr, daemon=True)
    out_thread.start()
    err_thread.start()

    def send(document: dict, *, track: bool = True) -> None:
        text = json.dumps(document, ensure_ascii=False, separators=(",", ":"))
        if track:
            record(">>>", text)
        assert proc.stdin is not None
        proc.stdin.write(text + "\n")
        proc.stdin.flush()

    def await_response(identifier: int) -> dict:
        deadline = time.perf_counter() + args.timeout_s
        while time.perf_counter() < deadline:
            with lock:
                found = responses.get(identifier)
            if found is not None:
                return found
            if proc.poll() is not None:
                with lock:
                    tail = " | ".join(stderr_lines[-6:])
                raise RuntimeError(
                    f"host exited rc={proc.returncode} before answering id={identifier}; "
                    "stderr tail: " + tail
                )
            time.sleep(0.02)
        raise TimeoutError(f"no response for id={identifier} within {args.timeout_s}s")

    send(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": args.protocol,
                "capabilities": {},
                "clientInfo": {"name": "w10-deliverables", "version": "1.0.0"},
            },
        }
    )
    handshake = await_response(1)
    send({"jsonrpc": "2.0", "method": "notifications/initialized"}, track=True)

    send({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    tool_list = await_response(2)

    results: list[dict] = []
    identifier = 3
    for entry in plan.get("calls", []):
        request = {
            "jsonrpc": "2.0",
            "id": identifier,
            "method": "tools/call",
            "params": {"name": entry["tool"], "arguments": entry["arguments"]},
        }
        sent_at = time.perf_counter()
        send(request)
        response = await_response(identifier)
        elapsed = round((time.perf_counter() - sent_at) * 1000, 1)
        results.append(
            {
                "label": entry.get("label", f"call-{identifier}"),
                "tool": entry["tool"],
                "arguments": entry["arguments"],
                "elapsed_ms": elapsed,
                "response": response,
            }
        )
        identifier += 1

    try:
        if proc.stdin is not None:
            proc.stdin.close()
    except OSError:
        pass
    try:
        proc.wait(timeout=30)
    except subprocess.TimeoutExpired:
        proc.terminate()
        proc.wait(timeout=10)
    out_thread.join(timeout=5)
    err_thread.join(timeout=5)

    with lock:
        ordered = sorted(frames, key=lambda item: item[0])
        captured_stderr = list(stderr_lines)

    lines = [
        f"# raw MCP JSON-RPC session over stdio ({plan.get('label', 'w10')})",
        f"# protocol_requested={args.protocol}",
        f"# host_script={args.host_script}",
        f"# axiom_home={args.home}",
        f"# host_exit_code={proc.returncode}",
        "",
    ]
    for at_ms, direction, text in ordered:
        lines.append(f"[{at_ms:>8.1f} ms] {direction} {text}")
    lines.append("")
    lines.append("# host stderr (transport diagnostics)")
    lines.extend(captured_stderr)
    Path(args.transcript).write_text("\n".join(lines) + "\n", encoding="utf-8")

    Path(args.results).write_text(
        json.dumps(
            {
                "label": plan.get("label", "w10"),
                "handshake": handshake,
                "tools_list": tool_list,
                "calls": results,
                "host_stderr": captured_stderr,
            },
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    pretty: list[str] = [
        f"=== MCP session: {plan.get('label', 'w10')} ===",
        "",
        "server: " + json.dumps(handshake.get("result", {}).get("serverInfo", {})),
        "protocol: " + json.dumps(handshake.get("result", {}).get("protocolVersion")),
        "",
        "tools advertised by the server:",
    ]
    for item in tool_list.get("result", {}).get("tools", []):
        pretty.append(f"  - {item['name']}: {item.get('description', '')}")
        annotations = item.get("annotations") or {}
        pretty.append(
            "      annotations="
            + json.dumps(
                {
                    "readOnlyHint": annotations.get("readOnlyHint"),
                    "destructiveHint": annotations.get("destructiveHint"),
                    "openWorldHint": annotations.get("openWorldHint"),
                }
            )
        )
    pretty.append("")
    for result in results:
        pretty.append(f"--- call: {result['label']} ({result['elapsed_ms']} ms) ---")
        pretty.append("request arguments: " + json.dumps(result["arguments"]))
        envelope = result["response"].get("result", {})
        structured = envelope.get("structuredContent")
        if structured is None and envelope.get("content"):
            try:
                structured = json.loads(envelope["content"][0]["text"])
            except (KeyError, ValueError, TypeError):
                structured = None
        if result["response"].get("error"):
            pretty.append("error: " + json.dumps(result["response"]["error"]))
        pretty.append(
            json.dumps(structured, indent=2, ensure_ascii=False)
            if structured is not None
            else json.dumps(envelope, indent=2, ensure_ascii=False)
        )
        pretty.append("")
    Path(args.pretty_results).write_text("\n".join(pretty) + "\n", encoding="utf-8")

    print(json.dumps({"transcript": args.transcript, "calls": len(results)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
