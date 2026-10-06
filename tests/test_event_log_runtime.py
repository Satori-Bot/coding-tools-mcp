from __future__ import annotations

import contextlib
import io
import json
import os
import shlex
import subprocess
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from coding_tools_mcp.errors import JsonRpcError
from coding_tools_mcp.protocol import dispatch_rpc
from coding_tools_mcp.server import Runtime
from tests.compliance.mcp_client import MCPClient, StdioMCPClient


class EventLogRuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.workspace = self.root / "workspace"
        self.workspace.mkdir()
        self.directory = self.root / "journal"
        self.env = {
            "DO_NOT_TRACK": "1",
            "CODING_TOOLS_MCP_TRACE": "0",
            "CODING_TOOLS_MCP_EVENT_LOG_DIR": str(self.directory),
        }
        env_patch = patch.dict(os.environ, self.env)
        env_patch.start()
        self.addCleanup(env_patch.stop)

    def runtime(self) -> Runtime:
        runtime = Runtime(self.workspace, permission_mode="trusted")
        self.addCleanup(runtime.close)
        return runtime

    def records(self) -> list[dict]:
        return [json.loads(line) for line in (self.directory / "events.jsonl").read_text().splitlines()]

    def test_disabled_logging_leaves_tool_result_unchanged(self) -> None:
        (self.workspace / "test.txt").write_text("example\n")
        with patch.dict(os.environ, {"CODING_TOOLS_MCP_EVENT_LOG_DIR": ""}):
            disabled = self.runtime()
            expected = disabled.call_tool("read_file", {"path": "test.txt"})
            disabled.close()
        self.assertFalse(self.directory.exists())
        actual = self.runtime().call_tool("read_file", {"path": "test.txt"})
        self.assertEqual(actual, expected)

    def test_metadata_excludes_content_paths_arguments_and_unknown_names(self) -> None:
        sentinel = "SYNTHETIC_PRIVATE_VALUE"
        (self.workspace / sentinel).write_text(sentinel)
        runtime = self.runtime()
        runtime.call_tool("read_file", {"path": sentinel})
        runtime.call_tool("read_file", {"path": "missing_" + sentinel})
        with self.assertRaises(JsonRpcError):
            runtime.call_tool(sentinel, {})
        with patch.dict(runtime._tool_handlers, {"server_info": lambda _: {
            "ok": False, "error": {"code": sentinel, "category": sentinel, "message": sentinel},
            "status": sentinel, "operation_outcome": sentinel, "command_id": sentinel,
        }}):
            runtime.call_tool("server_info", {})
        data = (self.directory / "events.jsonl").read_text()
        self.assertNotIn(sentinel, data)
        self.assertNotIn(str(self.workspace), data)
        records = self.records()
        self.assertEqual([row["outcome"] for row in records[1::2]],
                         ["success", "tool_error", "rpc_error", "tool_error"])
        self.assertEqual(records[4]["tool"], "unknown")
        self.assertEqual(records[5]["rpc_error_code"], -32602)
        for start, end in zip(records[::2], records[1::2]):
            self.assertEqual(start["call_id"], end["call_id"])
            self.assertEqual(start["event"], "tool_call_started")
            self.assertEqual(end["event"], "tool_call_finished")
            self.assertGreaterEqual(end["duration_ms"], 0)

    def test_validation_failure_and_interruption_keep_original_semantics(self) -> None:
        runtime = self.runtime()
        with self.assertRaises(JsonRpcError):
            runtime.call_tool("read_file", {})
        with patch.dict(runtime._tool_handlers, {"server_info": lambda _: (_ for _ in ()).throw(KeyboardInterrupt())}):
            with self.assertRaises(KeyboardInterrupt):
                runtime.call_tool("server_info", {})
        records = self.records()
        self.assertEqual(len(records), 3)
        self.assertEqual(records[1]["outcome"], "rpc_error")
        self.assertEqual(records[2]["event"], "tool_call_started")

    def test_reused_rpc_ids_and_client_metadata_do_not_mix_concurrent_calls(self) -> None:
        runtime = self.runtime()

        def call(index: int) -> None:
            response = dispatch_rpc(runtime, {
                "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {"name": "server_info", "arguments": {},
                           "_meta": {"openai/session": f"PRIVATE_SESSION_{index}"}},
            })
            self.assertIsNotNone(response)
            self.assertIn("result", response)

        with ThreadPoolExecutor(max_workers=4) as executor:
            list(executor.map(call, range(12)))
        records = self.records()
        self.assertEqual(len(records), 24)
        self.assertEqual(len({row["call_id"] for row in records}), 12)
        for call_id in {row["call_id"] for row in records}:
            self.assertEqual([row["event"] for row in records if row["call_id"] == call_id],
                             ["tool_call_started", "tool_call_finished"])
        self.assertNotIn("PRIVATE_SESSION", json.dumps(records))

    def test_logging_failure_does_not_prevent_or_repeat_a_mutation(self) -> None:
        runtime = self.runtime()
        stderr = io.StringIO()
        with patch("coding_tools_mcp.event_log._open_private", side_effect=OSError("PRIVATE_ERROR")), contextlib.redirect_stderr(stderr):
            result = runtime.call_tool("apply_patch", {
                "patch": "*** Begin Patch\n*** Add File: saved.txt\n+saved\n*** End Patch\n",
            })
        self.assertFalse(result["isError"])
        self.assertEqual((self.workspace / "saved.txt").read_text(), "saved\n")
        self.assertEqual(len(stderr.getvalue().splitlines()), 1)
        self.assertNotIn("PRIVATE_ERROR", stderr.getvalue())

    def test_idempotent_replay_is_identified_without_replaying_the_patch(self) -> None:
        runtime = self.runtime()
        args = {"patch": "*** Begin Patch\n*** Add File: saved.txt\n+saved\n*** End Patch\n",
                "idempotency_key": "PRIVATE_KEY"}
        runtime.call_tool("apply_patch", args)
        result = runtime.call_tool("apply_patch", args)
        self.assertTrue(result["structuredContent"]["idempotent_replay"])
        self.assertTrue(self.records()[-1]["idempotent_replay"])
        self.assertNotIn("PRIVATE_KEY", json.dumps(self.records()))

    def test_running_command_is_distinct_from_nonzero_process_exit(self) -> None:
        runtime = self.runtime()
        argv = [sys.executable, "-c", "import time; time.sleep(.3); raise SystemExit(3)"]
        command = subprocess.list2cmdline(argv) if os.name == "nt" else shlex.join(argv)
        started = runtime.call_tool("exec_command", {"cmd": command, "yield_time_ms": 1})
        payload = started["structuredContent"]
        self.assertEqual(payload["operation_outcome"], "running")
        command_id = payload["command_id"]
        runtime.call_tool("write_stdin", {"command_id": command_id, "yield_time_ms": 1000})
        starts, ends = self.records()[1], self.records()[3]
        self.assertEqual(starts["operation_outcome"], "running")
        self.assertEqual(ends["operation_outcome"], "exited_nonzero")
        self.assertEqual(starts["command_id"], ends["command_id"])

    def test_http_and_stdio_share_the_journal_and_restart_identity_changes(self) -> None:
        for client_type in (MCPClient, StdioMCPClient):
            with self.subTest(transport=client_type.__name__), client_type(self.workspace) as client:
                result = client.call_tool("server_info", {})
                self.assertFalse(result["isError"])
        records = self.records()
        self.assertEqual(len(records), 4)
        self.assertNotEqual(records[0]["runtime_id"], records[2]["runtime_id"])
        self.assertEqual([row["event"] for row in records],
                         ["tool_call_started", "tool_call_finished"] * 2)


if __name__ == "__main__":
    unittest.main()
