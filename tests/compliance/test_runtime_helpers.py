from __future__ import annotations

import os
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from coding_tools_mcp import server as server_module
from coding_tools_mcp.server import Runtime, ToolFailure, identify_image, truncate_text_head, truncate_text_tail


class RuntimeHelperTests(unittest.TestCase):
    def test_image_identification_reads_jpeg_and_webp_dimensions(self) -> None:
        jpeg = (
            b"\xff\xd8"
            b"\xff\xe0\x00\x02"
            b"\xff\xc0\x00\x11\x08\x00\x10\x00\x20\x03\x01\x11\x00\x02\x11\x00\x03\x11\x00"
            b"\xff\xd9"
        )
        self.assertEqual(identify_image(jpeg, path=file_path("sample.jpg")), ("image/jpeg", 32, 16))

        webp = b"RIFF" + (22).to_bytes(4, "little") + b"WEBPVP8X" + (10).to_bytes(4, "little")
        webp += b"\x00\x00\x00\x00" + (63).to_bytes(3, "little") + (31).to_bytes(3, "little")
        self.assertEqual(identify_image(webp, path=file_path("sample.webp")), ("image/webp", 64, 32))

    def test_tail_truncation_keeps_recent_complete_output(self) -> None:
        result = truncate_text_tail("\n".join(f"line-{index:03d}" for index in range(80)), max_bytes=128)
        self.assertTrue(result.truncated)
        self.assertEqual(result.truncated_by, "bytes")
        self.assertIn("line-079", result.content)
        self.assertNotIn("line-000", result.content)

    def test_head_truncation_keeps_overlong_first_line_prefix(self) -> None:
        result = truncate_text_head("a" * 200, max_bytes=20)
        self.assertTrue(result.truncated)
        self.assertEqual(result.truncated_by, "bytes")
        self.assertEqual(result.content, "a" * 20)
        self.assertEqual(result.output_bytes, 20)
        self.assertTrue(result.first_line_exceeds_limit)

    def test_head_truncation_keeps_utf8_boundary(self) -> None:
        result = truncate_text_head("é" * 100, max_bytes=21)
        self.assertTrue(result.truncated)
        self.assertTrue(result.content)
        self.assertLessEqual(len(result.content.encode("utf-8")), 21)
        self.assertNotIn("\ufffd", result.content)

    def test_tail_truncation_keeps_long_line_before_trailing_newline(self) -> None:
        result = truncate_text_tail(("a" * 200) + "\n", max_bytes=20)
        self.assertTrue(result.truncated)
        self.assertEqual(result.truncated_by, "bytes")
        self.assertEqual(result.content, "a" * 20)
        self.assertTrue(result.last_line_partial)

    def test_command_policy_allows_literal_patterns(self) -> None:
        with TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            (workspace / "index.html").write_text("</html>\n", encoding="utf-8")
            runtime = Runtime(workspace)
            runtime._check_command_policy("grep '</html>' index.html", {})
            runtime._check_command_policy('echo "https://example.com/a/b"', {})

    def test_package_module_entrypoint_exposes_help(self) -> None:
        result = subprocess.run(
            [sys.executable, "-m", "coding_tools_mcp", "--help"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--workspace", result.stdout)

    def test_command_policy_gates_inline_interpreter_code(self) -> None:
        with TemporaryDirectory() as tmp:
            runtime = Runtime(Path(tmp))
            for command in (
                "python3 -c \"print('</html>')\"",
                "bash -lc \"printf '</html>'\"",
                "node -e \"console.log('</div>')\"",
                "ruby -e \"puts '</html>'\"",
                "perl -e \"print '</html>'\"",
                "env FOO=bar python3 -c \"print('</html>')\"",
                "python3 -",
            ):
                with self.subTest(command=command):
                    with self.assertRaises(ToolFailure) as cm:
                        runtime._check_command_policy(command, {})
                    self.assertEqual(cm.exception.code, "PERMISSION_REQUIRED")
                    self.assertEqual(cm.exception.details.get("permission"), "inline_script")

    def test_command_policy_still_blocks_explicit_external_paths_and_network_tools(self) -> None:
        with TemporaryDirectory() as tmp:
            runtime = Runtime(Path(tmp))
            for command in ("cat /etc/passwd", "echo hi > /tmp/out", "curl https://example.com"):
                with self.subTest(command=command):
                    with self.assertRaises(ToolFailure) as cm:
                        runtime._check_command_policy(command, {})
                    self.assertEqual(cm.exception.code, "PERMISSION_REQUIRED")

    def test_command_policy_unwraps_env_before_path_checks(self) -> None:
        with TemporaryDirectory() as tmp:
            runtime = Runtime(Path(tmp))
            for command in (
                "env cat /tmp/secret",
                "env FOO=bar cat ../outside-secret.txt",
                "env -i --unset FOO cat /tmp/secret",
                "env --chdir /tmp cat secret",
                "env --ignore-signal cat /tmp/secret",
                'env -S "cat /tmp/secret"',
            ):
                with self.subTest(command=command):
                    with self.assertRaises(ToolFailure) as cm:
                        runtime._check_command_policy(command, {})
                    self.assertEqual(cm.exception.code, "PERMISSION_REQUIRED")

    def test_exec_command_warns_and_runs_when_landlock_is_unavailable(self) -> None:
        with TemporaryDirectory() as tmp:
            runtime = Runtime(Path(tmp))
            original = server_module.open_landlock_ruleset

            def unavailable(_workspace: Path, _read_roots: list[str]) -> int:
                raise ToolFailure("SANDBOX_UNAVAILABLE", "test landlock unavailable", category="security")

            server_module.open_landlock_ruleset = unavailable
            try:
                result = runtime.exec_command({"cmd": "printf ok", "timeout_ms": 5000, "yield_time_ms": 1000})
            finally:
                server_module.open_landlock_ruleset = original

            self.assertTrue(result["ok"])
            self.assertEqual(result["stdout"], "ok")
            self.assertTrue(any("Landlock" in warning for warning in result.get("warnings", [])))

    def test_exec_command_uses_landlock_wrapper_without_preexec_fn(self) -> None:
        with TemporaryDirectory() as tmp:
            runtime = Runtime(Path(tmp))
            read_fd, write_fd = os.pipe()
            original_open = server_module.open_landlock_ruleset
            original_popen = server_module.subprocess.Popen
            original_watchdog = server_module.start_session_watchdog
            captured: dict[str, object] = {}

            class FakeProcess:
                stdin = None
                stdout = None
                stderr = None
                pid = 1

                def poll(self) -> int:
                    return 0

            def fake_open(_workspace: Path, _read_roots: list[str]) -> int:
                return read_fd

            def fake_popen(*args: object, **kwargs: object) -> FakeProcess:
                captured["args"] = args
                captured["kwargs"] = kwargs
                return FakeProcess()

            server_module.open_landlock_ruleset = fake_open
            server_module.subprocess.Popen = fake_popen  # type: ignore[method-assign]
            server_module.start_session_watchdog = lambda _session: None
            try:
                runtime.exec_command({"cmd": "printf ok", "timeout_ms": 5000, "yield_time_ms": 0})
            finally:
                server_module.open_landlock_ruleset = original_open
                server_module.subprocess.Popen = original_popen  # type: ignore[method-assign]
                server_module.start_session_watchdog = original_watchdog
                os.close(write_fd)

            kwargs = captured["kwargs"]
            self.assertIsInstance(kwargs, dict)
            self.assertFalse(kwargs.get("shell"))
            self.assertNotIn("preexec_fn", kwargs)
            if os.name == "nt":
                self.assertIn("creationflags", kwargs)
            else:
                self.assertIn("start_new_session", kwargs)
            self.assertEqual(kwargs.get("pass_fds"), (read_fd,))
            popen_args = captured["args"]
            self.assertIsInstance(popen_args, tuple)
            argv = popen_args[0]
            self.assertIsInstance(argv, list)
            self.assertTrue(str(argv[1]).endswith("landlock_exec.py"))

    def test_dangerously_skip_all_permissions_auto_grants_permission_gates(self) -> None:
        with TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            default_runtime = Runtime(workspace)
            with self.assertRaises(ToolFailure) as cm:
                default_runtime._check_command_policy("curl https://example.com", {})
            self.assertEqual(cm.exception.code, "PERMISSION_REQUIRED")

            dangerous_runtime = Runtime(workspace, dangerously_skip_all_permissions=True)
            dangerous_runtime._check_command_policy("curl https://example.com", {})
            grant = dangerous_runtime.request_permissions(
                {
                    "tool_name": "exec_command",
                    "permission": "network",
                    "reason": "test dangerous mode",
                    "arguments": {"cmd": "curl https://example.com"},
                }
            )
            self.assertTrue(grant.get("ok"))
            self.assertEqual(grant.get("status"), "granted")

            filtered_env = default_runtime._command_env({"OPENAI_API_KEY": "sk-test-secret-value"})
            dangerous_env = dangerous_runtime._command_env({"OPENAI_API_KEY": "sk-test-secret-value"})
            self.assertNotIn("OPENAI_API_KEY", filtered_env)
            self.assertEqual(dangerous_env.get("OPENAI_API_KEY"), "sk-test-secret-value")

    def test_tool_profiles_filter_tools_and_compat_annotations(self) -> None:
        with TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            full = Runtime(workspace, tool_profile="full")
            full_tools = full.list_tools()["tools"]
            full_names = {tool["name"] for tool in full_tools}
            self.assertIn("apply_patch", full_names)
            self.assertIn("git_log", full_names)
            self.assertIn("server_info", full_names)

            read_only = Runtime(workspace, tool_profile="read-only")
            read_only_names = {tool["name"] for tool in read_only.list_tools()["tools"]}
            self.assertIn("server_info", read_only_names)
            self.assertIn("set_default_cwd", read_only_names)
            self.assertIn("git_blame", read_only_names)
            self.assertNotIn("apply_patch", read_only_names)
            self.assertNotIn("exec_command", read_only_names)
            self.assertNotIn("write_stdin", read_only_names)
            self.assertNotIn("request_permissions", read_only_names)

            compat = Runtime(workspace, tool_profile="compat-readonly-all")
            compat_tools = compat.list_tools()["tools"]
            self.assertEqual({tool["name"] for tool in compat_tools}, full_names)
            for tool in compat_tools:
                annotations = tool["annotations"]
                self.assertIs(annotations.get("readOnlyHint"), True)
                self.assertIs(annotations.get("destructiveHint"), False)
                self.assertIs(annotations.get("openWorldHint"), False)

    def test_default_cwd_and_git_convenience_tools(self) -> None:
        if server_module.shutil.which("git") is None:
            self.skipTest("git is not available")
        with TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            (workspace / "src").mkdir()
            (workspace / "src" / "hello.txt").write_text("hello\n", encoding="utf-8")
            for cmd in (
                ["git", "init", "-q"],
                ["git", "config", "user.email", "test@example.invalid"],
                ["git", "config", "user.name", "Runtime Test"],
                ["git", "config", "commit.gpgsign", "false"],
                ["git", "config", "tag.gpgsign", "false"],
                ["git", "add", "-A"],
                ["git", "commit", "-q", "-m", "initial commit"],
            ):
                completed = subprocess.run(cmd, cwd=workspace, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                if completed.returncode != 0:
                    self.skipTest(f"git fixture setup failed: {completed.stderr.strip()}")

            runtime = Runtime(workspace)
            cwd = runtime.set_default_cwd({"path": "src"})
            self.assertEqual(cwd.get("default_cwd"), "src")
            read = runtime.read_file({"path": "hello.txt"})
            self.assertEqual(read.get("content"), "hello\n")

            log = runtime.git_log({"max_count": 5})
            self.assertTrue(log.get("is_repo"))
            self.assertEqual(log.get("commits", [])[0].get("subject"), "initial commit")

            show = runtime.git_show({"include_diff": False, "max_bytes": 4096})
            self.assertTrue(show.get("is_repo"))
            self.assertIn("initial commit", show.get("content", ""))

            blame = runtime.git_blame({"path": "hello.txt", "max_lines": 5})
            self.assertTrue(blame.get("is_repo"))
            self.assertEqual(blame.get("lines", [])[0].get("content"), "hello")

            with self.assertRaises(ToolFailure):
                runtime.set_default_cwd({"path": "../outside"})


def file_path(name: str):
    return Path(name)
