"""Unified routing and helper hardening tests; no mock is native acceptance."""
from __future__ import annotations

import ast
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from coding_tools_mcp.errors import ToolFailure
from coding_tools_mcp.executor import WorkspaceExecutor, filtered_environment
from coding_tools_mcp.file_broker import FileBroker, broker_supported
from coding_tools_mcp.policy import IsolationConfig, compile_policy
from coding_tools_mcp.project_context import load_project_context
from coding_tools_mcp.server import Runtime


class WorkspaceExecutorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "workspace"
        self.root.mkdir()
        self.runtime_dir = self.root.parent / "runtime"

    def executor(self, config: IsolationConfig = IsolationConfig(), broker: FileBroker | None = None) -> WorkspaceExecutor:
        return WorkspaceExecutor(lambda purpose: compile_policy(config, self.root, self.runtime_dir, purpose=purpose),
                                 lambda: dict(os.environ), file_broker=broker)

    def test_runtime_modules_have_no_direct_workspace_spawn(self) -> None:
        package = Path(__file__).parents[1] / "coding_tools_mcp"
        for name in ("server.py", "project_context.py"):
            tree = ast.parse((package / name).read_text())
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                    if isinstance(node.func.value, ast.Name) and node.func.value.id == "subprocess":
                        self.assertNotIn(node.func.attr, {"run", "Popen", "call", "check_output", "check_call"}, name)

    def test_helper_filters_preprocessors_loaders_credentials_and_git_injection(self) -> None:
        env = filtered_environment({"PATH": "/usr/bin", "HOME": "/private-home", "SECRET_TOKEN": "s",
                                    "RIPGREP_CONFIG_PATH": "evil", "LD_PRELOAD": "evil", "GIT_CONFIG_COUNT": "1",
                                    "GIT_SSH_COMMAND": "evil", "PYTHONPATH": "evil"}, helper=True, strict=True)
        self.assertEqual(env["PATH"], "/usr/bin")
        for name in ("SECRET_TOKEN", "RIPGREP_CONFIG_PATH", "LD_PRELOAD", "GIT_CONFIG_COUNT", "GIT_SSH_COMMAND", "PYTHONPATH"):
            self.assertNotIn(name, env)
        self.assertEqual(env["GIT_CONFIG_GLOBAL"], os.devnull)

    def test_compatibility_helper_keeps_default_system_config_enabled(self) -> None:
        env = filtered_environment({"PATH": os.defpath}, helper=True, strict=False)
        self.assertNotIn("GIT_CONFIG_NOSYSTEM", env)
        self.assertNotIn("GIT_CONFIG_SYSTEM", env)
        self.assertNotIn("GIT_CONFIG_GLOBAL", env)

    def test_protected_git_config_selection_is_compatibility_only(self) -> None:
        for nosystem in ("0", "false", "1", "true"):
            source = {"GIT_CONFIG_SYSTEM": "system-config", "GIT_CONFIG_GLOBAL": "global-config",
                      "GIT_CONFIG_NOSYSTEM": nosystem, "GIT_TEST_ASSUME_DIFFERENT_OWNER": "1",
                      "GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "core.fsmonitor",
                      "GIT_CONFIG_VALUE_0": "ignored", "GIT_CONFIG_PARAMETERS": "ignored"}
            with self.subTest(nosystem=nosystem):
                compatible = filtered_environment(source, helper=True, strict=False)
                for key in ("GIT_CONFIG_SYSTEM", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_NOSYSTEM"):
                    self.assertEqual(compatible[key], source[key])
                strict = filtered_environment(source, helper=True, strict=True)
                self.assertEqual(strict["GIT_CONFIG_NOSYSTEM"], "1")
                self.assertEqual(strict["GIT_CONFIG_GLOBAL"], os.devnull)
                self.assertNotIn("GIT_CONFIG_SYSTEM", strict)
                self.assertNotIn("GIT_TEST_ASSUME_DIFFERENT_OWNER", strict)
                for env in (compatible, strict):
                    for key in ("GIT_CONFIG_COUNT", "GIT_CONFIG_KEY_0", "GIT_CONFIG_VALUE_0", "GIT_CONFIG_PARAMETERS"):
                        self.assertNotIn(key, env)

    def test_compatibility_git_config_does_not_remove_helper_hardening(self) -> None:
        executor = self.executor()
        env = {"GIT_CONFIG_SYSTEM": "system-config", "GIT_CONFIG_GLOBAL": "global-config"}
        null_path = "NUL" if os.name == "nt" else os.devnull
        for operation in ("diff", "show", "log", "blame"):
            with self.subTest(operation=operation):
                command, clean_env, _ = executor._prepare(["git", operation], "read-helper", env)
                self.assertEqual(clean_env["GIT_CONFIG_SYSTEM"], env["GIT_CONFIG_SYSTEM"])
                for setting in ("core.fsmonitor=false", f"core.hooksPath={null_path}",
                                "diff.external=", "credential.helper=", "protocol.allow=never"):
                    self.assertIn(setting, command)
                self.assertIn("--no-textconv", command)
                if operation != "blame":
                    self.assertIn("--no-ext-diff", command)

    def test_startup_git_uses_executor(self) -> None:
        executor = self.executor()
        with patch.object(executor, "run", wraps=executor.run) as run:
            load_project_context(self.root, executor=executor)
        self.assertTrue(run.called)
        self.assertIn("ls-files", run.call_args.args[0])

    @unittest.skipUnless(shutil.which("git") and os.name != "nt", "POSIX Git fixture")
    def test_repository_fsmonitor_and_textconv_do_not_execute(self) -> None:
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        marker = self.root / "executed"
        hook = self.root / "hook.sh"
        hook.write_text(f'#!/bin/sh\ntouch "{marker}"\n')
        hook.chmod(0o755)
        subprocess.run(["git", "-C", str(self.root), "config", "core.fsmonitor", str(hook)], check=True)
        subprocess.run(["git", "-C", str(self.root), "config", "diff.evil.textconv", str(hook)], check=True)
        (self.root / ".gitattributes").write_text("*.txt diff=evil\n")
        (self.root / "file.txt").write_text("one\n")
        runtime = Runtime(self.root)
        self.addCleanup(runtime.close)
        runtime.git_status({})
        runtime.git_diff({})
        self.assertFalse(marker.exists())

    @unittest.skipUnless(shutil.which("rg") and os.name != "nt", "POSIX rg fixture")
    def test_rg_inherited_preprocessor_is_ignored(self) -> None:
        marker = self.root / "executed"
        hook = self.root / "hook.sh"
        hook.write_text(f'#!/bin/sh\ntouch "{marker}"\ncat "$1"\n')
        hook.chmod(0o755)
        config = self.root / "rgconfig"
        config.write_text(f"--pre={hook}\n")
        (self.root / "file.txt").write_text("needle\n")
        with patch.dict(os.environ, {"RIPGREP_CONFIG_PATH": str(config)}):
            runtime = Runtime(self.root)
            self.addCleanup(runtime.close)
            result = runtime.search_text({"query": "needle"})
        self.assertTrue(result["matches"])
        self.assertFalse(marker.exists())

    @unittest.skipUnless(broker_supported(), "POSIX handle broker")
    def test_external_git_storage_rejected_before_process_spawn(self) -> None:
        (self.root / ".git").write_text("gitdir: ../secret-git\n")
        with FileBroker(self.root) as broker:
            executor = self.executor(IsolationConfig(mode="strict"), broker)
            with patch.object(executor, "_backend") as backend, self.assertRaises(ToolFailure) as caught:
                executor.run([shutil.which("git") or "/usr/bin/git", "status"])
            self.assertEqual(caught.exception.code, "EXTERNAL_GIT_STORAGE_DENIED")
            backend.assert_not_called()

    def test_strict_spawn_error_has_no_compatibility_fallback(self) -> None:
        executor = self.executor(IsolationConfig(mode="strict"))
        with patch.object(executor, "_backend", side_effect=ToolFailure("SANDBOX_UNAVAILABLE", "fixture", category="security")), \
                patch("coding_tools_mcp.executor.spawn_process") as plain, self.assertRaises(ToolFailure):
            executor.spawn_managed(["/bin/true"], cwd=str(self.root), shell=False, env={}, tty=False, popen_kwargs={})
        plain.assert_not_called()

    @unittest.skipIf(os.name == "nt", "POSIX symlink fixture")
    def test_unresolvable_executable_fails_before_launch(self) -> None:
        loop = self.root / "loop"
        loop.symlink_to(loop)
        executor = self.executor(IsolationConfig(mode="strict"))
        with patch.object(executor, "_backend") as backend, \
                patch("coding_tools_mcp.executor.spawn_process") as plain:
            with self.assertRaises(ToolFailure) as caught:
                executor.spawn_managed([str(loop)], cwd=str(self.root), shell=False, env={}, tty=False, popen_kwargs={})
        self.assertEqual(caught.exception.code, "COMMAND_SPAWN_FAILED")
        self.assertFalse(executor.last_launch_confirmed)
        backend.assert_not_called()
        plain.assert_not_called()

    def test_strict_text_streams_preserve_popen_contract(self) -> None:
        import sys
        from types import SimpleNamespace
        executor = self.executor(IsolationConfig(mode="strict"))
        def spawn(argv: list[str], *, cwd: Path, env: dict[str, str], stdio: dict[str, int], **text_options):
            return subprocess.Popen(argv, cwd=cwd, env=env, **stdio, **text_options, start_new_session=True), None
        with patch.object(executor, "_backend", return_value=SimpleNamespace(spawn=spawn)):
            output = executor.run([sys.executable, "-c", "print('hello')"], purpose="command", text=True,
                                  stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            self.assertEqual(output.stdout, "hello\n")
            self.assertIsNone(output.stderr)
            output = executor.run([sys.executable, "-c", "import sys; print(sys.stdin.read())"],
                                  purpose="command", text=True, input="input", stdout=subprocess.PIPE)
            self.assertEqual(output.stdout, "input\n")

    def test_windows_helper_timeout_always_cleans_up_owned_process(self) -> None:
        import io
        from types import SimpleNamespace
        from unittest.mock import Mock
        from coding_tools_mcp import executor as executor_module
        from coding_tools_mcp.processes import HARD_KILL_SIGNAL
        executor = self.executor()
        failure = subprocess.TimeoutExpired(["git"], 0.01)
        process = Mock(stdin=io.BytesIO(), stdout=io.BytesIO(), stderr=io.BytesIO())
        process.communicate.side_effect = [failure, (b"", b"")]
        with patch.object(executor_module, "os", SimpleNamespace(name="nt")), \
                patch.object(executor_module, "signal", SimpleNamespace(SIGTERM=15), create=True), \
                patch.object(executor, "popen", return_value=process), \
                patch.object(executor_module, "terminate_process_group") as terminate:
            with self.assertRaises(subprocess.TimeoutExpired):
                executor.run(["git"], timeout=0.01)
        terminate.assert_called_once_with(process, HARD_KILL_SIGNAL)
        self.assertEqual(process.communicate.call_count, 2)
        self.assertTrue(process.stdout.closed)
