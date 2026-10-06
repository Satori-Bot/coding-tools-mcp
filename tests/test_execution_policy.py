"""Policy compilation tests, not native sandbox acceptance."""
from __future__ import annotations

import tempfile
import unittest
from argparse import Namespace
from dataclasses import FrozenInstanceError
from pathlib import Path
from unittest.mock import patch

from coding_tools_mcp.errors import ToolFailure
from coding_tools_mcp.policy import IsolationConfig, compile_policy


class ExecutionPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.workspace = self.root / "workspace"
        self.workspace.mkdir()
        self.runtime = self.root / "runtime"

    def test_strict_helper_is_readonly_offline_and_has_no_destinations(self) -> None:
        config = IsolationConfig(mode="strict", network="proxy", allowed_destinations=("example.com:443",))
        policy = compile_policy(config, self.workspace, self.runtime, purpose="read-helper")
        self.assertEqual(policy.network, "offline")
        self.assertEqual(policy.write_roots, (self.runtime,))
        self.assertEqual(policy.allowed_destinations, ())
        with self.assertRaises(FrozenInstanceError):
            policy.network = "proxy"  # type: ignore[misc]

    def test_structured_only_does_not_authorize_workspace_writes(self) -> None:
        build = self.workspace / "build"
        policy = compile_policy(IsolationConfig(mode="strict"), self.workspace, self.runtime,
                                structured_only=True, write_paths=(build,))
        self.assertEqual(policy.write_roots, (self.runtime, build))
        self.assertIn(self.workspace, policy.read_roots)

    def test_denial_overrides_read_root(self) -> None:
        secret = self.workspace / "credentials"
        policy = compile_policy(IsolationConfig(mode="strict", deny_roots=(secret,)), self.workspace, self.runtime)
        self.assertFalse(policy.permits_read(secret / "key"))
        self.assertTrue(policy.permits_read(self.workspace / "src"))

    def test_runtime_and_service_roots_cannot_be_accidentally_widened(self) -> None:
        with self.assertRaises(ToolFailure):
            compile_policy(IsolationConfig(mode="strict"), self.workspace, self.workspace / "runtime")
        with self.assertRaises(ToolFailure):
            compile_policy(IsolationConfig(mode="strict", deny_roots=(self.root,)), self.workspace, self.runtime)

    def test_config_requires_absolute_pinned_helper(self) -> None:
        for config in ({"helper_path": Path("helper")}, {"helper_sha256": "bad"}, {"mode": "best-effort"}):
            with self.subTest(config=config), self.assertRaises(ToolFailure):
                IsolationConfig(**config)

    def test_cli_is_additive_and_environment_configuration_is_static(self) -> None:
        with patch.dict("os.environ", {}, clear=True):
            self.assertEqual(IsolationConfig.from_args(Namespace()).mode, "compatibility")
            config = IsolationConfig.from_args(Namespace(execution_isolation="strict", sandbox_network="proxy",
                                                         sandbox_allow_destination=["example.com:443"]))
            self.assertEqual(config.allowed_destinations, ("example.com:443",))

    def test_default_toolchain_roots_do_not_expose_private_tls_keys(self) -> None:
        policy = compile_policy(IsolationConfig(mode="strict"), self.workspace, self.runtime)
        self.assertFalse(policy.permits_read(Path("/etc/ssl/private/server.key")))
        if Path("/etc/ssl/certs").exists():
            self.assertTrue(policy.permits_read(Path("/etc/ssl/certs/ca-certificates.crt")))

    def test_missing_static_root_is_a_configuration_error(self) -> None:
        with self.assertRaises(ToolFailure) as caught:
            compile_policy(IsolationConfig(mode="strict", read_roots=(self.root / "missing",)), self.workspace, self.runtime)
        self.assertEqual(caught.exception.code, "INVALID_ARGUMENT")

    def test_invalid_cli_configuration_is_reportable_without_traceback(self) -> None:
        from coding_tools_mcp.server import build_parser, runtime_policy_from_args
        args = build_parser().parse_args(["--sandbox-allow-destination", "https://example.com"])
        with self.assertRaises(ValueError):
            runtime_policy_from_args(args)
