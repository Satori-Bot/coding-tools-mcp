from __future__ import annotations

import hashlib
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from coding_tools_mcp.errors import ToolFailure
from coding_tools_mcp.sandbox import (
    HELPER_VERSION, PROTOCOL_VERSION, SandboxBackend, SandboxSpec,
    _canonical_roots, _open_pinned, _trusted_install, seatbelt_profile,
)


class SandboxTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.workspace = self.base / "workspace"
        self.workspace.mkdir()
        self.install = self.base / "install"
        self.install.mkdir(mode=0o700)
        self.helper = self.install / "helper"
        self.helper.write_bytes(b"trusted pinned binary")
        self.helper.chmod(0o755)
        self.pin = hashlib.sha256(self.helper.read_bytes()).hexdigest()

    def spec(self, **kwargs):
        values = dict(workspace=self.workspace, read_roots=(self.workspace,), write_roots=(self.workspace,), deny_roots=(), helper_path=self.helper, helper_sha256=self.pin)
        values.update(kwargs)
        return SandboxSpec(**values)

    def test_windows_strict_is_rejected_before_any_spawn(self):
        backend = SandboxBackend(self.spec())
        backend.platform = "win32"
        with patch("coding_tools_mcp.sandbox.spawn_process") as spawn:
            with self.assertRaises(ToolFailure) as caught:
                backend.spawn(["C:\\Windows\\System32\\cmd.exe"], cwd=self.workspace, env={})
            self.assertEqual(caught.exception.code, "SANDBOX_UNAVAILABLE")
            spawn.assert_not_called()
        self.assertFalse(backend.capability_report()["descendant_cleanup"])

    def test_macos_strict_rejects_unenforced_descendant_lifetime(self):
        backend = SandboxBackend(self.spec())
        backend.platform = "darwin"
        with patch("coding_tools_mcp.sandbox.spawn_process") as spawn:
            with self.assertRaises(ToolFailure) as caught:
                backend.spawn(["/bin/sh", "-c", "touch side-effect"], cwd=self.workspace, env={})
            self.assertIn("descendant", caught.exception.message)
            spawn.assert_not_called()
        self.assertFalse((self.workspace / "side-effect").exists())

    def test_proxy_is_fail_closed(self):
        backend = SandboxBackend(self.spec(network="proxy"))
        with patch("coding_tools_mcp.sandbox.spawn_process") as spawn:
            with self.assertRaises(ToolFailure) as caught:
                backend.spawn(["/bin/true"], cwd=self.workspace, env={})
            self.assertEqual(caught.exception.code, "SANDBOX_NETWORK_UNSUPPORTED")
            spawn.assert_not_called()

    def test_seatbelt_is_deny_default_offline_and_escaped(self):
        odd = self.base / 'quote" newline\npath'
        profile = seatbelt_profile(self.spec(read_roots=(odd,), deny_roots=(self.base / "secret",)))
        self.assertIn("(deny default)", profile)
        self.assertIn("(deny network*)", profile)
        self.assertIn('quote\\" newline\\npath', profile)
        self.assertNotIn("(allow network", profile)
        self.assertNotIn("(allow mach-lookup", profile)
        self.assertIn("(allow file-map-executable (subpath", profile)
        self.assertIn("(deny file-read* file-write*", profile)

    def test_root_grant_rejected(self):
        with self.assertRaises(ToolFailure):
            _canonical_roots((Path("/"),), must_exist=True)

    @unittest.skipIf(os.name == "nt", "POSIX descriptor and ownership checks")
    def test_pinned_open_rejects_intermediate_symlink(self):
        target = self.base / "target"
        target.mkdir()
        (target / "file").write_text("outside")
        link = self.workspace / "link"
        link.symlink_to(target, target_is_directory=True)
        with self.assertRaises(OSError):
            _open_pinned(link / "file")
        with self.assertRaises(ToolFailure):
            _canonical_roots((link,), must_exist=True)

    @unittest.skipIf(os.name == "nt", "POSIX descriptor and ownership checks")
    def test_helper_workspace_and_shared_install_rejected(self):
        with self.assertRaises(ToolFailure):
            _trusted_install(self.helper, (self.base,))
        self.install.chmod(0o777)
        self.addCleanup(self.install.chmod, 0o700)
        with self.assertRaises(ToolFailure):
            _trusted_install(self.helper, ())

    @unittest.skipIf(os.name == "nt", "POSIX descriptor and ownership checks")
    def test_helper_pin_and_trust_checked_without_executing_it(self):
        backend = SandboxBackend(self.spec(helper_sha256="0" * 64))
        with self.assertRaises(ToolFailure) as caught:
            backend._helper_fd(())
        self.assertEqual(caught.exception.code, "SANDBOX_HELPER_UNTRUSTED")
        fd = SandboxBackend(self.spec())._helper_fd(())
        self.addCleanup(os.close, fd)
        self.assertEqual(os.read(fd, 100), b"trusted pinned binary")

    @unittest.skipIf(os.name == "nt", "POSIX control descriptors")
    def test_stdout_cannot_forge_startup(self):
        backend = SandboxBackend(self.spec())
        backend.platform = "linux"
        # The replacement launcher can only print to stdout. It never has the
        # inherited control descriptor and must not be accepted as isolated.
        def fake_argv(argv, cwd, control_fd, nonce, fds, reads, writes):
            return ["/bin/sh", "-c", f"printf 'CTMCP_SANDBOX {PROTOCOL_VERSION} {HELPER_VERSION} linux-bwrap {nonce}\\n'"]
        with patch.object(backend, "_linux_argv", side_effect=fake_argv), patch.object(backend, "capability_report", return_value={"reason": None}), patch("coding_tools_mcp.sandbox.os.killpg"):
            # The short-lived spoof fixture is not a namespace process tree.
            # Never signal a real process group from this protocol unit test.
            with self.assertRaises(ToolFailure) as caught:
                backend.spawn(["/bin/true"], cwd=self.workspace, env={})
        self.assertEqual(caught.exception.code, "SANDBOX_INITIALIZATION_FAILED")
        self.assertFalse(backend.capability_report()["last_launch_confirmed"])

    @unittest.skipIf(os.name == "nt", "POSIX control descriptors")
    def test_wrong_version_control_message_rejected_before_go(self):
        backend = SandboxBackend(self.spec())
        backend.platform = "linux"
        marker = self.workspace / "side-effect"
        code = (
            "import os,socket,sys; s=socket.socket(fileno=int(sys.argv[1])); "
            "s.sendall(('CTMCP_SANDBOX 999 9.9.9 linux-bwrap '+sys.argv[2]+'\\n').encode()); "
            "gate=s.recv(100); "
            "open(sys.argv[3],'w').write('bad') if gate else None"
        )
        import sys
        def fake_argv(argv, cwd, control_fd, nonce, fds, reads, writes):
            return [sys.executable, "-c", code, str(control_fd), nonce, str(marker)]
        with patch.object(backend, "_linux_argv", side_effect=fake_argv), patch.object(backend, "capability_report", return_value={"reason": None}), patch("coding_tools_mcp.sandbox.os.killpg"):
            # The short-lived spoof fixture is not a namespace process tree.
            # Never signal a real process group from this protocol unit test.
            with self.assertRaises(ToolFailure):
                backend.spawn(["/bin/true"], cwd=self.workspace, env={})
        self.assertFalse(marker.exists())

    @unittest.skipUnless(__import__("sys").platform.startswith("linux"), "Linux version probe")
    def test_old_bwrap_is_rejected(self):
        backend = SandboxBackend(self.spec())
        with patch("coding_tools_mcp.sandbox.Path.resolve", return_value=self.helper), patch("coding_tools_mcp.sandbox._trusted_install"), patch("coding_tools_mcp.sandbox.subprocess.run", return_value=subprocess.CompletedProcess([], 0, b"bubblewrap 0.9.0\n", b"")):
            with self.assertRaises(ToolFailure) as caught:
                backend._bwrap(())
        self.assertIn("0.12.0", caught.exception.message)

    def test_missing_bwrap_raises_domain_failure(self):
        backend = SandboxBackend(self.spec())
        with patch("coding_tools_mcp.sandbox.Path.resolve", side_effect=FileNotFoundError("missing bwrap")):
            with self.assertRaises(ToolFailure) as caught:
                backend._bwrap(())
        self.assertEqual(caught.exception.code, "SANDBOX_UNAVAILABLE")

    def test_nested_denies_rejected_even_for_readonly_roots(self):
        secret = self.workspace / "credential"
        secret.write_text("private")
        for writes in ((self.workspace,), ()):
            backend = SandboxBackend(self.spec(write_roots=writes, deny_roots=(secret,)))
            backend.platform = "linux"
            with patch.object(backend, "capability_report", return_value={"reason": None}), patch("coding_tools_mcp.sandbox.spawn_process") as spawn:
                with self.assertRaises(ToolFailure) as caught:
                    backend.spawn(["/bin/true"], cwd=self.workspace, env={})
                self.assertEqual(caught.exception.code, "SANDBOX_POLICY_INVALID")
                self.assertIn("disjoint", caught.exception.message)
                spawn.assert_not_called()

    @unittest.skipIf(os.name == "nt", "POSIX inode trust checks")
    def test_hardlinked_helper_rejected(self):
        os.link(self.helper, self.workspace / "alias")
        with self.assertRaises(ToolFailure) as caught:
            SandboxBackend(self.spec())._helper_fd(())
        self.assertEqual(caught.exception.code, "SANDBOX_HELPER_UNTRUSTED")

    def test_capabilities_do_not_claim_completed_probe(self):
        report = SandboxBackend(self.spec()).capability_report()
        self.assertFalse(report["last_launch_confirmed"])
        self.assertFalse(report["proxy_egress"])
        self.assertEqual(report["protocol_version"], 1)


if __name__ == "__main__":
    unittest.main()
