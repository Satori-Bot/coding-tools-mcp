"""Real kernel tests, separately labeled from mocked launcher-policy tests.

Set CODING_TOOLS_SANDBOX_REQUIRE_NATIVE=1 to make unavailable Linux isolation a
failure, not a green skip. macOS/Windows intentionally test strict rejection;
these jobs are NOT evidence of enforced sandbox support on those platforms.
"""
from __future__ import annotations

import hashlib
import json
import os
import signal
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from coding_tools_mcp.errors import ToolFailure
from coding_tools_mcp.policy import system_read_roots
from coding_tools_mcp.sandbox import SandboxBackend, SandboxSpec, _trusted_install, seatbelt_profile

REQUIRED = os.environ.get("CODING_TOOLS_SANDBOX_REQUIRE_NATIVE") == "1"
HELPER = os.environ.get("CODING_TOOLS_SANDBOX_HELPER", "")


def require_helper() -> Path:
    if HELPER and Path(HELPER).is_file():
        return Path(HELPER).resolve()
    message = "Set CODING_TOOLS_SANDBOX_HELPER to the built 0.1.0 native helper."
    if REQUIRED:
        raise AssertionError(message)
    raise unittest.SkipTest(message)


def stop(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.communicate(timeout=5)


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux seccomp helper tests")
class NativeHelperTests(unittest.TestCase):
    """Tests the actual helper syscall boundary, NOT namespace filesystem isolation."""
    @classmethod
    def setUpClass(cls):
        cls.helper = require_helper()

    def launch(self, code: str, *, go: bool = True):
        parent, child = socket.socketpair()
        self.addCleanup(parent.close)
        self.addCleanup(child.close)
        nonce = "a" * 64
        process = subprocess.Popen([str(self.helper), "--control-fd", str(child.fileno()), "--nonce", nonce, "--", sys.executable, "-c", code], pass_fds=(child.fileno(),), stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        self.addCleanup(lambda: stop(process) if process.poll() is None else None)
        child.close()
        parent.settimeout(5)
        ready = parent.recv(256)
        self.assertEqual(ready, f"CTMCP_SANDBOX 1 0.1.0 linux-bwrap {nonce}\n".encode())
        if go:
            parent.sendall(f"GO {nonce}\n".encode())
        else:
            parent.close()
        return process

    def test_native_seccomp_denies_socket_families(self):
        code = """
import json, socket
results = []
for family, kind in [(socket.AF_INET, socket.SOCK_STREAM), (socket.AF_INET6, socket.SOCK_STREAM), (socket.AF_INET, socket.SOCK_DGRAM), (socket.AF_UNIX, socket.SOCK_STREAM)]:
    try:
        socket.socket(family, kind)
        results.append('ESCAPED')
    except PermissionError:
        results.append('denied')
print(json.dumps(results))
"""
        process = self.launch(code)
        out, err = process.communicate(timeout=5)
        self.assertEqual(process.returncode, 0, err)
        self.assertEqual(json.loads(out), ["denied"] * 4)

    def test_native_launch_gate_prevents_side_effect_without_go(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "must-not-exist"
            process = self.launch(f"open({str(marker)!r},'w').write('bad')", go=False)
            _, err = process.communicate(timeout=5)
            self.assertNotEqual(process.returncode, 0, err)
            self.assertFalse(marker.exists())

    def test_native_control_descriptor_is_closed_before_exec(self):
        code = """
import os
# listdir's own transient descriptor disappears before this loop.
leaks = []
for name in os.listdir('/proc/self/fd'):
    if int(name) > 2:
        try: leaks.append(os.readlink('/proc/self/fd/' + name))
        except FileNotFoundError: pass
assert not leaks, leaks
print('clean')
"""
        process = self.launch(code)
        out, err = process.communicate(timeout=5)
        self.assertEqual(process.returncode, 0, err)
        self.assertEqual(out.strip(), b"clean")


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux namespace acceptance only")
class NativeSandboxTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.helper = require_helper()
        cls.pin = hashlib.sha256(cls.helper.read_bytes()).hexdigest()
        # Probe with a command that cannot mutate the workspace. No fallback.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            spec = SandboxSpec(root, (root, *system_read_roots()), (root,), (), helper_path=cls.helper, helper_sha256=cls.pin)
            try:
                process, _ = SandboxBackend(spec).spawn([str(Path(sys.executable).resolve()), "-c", "pass"], cwd=root, env={"PATH": "/usr/bin:/bin"})
                out, err = process.communicate(timeout=10)
                if process.returncode:
                    raise AssertionError(f"Native probe failed: {out!r} {err!r}")
            except (ToolFailure, OSError, subprocess.SubprocessError) as error:
                if REQUIRED:
                    raise AssertionError(f"Required native Linux isolation unavailable: {error}; {getattr(error, 'details', {})}") from error
                raise unittest.SkipTest(f"Native Linux isolation unavailable: {error}") from error

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.workspace = self.base / "workspace"
        self.workspace.mkdir()
        # /tmp is intentionally replaced by a writable private tmpfs. Use a
        # different host tree for strict outside-write denial; otherwise a
        # successful write could merely create an unrelated private-temp file.
        self.outside_temp = tempfile.TemporaryDirectory(prefix="ctmcp-native-private-", dir="/var/tmp")
        self.addCleanup(self.outside_temp.cleanup)
        self.outside = Path(self.outside_temp.name).resolve() / "outside-secret"
        self.outside.write_text("host-secret")

    def backend(self, *, readonly=False, deny=(), network="offline", allowed=()):
        return SandboxBackend(SandboxSpec(self.workspace, (self.workspace, *system_read_roots()), () if readonly else (self.workspace,), tuple(deny), network=network, helper_path=self.helper, helper_sha256=self.pin, allowed_destinations=tuple(allowed)))

    def run_code(self, code, *, backend=None):
        process, _ = (backend or self.backend()).spawn([str(Path(sys.executable).resolve()), "-c", code], cwd=self.workspace, env={"PATH": "/usr/bin:/bin"})
        self.addCleanup(lambda: stop(process) if process.poll() is None else None)
        out, err = process.communicate(timeout=10)
        self.assertEqual(process.returncode, 0, err.decode(errors="replace"))
        return out.decode().strip()

    def test_workspace_write_allowed_outside_read_write_delete_denied(self):
        code = f"""
from pathlib import Path
Path('allowed').write_text('ok')
secret = Path({str(self.outside)!r})
for name, operation in [('read', secret.read_text), ('write', lambda: secret.write_text('bad')), ('delete', secret.unlink)]:
    try: operation()
    except (PermissionError, FileNotFoundError): pass
    else: raise AssertionError(name + ' unexpectedly succeeded at ' + str(secret))
"""
        try:
            self.run_code(code)
        finally:
            self.assertEqual(self.outside.read_text(), "host-secret", "Host sentinel was modified")
        self.assertEqual((self.workspace / "allowed").read_text(), "ok")

    def test_private_tmp_shadows_host_tmp_without_reading_or_mutating_it(self):
        host_tmp = self.base / "host-tmp-secret"
        host_tmp.write_text("host tmp sentinel")
        code = f"""
from pathlib import Path
private = Path({str(host_tmp)!r})
assert not private.exists(), 'host tmp content was exposed'
private.parent.mkdir(parents=True, exist_ok=True)
private.write_text('private tmp content')
assert private.read_text() == 'private tmp content'
private.unlink()
assert not private.exists()
"""
        try:
            self.run_code(code)
        finally:
            self.assertEqual(host_tmp.read_text(), "host tmp sentinel", "Private tmp operation changed host tmp")

    def test_readonly_workspace_dynamic_deletion_denied(self):
        source = self.workspace / "source.py"
        source.write_text("keep")
        self.run_code("from pathlib import Path\np=Path('source.py')\ntry: getattr(p,'un'+'link')()\nexcept OSError: pass\nelse: raise AssertionError('deleted')", backend=self.backend(readonly=True))
        self.assertEqual(source.read_text(), "keep")

    def test_explicit_external_service_credentials_unreadable(self):
        service = self.outside.parent / "service-control"
        service.mkdir()
        secret = service / "credential"
        secret.write_text("private")
        code = f"from pathlib import Path\ntry: Path({str(secret)!r}).read_text()\nexcept OSError: pass\nelse: raise AssertionError('credential exposed')"
        self.run_code(code, backend=self.backend(deny=(service,)))
        self.assertEqual(secret.read_text(), "private")

    def test_symlink_to_host_secret_cannot_escape(self):
        (self.workspace / "escape").symlink_to(self.outside)
        self.run_code("from pathlib import Path\ntry: Path('escape').read_text()\nexcept OSError: pass\nelse: raise AssertionError('symlink escaped')")

    def test_no_host_or_control_descriptors_in_command(self):
        self.run_code("import os\nleaks=[]\nfor n in os.listdir('/proc/self/fd'):\n if int(n)>2:\n  try: leaks.append(os.readlink('/proc/self/fd/'+n))\n  except FileNotFoundError: pass\nassert not leaks,leaks")

    def test_real_ipv4_ipv6_tcp_udp_dns_loopback_denial(self):
        # Every test destination is proven reachable outside the sandbox first.
        # DNS uses a local UDP DNS-wire fixture to avoid internet/flaky resolvers.
        listeners = []
        endpoints = []
        threads = []
        for family, host in ((socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")):
            for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
                listener = socket.socket(family, kind)
                listener.settimeout(5)
                self.addCleanup(listener.close)
                listener.bind((host, 0))
                if kind == socket.SOCK_STREAM:
                    listener.listen()
                    def echo_tcp(server=listener):
                        connection, _ = server.accept()
                        with connection:
                            connection.sendall(connection.recv(512))
                    worker = threading.Thread(target=echo_tcp)
                else:
                    def echo_udp(server=listener):
                        data, address = server.recvfrom(512)
                        server.sendto(data, address)
                    worker = threading.Thread(target=echo_udp)
                worker.start()
                threads.append(worker)
                address = listener.getsockname()
                with socket.socket(family, kind) as client:
                    client.settimeout(3)
                    client.connect(address)
                    payload = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"
                    client.sendall(payload)
                    self.assertEqual(client.recv(512), payload)
                worker.join(timeout=5)
                endpoints.append((int(family), int(kind), host, address[1]))
                listeners.append(listener)
        code = f"""
import socket
for family, kind, host, port in {endpoints!r}:
    try:
        with socket.socket(family, kind) as stream:
            stream.settimeout(1)
            stream.connect((host, port))
            stream.send(b'\\x12\\x34\\x01\\x00')
    except PermissionError: pass
    else: raise AssertionError('direct socket bypass')
"""
        self.run_code(code)

    def test_controlled_proxy_sole_egress_and_live_revocation(self):
        from coding_tools_mcp import network_proxy
        # This fixture deliberately maps a synthetic granted public hostname
        # to an actual host-side TCP echo server. Public-IP classification is
        # tested independently without patches in test_network_proxy. Here we
        # exercise real namespaces, native relay, CONNECT checks, and sockets.
        host = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        host.settimeout(.1)
        host.bind(("127.0.0.1", 0))
        host.listen()
        self.addCleanup(host.close)
        port = host.getsockname()[1]
        stopped = threading.Event()
        self.addCleanup(stopped.set)
        def serve():
            while not stopped.is_set():
                try:
                    stream, _ = host.accept()
                except socket.timeout:
                    continue
                except OSError:
                    return
                def echo(connection=stream):
                    with connection:
                        connection.settimeout(5)
                        try:
                            while data := connection.recv(512):
                                connection.sendall(data)
                        except OSError:
                            pass
                threading.Thread(target=echo, daemon=True).start()
        threading.Thread(target=serve, daemon=True).start()
        with socket.create_connection(("127.0.0.1", port), timeout=3) as baseline:
            baseline.sendall(b"baseline")
            self.assertEqual(baseline.recv(512), b"baseline")
        original_resolve = socket.getaddrinfo
        def resolve(name, target_port, *args, **kwargs):
            if name == "fixture.example":
                return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("127.0.0.1", port))]
            return original_resolve(name, target_port, *args, **kwargs)
        original_proxy = network_proxy.ControlledProxy
        proxies = []
        def create_proxy(allowed):
            proxy = original_proxy(allowed)
            proxies.append(proxy)
            return proxy
        code = f"""
import os,socket,time
from pathlib import Path
from urllib.parse import urlsplit
proxy=urlsplit(os.environ['HTTPS_PROXY'])
try: socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
except PermissionError: pass
else: raise AssertionError('Unix socket escape')
# No host loopback service should be reachable without the relay.
if proxy.port != {port}:
    try: socket.create_connection(('127.0.0.1',{port}),timeout=.2)
    except OSError: pass
    else: raise AssertionError('host loopback escape')
stream=socket.create_connection((proxy.hostname,proxy.port),timeout=3)
stream.sendall(b'CONNECT fixture.example:{port} HTTP/1.1\\r\\nHost: fixture.example:{port}\\r\\n\\r\\n')
reply=b''
while b'\\r\\n\\r\\n' not in reply: reply+=stream.recv(1)
assert reply.startswith(b'HTTP/1.1 200'),reply
stream.sendall(b'allowed')
assert stream.recv(512)==b'allowed'
# A new target cannot use an earlier allowed tunnel's destination grant.
with socket.create_connection((proxy.hostname,proxy.port),timeout=3) as denied:
    denied.sendall(b'CONNECT other.example:{port} HTTP/1.1\\r\\n\\r\\n')
    assert b'403' in denied.recv(512)
Path('proxy-ready').touch()
end=time.monotonic()+5
while not Path('proxy-closed').exists() and time.monotonic()<end: time.sleep(.02)
stream.settimeout(2)
try:
    stream.sendall(b'after-close')
    assert not stream.recv(512),'revoked tunnel still carries bytes'
except OSError: pass
"""
        with patch.object(network_proxy.socket, "getaddrinfo", side_effect=resolve), patch.object(network_proxy, "_is_public_address", side_effect=lambda ip: ip == "127.0.0.1"), patch.object(network_proxy, "_is_host_local_address", return_value=False), patch.object(network_proxy, "ControlledProxy", side_effect=create_proxy):
            backend = self.backend(network="proxy", allowed=(f"fixture.example:{port}",))
            process, _ = backend.spawn([str(Path(sys.executable).resolve()), "-c", code], cwd=self.workspace, env={"PATH": "/usr/bin:/bin"})
            self.addCleanup(lambda: stop(process) if process.poll() is None else None)
            deadline = time.monotonic()+5
            while not (self.workspace / "proxy-ready").exists() and process.poll() is None and time.monotonic()<deadline:
                time.sleep(.02)
            self.assertTrue((self.workspace / "proxy-ready").exists(), "native relay never reached allowed target")
            proxies[0].close()
            (self.workspace / "proxy-closed").touch()
            _, err = process.communicate(timeout=5)
            self.assertEqual(process.returncode, 0, err.decode(errors="replace"))

    def test_cancel_kills_setsid_grandchild(self):
        code = """
import os,time
if os.fork() == 0:
    os.setsid()
    if os.fork() == 0:
        while True:
            with open('heartbeat','a') as f: f.write('.')
            time.sleep(.05)
    os._exit(0)
while True: time.sleep(1)
"""
        process, _ = self.backend().spawn([str(Path(sys.executable).resolve()), "-c", code], cwd=self.workspace, env={"PATH": "/usr/bin:/bin"})
        self.addCleanup(lambda: stop(process) if process.poll() is None else None)
        heartbeat = self.workspace / "heartbeat"
        deadline = time.monotonic() + 5
        while not heartbeat.exists() and time.monotonic() < deadline:
            time.sleep(.02)
        self.assertTrue(heartbeat.exists())
        stop(process)
        time.sleep(.1)
        after = heartbeat.read_bytes()
        time.sleep(.3)
        self.assertEqual(heartbeat.read_bytes(), after, "escaped descendant survived cancellation")


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux Runtime acceptance only")
class NativeRuntimeTests(unittest.TestCase):
    """Real Runtime -> policy -> executor -> native backend integration."""
    @classmethod
    def setUpClass(cls):
        # Reuse the exact no-side-effect capability probe, without inheriting
        # and accidentally rerunning all of the backend-only test methods.
        NativeSandboxTests.setUpClass()
        cls.helper = NativeSandboxTests.helper
        cls.pin = NativeSandboxTests.pin
        cls.git = shutil.which("git")
        cls.rg = shutil.which("rg")
        cls.fd = shutil.which("fd") or shutil.which("fdfind")
        if cls.git is None or cls.rg is None or cls.fd is None:
            message = "Native Runtime acceptance requires git, ripgrep and fd/fdfind."
            if REQUIRED:
                raise AssertionError(message)
            raise unittest.SkipTest(message)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.workspace = self.base / "workspace"
        self.workspace.mkdir()
        (self.workspace / "source.txt").write_text("alpha native needle\n")
        (self.workspace / "AGENTS.md").write_text("Native fixture root guidance.\n")
        (self.workspace / "docs").mkdir()
        (self.workspace / "docs/AGENTS.md").write_text("Native fixture nested guidance.\n")
        (self.workspace / "ignored").mkdir()
        (self.workspace / "ignored/AGENTS.md").write_text("Ignored context must not be discovered.\n")
        (self.workspace / ".gitignore").write_text("ignored/\n")
        git_env = {"PATH": "/usr/bin:/bin", "HOME": str(self.base), "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull}
        assert self.git is not None
        for arguments in (("init", "--quiet"), ("add", "source.txt", "AGENTS.md", "docs/AGENTS.md", ".gitignore")):
            subprocess.run([self.git, "-c", "core.hooksPath=/dev/null", *arguments], cwd=self.workspace, env=git_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, timeout=5)
        # Repository configuration must never run a program in any supposedly
        # readonly helper, including the constructor's git ls-files discovery.
        fsmonitor = self.workspace / "fsmonitor-hook"
        fsmonitor.write_text("#!/bin/sh\ntouch fsmonitor-ran\n")
        fsmonitor.chmod(0o755)
        subprocess.run([self.git, "config", "core.fsmonitor", str(fsmonitor)], cwd=self.workspace, env=git_env, check=True, timeout=5)

    def runtime(self, *, structured_only=False):
        from coding_tools_mcp.policy import IsolationConfig
        from coding_tools_mcp.server import Runtime, WorkspaceMutationPolicy
        runtime = Runtime(
            self.workspace,
            permission_mode="trusted",
            isolation=IsolationConfig(mode="strict", helper_path=self.helper, helper_sha256=self.pin),
            workspace_mutation=WorkspaceMutationPolicy(mode="structured-only" if structured_only else "unrestricted"),
        )
        self.addCleanup(runtime.close)
        return runtime

    def test_actual_startup_commands_git_search_listing_and_broker_patch(self):
        runtime = self.runtime()
        self.assertTrue(runtime.executor.last_launch_confirmed, "startup Git discovery did not confirm isolation")
        self.assertEqual([entry.path for entry in runtime.project_context.root_files], ["AGENTS.md"])
        self.assertIn("docs/AGENTS.md", runtime.project_context.nested_files)
        self.assertNotIn("ignored/AGENTS.md", runtime.project_context.nested_files, "Git discovery fell back to an unfiltered tree walk")
        self.assertFalse((self.workspace / "fsmonitor-ran").exists())
        started = runtime.exec_command({"cmd": "printf 'created\\n' > command-created.txt; printf 'runtime-marker\\n'", "yield_time_ms": 10000, "timeout_ms": 10000})
        self.assertEqual(started["exit_code"], 0, started)
        self.assertEqual(started["status"], "exited", started)
        self.assertTrue(started["command_id"])
        self.assertTrue(started["execution_isolation"]["confirmed"])
        output_ref = started["output_refs"]["stdout"]
        self.assertEqual(output_ref, f"command:{started['command_id']}:stdout")
        self.assertIn("runtime-marker", runtime.read_output({"output_ref": output_ref})["content"])
        self.assertEqual((self.workspace / "command-created.txt").read_text(), "created\n")
        status = runtime.git_status({})
        self.assertTrue(status["is_repo"], status)
        self.assertIn("source.txt", [entry["path"] for entry in status["entries"]])
        observed_fd = []
        actual_run = runtime.executor.run
        def observe_run(argv, *args, **kwargs):
            completed = actual_run(argv, *args, **kwargs)
            if Path(argv[0]).name in {"fd", "fdfind"}:
                observed_fd.append({"argv": list(argv), "returncode": completed.returncode,
                                    "stdout": completed.stdout, "stderr": completed.stderr})
            return completed
        # Instrument the real native executor only. No result is synthesized,
        # and all fd launches retain the strict per-execution policy.
        with patch.object(runtime.executor, "run", side_effect=observe_run):
            listing = runtime.list_files({"patterns": ["*.txt"]})
        fd_diagnostic = f"listing={listing!r}; actual fd executions={observed_fd!r}"
        self.assertEqual(listing.get("engine"), "fd", fd_diagnostic)
        self.assertIn("source.txt", [entry["path"] for entry in listing["files"]], fd_diagnostic)
        search = runtime.search_text({"query": "native needle"})
        self.assertEqual(search.get("engine"), "rg", search)
        self.assertEqual([match["path"] for match in search["matches"]], ["source.txt"])
        self.assertEqual(runtime.read_file({"path": "source.txt"})["content"], "alpha native needle\n")
        patched = runtime.apply_patch({"patch": "*** Begin Patch\n*** Update File: source.txt\n@@\n-alpha native needle\n+beta native needle\n*** End Patch"})
        self.assertIn("affected_files", patched)
        self.assertEqual(runtime.read_file({"path": "source.txt"})["content"], "beta native needle\n")
        self.assertFalse((self.workspace / "fsmonitor-ran").exists())

    def test_actual_structured_only_command_denied_broker_write_allowed(self):
        runtime = self.runtime(structured_only=True)
        started = runtime.exec_command({"cmd": "printf 'bad\\n' > source.txt", "yield_time_ms": 10000, "timeout_ms": 10000})
        self.assertTrue(started["execution_isolation"]["confirmed"])
        self.assertNotEqual(started["exit_code"], 0, started)
        self.assertEqual((self.workspace / "source.txt").read_text(), "alpha native needle\n")
        runtime.apply_patch({"patch": "*** Begin Patch\n*** Update File: source.txt\n@@\n-alpha native needle\n+structured write accepted\n*** End Patch"})
        self.assertEqual(runtime.read_file({"path": "source.txt"})["content"], "structured write accepted\n")
        self.assertTrue(runtime.workspace_mutation_payload()["enforced"])
        self.assertFalse((self.workspace / "fsmonitor-ran").exists())


@unittest.skipUnless(sys.platform == "darwin", "Native Seatbelt profile validation only")
class NativeSeatbeltProfileTests(unittest.TestCase):
    """Partial platform evidence; does NOT establish strict descendant cleanup."""
    @classmethod
    def setUpClass(cls):
        cls.launcher = Path("/usr/bin/sandbox-exec")
        if not cls.launcher.is_file():
            if REQUIRED:
                raise AssertionError("Native Seatbelt profile validation requires /usr/bin/sandbox-exec")
            raise unittest.SkipTest("sandbox-exec is unavailable")
        _trusted_install(cls.launcher, (), root_owned=True)

    def test_process_group_escape_and_syscall_filter_limit(self):
        """Characterize the blocker; this is not strict-backend acceptance.

        Every probe is finite and reaps its own fork/spawn child. No daemon
        waits in the background. Blocking setsid/setpgid syscall entry does
        not cover posix_spawn's in-kernel process-group attribute handling.
        """
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory).resolve()
            spec = SandboxSpec(workspace, (workspace, *system_read_roots()), (workspace,), ())
            base_profile = seatbelt_profile(spec)
            # Darwin syscall numbers are shared by arm64 and x86_64. These
            # test-only restrictions are deliberately NOT a production fix:
            # posix_spawn can perform these transitions inside the kernel.
            syscall_profile = base_profile + "\n" + "\n".join((
                "(disable-syscall-inference)",
                "(allow syscall-unix)",
                "(deny syscall-unix (syscall-number 82 147))",
            ))
            # A tiny native fixture avoids granting unrelated Python/ctypes
            # initialization sysctls just to test POSIX process attributes.
            source = workspace / "lifetime.c"
            executable = workspace / "lifetime"
            source.write_text(r"""
#define _DARWIN_C_SOURCE
#include <errno.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
extern char **environ;
static int wait_child(pid_t child) {
    int status;
    if (child < 0 || waitpid(child, &status, 0) != child) return 2;
    return WIFEXITED(status) ? WEXITSTATUS(status) : 3;
}
int main(int argc, char **argv) {
    if (argc < 2) return 2;
    const char *operation = argv[1];
    pid_t original_group = getpgrp();
    if (strcmp(operation, "spawn_child") == 0) {
        if (argc != 3) return 2;
        printf("{\"operation\":\"spawn_setpgroup\",\"changed_group\":%s,\"error\":0}\n",
               getpgrp() != (pid_t)atoi(argv[2]) ? "true" : "false");
        return 0;
    }
    if (strcmp(operation, "spawn_setpgroup") == 0) {
        posix_spawnattr_t attributes;
        if (posix_spawnattr_init(&attributes) != 0) return 2;
        if (posix_spawnattr_setpgroup(&attributes, 0) != 0 ||
            posix_spawnattr_setflags(&attributes, POSIX_SPAWN_SETPGROUP) != 0) return 2;
        char group[32];
        snprintf(group, sizeof group, "%d", original_group);
        char *arguments[] = {argv[0], "spawn_child", group, NULL};
        pid_t child;
        int error = posix_spawn(&child, argv[0], NULL, &attributes, arguments, environ);
        posix_spawnattr_destroy(&attributes);
        return error ? 2 : wait_child(child);
    }
    pid_t child = fork();
    if (child != 0) return wait_child(child);
    int result;
    if (strcmp(operation, "setsid") == 0) result = setsid();
    else if (strcmp(operation, "setpgid") == 0) result = setpgid(0, 0);
    else if (strcmp(operation, "daemon") == 0) result = daemon(1, 1);
    else _exit(2);
    int error = result < 0 ? errno : 0;
    printf("{\"operation\":\"%s\",\"changed_group\":%s,\"error\":%d}\n", operation,
           getpgrp() != original_group ? "true" : "false", error);
    fflush(stdout);
    _exit(0);
}
""")
            subprocess.run(["/usr/bin/cc", "-std=c11", "-Wno-deprecated-declarations", str(source), "-o", str(executable)],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=True)
            environment = {"PATH": "/usr/bin:/bin", "HOME": str(workspace), "TMPDIR": str(workspace)}
            evidence = {}
            for label, profile in (("current_profile", base_profile), ("syscall_filter_only", syscall_profile)):
                evidence[label] = {}
                for operation in ("setsid", "setpgid", "daemon", "spawn_setpgroup"):
                    with self.subTest(profile=label, operation=operation):
                        completed = subprocess.run(
                            [str(self.launcher), "-p", profile, str(executable), operation],
                            cwd=workspace, env=environment, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15,
                            start_new_session=True, check=False,
                        )
                        self.assertEqual(completed.returncode, 0, (label, operation, completed.stdout, completed.stderr))
                        observed = json.loads(completed.stdout)
                        evidence[label][operation] = observed
                        expected_escape = label == "current_profile" or operation == "spawn_setpgroup"
                        self.assertEqual(observed["changed_group"], expected_escape, observed)
                        self.assertEqual(observed["error"], 0 if expected_escape else 1, observed)
            print("SEATBELT_LIFETIME_LIMIT=" + json.dumps(evidence, sort_keys=True), flush=True)

    def test_native_seatbelt_file_network_rules_with_reachable_baselines(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            workspace = base / "workspace"
            workspace.mkdir()
            outside = base / "outside-secret"
            outside.write_text("private")
            self.assertEqual(outside.read_text(), "private")
            # Test both IP families and TCP/UDP directly. A local DNS-wire
            # exchange is among the UDP probes; no public DNS dependency.
            endpoints = []
            for family, host in ((socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")):
                for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
                    server = socket.socket(family, kind)
                    self.addCleanup(server.close)
                    server.settimeout(5)
                    server.bind((host, 0))
                    if kind == socket.SOCK_STREAM:
                        server.listen()
                        def echo(listener=server):
                            stream, _ = listener.accept()
                            with stream:
                                stream.sendall(stream.recv(512))
                    else:
                        def echo(listener=server):
                            data, peer = listener.recvfrom(512)
                            listener.sendto(data, peer)
                    worker = threading.Thread(target=echo, daemon=True)
                    worker.start()
                    address = server.getsockname()
                    with socket.socket(family, kind) as client:
                        client.settimeout(3)
                        client.connect(address)
                        payload = bytes.fromhex("123401000001000000000000076578616d706c6503636f6d0000010001")
                        client.sendall(payload)
                        self.assertEqual(client.recv(512), payload)
                    worker.join(timeout=5)
                    endpoints.append((int(family), int(kind), host, address[1]))
            spec = SandboxSpec(workspace, (workspace, *system_read_roots()), (workspace,), ())
            code = f"""
from pathlib import Path
import socket
Path('allowed').write_text('ok')
p=Path({str(outside)!r})
for action in [p.read_text,lambda:p.write_text('bad'),p.unlink]:
    try: action()
    except OSError: pass
    else: raise AssertionError('outside filesystem access')
for family,kind,host,port in {endpoints!r}:
    try:
        with socket.socket(family,kind) as stream:
            stream.settimeout(.5)
            stream.connect((host,port))
            stream.sendall(b'dns-wire')
    except OSError: pass
    else: raise AssertionError('Seatbelt network escape')
print('profile file/network checks passed; strict lifecycle not supported')
"""
            profile = seatbelt_profile(spec)
            interpreter = str(Path(sys.executable).resolve())
            environment = {"PATH": "/usr/bin:/bin", "HOME": str(workspace), "TMPDIR": str(workspace)}
            completed = subprocess.run([str(self.launcher), "-p", profile, interpreter, "-c", code], cwd=workspace, env=environment, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15, check=False)
            diagnostic = ""
            if completed.returncode != 0:
                # Only read-only/no-op probes; neither relaxes the tested
                # profile nor turns an unavailable platform into a skip.
                bootstrap = []
                for label, argv in (("system true", ["/usr/bin/true"]), ("Python startup", [interpreter, "-c", "pass"])):
                    probe = subprocess.run([str(self.launcher), "-p", profile, *argv], cwd=workspace, env=environment, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10, check=False)
                    bootstrap.append(f"{label}: returncode={probe.returncode}, stdout={probe.stdout!r}, stderr={probe.stderr!r}")
                # This permissive profile runs ONLY /usr/bin/true as a
                # diagnostic to distinguish launcher/OS failure from a missing
                # runtime operation. It never replaces the acceptance profile.
                baseline = subprocess.run([str(self.launcher), "-p", "(version 1)(allow default)(deny network*)", "/usr/bin/true"], cwd=workspace, env=environment, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10, check=False)
                bootstrap.append(f"allow-default true diagnostic: returncode={baseline.returncode}, stdout={baseline.stdout!r}, stderr={baseline.stderr!r}")
                try:
                    log = subprocess.run(["/usr/bin/log", "show", "--style", "compact", "--last", "1m", "--predicate", 'eventMessage CONTAINS[c] "Sandbox:" OR process == "sandboxd"'], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10, check=False)
                    bootstrap.append("Recent native sandbox diagnostics:\n" + log.stdout.decode(errors="replace")[-12000:] + log.stderr.decode(errors="replace")[-1000:])
                except (OSError, subprocess.TimeoutExpired) as error:
                    bootstrap.append(f"Native diagnostic log unavailable: {error}")
                crash_root = Path.home() / "Library/Logs/DiagnosticReports"
                reports = []
                for pattern in ("sandbox-exec*.ips", "true*.ips", "Python*.ips", "python*.ips"):
                    reports.extend(crash_root.glob(pattern))
                for report in sorted(reports, key=lambda path: path.stat().st_mtime, reverse=True)[:3]:
                    if report.stat().st_mtime >= time.time() - 120:
                        try:
                            bootstrap.append(f"Recent fixture crash report {report.name}:\n" + report.read_text(errors="replace")[:16000])
                        except OSError as error:
                            bootstrap.append(f"Crash report unavailable: {error}")
                diagnostic = (f"Seatbelt fixture returncode={completed.returncode}; interpreter={interpreter}\n"
                              f"stdout={completed.stdout!r}\nstderr={completed.stderr!r}\n"
                              + "\n".join(bootstrap) + "\nProfile:\n" + profile)
            self.assertEqual(completed.returncode, 0, diagnostic)
            self.assertIn(b"profile file/network checks passed", completed.stdout)
            self.assertEqual((workspace / "allowed").read_text(), "ok")
            self.assertEqual(outside.read_text(), "private")


class NativePlatformRejectionTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform in {"darwin", "win32"}, "Unsupported native strict platforms")
    def test_actual_platform_strict_rejected_without_side_effect(self):
        if sys.platform == "win32":
            import ctypes
            import platform
            # Readiness metadata only. Load the OS library from System32;
            # never call these APIs or create profiles/security environments.
            metadata: dict[str, object] = {
                "os_build": list(sys.getwindowsversion().platform_version),
                "product_type": sys.getwindowsversion().product_type,
                "architecture": platform.machine(), "process_bits": ctypes.sizeof(ctypes.c_void_p) * 8,
                "runner_image_version": os.environ.get("ImageVersion"),
                "dll_loaded": False,
            }
            names = ("CreateProcessSecurityEnvironment", "QueryProcessSecurityEnvironmentSupport", "CloseProcessSecurityEnvironment")
            try:
                processmodel = ctypes.WinDLL("processmodel.dll", winmode=0x00000800)
            except OSError as error:
                metadata["load_error"] = {"winerror": error.winerror, "errno": error.errno, "message": str(error)}
            else:
                metadata["dll_loaded"] = True
                metadata["exports"] = {name: hasattr(processmodel, name) for name in names}
            print("WINDOWS_PSEC_READINESS_ONLY=" + json.dumps(metadata, sort_keys=True), flush=True)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            marker = root / "side-effect"
            backend = SandboxBackend(SandboxSpec(root, (root,), (root,), ()))
            with self.assertRaises(ToolFailure) as caught:
                backend.spawn([sys.executable, "-c", f"open({str(marker)!r},'w').write('bad')"], cwd=root, env={})
            self.assertEqual(caught.exception.code, "SANDBOX_UNAVAILABLE")
            self.assertFalse(marker.exists())
            self.assertFalse(backend.capability_report()["strict_supported"])


if __name__ == "__main__":
    unittest.main()
