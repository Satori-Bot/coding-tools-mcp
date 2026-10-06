"""The only entry point for workspace-derived subprocesses.

The process module remains responsible for byte buffers and lifecycle. Every
launch here takes an immutable policy; read helpers receive narrower authority
and have configuration-driven program execution disabled.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .errors import ToolFailure
from .policy import ExecutionPolicy
from .processes import HARD_KILL_SIGNAL, spawn_process, terminate_process_group

if TYPE_CHECKING:
    from .file_broker import FileBroker
    from .sandbox import SandboxBackend

_GIT_CONFIG = (
    "core.fsmonitor=false", "core.hooksPath=/dev/null", "core.pager=cat",
    "core.attributesFile=/dev/null", "diff.external=", "diff.trustExitCode=false",
    "protocol.allow=never", "protocol.file.allow=never", "credential.helper=",
    "submodule.recurse=false",
)
_ENV_REJECT = re.compile(r"(TOKEN|SECRET|CREDENTIAL|PASSWORD|PASSWD|API.?KEY|PRIVATE)", re.I)
_HELPER_ENV = frozenset({
    "PATH", "PATHEXT", "SYSTEMROOT", "WINDIR", "COMSPEC", "LANG", "LC_ALL", "LC_CTYPE",
    "HOME", "TMPDIR", "TEMP", "TMP", "USERPROFILE",
})
_DANGEROUS_ENV = frozenset({
    "BASH_ENV", "ENV", "PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP", "NODE_OPTIONS",
    "PERL5LIB", "PERL5OPT", "RUBYLIB", "RUBYOPT", "RIPGREP_CONFIG_PATH",
    "GIT_CONFIG", "GIT_CONFIG_COUNT", "GIT_CONFIG_PARAMETERS", "GIT_CONFIG_SYSTEM",
    "GIT_CONFIG_GLOBAL", "GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR",
    "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_EXEC_PATH",
    "GIT_SSH", "GIT_SSH_COMMAND", "GIT_ASKPASS", "SSH_ASKPASS", "GIT_EXTERNAL_DIFF",
})
_COMPATIBILITY_GIT_ENV = frozenset({
    "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM", "GIT_CONFIG_NOSYSTEM",
    "GIT_TEST_ASSUME_DIFFERENT_OWNER",
})


def filtered_environment(env: dict[str, str], *, helper: bool, strict: bool) -> dict[str, str]:
    result: dict[str, str] = {}
    for key, value in env.items():
        upper = key.upper()
        # Preserve the operator's protected-config selection in compatibility
        # mode, including system safe.directory entries and explicit opt-outs.
        # Git's executable mechanisms are still disabled by _prepare below.
        compatibility_git = helper and not strict and upper in _COMPATIBILITY_GIT_ENV
        if (helper or strict) and not compatibility_git and (
            _ENV_REJECT.search(upper) or upper in _DANGEROUS_ENV
            or upper.startswith(("LD_", "DYLD_", "GIT_CONFIG_KEY_", "GIT_CONFIG_VALUE_"))
        ):
            continue
        if helper and not compatibility_git and upper not in _HELPER_ENV:
            continue
        # Windows has a single case-insensitive namespace, not Path and PATH.
        canonical = upper if os.name == "nt" else key
        result[canonical] = value
    if helper:
        result.update({
            "GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0",
            "GIT_PAGER": "cat", "PAGER": "cat",
        })
        if strict:
            result["GIT_CONFIG_NOSYSTEM"] = "1"
            result["GIT_CONFIG_GLOBAL"] = os.devnull
    return result


class WorkspaceExecutor:
    def __init__(
        self,
        policy: Callable[[str], ExecutionPolicy],
        environment: Callable[[], dict[str, str]],
        *,
        file_broker: FileBroker | None = None,
    ) -> None:
        self._policy = policy
        self._environment = environment
        self.file_broker = file_broker
        self.last_launch_confirmed = False

    def _prepare(
        self, argv: Sequence[str], purpose: str, env: dict[str, str] | None,
    ) -> tuple[list[str], dict[str, str], ExecutionPolicy]:
        raw_env = self._environment() if env is None else env
        # Environment preparation may select a writable fallback runtime tree.
        # Compile only after that one-time choice so mounts and HOME agree.
        policy = self._policy(purpose)
        if not argv or not all(isinstance(item, str) and "\0" not in item for item in argv):
            raise ToolFailure("INVALID_ARGUMENT", "An argv list of non-NUL strings is required.", category="validation")
        helper = purpose == "read-helper"
        clean_env = filtered_environment(raw_env, helper=helper, strict=policy.strict)
        command = list(argv)
        executable = Path(command[0])
        if not executable.is_absolute():
            found = shutil.which(command[0], path=clean_env.get("PATH", os.defpath))
            if found:
                executable = Path(found)
        if policy.strict:
            try:
                real = executable.resolve(strict=True)
            except (OSError, RuntimeError, ValueError) as exc:
                raise ToolFailure("COMMAND_SPAWN_FAILED", "Executable is unavailable.", category="runtime") from exc
            # Read helpers are part of the service, never workspace-selected
            # programs. Arbitrary commands are intentionally allowed inside
            # the sandbox and do not receive service/helper authority.
            if helper and (
                not executable.is_absolute() or not policy.permits_read(real)
                or any(real.is_relative_to(root) for root in policy.write_roots)
                or real.is_relative_to(policy.workspace)
            ):
                raise ToolFailure("UNTRUSTED_EXECUTABLE", "Read-helper executable is not in a trusted toolchain root.", category="security")
            command[0] = str(real)
        name = executable.name.lower().removesuffix(".exe")
        if helper and name == "git":
            if policy.strict:
                self._validate_git_storage(policy)
            settings = list(_GIT_CONFIG)
            if os.name == "nt":
                settings = [s.replace("/dev/null", "NUL") for s in settings]
            command = [command[0], *(part for setting in settings for part in ("-c", setting)), *command[1:]]
            # --no-ext-diff and --no-textconv are command-specific, not global
            # options. These cover every read operation that can invoke them.
            for index, arg in enumerate(command):
                if arg in {"diff", "show", "log", "blame"}:
                    command[index + 1:index + 1] = ["--no-textconv"] + ([] if arg == "blame" else ["--no-ext-diff"])
                    break
        elif helper and name == "rg" and "--no-config" not in command:
            command.insert(1, "--no-config")
        return command, clean_env, policy

    def _validate_git_storage(self, policy: ExecutionPolicy) -> None:
        """Do not let .git indirection silently grant external storage access."""
        broker = self.file_broker
        if broker is None:
            raise ToolFailure("SANDBOX_UNAVAILABLE", "Strict Git helpers require the structured file broker.", category="security")
        if not broker.exists(".git"):
            return
        git_dir = policy.workspace / ".git"
        if broker.is_file(".git"):
            text = broker.read_text(".git").strip()
            if not text.startswith("gitdir:"):
                raise ToolFailure("GIT_ERROR", "Invalid Git directory file.", category="validation")
            git_dir = (policy.workspace / text[7:].strip()).resolve(strict=False)
        if not git_dir.is_relative_to(policy.workspace):
            raise ToolFailure("EXTERNAL_GIT_STORAGE_DENIED", "External Git worktrees require an explicitly authorized storage policy.", category="security")
        common = git_dir / "commondir"
        if broker.exists(common):
            target = (git_dir / broker.read_text(common).strip()).resolve(strict=False)
            if not target.is_relative_to(policy.workspace):
                raise ToolFailure("EXTERNAL_GIT_STORAGE_DENIED", "External Git common directories are denied.", category="security")
            git_dir = target
        alternates = git_dir / "objects" / "info" / "alternates"
        if broker.exists(alternates) and broker.read_text(alternates).strip():
            # Git's quoting and recursive alternate syntax is deliberately not
            # interpreted as authority. A future explicit storage grant can
            # support these; no repository file can grant itself access.
            raise ToolFailure("EXTERNAL_GIT_STORAGE_DENIED", "Git object alternates are unsupported in strict mode.", category="security")

    @staticmethod
    def _backend(policy: ExecutionPolicy) -> SandboxBackend:
        from .sandbox import SandboxBackend, SandboxSpec
        return SandboxBackend(SandboxSpec(
            workspace=policy.workspace, read_roots=policy.read_roots,
            write_roots=policy.write_roots, deny_roots=policy.deny_roots,
            network=policy.network, helper_path=policy.helper_path,
            helper_sha256=policy.helper_sha256, allowed_destinations=policy.allowed_destinations,
        ))

    def capability_report(self) -> dict[str, Any]:
        policy = self._policy("command")
        if not policy.strict:
            return {"mode": "compatibility", "strict": False, "network_enforced": False}
        return {
            "mode": "strict", "network": policy.network,
            **self._backend(policy).capability_report(),
            "last_launch_confirmed": self.last_launch_confirmed,
        }

    def spawn_managed(
        self, command: Any, *, cwd: str, shell: bool, env: dict[str, str], tty: bool,
        popen_kwargs: dict[str, Any],
    ) -> tuple[subprocess.Popen[bytes], int | None]:
        policy = self._policy("command")
        if not policy.strict:
            return spawn_process(command, cwd=cwd, shell=shell, env=env, tty=tty, popen_kwargs=popen_kwargs)
        if shell:
            command = ["/bin/sh", "-c", command]
        self.last_launch_confirmed = False
        argv, clean_env, policy = self._prepare(command, "command", env)
        result = self._backend(policy).spawn(argv, cwd=Path(cwd), env=clean_env, tty=tty)
        self.last_launch_confirmed = True
        return result

    def popen(
        self, argv: Sequence[str], *, cwd: str | None = None, env: dict[str, str] | None = None,
        purpose: str = "read-helper", **kwargs: Any,
    ) -> subprocess.Popen[Any]:
        self.last_launch_confirmed = False
        command, clean_env, policy = self._prepare(argv, purpose, env)
        if not policy.strict:
            if os.name != "nt":
                kwargs.setdefault("start_new_session", True)
            kwargs.setdefault("close_fds", True)
            if os.name == "nt":
                from .windows_job import spawn_windows_process
                return spawn_windows_process(command, cwd=cwd or str(policy.workspace), env=clean_env, **kwargs)
            return subprocess.Popen(command, cwd=cwd or str(policy.workspace), env=clean_env, **kwargs)
        text = kwargs.pop("text", False) or kwargs.pop("universal_newlines", False)
        encoding = kwargs.pop("encoding", None)
        errors = kwargs.pop("errors", None)
        stdio: dict[str, Any] = {}
        for key in ("stdin", "stdout", "stderr"):
            value = kwargs.pop(key, subprocess.PIPE)
            stdio[key] = subprocess.DEVNULL if value is None else value
            if value not in (None, subprocess.PIPE, subprocess.DEVNULL):
                raise ToolFailure("INVALID_ARGUMENT", "Strict helpers support only private pipes.", category="validation")
        if kwargs:
            raise ToolFailure("INVALID_ARGUMENT", f"Unsupported strict process options: {', '.join(kwargs)}", category="validation")
        process, _ = self._backend(policy).spawn(
            command, cwd=Path(cwd or policy.workspace), env=clean_env, stdio=stdio,
            text=bool(text), encoding=encoding, errors=errors,
        )
        self.last_launch_confirmed = True
        return process

    def run(
        self, argv: Sequence[str], *, timeout: float | None = None, input: Any = None,
        check: bool = False, **kwargs: Any,
    ) -> subprocess.CompletedProcess[Any]:
        # communicate's timeout cleanup normally kills only the direct child;
        # managed helper process groups and native supervisors own descendants.
        if os.name != "nt" and not self._policy(str(kwargs.get("purpose", "read-helper"))).strict:
            purpose = kwargs.pop("purpose", "read-helper")
            env = kwargs.pop("env", None)
            command, clean_env, policy = self._prepare(argv, purpose, env)
            kwargs.setdefault("cwd", str(policy.workspace))
            kwargs.setdefault("close_fds", True)
            return subprocess.run(command, env=clean_env, timeout=timeout, input=input, check=check, **kwargs)
        if input is not None:
            kwargs.setdefault("stdin", subprocess.PIPE)
        process = self.popen(argv, **kwargs)
        try:
            stdout, stderr = process.communicate(input=input, timeout=timeout)
        except BaseException:
            terminate_process_group(process, HARD_KILL_SIGNAL)
            process.communicate()
            raise
        finally:
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is not None:
                    stream.close()
        completed = subprocess.CompletedProcess(list(argv), process.returncode, stdout, stderr)
        if check:
            completed.check_returncode()
        return completed
