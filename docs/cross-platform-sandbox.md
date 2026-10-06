# Cross-platform execution isolation

This is the reference for the additive execution-isolation mode. Existing
[permission modes](permission-modes.md) remain command-policy settings; they
are not, by themselves, a cross-platform security boundary.

## Contract and migration

`--execution-isolation compatibility` is the default. It preserves existing
configuration semantics, including the documented limitations of optional
Landlock enforcement. Enabling strict execution is an explicit deployment
choice, separate from `--permission-mode` and `--workspace-mutation`.

### Configuration

| CLI option | Environment equivalent | Meaning |
| --- | --- | --- |
| `--execution-isolation compatibility\|strict` | `CODING_TOOLS_MCP_EXECUTION_ISOLATION` | Select the boundary; default `compatibility`. |
| `--sandbox-network offline\|proxy` | `CODING_TOOLS_MCP_SANDBOX_NETWORK` | Request the network capability; default `offline`. Unsupported modes fail closed. |
| `--sandbox-allow-destination HOST:PORT` (repeatable) | `CODING_TOOLS_MCP_SANDBOX_ALLOW_DESTINATIONS` | Exact destinations for strict `proxy` mode; environment value is comma-separated. |
| `--sandbox-helper /absolute/path` | `CODING_TOOLS_MCP_SANDBOX_HELPER` | Explicit native helper installation. |
| `--sandbox-helper-sha256 HEX` | `CODING_TOOLS_MCP_SANDBOX_HELPER_SHA256` | Expected helper binary SHA-256, 64 hexadecimal characters. |
| `--sandbox-read-root PATH` (repeatable) | `CODING_TOOLS_MCP_SANDBOX_READ_ROOTS` | Additional administrator-approved toolchain read roots. |
| `--sandbox-deny-root PATH` (repeatable) | `CODING_TOOLS_MCP_SANDBOX_DENY_ROOTS` | Protected paths; strict process read/write grants must be disjoint from them. The structured broker gives denials precedence. |

Root-list environment variables use the platform path-list separator (`:` on
POSIX, `;` on Windows). These are server/operator settings, not per-command
permissions supplied by an untrusted client.
The sandbox network settings enforce a boundary only with strict execution;
setting them in compatibility mode does not install an egress firewall.

Build and install the native binary using the
[helper installation instructions](../native/sandbox-helper/README.md#build-and-install).
The Python wheel does not bundle it. For example, on a provisioned Linux host:

```sh
helper=/opt/coding-tools-mcp/bin/coding-tools-sandbox-helper
digest=$(python -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest())' "$helper")
coding-tools-mcp --workspace /srv/workspace --permission-mode trusted \
  --execution-isolation strict --sandbox-network offline \
  --sandbox-helper "$helper" --sandbox-helper-sha256 "$digest"
```

Use a preverified installed binary when recording the digest; hashing an
untrusted file does not establish trust. `trusted` relaxes command scanning;
strict OS restrictions still apply, including with `--permission-mode dangerous`.
`server_info.execution_isolation` and `check_exec_environment.execution_isolation`
report capabilities and `availability`. An `unprobed` report is not an installed
sandbox. Successful strict `exec_command` results include
`execution_isolation.confirmed=true` only after the private startup handshake.

### Platform status

| Platform | Strict execution in this implementation | Required evidence |
| --- | --- | --- |
| Linux x86-64 / AArch64 | Offline and controlled-CONNECT-proxy backends use bubblewrap and the pinned Rust helper; host prerequisites are mandatory. | Native kernel-boundary and proxy suites on the integration commit; acceptance remains pending until those run successfully. |
| macOS | Unavailable; strict command launch is rejected. Seatbelt profiles alone do not guarantee cleanup of hostile descendants that detach from a process group. | Native rejection, experimental Seatbelt file/network policy, and structured-broker tests; these do not establish a supported full-strict backend. |
| Windows | Unavailable; strict execution and strict structured access are rejected. Native shell compatibility is separate. | Native cmd and PowerShell 7 compatibility suites and explicit strict rejection. |

Linux requires bubblewrap 0.12.0 or newer and usable unprivileged namespaces.
The minimum includes the upstream
[source-path resolution security fix](https://github.com/containers/bubblewrap/releases/tag/v0.12.0).
CI builds the pinned 0.12.0 source instead of assuming a runner's distro package
is sufficient. Do not pass bubblewrap's `--not-a-security-boundary` option or
disable host security policy to make a failing sandbox start.

The [helper reference](../native/sandbox-helper/README.md) describes the
versioned control protocol, seccomp restrictions, and the source evidence for
the macOS descendant-lifetime blocker. Unsupported syscall architectures and
compatibility ABIs fail closed.

Strict mode must fail closed. A missing or untrusted helper, unavailable
backend, unsupported capability, invalid policy, or failure to install the
isolation cannot silently fall back to an ordinary subprocess. Installing
restrictions is a prerequisite for running the requested payload. An error
does not authorize retrying in compatibility mode.

Common startup failures are `SANDBOX_UNAVAILABLE` (missing platform capability),
`SANDBOX_NETWORK_UNSUPPORTED` (unsupported network request or missing proxy
allowlist), `SANDBOX_HELPER_UNTRUSTED` (installation or hash validation),
`SANDBOX_POLICY_INVALID` (invalid roots/policy), and
`SANDBOX_INITIALIZATION_FAILED` (restriction installation or startup protocol).
Use the error details to fix the prerequisite; do not disable isolation as an
automatic recovery path.

Before enabling strict mode:

1. Use a dedicated service account with no unrelated secrets. Keep the helper,
   authentication material, policy/control state, and logs outside writable
   command roots.
2. Install and pin the native helper from the same reviewed source version as
   the server. Do not discover it through workspace-controlled `PATH` entries.
3. Identify the minimum toolchain read roots and command write roots. A
   read-root exception grants access to everything under that root; avoid
   home directories and broad host mounts.
4. Run the native acceptance tests on the actual host and filesystem. A unit
   test with a mocked launcher does not establish a kernel boundary.
5. Enable strict mode explicitly and inspect the reported capabilities and
   errors before accepting work. Do not treat a successful server startup as
   proof that a command's sandbox was installed.

Changing the default to strict in a future release needs its own migration
notice. Hosts that previously continued after a Landlock warning may be unable
to run commands under strict mode.

## Boundary and threat model

The intended boundary includes all workspace-derived subprocesses and
structured file access, not just `exec_command`. Git discovery during startup,
Git tools, `git check-ignore`, `rg`, and `fd` must go through the execution layer.
Read-like subprocesses need read-only workspace access, offline networking,
and a minimal environment. Git hooks, fsmonitor, external diff, textconv, and
search-tool configuration or preprocessors must not become implicit grants.

The MCP service, native helper, helper installation, OS kernel, and configured
toolchain are trusted. A malicious administrator or compromised kernel is
outside this boundary. The isolation is not a VM boundary and does not make
the host safe against kernel vulnerabilities or arbitrary resource exhaustion.

The environment must keep service credentials and loader/startup variables
away from the child. An independent command HOME and temporary directory are
not places to store the service's own control data. Inherited descriptors and
Windows handles must be restricted to those needed for the command.

### Writable source permits deletion

Allowing arbitrary programs to write a workspace also allows them to delete
or replace source files there. Command scanning can warn about recognizable
destructive syntax; it cannot prevent all equivalent operations.

Use `--workspace-mutation structured-only` when source should be read-only to
commands. Give build tools only the necessary `--write-path` directories and
perform source edits through structured file tools. This separates who may
write; it is not version control, a backup, or a transaction across every
file in a patch.

### Protected roots and path races

Sensitive server state and the helper installation must remain outside every
command-readable or command-writable root. Strict process launch rejects any
overlap rather than using pathname masks: renaming an ancestor or a preexisting
hardlink alias can defeat a mask. A granted tree authorizes its contents, including
preexisting aliases; the host must not expose private data through those trees.
Declaring a broad toolchain root must not implicitly expose service credentials.
The structured broker separately enforces nested path and known-inode denials.
The helper's installation directory is automatically included in denied roots;
do not install it in a general toolchain directory that commands need to read.
Use a dedicated installation directory such as the example above.

Path normalization followed by a later path-based open is insufficient when
an adversarial process can replace an ancestor with a symlink or junction.
The strict POSIX file broker anchors the workspace with a directory descriptor,
opens intermediate directories with no-follow checks, and uses descriptor-relative
operations. It rejects symlinks, hard-linked regular files, and device/FIFO/socket
leaves; listing skips denied entries. Existing denied-root inode identities
remain denied after rename. Strict Windows access is unavailable until there
is an equivalent handle-relative, reparse-point-aware broker.

The root descriptor authorizes the directory object, even if a host process
renames that directory. Patch revision checks remain optimistic concurrency
checks; they are not an adversarial compare-and-swap transaction. Test
intermediate links as well as final links, absent destinations, and concurrent
path swaps.
Atomic replacement does not by itself solve ancestor races or make several
file updates atomic.

An external Git worktree administration directory or object alternate is not
authorized merely because repository configuration points to it. The current
strict executor rejects external Git worktree/common directories and object
alternates. Adding a general read root does not enable those unsupported
storage layouts.

## Networking

Linux offline mode combines a disconnected network namespace with a seccomp
filter denying socket and socketpair creation, including Internet, Unix,
netlink, and vsock families. Blocking recognizable commands or setting
`HTTP_PROXY` and `HTTPS_PROXY` cannot provide this boundary.

Linux controlled proxy mode is implemented, with native acceptance required
before deployment. Add `--sandbox-network proxy` and repeat
`--sandbox-allow-destination example.com:443` for the actual destinations to
authorize. There are no wildcard or URL/path grants. An empty allowlist fails
closed. The environment equivalent accepts comma-separated exact authorities;
IPv6 literals use `[ADDRESS]:PORT`.

A trusted relay inside the isolated network namespace exposes one private
loopback proxy entry and forwards CONNECT traffic to the host policy proxy
over a dedicated Unix socket. Command code cannot open Unix sockets or acquire
the relay's descriptors. The namespace has no direct Internet or host-loopback
route; namespace-local communication is not a grant to host services.
Proxy environment variables only help clients locate this enforced exit.

The host proxy implements CONNECT TCP tunneling. It checks exact hostname and
port, validates every resolved address as globally routable, rejects host-local
addresses, and connects to a checked numeric address. Private, link-local,
loopback, transition, and other special-use addresses are blocked even if their
hostname is listed. There is no private-address override in this release.
Each new CONNECT is checked, including a redirect that needs another target.
TLS bytes pass through unchanged; plaintext HTTP forwarding is not implemented.
Closing the proxy revokes its listener and active tunnels.

A controlled proxy is a distinct capability, not a synonym for offline mode
or proxy environment variables. Its acceptance contract requires:

- The command's only external egress is the configured proxy endpoint, with
  no access to host loopback ports or direct remote addresses.
- The proxy checks the requested hostname and port and the actual resolved
  addresses. Private, link-local, loopback, and host services remain denied.
- Each new connection or redirect target is checked. The client cannot turn
  an allowed hostname into a different destination through DNS changes.
- Proxy death or unavailable policy causes the request to fail.
- Ignoring proxy variables and using TCP, IPv6, UDP, or QUIC does not bypass
  the OS restriction.

Allowing a destination lets it receive data that the command can read.
Domain rules are not content inspection or a data-loss-prevention system.
TLS interception, credential injection, and general UDP forwarding are
separate features and must not be inferred from HTTPS support.

## Windows compatibility and deployment

Native Windows compatibility is not a claim of strict filesystem or network
isolation. Shell selection, environment merging, encoding, MSVC support, and
process cleanup can work without creating a deny-by-default read boundary.
Job Objects alone do not provide filesystem isolation.

| Server environment setting | Behavior |
| --- | --- |
| `CODING_TOOLS_MCP_WINDOWS_SHELL=auto` | Default; prefer a trusted PowerShell 7 installation, then use cmd only if fallback is allowed. |
| `CODING_TOOLS_MCP_WINDOWS_SHELL=pwsh` | Require PowerShell 7; do not fall back. |
| `CODING_TOOLS_MCP_WINDOWS_SHELL=cmd` | Select the Windows system cmd.exe without probing PowerShell. |
| `CODING_TOOLS_MCP_PWSH_PATH` | Pin an absolute administrator-managed PowerShell executable; invalid pins fail and cannot be combined with cmd mode. |
| `CODING_TOOLS_MCP_ALLOW_CMD_FALLBACK=true\|false` | Control automatic fallback; compatibility default is `true`. |

The `exec_command` result's `shell` diagnostic includes `kind`, `executable`, `fallback`,
`fallback_reason`, and `warning`. Use the syntax of the actual selected shell;
the server does not translate a PowerShell program into cmd syntax.

Windows PowerShell 5.1 is not PowerShell 7. Explicit PowerShell configuration
must be validated before any version probe; a bad explicit path is an error,
not permission to search an untrusted workspace for another executable.
Automatic selection must consider only trusted installations and disclose
the actual shell and any fallback reason. Windows environment names are
case-insensitive; preserve required MSVC variables without allowing duplicate
case spellings to reintroduce filtered credentials or loader variables.
The default `--shell-env-inherit core` remains narrow. Initialize the Visual
Studio environment before starting the service and explicitly use
`--shell-env-inherit all` or the existing include controls when a build needs
the MSVC environment; credential/loader filtering still applies.

When native strict capabilities are unavailable, strict execution must be
rejected. For an MSVC workload requiring a strong deployable host boundary,
run the entire service and toolchain inside a dedicated Windows VM. Expose
only the required work directory and enforce networking at the VM boundary;
do not expose host secrets, broad shared drives, or an unrestricted host
management channel. VM configuration is operator-owned and is not installed
or attested by this package.

WSL2 is a Linux-toolchain route only when host disk mounts and Windows interop
are appropriately restricted. It is not native MSVC compatibility. Restricted
tokens, ACLs, or experimental MXC/PSEC/AppContainer work must be evaluated
against the complete read/write/network contract before being called strict.

## Native acceptance and evidence

The [native workflow](../.github/workflows/cross-platform-sandbox.yml) runs on
pull requests. A workflow definition is not a passing run. Record the commit,
native runner/OS, backend and helper version, executed test names, failures,
and skips before claiming a platform is accepted. Linux mock tests cannot
substitute for native Windows or macOS results.

The workflow's Windows matrix explicitly selects cmd and PowerShell 7. The
cmd group verifies execution without a PowerShell probe, but GitHub's hosted
image may still contain PowerShell; this is not evidence from an image where
PowerShell 7 is uninstalled. Automatic missing-PowerShell fallback is covered
separately by selection unit tests. Existing cmd-oriented lifecycle/encoding
tests run only in the cmd group. The existing
[MSVC smoke job](../.github/workflows/compliance.yml) remains the native compiler
and environment-inheritance gate.

The Windows matrix also runs `tests.test_windows_job_native` in both shell
groups. Its acceptance scope is ordinary CreateProcess descendants, including
root exit, kill, and timeout after assignment to a kill-on-close Job before the
root begins execution. Independently brokered launches through WMI or scheduled
tasks are outside that lifecycle claim. This gate does not turn Windows
compatibility into strict filesystem or network isolation.

Acceptance must cover the following with real programs and disposable
fixtures:

- Allowed reads/writes succeed. External reads, writes, and deletes fail;
  protected service/approval/helper paths remain unreadable or unwritable as
  required by policy.
- Source mutation follows read-only versus writable policy, including dynamic
  shell syntax and interpreter-generated code.
- Symlinks, junctions, path exchanges, public writable directories, and
  external Git directories do not expand the grant.
- Direct TCP/UDP, IPv4/IPv6, DNS, and host loopback cannot bypass networking.
  First prove each fixture is reachable outside isolation so ordinary network
  failure cannot pass a denial test.
- Repository-controlled Git helpers and search preprocessors cannot escape;
  include startup Git discovery as well as explicit tool calls.
- Timeout, kill, and service shutdown stop the child and grandchildren.
  Detect surviving descendants instead of checking only the parent PID.
- Failed initialization runs no payload and produces no side effects. A
  proxy outage cannot fall back to direct access.
- Windows runs distinct cmd and PowerShell 7 suites, Chinese paths, quoting,
  PATHEXT, encoding regressions, and initialized MSVC compilation.

A skipped capability test is unavailable evidence, not successful isolation.
Keep existing protocol, command-ID/output, timeout, encoding, and mutation
regressions alongside these tests.

## Integration history and closure criteria

This development line selectively carries forward the Windows compatibility
work discussed in [PR #37](https://github.com/xyTom/coding-tools-mcp/pull/37)
and its [PR #69 CI mirror](https://github.com/xyTom/coding-tools-mcp/pull/69).
The compatibility implementation is selectively adapted, not wholesale
cherry-picked, from:

- Frederick Daell Lied Diaz (`Yuzu02@users.noreply.github.com`),
  [73ffb99e7920dacfc1166c1554b91dfdad4898a5](https://github.com/xyTom/coding-tools-mcp/commit/73ffb99e7920dacfc1166c1554b91dfdad4898a5).
- `cf-pages` (`80505777+cf-pages@users.noreply.github.com`),
  [784404c4492461d2ed37be8b038c328684dac8e2](https://github.com/xyTom/coding-tools-mcp/commit/784404c4492461d2ed37be8b038c328684dac8e2)
  and
  [b8d8bb38ebdaaa639ff41179ef21e6e61830b4f1](https://github.com/xyTom/coding-tools-mcp/commit/b8d8bb38ebdaaa639ff41179ef21e6e61830b4f1).

Preserve original contributor attribution and identify actual source commits
when moving code. Do not merge old branches wholesale over newer encoding,
process-management, or protocol fixes. New implementation and an architectural
reference are different from copied source; retain licenses and modification
records for any source that is reused.

The design was informed by the
[Codex reference at commit 822e58cc3d666166c7446c5b1ea2e52f5d09594c](https://github.com/openai/codex/tree/822e58cc3d666166c7446c5b1ea2e52f5d09594c).
That reference does not establish this project's capabilities or guarantee
that different Windows backends have equivalent boundaries.

Use one integration pull request with its own CI. Closing historical tickets
requires evidence for the specific scope, not just the existence of this
document or a replacement pull request:

| Item | Closure acceptance |
| --- | --- |
| [#37](https://github.com/xyTom/coding-tools-mcp/pull/37) | Preserve closed history and link the integration PR; do not represent it as merged. |
| [#69](https://github.com/xyTom/coding-tools-mcp/pull/69) | Retire the CI mirror only after the authoritative integration PR and normal CI exist. |
| [#36](https://github.com/xyTom/coding-tools-mcp/issues/36) | Native Windows shell selection, environment, quoting, fallback, MSVC, and encoding acceptance passes. |
| [#43](https://github.com/xyTom/coding-tools-mcp/issues/43) | All promised native filesystem and descendant-process boundaries pass; Job Objects or weaker tokens alone are insufficient. |
| [#44](https://github.com/xyTom/coding-tools-mcp/issues/44) | Dynamic commands cannot bypass the declared file/network policy, and scanner claims match actual capabilities. |
| [#45](https://github.com/xyTom/coding-tools-mcp/issues/45) | Both offline and controlled-proxy modes defeat direct-connection bypasses. |
| [#79](https://github.com/xyTom/coding-tools-mcp/issues/79) | Real approvals are identity/workspace/scope/expiry-bound and consumed by execution. Static configuration or a stub grant does not qualify. |

OS isolation does not establish per-client command ownership or implement
approval grants. A workspace remains one shared trust domain unless a
separate identity/ownership change explicitly provides stronger guarantees.
