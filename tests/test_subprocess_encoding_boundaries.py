"""Real Git/fd/rg byte-boundary regression tests; discovery credited to PR #85."""

from __future__ import annotations
import codecs
import json
import locale
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path
from coding_tools_mcp.server import Runtime, Workspace


@unittest.skipUnless(shutil.which("git"), "git not installed")
class SubprocessEncodingBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        self.runtime = Runtime(self.root)

    def tearDown(self):
        self.runtime.close()
        self.tmp.cleanup()

    def commit(self, subject):
        (self.root / "file.txt").write_text("hello\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.root), "add", "file.txt"], check=True)
        subprocess.run(
            [
                "git",
                "-C",
                str(self.root),
                "-c",
                "user.name=Audit",
                "-c",
                "user.email=audit@example.invalid",
                "commit",
                "-qm",
                subject,
            ],
            check=True,
        )

    def test_git_log_does_not_silently_corrupt_configured_encoding(self):
        self.commit("caf\u00e9")
        subprocess.run(
            [
                "git",
                "-C",
                str(self.root),
                "config",
                "i18n.logOutputEncoding",
                "ISO-8859-1",
            ],
            check=True,
        )
        result = self.runtime.git_log({})
        self.assertEqual(result["commits"][0]["subject"], "caf\u00e9")

    @unittest.skipIf(os.name == "nt", "POSIX byte filenames only")
    def test_ignored_byte_filename_is_not_silently_unignored(self):
        name = os.fsdecode(b"ignored-\xff.txt")
        (self.root / ".gitignore").write_bytes(b"ignored-\xff.txt\n")
        os.close(
            os.open(
                os.fsencode(self.root) + b"/ignored-\xff.txt",
                os.O_CREAT | os.O_WRONLY,
                0o600,
            )
        )
        ignored = Workspace(self.root).git_ignored_paths([name])
        self.assertIn(name, ignored)

    def test_utf8_git_log_is_correct_under_selected_locale(self):
        self.commit("\u4e2d\u6587 \u6587\u4ef6 caf\u00e9")
        result = self.runtime.git_log({})
        self.assertEqual(
            result["commits"][0]["subject"], "\u4e2d\u6587 \u6587\u4ef6 caf\u00e9"
        )

    def test_utf8_git_ignore_roundtrip(self):
        name = "\u4e2d\u6587-\u6587\u4ef6.txt"
        (self.root / name).write_text("hello", encoding="utf-8")
        (self.root / ".gitignore").write_text(name + "\n", encoding="utf-8")
        self.assertIn(name, Workspace(self.root).git_ignored_paths([name]))

    @unittest.skipUnless(
        shutil.which("fd") or shutil.which("fdfind"), "fd not installed"
    )
    def test_fd_utf8_filename(self):
        name = "\u4e2d\u6587-\u6587\u4ef6.txt"
        (self.root / name).write_text("hello", encoding="utf-8")
        result = self.runtime._list_files_with_fd(
            self.runtime.workspace.resolve_existing("."),
            ["**"],
            [],
            include_hidden=False,
            include_ignored=True,
            max_results=100,
            sort_key="path",
        )
        self.assertIsNotNone(result, "fd fast path failed or silently fell back")
        self.assertIn(name, [x["path"] for x in result["files"]])

    @unittest.skipUnless(
        shutil.which("fd") or shutil.which("fdfind"), "fd not installed"
    )
    @unittest.skipIf(os.name == "nt", "POSIX byte filenames only")
    def test_fd_nonutf8_name_is_not_silently_omitted(self):
        name = os.fsdecode(b"raw-\xff.txt")
        os.close(
            os.open(
                os.fsencode(self.root) + b"/raw-\xff.txt",
                os.O_CREAT | os.O_WRONLY,
                0o600,
            )
        )
        try:
            result = self.runtime._list_files_with_fd(
                self.runtime.workspace.resolve_existing("."),
                ["**"],
                [],
                include_hidden=False,
                include_ignored=True,
                max_results=100,
                sort_key="path",
            )
        except UnicodeError:
            return
        if result is None:
            return  # Explicit fallback preserves the original fallback path.
        self.assertIn(name, [x["path"] for x in result["files"]])

    @unittest.skipUnless(shutil.which("rg"), "ripgrep not installed")
    def test_rg_utf8_json(self):
        name = "\u4e2d\u6587.txt"
        (self.root / name).write_text("needle \u4e2d\u6587\n", encoding="utf-8")
        result = self.runtime._search_text_with_rg(
            self.runtime.workspace.resolve_existing("."),
            "needle",
            regex=False,
            case_sensitive=True,
            include_globs=[],
            exclude_globs=[],
            context_lines=0,
            max_results=100,
            max_preview_bytes=1000,
        )
        self.assertIsNotNone(result)
        self.assertEqual(result["matches"][0]["path"], name)
        self.assertIn("\u4e2d\u6587", str(result["matches"][0]))


if __name__ == "__main__":
    selected = os.environ.get("AUDIT_LOCALE")
    if selected:
        locale.setlocale(locale.LC_CTYPE, selected)
    native_encoding = locale.getencoding()
    injected = os.environ.get("AUDIT_DEFAULT_ENCODING")
    if injected:
        # Windows hosted runners retain system ACP1252 even after setlocale.
        # Inject only Python's default pipe encoding, then verify the actual wrapper.
        patch("subprocess._text_encoding", return_value=injected).start()
    with subprocess.Popen(
        [sys.executable, "-c", "pass"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ) as probe:
        actual_pipe_encoding = probe.stdout.encoding
        probe.communicate()
    if injected:
        assert codecs.lookup(actual_pipe_encoding).name == codecs.lookup(injected).name
    print(
        json.dumps(
            {
                "platform": sys.platform,
                "ctype": locale.setlocale(locale.LC_CTYPE),
                "native_encoding": native_encoding,
                "actual_pipe_encoding": actual_pipe_encoding,
                "injected_default": injected,
                "utf8_mode": sys.flags.utf8_mode,
                "git": shutil.which("git"),
                "fd": shutil.which("fd") or shutil.which("fdfind"),
                "rg": shutil.which("rg"),
            },
            ensure_ascii=True,
        ),
        flush=True,
    )
    unittest.main(verbosity=2)
