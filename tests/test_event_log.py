from __future__ import annotations

import contextlib
import io
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from coding_tools_mcp.event_log import ToolEventJournal


_ENV_KEY = "CODING_TOOLS_MCP_EVENT_LOG_DIR"


def _records(directory: Path, backup_count: int = 3) -> list[dict[str, object]]:
    """Read the retained journal oldest first and reject incomplete JSON lines."""
    records: list[dict[str, object]] = []
    names = [f"events.jsonl.{index}" for index in range(backup_count, 0, -1)]
    for name in [*names, "events.jsonl"]:
        path = directory / name
        if not path.exists():
            continue
        data = path.read_bytes()
        if data:
            if not data.endswith(b"\n"):
                raise AssertionError(f"Incomplete final JSONL line in {name}")
            for line in data.splitlines():
                value = json.loads(line)
                if not isinstance(value, dict):
                    raise AssertionError("A journal record must remain an object")
                records.append(value)
    return records


class ToolEventJournalTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.directory = self.root / "journal"

    def journal(self, **options: int) -> ToolEventJournal:
        journal = ToolEventJournal(self.directory, **options)
        self.addCleanup(journal.close)
        return journal

    def test_default_disabled_and_empty_setting_do_not_construct_a_journal(self) -> None:
        for value in (None, ""):
            with self.subTest(value=value), patch.dict(os.environ):
                os.environ.pop(_ENV_KEY, None)
                if value is not None:
                    os.environ[_ENV_KEY] = value
                with patch.object(ToolEventJournal, "__init__", return_value=None) as constructor:
                    self.assertIsNone(ToolEventJournal.from_env())
                constructor.assert_not_called()
        self.assertEqual(list(self.root.iterdir()), [])

    def test_factory_uses_opted_in_directory(self) -> None:
        with patch.dict(os.environ, {_ENV_KEY: str(self.directory)}):
            journal = ToolEventJournal.from_env()
        self.assertIsNotNone(journal)
        assert journal is not None
        self.addCleanup(journal.close)
        journal.record({"event": "tool_started", "tool": "read_file"})
        journal.close()
        self.assertEqual(_records(self.directory), [{"event": "tool_started", "tool": "read_file"}])

    def test_records_round_trip_without_splitting_embedded_newlines(self) -> None:
        journal = self.journal()
        event = {"event": "tool_finished", "label": "测试\nnext line", "ok": True, "count": 0}
        journal.record(event)
        journal.close()
        self.assertEqual(_records(self.directory), [event])
        self.assertEqual(len((self.directory / "events.jsonl").read_bytes().splitlines()), 1)

    def test_restart_appends_and_close_is_idempotent(self) -> None:
        first = self.journal()
        first.record({"sequence": 1})
        first.close()
        first.close()
        first.record({"sequence": "ignored after close"})
        second = self.journal()
        second.record({"sequence": 2})
        second.close()
        self.assertEqual(_records(self.directory), [{"sequence": 1}, {"sequence": 2}])

    def test_concurrent_records_are_complete_and_written_once(self) -> None:
        journal = self.journal()
        with ThreadPoolExecutor(max_workers=8) as executor:
            list(executor.map(lambda sequence: journal.record({"sequence": sequence}), range(200)))
        journal.close()
        records = _records(self.directory)
        self.assertEqual(len(records), 200)
        self.assertEqual(sorted(record["sequence"] for record in records), list(range(200)))

    def test_rotation_and_restart_keep_a_bounded_recent_suffix(self) -> None:
        budget = 256
        for start in (0, 40):
            journal = self.journal(max_bytes=budget, backup_count=2)
            for sequence in range(start, start + 40):
                journal.record({"sequence": sequence, "label": "测" * 12})
            journal.close()
        files = list(self.directory.glob("events.jsonl*"))
        self.assertLessEqual(len(files), 3)
        self.assertTrue((self.directory / "events.jsonl.2").is_file())
        self.assertFalse((self.directory / "events.jsonl.3").exists())
        for path in files:
            self.assertLessEqual(path.stat().st_size, budget)
        records = _records(self.directory, backup_count=2)
        sequences = [record["sequence"] for record in records]
        self.assertTrue(sequences)
        self.assertEqual(sequences[-1], 79)
        self.assertLess(len(sequences), 80)
        self.assertEqual(sequences, list(range(int(sequences[0]), 80)))

    def test_invalid_limits_are_rejected(self) -> None:
        for options in ({"max_bytes": 0}, {"max_bytes": -1}, {"backup_count": -1}):
            with self.subTest(options=options), self.assertRaises((OSError, ValueError)):
                self.journal(**options)

    def test_oversized_record_disables_with_one_sanitized_warning(self) -> None:
        journal = self.journal(max_bytes=128)
        journal.record({"sequence": "kept"})
        stderr = io.StringIO()
        secret_marker = "SYNTHETIC_PRIVATE_PAYLOAD"
        with contextlib.redirect_stderr(stderr):
            journal.record({"label": secret_marker * 40})
            journal.record({"sequence": "ignored after failure"})
            journal.record({"label": secret_marker * 40})
            journal.close()
        self.assertEqual(_records(self.directory), [{"sequence": "kept"}])
        warning = stderr.getvalue()
        self.assertEqual(len(warning.strip().splitlines()), 1)
        self.assertNotIn(secret_marker, warning)
        self.assertNotIn(str(self.directory), warning)

    def test_write_failure_disables_once_without_leaking_error_details(self) -> None:
        journal = self.journal()
        journal.record({"sequence": 1})
        stderr = io.StringIO()
        with patch(
            "coding_tools_mcp.event_log.os.write",
            side_effect=OSError(f"SYNTHETIC_PRIVATE_ERROR: {self.directory}"),
        ) as writer, contextlib.redirect_stderr(stderr):
            journal.record({"sequence": 2})
            journal.record({"sequence": 3})
            journal.close()
        self.assertEqual(writer.call_count, 1)
        self.assertEqual(_records(self.directory), [{"sequence": 1}])
        warning = stderr.getvalue()
        self.assertEqual(len(warning.strip().splitlines()), 1)
        self.assertNotIn("SYNTHETIC_PRIVATE_ERROR", warning)
        self.assertNotIn(str(self.directory), warning)
        self.assertNotIn("OSError", warning)

    def test_rotation_close_error_does_not_close_a_reused_descriptor(self) -> None:
        journal = self.journal(max_bytes=128)
        journal.record({"sequence": 1, "label": "x" * 65})
        real_close = os.close
        released_fd: int | None = None
        unrelated_fd: int | None = None
        unrelated_path = self.root / "unrelated.txt"

        def close_then_fail(fd: int) -> None:
            nonlocal released_fd, unrelated_fd
            if released_fd is None:
                released_fd = fd
                real_close(fd)
                unrelated_fd = os.open(unrelated_path, os.O_CREAT | os.O_RDWR, 0o600)
                raise OSError("simulated close error after descriptor release")
            real_close(fd)

        try:
            with patch("coding_tools_mcp.event_log.os.close", side_effect=close_then_fail):
                with contextlib.redirect_stderr(io.StringIO()):
                    journal.record({"sequence": 2, "label": "x" * 65})
            self.assertIsNotNone(released_fd, "The second record must trigger rotation")
            self.assertEqual(unrelated_fd, released_fd, "The OS must reuse the released descriptor")
            assert unrelated_fd is not None
            self.assertEqual(os.write(unrelated_fd, b"still open"), len(b"still open"))
            self.assertEqual(unrelated_path.read_bytes(), b"still open")
        finally:
            if unrelated_fd is not None:
                try:
                    real_close(unrelated_fd)
                except OSError:
                    pass

    def test_restart_preserves_partial_write_and_separates_the_next_record(self) -> None:
        first = self.journal()
        first.record({"sequence": 0})
        real_write = os.write
        calls = 0

        def interrupted_write(fd: int, data: bytes) -> int:
            nonlocal calls
            calls += 1
            if calls == 1:
                return real_write(fd, data[:5])
            raise OSError("simulated disk failure")

        stderr = io.StringIO()
        with patch("coding_tools_mcp.event_log.os.write", side_effect=interrupted_write):
            with contextlib.redirect_stderr(stderr):
                first.record({"sequence": 1})
                first.record({"sequence": "ignored after partial write"})
        first.close()
        partial_data = (self.directory / "events.jsonl").read_bytes()
        self.assertFalse(partial_data.endswith(b"\n"))
        second = self.journal()
        second.record({"sequence": 2})
        second.close()
        recovered = (self.directory / "events.jsonl").read_bytes()
        self.assertTrue(recovered.startswith(partial_data + b"\n"))
        lines = recovered.splitlines()
        self.assertEqual(len(lines), 3)
        self.assertEqual(json.loads(lines[0]), {"sequence": 0})
        with self.assertRaises(json.JSONDecodeError):
            json.loads(lines[1])
        self.assertEqual(json.loads(lines[2]), {"sequence": 2})
        self.assertEqual(len(stderr.getvalue().strip().splitlines()), 1)

    def test_rotation_without_backups_remains_bounded(self) -> None:
        journal = self.journal(max_bytes=128, backup_count=0)
        for sequence in range(40):
            journal.record({"sequence": sequence, "label": "x" * 20})
        journal.close()
        self.assertEqual([p.name for p in self.directory.glob("events.jsonl*")], ["events.jsonl"])
        self.assertLessEqual((self.directory / "events.jsonl").stat().st_size, 128)
        self.assertEqual(_records(self.directory)[-1]["sequence"], 39)

    def test_second_instance_cannot_write_until_first_closes(self) -> None:
        first = self.journal()
        first.record({"sequence": 1})
        with self.assertRaises((OSError, ValueError)):
            self.journal()
        stderr = io.StringIO()
        with patch.dict(os.environ, {_ENV_KEY: str(self.directory)}), contextlib.redirect_stderr(stderr):
            self.assertIsNone(ToolEventJournal.from_env())
        warning = stderr.getvalue()
        self.assertEqual(len(warning.strip().splitlines()), 1)
        self.assertNotIn(str(self.directory), warning)
        self.assertNotIn("BlockingIOError", warning)
        self.assertNotIn("Traceback", warning)
        first.close()
        second = self.journal()
        second.record({"sequence": 2})
        second.close()
        self.assertEqual(_records(self.directory), [{"sequence": 1}, {"sequence": 2}])

    def test_lock_excludes_another_process(self) -> None:
        first = self.journal()
        first.record({"sequence": 1})
        child = subprocess.run(
            [
                sys.executable,
                "-c",
                "from pathlib import Path; import sys\n"
                "from coding_tools_mcp.event_log import ToolEventJournal\n"
                "try:\n"
                "    journal = ToolEventJournal(Path(sys.argv[1]))\n"
                "except (OSError, ValueError):\n"
                "    sys.exit(0)\n"
                "journal.close()\n"
                "sys.exit(2)\n",
                str(self.directory),
            ],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        self.assertEqual(child.returncode, 0, child.stderr)
        self.assertEqual(_records(self.directory), [{"sequence": 1}])

    def test_process_exit_releases_lock_without_explicit_close(self) -> None:
        child = subprocess.run(
            [
                sys.executable,
                "-c",
                "from pathlib import Path; import os, sys\n"
                "from coding_tools_mcp.event_log import ToolEventJournal\n"
                "journal = ToolEventJournal(Path(sys.argv[1]))\n"
                "journal.record({'sequence': 1})\n"
                "os._exit(0)\n",
                str(self.directory),
            ],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        self.assertEqual(child.returncode, 0, child.stderr)
        recovered = self.journal()
        recovered.record({"sequence": 2})
        recovered.close()
        self.assertEqual(_records(self.directory), [{"sequence": 1}, {"sequence": 2}])

    def test_factory_does_not_disclose_invalid_path(self) -> None:
        private_path = self.root / "SYNTHETIC_PRIVATE_PATH"
        private_path.write_text("must stay unchanged", encoding="utf-8")
        stderr = io.StringIO()
        with patch.dict(os.environ, {_ENV_KEY: str(private_path)}), contextlib.redirect_stderr(stderr):
            self.assertIsNone(ToolEventJournal.from_env())
        warning = stderr.getvalue()
        self.assertEqual(len(warning.strip().splitlines()), 1)
        self.assertNotIn(str(private_path), warning)
        self.assertNotIn(private_path.name, warning)
        self.assertNotIn("Traceback", warning)
        self.assertNotIn("Error:", warning)
        self.assertEqual(private_path.read_text(encoding="utf-8"), "must stay unchanged")

    @unittest.skipUnless(os.name == "posix", "POSIX file modes")
    def test_new_directory_and_all_journal_files_are_private(self) -> None:
        journal = self.journal(max_bytes=128)
        for sequence in range(30):
            journal.record({"sequence": sequence, "label": "x" * 20})
        journal.close()
        self.assertEqual(stat.S_IMODE(self.directory.stat().st_mode), 0o700)
        paths = list(self.directory.iterdir())
        self.assertTrue(paths)
        self.assertTrue((self.directory / "journal.lock").exists())
        for path in paths:
            self.assertTrue(path.is_file())
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    @unittest.skipUnless(os.name == "posix", "POSIX file modes")
    def test_existing_permissive_directory_is_rejected_without_chmod(self) -> None:
        self.directory.mkdir(mode=0o755)
        self.directory.chmod(0o755)
        with self.assertRaises((OSError, ValueError)):
            self.journal()
        self.assertEqual(stat.S_IMODE(self.directory.stat().st_mode), 0o755)
        self.assertEqual(list(self.directory.iterdir()), [])

    @unittest.skipUnless(os.name == "posix", "POSIX file modes")
    def test_existing_permissive_files_are_rejected_without_chmod(self) -> None:
        self.directory.mkdir(mode=0o700)
        for name in ("events.jsonl", "events.jsonl.1", "journal.lock"):
            with self.subTest(name=name):
                path = self.directory / name
                path.write_text("private test marker\n", encoding="utf-8")
                path.chmod(0o644)
                try:
                    with self.assertRaises((OSError, ValueError)):
                        self.journal()
                    self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o644)
                    self.assertEqual(path.read_text(encoding="utf-8"), "private test marker\n")
                finally:
                    path.unlink()

    @unittest.skipUnless(os.name == "posix", "POSIX symlink support")
    def test_final_directory_symlink_is_rejected(self) -> None:
        target = self.root / "target"
        target.mkdir(mode=0o700)
        self.directory.symlink_to(target, target_is_directory=True)
        with self.assertRaises((OSError, ValueError)):
            self.journal()
        self.assertEqual(list(target.iterdir()), [])

    @unittest.skipUnless(os.name == "posix", "POSIX links and regular-file checks")
    def test_journal_files_reject_symlinks_hardlinks_and_directories(self) -> None:
        for kind in ("symlink", "hardlink", "directory"):
            for name in ("events.jsonl", "events.jsonl.1", "journal.lock"):
                with self.subTest(kind=kind, name=name):
                    directory = self.root / f"{kind}-{name}"
                    directory.mkdir(mode=0o700)
                    target = self.root / f"target-{kind}-{name}"
                    target.write_text("untouched\n", encoding="utf-8")
                    target.chmod(0o600)
                    path = directory / name
                    if kind == "symlink":
                        path.symlink_to(target)
                    elif kind == "hardlink":
                        os.link(target, path)
                    else:
                        path.mkdir(mode=0o700)
                    with self.assertRaises((OSError, ValueError)):
                        ToolEventJournal(directory)
                    self.assertEqual(target.read_text(encoding="utf-8"), "untouched\n")


if __name__ == "__main__":
    unittest.main()
