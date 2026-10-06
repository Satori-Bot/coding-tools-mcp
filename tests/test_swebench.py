from __future__ import annotations

import contextlib
import io
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

os.environ.setdefault("CODING_TOOLS_MCP_TELEMETRY", "off")

from benchmarks.swebench import generate_reference_predictions as reference
from benchmarks.swebench import pinned, replay_mcp, run_smoke


class PinnedInputTests(unittest.TestCase):
    def test_fixture_revision_patch_and_source_are_immutable(self) -> None:
        pins = pinned.load_pins()
        rows = pinned.load_instances(pins)
        self.assertEqual(len(rows), 10)
        self.assertEqual(len(pins["dataset"]["revision"]), 40)
        self.assertEqual(pins["swebench_version"], "4.1.0")
        row = pinned.replay_instance(pins)
        self.assertEqual(row["instance_id"], "sympy__sympy-12419")
        self.assertEqual(row["base_commit"], "479939f8c65c8c2908bbedc959549a257a7c0b0b")
        self.assertEqual(pinned.sha256((pinned.ROOT / pins["replay"]["source_fixture"]).read_bytes()),
                         pins["replay"]["source_sha256"])
        for row in rows:
            source, tag = pinned.docker_image(pins, row["instance_id"])
            self.assertIn("@sha256:", source)
            self.assertNotIn(":latest", tag)
            self.assertEqual(pins["docker"]["images"][row["instance_id"]]["platform"], "linux/amd64")

    def test_corrupt_fixture_is_rejected(self) -> None:
        pins = pinned.load_pins()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture = root / pins["dataset"]["fixture"]
            fixture.parent.mkdir()
            fixture.write_text("[]")
            with patch.object(pinned, "ROOT", root), self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                pinned.load_instances(pins)

    def test_changed_reference_patch_hash_is_rejected(self) -> None:
        pins = pinned.load_pins()
        pins["replay"]["reference_patch_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "patch SHA-256"):
            pinned.replay_instance(pins)

    def test_reference_generation_is_offline_and_labeled(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            result = reference.main(["--instance-id", "sympy__sympy-12419", "--baseline-output", str(root / "b.jsonl"),
                                     "--candidate-output", str(root / "c.jsonl"), "--metadata-output", str(root / "meta.json")])
            self.assertEqual(result, 0)
            metadata = json.loads((root / "meta.json").read_text())
            self.assertEqual(metadata["prediction_source"], "reference_patch")
            self.assertIn("not model-generated", metadata["warning"])
            self.assertEqual(metadata["pins"], pinned.load_pins())
            self.assertIn("harness_control", json.loads((root / "c.jsonl").read_text())["model_name_or_path"])

    def test_reference_generation_rejects_floating_dataset_or_unknown_instance(self) -> None:
        with self.assertRaises(ValueError):
            reference.fetch_reference_patches("other/dataset", "test", ["sympy__sympy-12419"])
        with self.assertRaises(ValueError):
            reference.fetch_reference_patches("princeton-nlp/SWE-bench_Lite", "test", ["unknown"])


class PredictionValidationTests(unittest.TestCase):
    def validate(self, rows: list[object], ids: set[str] | None = None) -> run_smoke.PredictionSet:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "predictions.jsonl"
            path.write_text("\n".join(json.dumps(row) for row in rows) + "\n")
            return run_smoke.validate_predictions(path, ids if ids is not None else {"one"})

    def row(self, instance: str = "one", content: object = "diff") -> dict[str, object]:
        return {"instance_id": instance, "model_name_or_path": "model", "model_patch": content}

    def test_non_object_prediction_is_rejected(self) -> None:
        self.assertTrue(self.validate([[]]).errors)

    def test_non_string_patch_is_rejected(self) -> None:
        self.assertTrue(self.validate([self.row(content=123)]).errors)

    def test_duplicate_prediction_is_rejected(self) -> None:
        self.assertIn("duplicate", " ".join(self.validate([self.row(), self.row()]).errors))

    def test_any_empty_selected_patch_is_a_placeholder(self) -> None:
        result = self.validate([self.row(), self.row("two", "")], {"one", "two"})
        self.assertTrue(result.placeholder)

    def test_empty_selection_is_rejected(self) -> None:
        self.assertTrue(self.validate([self.row()], set()).errors)

    def test_unknown_subset_instance_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "not in pinned subset"):
            run_smoke.selected_instances({"instances": [{"instance_id": "one"}]}, ["typo"])

    def test_missing_and_invalid_model_are_rejected(self) -> None:
        for model in ("", "..", ".", None):
            row = self.row()
            row["model_name_or_path"] = model
            with self.subTest(model=model):
                self.assertTrue(self.validate([row]).errors)


class HarnessTests(unittest.TestCase):
    def test_command_uses_verified_local_dataset_and_tag(self) -> None:
        command = run_smoke.evaluation_command(Path("predictions.jsonl"), "unique-run", 1, ["sympy__sympy-12419"])
        self.assertEqual(command[command.index("--dataset_name") + 1], str(pinned.dataset_path(pinned.load_pins())))
        self.assertEqual(command[command.index("--instance_image_tag") + 1], "coding-tools-pinned-v1")
        self.assertNotIn("latest", command)
        self.assertIn("--split", command)

    def test_wrong_harness_version_does_not_run(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, patch.object(run_smoke, "package_version", return_value="99.0"), patch.object(run_smoke, "capture") as capture:
            available, detail, _, _ = run_smoke.check_swebench(Path(tmp), install=False)
            self.assertFalse(available)
            self.assertIn("4.1.0", detail)
            capture.assert_not_called()

    def test_install_requests_exact_harness_version(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, patch.object(run_smoke, "package_version", side_effect=[None, "4.1.0"]), patch.object(run_smoke, "capture", return_value={"returncode": 0}) as capture:
            self.assertTrue(run_smoke.check_swebench(Path(tmp), install=True)[0])
            self.assertIn("swebench==4.1.0", capture.call_args_list[0].args[0])

    def test_images_are_pulled_by_digest_and_local_alias_is_verified(self) -> None:
        responses = [{"returncode": 0}, {"returncode": 0}, {"returncode": 0, "stdout": "sha256:abc\nsha256:abc\n"}]
        with tempfile.TemporaryDirectory() as tmp, patch.object(run_smoke, "capture", side_effect=responses) as capture:
            ok, _ = run_smoke.prepare_images(["sympy__sympy-12419"], Path(tmp))
            self.assertTrue(ok)
            self.assertIn("@sha256:", capture.call_args_list[0].args[0][-1])
            self.assertEqual(capture.call_args_list[1].args[0][1], "tag")
            self.assertIn("inspect", capture.call_args_list[2].args[0])

    def test_image_pull_failure_stops_before_tag_or_harness(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, patch.object(run_smoke, "capture", return_value={"returncode": 1}) as capture:
            self.assertFalse(run_smoke.prepare_images(["sympy__sympy-12419"], Path(tmp))[0])
            self.assertEqual(capture.call_count, 1)

    def test_mismatched_local_image_alias_fails_closed(self) -> None:
        responses = [{"returncode": 0}, {"returncode": 0}, {"returncode": 0, "stdout": "sha256:abc\nsha256:def\n"}]
        with tempfile.TemporaryDirectory() as tmp, patch.object(run_smoke, "capture", side_effect=responses):
            self.assertFalse(run_smoke.prepare_images(["sympy__sympy-12419"], Path(tmp))[0])

    def test_zero_resolution_cannot_pass(self) -> None:
        self.assertEqual(run_smoke.comparison_conclusion({"completed": 1, "resolved": 0}, {"completed": 1, "resolved": 0}, 1), "FAIL")

    def test_partial_reports_cannot_pass(self) -> None:
        self.assertEqual(run_smoke.comparison_conclusion({"completed": 1, "resolved": 1}, {"completed": 1, "resolved": 1}, 2), "INCONCLUSIVE")

    def test_complete_nonzero_reports_pass(self) -> None:
        self.assertEqual(run_smoke.comparison_conclusion({"completed": 1, "resolved": 1}, {"completed": 1, "resolved": 1}, 1), "PASS")

    def test_missing_docker_is_blocked_and_reruns_have_distinct_ids(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, patch.object(run_smoke, "check_docker", return_value=(False, "missing", {})), patch.object(run_smoke, "check_swebench", return_value=(True, "ok", None, {})), patch.object(run_smoke, "capture_environment", return_value={}):
            root = Path(tmp)
            prediction = root / "p.jsonl"
            reference.write_predictions(prediction, "test", {"sympy__sympy-12419": "nonempty"})
            args = ["--run-evaluation", "--require-evaluation-pass", "--instance-id", "sympy__sympy-12419",
                    "--baseline-predictions", str(prediction), "--candidate-predictions", str(prediction),
                    "--report-json", str(root / "report.json"), "--report-md", str(root / "report.md")]
            self.assertEqual(run_smoke.main(args), 1)
            first = json.loads((root / "report.json").read_text())
            self.assertEqual(first["conclusion"], "BLOCKED")
            self.assertFalse(first["candidate"]["run"]["ran"])
            old_raw = Path(first["raw_dir"])
            old_raw.mkdir(parents=True)
            (old_raw / "historical-success.json").write_text('{"resolved": true}')
            self.assertEqual(run_smoke.main(args), 1)
            second = json.loads((root / "report.json").read_text())
            self.assertNotEqual(first["run_ids"], second["run_ids"])
            self.assertNotEqual(first["raw_dir"], second["raw_dir"])
            self.assertTrue((old_raw / "historical-success.json").exists())
            self.assertFalse((Path(second["raw_dir"]) / "historical-success.json").exists())

    def test_early_failure_replaces_stale_pass_reports(self) -> None:
        for failure in ("instance", "pins", "workers"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                report, markdown = root / "report.json", root / "report.md"
                report.write_text('{"conclusion": "PASS", "baseline": {"resolved": 1}}')
                markdown.write_text("# Historical result\nPASS\n")
                args = ["--report-json", str(report), "--report-md", str(markdown)]
                if failure == "instance":
                    args.extend(["--instance-id", "unknown-typo"])
                elif failure == "workers":
                    args.extend(["--max-workers", "0"])
                with contextlib.ExitStack() as stack:
                    if failure == "pins":
                        stack.enter_context(patch.object(run_smoke, "load_pins", side_effect=ValueError("broken pin")))
                    stack.enter_context(contextlib.redirect_stderr(io.StringIO()))
                    self.assertEqual(run_smoke.main(args), 1)
                current = json.loads(report.read_text())
                self.assertEqual(current["conclusion"], "ERROR")
                self.assertNotIn("resolved", current["baseline"])
                self.assertNotIn("PASS", markdown.read_text())
                self.assertIn("failed:", " ".join(current["limitations"]))

    def test_interruption_cannot_leave_a_prior_pass(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report, markdown = root / "report.json", root / "report.md"
            report.write_text('{"conclusion": "PASS"}')
            with patch.object(run_smoke, "load_pins", side_effect=KeyboardInterrupt), self.assertRaises(KeyboardInterrupt):
                run_smoke.main(["--report-json", str(report), "--report-md", str(markdown)])
            self.assertEqual(json.loads(report.read_text())["conclusion"], "INCONCLUSIVE")
            self.assertNotIn("PASS", markdown.read_text())


class WorkflowTests(unittest.TestCase):
    def test_advisory_workflow_runs_both_sources_at_pinned_sha(self) -> None:
        text = (pinned.ROOT.parents[1] / ".github/workflows/swebench-lite.yml").read_text()
        self.assertIn("source_ref:", text)
        self.assertIn("ref: ${{ inputs.source_ref || github.sha }}", text)
        self.assertIn("default: both", text)
        self.assertIn("overwrite: true", text)
        self.assertIn("--prediction-source mcp_reference_replay", text)
        self.assertIn("source=reference_patch", text)
        self.assertNotIn('ids="${{', text)
        self.assertNotIn('--max-workers "${{', text)

    def test_only_current_attempt_evidence_is_uploaded(self) -> None:
        workflow = yaml.safe_load((pinned.ROOT.parents[1] / ".github/workflows/swebench-lite.yml").read_text())
        job = workflow["jobs"]["swebench-lite"]
        self.assertIn("runner.temp", job["env"]["EVIDENCE_ROOT"])
        self.assertIn("github.run_id", job["env"]["EVIDENCE_ROOT"])
        self.assertIn("github.run_attempt", job["env"]["EVIDENCE_ROOT"])
        self.assertIn("attempt.json", job["steps"][0]["run"])
        uploads = [step for step in job["steps"] if step.get("uses", "").startswith("actions/upload-artifact@")]
        self.assertEqual(len(uploads), 1)
        self.assertEqual(uploads[0]["with"]["path"], "${{ env.EVIDENCE_ROOT }}")
        for step in job["steps"]:
            run = step.get("run", "")
            self.assertNotIn("reports/benchmark", run)
            if "replay_mcp.py" in run:
                self.assertIn('--output-dir "$EVIDENCE_ROOT/mcp-replay"', run)
            if "run_smoke.py" in run:
                self.assertIn('--report-json "$EVIDENCE_ROOT/', run)
                self.assertIn('--report-md "$EVIDENCE_ROOT/', run)

    def test_failed_workflow_validation_leaves_only_current_attempt_manifest(self) -> None:
        workflow = yaml.safe_load((pinned.ROOT.parents[1] / ".github/workflows/swebench-lite.yml").read_text())
        steps = workflow["jobs"]["swebench-lite"]["steps"]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            old = root / "reports/benchmark/historical.json"
            old.parent.mkdir(parents=True)
            old.write_text('{"conclusion": "PASS"}')
            evidence = root / "current-attempt"
            env = {**os.environ, "EVIDENCE_ROOT": str(evidence), "SOURCE_REF": "invalid",
                   "PREDICTION_SOURCE": "mcp_reference_replay", "GITHUB_SHA": "a" * 40,
                   "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "2"}
            subprocess.run(["bash", "-e", "-c", steps[0]["run"]], cwd=root, env=env, check=True)
            validation = subprocess.run(["bash", "-e", "-c", steps[1]["run"]], cwd=root, env=env, check=False)
            self.assertNotEqual(validation.returncode, 0)
            self.assertEqual([path.name for path in evidence.iterdir()], ["attempt.json"])
            attempt = json.loads((evidence / "attempt.json").read_text())
            self.assertEqual(attempt["run_attempt"], "2")
            self.assertEqual(attempt["prediction_source"], "mcp_reference_replay")
            self.assertNotIn("conclusion", attempt)


class ReplayTests(unittest.TestCase):
    def test_line_edit_uses_current_revision_and_unique_context(self) -> None:
        content = "header\n" + replay_mcp.OLD_ENTRY + "\nfooter\n"
        change = replay_mcp.line_edit(content, "revision")["changes"][0]
        self.assertEqual(change["revision"], "revision")
        self.assertEqual(change["edits"][0]["start_line"], 2)
        self.assertEqual(change["edits"][0]["end_line"], 6)
        with self.assertRaises(ValueError):
            replay_mcp.line_edit(content + content, "revision")

    def test_actual_http_mcp_replay_matches_native_patch_offline(self) -> None:
        pins = pinned.load_pins()
        row = pinned.replay_instance(pins)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            native, workspace = root / "native", root / "candidate"
            for checkout in (native, workspace):
                file = checkout / replay_mcp.PATH
                file.parent.mkdir(parents=True)
                file.write_bytes((pinned.ROOT / pins["replay"]["source_fixture"]).read_bytes())
                replay_mcp.run(["git", "init", "--quiet"], checkout)
                replay_mcp.run(["git", "add", "."], checkout)
                replay_mcp.run(["git", "-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "--quiet", "-m", "Fixture"], checkout)
            replay_mcp.run(["git", "apply", "-"], native, stdin=row["patch"])
            expected = (native / replay_mcp.PATH).read_text()
            self.assertEqual(pinned.sha256(expected.encode()), pins["replay"]["result_sha256"])
            calls: list[dict] = []
            actual = replay_mcp.replay(workspace, expected, root / "raw", calls)
            self.assertEqual(actual, replay_mcp.run(["git", "diff", "--unified=3"], native))
            self.assertEqual([call["tool"] for call in calls][:7],
                             ["read_file", "apply_patch", "read_file", "apply_changes", "read_file", "git_diff", "exec_command"])
            self.assertTrue((root / "raw/mcp-transcript.json").is_file())

    def test_failed_replay_removes_stale_prediction_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, patch.object(replay_mcp, "replay_instance", side_effect=ValueError("broken fixture")):
            root = Path(tmp)
            for name in ("baseline_native.jsonl", "candidate_mcp.jsonl"):
                (root / name).write_text("stale")
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(replay_mcp.main(["--output-dir", str(root)]), 1)
            self.assertFalse((root / "candidate_mcp.jsonl").exists())
            self.assertEqual(json.loads((root / "report.json").read_text())["conclusion"], "FAIL")


if __name__ == "__main__":
    unittest.main()
