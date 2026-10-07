from __future__ import annotations

from contextlib import redirect_stdout
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import yaml

from scripts import check_release_versions
from tests import test_release_checks


ROOT = Path(__file__).resolve().parents[1]


class IntegrationResolutionTests(unittest.TestCase):
    def test_all_compliance_jobs_check_out_the_selected_source(self) -> None:
        workflow = yaml.safe_load((ROOT / '.github/workflows/compliance.yml').read_text())
        checked_jobs = set()
        for name, job in workflow['jobs'].items():
            for step in job.get('steps', []):
                if str(step.get('uses', '')).startswith('actions/checkout@'):
                    self.assertEqual(step['with']['ref'], '${{ inputs.source_ref || github.sha }}', name)
                    self.assertFalse(step['with']['persist-credentials'], name)
                    checked_jobs.add(name)
        self.assertIn('package', checked_jobs)

    def test_release_verifies_boundaries_and_installed_wheel(self) -> None:
        workflow = yaml.safe_load((ROOT / '.github/workflows/release.yml').read_text())
        steps = workflow['jobs']['build']['steps']
        verify = next(step for step in steps if step.get('name') == 'Verify wheel contents and installation')
        self.assertIn('check_release_versions.py --root source --dist-dir source/dist', verify['run'])
        self.assertIn('verify_release_packages.py --source source', verify['run'])
        self.assertEqual(verify['env']['EXPECTED_VERSION'], '${{ needs.plan.outputs.version }}')

    def test_package_only_cli_uses_explicit_source_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            directory = test_release_checks.DistributionMetadataTests()._write_distributions(root)
            with patch('sys.argv', ['check_release_versions.py', '--root', str(root), '--dist-dir', str(directory)]):
                with redirect_stdout(io.StringIO()) as output:
                    self.assertEqual(check_release_versions.main(), 0)
            self.assertIn('Distribution contents OK: Python 0.5.0', output.getvalue())

    def test_unchanged_version_still_validates_requested_distributions(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            directory = test_release_checks.DistributionMetadataTests()._write_distributions(root, wheel_desktop=True)
            arguments = ['check_release_versions.py', '--root', str(root), '--tag', 'v0.5.0',
                         '--changed-from', 'base', '--dist-dir', str(directory)]
            with patch('sys.argv', arguments), patch.object(
                check_release_versions.subprocess, 'check_output', return_value='[project]\nversion="0.5.0"\n',
            ), redirect_stdout(io.StringIO()):
                with self.assertRaisesRegex(SystemExit, 'desktop application files'):
                    check_release_versions.main()

    def test_makefile_preserves_release_tools_and_replay_after_desktop_removal(self) -> None:
        makefile = (ROOT / 'Makefile').read_text()
        self.assertNotIn('apps/desktop-client', makefile)
        self.assertNotIn('desktop-i18n', makefile)
        self.assertIn('scripts/verify_release_packages.py', makefile)
        self.assertIn('scripts/release_plan.py', makefile)
        self.assertIn('benchmarks/swebench/pinned.py', makefile)
        self.assertIn('swebench-mcp-replay:\n', makefile)

    def test_desktop_setup_requires_native_application_in_both_readmes(self) -> None:
        for filename, clarification in (
            ('README.md', 'does not install the GUI'),
            ('README.zh-CN.md', '不会安装图形界面'),
        ):
            with self.subTest(filename=filename):
                text = (ROOT / filename).read_text(encoding='utf-8')
                desktop = text.split('**5.', 1)[1].split('**6.', 1)[0]
                self.assertIn('Rust/Tauri', desktop)
                self.assertIn(clarification, desktop)
                self.assertIn('CODING_TOOLS_MCP_DESKTOP_BINARY', desktop)
                self.assertNotIn('python -m pip install -e .', desktop)
