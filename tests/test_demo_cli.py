"""Direct local demo commands, exit meaning, evidence retention and reporting."""

from contextlib import redirect_stderr, redirect_stdout
from dataclasses import replace
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from structural_safety import DemoResult, Limits, cli, run_demo


class DemoCLITests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def command(self, *arguments):
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(Path(cli.__file__).resolve().parents[1])
        return subprocess.run(
            [sys.executable, "-m", "structural_safety", *map(str, arguments)],
            capture_output=True, env=environment, cwd=self.root, timeout=30,
            check=False,
        )

    @staticmethod
    def completed(**changes):
        values = {
            "demo_status": "completed", "scenario": "A", "protocol_verdict": "matched",
            "cases": ({"case_id": "A", "runtime_status": "completed",
                       "protocol_verdict": "matched",
                       "actual_effects": [{"classification": "observed_boundary_violation"}]},),
        }
        values.update(changes)
        return DemoResult(**values)

    def test_a_and_b_complete_fixed_protocol_through_public_api_and_cli(self):
        for scenario in ("A", "B"):
            with self.subTest(scenario=scenario):
                api_result = run_demo(scenario)
                self.assertIsInstance(api_result, DemoResult)
                result = self.command("demo", scenario)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stderr, b"")
                report = json.loads(result.stdout)
                self.assertEqual(report["result_schema_version"], "sst.demo/0.1")
                self.assertEqual(report["scenario"], scenario)
                self.assertEqual(report["protocol_verdict"], "matched")
                self.assertEqual(report["cases"][0]["runtime_status"], "completed")
                self.assertEqual(report["cases"][0]["analysis_comparison"]["verdict"], "matched")
                self.assertEqual(report["cases"][0]["runtime_comparison"]["verdict"], "matched")
                self.assertEqual(set(report["cases"][0]["normal_tasks"]), {"U-internal", "U-public"})
                self.assertEqual(api_result.protocol_verdict, report["protocol_verdict"])
                self.assertIsNone(report["run_directory"])
                self.assertNotIn("safe", report)

    def test_work_directory_retains_separate_runs_and_allows_sibling_summary(self):
        work_dir = self.root / "runs"
        first = self.command("demo", "A", "--work-dir", work_dir)
        self.assertEqual(first.returncode, 0, first.stderr)
        first_root = Path(json.loads(first.stdout)["run_directory"])
        prior = {path: path.read_bytes() for path in first_root.rglob("*") if path.is_file()}
        self.assertTrue(prior)
        output = work_dir / "summary.md"
        second = self.command("demo", "B", "--work-dir", work_dir,
                              "--format", "markdown", "--output", output)
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual(second.stdout, b"")
        self.assertIn(b"Demo report saved", second.stderr)
        self.assertEqual(len(list(work_dir.glob("sst-demo-*"))), 2)
        for path, original in prior.items():
            self.assertEqual(path.read_bytes(), original)
        markdown = output.read_text(encoding="utf-8")
        for text in ("Protocol verdict: matched", "Normal task utility", "Observed effects",
                     "Analysis expectation comparison", "Independent runtime observations"):
            self.assertIn(text, markdown)

    def test_output_cannot_replace_previous_runtime_files_or_their_aliases(self):
        work_dir = self.root / "runs"
        completed = self.command("demo", "A", "--work-dir", work_dir)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        run_root = Path(json.loads(completed.stdout)["run_directory"])
        source = next(path for path in run_root.rglob("*") if path.is_file())
        original = source.read_bytes()
        hardlink = self.root / "alias.json"
        os.link(source, hardlink)
        targets = [source, hardlink]
        symlink = self.root / "alias-link.json"
        try:
            symlink.symlink_to(source)
        except (OSError, NotImplementedError):
            pass
        else:
            targets.append(symlink)
        for target in targets:
            with self.subTest(target=target):
                result = self.command("demo", "B", "--work-dir", work_dir, "--output", target)
                self.assertEqual(result.returncode, 5, result.stderr)
                self.assertEqual(source.read_bytes(), original)
                self.assertEqual(target.read_bytes(), original)
        self.assertFalse(list(work_dir.rglob(".structural-safety-*.tmp")))

    def test_current_run_output_boundary_is_checked_after_experiment(self):
        run_root = self.root / "sst-demo-current"
        run_root.mkdir()
        source = run_root / "observations.json"
        source.write_text("retained observations")
        result = self.completed(run_directory=str(run_root))
        with patch.object(cli, "run_demo", return_value=result):
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                code = cli.main(["demo", "A", "--output", str(source)])
        self.assertEqual(code, 5)
        self.assertEqual(source.read_text(), "retained observations")

    def test_analysis_budget_inconclusive_keeps_completed_runtime_observations(self):
        result = self.command("demo", "A", "--max-states", "1")
        self.assertEqual(result.returncode, 3, result.stderr)
        report = json.loads(result.stdout)
        case = report["cases"][0]
        self.assertEqual(case["analysis"]["analysis_status"], "partial")
        self.assertEqual(case["runtime_status"], "completed")
        self.assertEqual(case["runtime_comparison"]["verdict"], "matched")
        self.assertTrue(case["actual_effects"])

    def test_all_five_budget_flags_reach_demo_api(self):
        values = {"max_states": 7, "max_transition_checks": 8, "max_scope_combinations": 9,
                  "max_clause_checks": 10, "max_findings": 11}
        arguments = ["demo", "B", "--work-dir", str(self.root)]
        for name, value in values.items():
            arguments.extend(["--" + name.replace("_", "-"), str(value)])
        with patch.object(cli, "run_demo", return_value=self.completed(scenario="B")) as call:
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                self.assertEqual(cli.main(arguments), 0)
        self.assertEqual(call.call_args.args, ("B",))
        self.assertEqual(call.call_args.kwargs, {"work_dir": self.root, "limits": Limits(**values)})
        for value in ("0", "-1", "true", "1.5"):
            with self.subTest(value=value):
                invalid = self.command("demo", "A", "--max-findings", value)
                self.assertEqual(invalid.returncode, 2)
                self.assertEqual(invalid.stdout, b"")

    def test_invalid_subcases_and_arbitrary_paths_are_not_executed(self):
        for scenario in ("D-other", "E-other", "F-other", "./custom.py"):
            with self.subTest(scenario=scenario):
                result = self.command("demo", scenario)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, b"")

    def test_environment_failure_has_usable_json_report_and_exit_five(self):
        unavailable = self.root / "regular-file"
        unavailable.write_text("preserve")
        result = self.command("demo", "A", "--work-dir", unavailable)
        self.assertEqual(result.returncode, 5, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["demo_status"], "error")
        self.assertTrue(report["environment_errors"])
        self.assertNotEqual(report["protocol_verdict"], "matched")
        self.assertEqual(unavailable.read_text(), "preserve")

    def test_exit_precedence_retains_observed_violation(self):
        base = self.completed()
        cases = (
            (base, 0),
            (replace(base, protocol_verdict="inconclusive"), 3),
            (replace(base, protocol_verdict="mismatched"), 4),
            (replace(base, demo_status="resource_rejected", protocol_verdict="mismatched"), 2),
            (replace(base, demo_status="error", protocol_verdict="mismatched",
                     environment_errors=({"code": "utility_io_failure"},)), 5),
            (replace(base, cases=({"runtime_status": "incomplete",
                                  "actual_effects": [{"classification": "observed_boundary_violation"}]},)), 3),
        )
        for result, expected in cases:
            with self.subTest(expected=expected):
                stdout = io.StringIO()
                with patch.object(cli, "run_demo", return_value=result):
                    with redirect_stdout(stdout), redirect_stderr(io.StringIO()):
                        self.assertEqual(cli.main(["demo", "A"]), expected)
                report = json.loads(stdout.getvalue())
                self.assertEqual(report, result.to_dict())
                self.assertEqual(report["cases"][0]["actual_effects"][0]["classification"],
                                 "observed_boundary_violation")

    def test_demo_internal_errors_and_interrupts_are_not_unknown_effects(self):
        for error, expected in ((RuntimeError("PRIVATE_BUG_DETAIL"), 70), (KeyboardInterrupt(), 130)):
            with self.subTest(expected=expected):
                stdout, stderr = io.StringIO(), io.StringIO()
                with patch.object(cli, "run_demo", side_effect=error):
                    with redirect_stdout(stdout), redirect_stderr(stderr):
                        self.assertEqual(cli.main(["demo", "A"]), expected)
                self.assertEqual(stdout.getvalue(), "")
                self.assertNotIn("PRIVATE_BUG_DETAIL", stderr.getvalue())

    def test_markdown_escapes_nested_observations_and_retains_evidence_basis(self):
        hostile = "<script> ![x](https://example.invalid) |\n\x1b[31m \u202e"
        result = self.completed(cases=({
            "case_id": "A", "runtime_status": "error", "protocol_verdict": "inconclusive",
            "actual_effects": [{"classification": "observed_boundary_violation", "payload": hostile}],
            "normal_tasks": {"U-internal": "completed", "U-public": "unknown"},
            "runtime_comparison": {"verdict": "inconclusive", "checks": [{"difference": hostile}]},
            "runtime": {"evidence_basis": "runtime_observation", "environment": "local_controlled_simulation",
                        "observations": [hostile]},
        },))
        output = result.to_markdown()
        for fragment in ("<script>", "![x]", "https://", "\x1b", "\u202e"):
            self.assertNotIn(fragment, output)
        for fragment in ("&lt;script&gt;", "observed\\_boundary\\_violation", "runtime\\_observation",
                         "Normal task utility", "Runtime expectation comparison and differences"):
            self.assertIn(fragment, output)


if __name__ == "__main__":
    unittest.main()
