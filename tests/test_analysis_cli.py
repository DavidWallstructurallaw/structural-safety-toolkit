"""Public analysis reports, exit precedence, bounded CLI and immutable results."""

from contextlib import redirect_stderr, redirect_stdout
from dataclasses import FrozenInstanceError
from importlib import resources
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from structural_safety import AnalysisResult, Limits, analyze_json, cli


class AnalysisReportTests(unittest.TestCase):
    def test_result_is_deeply_immutable_and_serialization_is_an_independent_copy(self):
        finding = {"rule_id": "SS001", "witness": [{"action_id": "a1"}]}
        counters = {"states": 1}
        scope = {"snapshot_id": "snapshot:one", "declared_scope": ["task:one"]}
        result = AnalysisResult("completed_for_supported_scope", findings=(finding,), budget_usage=counters, scope=scope)
        finding["witness"][0]["action_id"] = "changed"
        counters["states"] = 99
        scope["declared_scope"].append("task:changed")
        self.assertEqual(result.findings[0]["witness"][0]["action_id"], "a1")
        self.assertEqual(result.budget_usage["states"], 1)
        self.assertEqual(result.scope["declared_scope"], ("task:one",))
        with self.assertRaises(TypeError):
            result.findings[0]["witness"][0]["action_id"] = "changed"
        with self.assertRaises(FrozenInstanceError):
            result.analysis_status = "changed"
        serialized = result.to_dict()
        serialized["findings"][0]["witness"][0]["action_id"] = "changed"
        serialized["scope"]["declared_scope"].append("task:changed")
        self.assertEqual(result.to_dict()["findings"][0]["witness"][0]["action_id"], "a1")
        self.assertEqual(result.to_dict()["scope"]["declared_scope"], ["task:one"])
        self.assertEqual(serialized["result_schema_version"], "sst.report/0.1")
        self.assertEqual(serialized["rule_version"], "sst.rules/0.1")
        self.assertNotIn("model", serialized)
        self.assertNotIn("safe", serialized)
        json.dumps(serialized, allow_nan=False)

    def test_markdown_preserves_witnesses_and_unknowns_as_inert_text(self):
        hostile = "<script> ![x](https://example.invalid) |\n\x1b[31m \u202e"
        result = AnalysisResult(
            "partial", supported_capabilities=("read_transfer_analysis",),
            findings=({"rule_id": "SS001", "witness": [{"action_id": "read-a"}, {"action_id": "send-b"}],
                       "message": hostile, "evidence_class": "model_deduction"},),
            unresolved_items=({"reason": "policy independence unavailable"},),
            obligations=({"check_status": "not_checked", "obligation_status": "unresolved"},),
            budget_usage={"states": 1}, truncation=({"budget": "max_states"},),
        )
        output = result.to_markdown()
        for fragment in ("<script>", "![x]", "https://", "\x1b", "\u202e"):
            self.assertNotIn(fragment, output)
        for fragment in ("&lt;script&gt;", "read\\-a", "send\\-b", "policy independence unavailable",
                         "not\\_checked", "max\\_states", "No runtime experiment"):
            self.assertIn(fragment, output)


class AnalysisCLITests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.source = self.root / "input.json"
        self.source.write_bytes(self.example("A.json"))

    @staticmethod
    def example(name):
        return resources.files("structural_safety").joinpath("examples", name).read_bytes()

    def invoke(self, *arguments, data=None, stdin=None):
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(Path(cli.__file__).resolve().parents[1])
        return subprocess.run(
            [sys.executable, "-m", "structural_safety", *map(str, arguments)],
            input=data, stdin=stdin, capture_output=True, env=environment,
            cwd=self.root, check=False, timeout=30,
        )

    def test_analysis_exit_precedence_and_unchecked_scope(self):
        completed = "completed_for_supported_scope"
        cases = (
            (AnalysisResult(completed), 0),
            (AnalysisResult(completed, findings=({"rule_id": "SS001"},)), 1),
            (AnalysisResult(completed, findings=({"rule_id": "SS001"},), unresolved_items=({"reason": "unknown"},)), 3),
            (AnalysisResult(completed, unsupported_items=({"reason": "unsupported"},)), 3),
            (AnalysisResult(completed, obligations=({"check_status": "not_checked"},)), 3),
            (AnalysisResult(completed, obligations=({"obligation_status": "unresolved"},)), 3),
            (AnalysisResult(completed, coverage=({"check_status": "partial"},)), 3),
            (AnalysisResult(completed, coverage=({"check_status": "checked", "model_coverage": "unresolved"},)), 3),
            (AnalysisResult("partial", findings=({"rule_id": "SS001"},)), 3),
            (AnalysisResult("input_invalid", analysis_performed=False, unresolved_items=({"reason": "unknown"},)), 2),
            (AnalysisResult("unsupported_schema", analysis_performed=False), 2),
            (AnalysisResult("resource_rejected", analysis_performed=False), 2),
        )
        for result, expected in cases:
            with self.subTest(expected=expected, result=result):
                stdout, stderr = io.StringIO(), io.StringIO()
                with patch.object(cli, "analyze_json", return_value=result):
                    with redirect_stdout(stdout), redirect_stderr(stderr):
                        actual = cli.main(["analyze", str(self.source)])
                self.assertEqual(actual, expected)
                self.assertEqual(json.loads(stdout.getvalue()), result.to_dict())
                self.assertEqual(stderr.getvalue(), "")

    def test_all_five_budget_flags_form_caller_policy(self):
        arguments = ["analyze", str(self.source)]
        values = {"max_states": 7, "max_transition_checks": 8, "max_scope_combinations": 9,
                  "max_clause_checks": 10, "max_findings": 11}
        for name, value in values.items():
            arguments.extend(["--" + name.replace("_", "-"), str(value)])
        with patch.object(cli, "analyze_json", return_value=AnalysisResult("completed_for_supported_scope")) as call:
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                self.assertEqual(cli.main(arguments), 0)
        self.assertEqual(call.call_args.args[0], self.source.read_bytes())
        self.assertEqual(call.call_args.kwargs["limits"], Limits(**values))
        for value in ("0", "-1", "true", "1.5"):
            with self.subTest(value=value):
                result = self.invoke("analyze", self.source, "--max-states", value)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, b"")
        result = self.invoke("validate", self.source, "--max-states", "2")
        self.assertEqual(result.returncode, 2)

    def test_real_api_and_cli_agree_for_both_installed_examples(self):
        for name in ("A.json", "B.json"):
            with self.subTest(example=name):
                document = self.example(name)
                result = analyze_json(document)
                command = self.invoke("analyze", "-", data=document)
                self.assertEqual(command.returncode, cli._analysis_exit(result), command.stderr)
                self.assertEqual(command.stderr, b"")
                self.assertEqual(json.loads(command.stdout), result.to_dict())
                self.assertTrue(result.analysis_performed)
                self.assertNotEqual(result.analysis_status, "input_invalid")

    def test_input_errors_have_analysis_envelope_and_no_raw_payload(self):
        secret = b"PRIVATE_TOKEN_NOT_FOR_DIAGNOSTICS"
        result = self.invoke("analyze", "-", data=b'{"broken":' + secret)
        self.assertEqual(result.returncode, 2)
        report = json.loads(result.stdout)
        self.assertEqual(report["analysis_status"], "input_invalid")
        self.assertIs(report["analysis_performed"], False)
        self.assertNotIn(secret, result.stdout + result.stderr)
        oversized = self.invoke("analyze", "-", data=b" " * (Limits().max_input_bytes + 1))
        self.assertEqual(oversized.returncode, 2)
        self.assertEqual(json.loads(oversized.stdout)["analysis_status"], "resource_rejected")

    def test_truncation_and_lower_input_budget_stay_visible(self):
        document = json.loads(self.source.read_bytes())
        document["limits"]["max_states"] = 1
        result = self.invoke("analyze", "-", "--max-states", "10", data=json.dumps(document).encode())
        self.assertEqual(result.returncode, 3, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["effective_limits"]["max_states"], 1)
        self.assertEqual(report["analysis_status"], "partial")
        self.assertTrue(report["truncation"])

    def test_markdown_output_preserves_input_and_refuses_aliases(self):
        output = self.root / "report.md"
        result = self.invoke("analyze", self.source, "--format", "markdown", "--output", output)
        self.assertIn(result.returncode, (0, 1, 3), result.stderr)
        self.assertEqual(result.stdout, b"")
        self.assertIn("Analysis report saved", result.stderr.decode())
        self.assertIn("Findings and witnesses", output.read_text())
        self.assertEqual(self.source.read_bytes(), self.example("A.json"))
        alias = self.root / "alias.json"
        os.link(self.source, alias)
        for target in (self.source, alias):
            with self.subTest(target=target):
                result = self.invoke("analyze", self.source, "--output", target)
                self.assertEqual(result.returncode, 5)
                self.assertEqual(self.source.read_bytes(), self.example("A.json"))
        with self.source.open("rb") as stream:
            result = self.invoke("analyze", "-", "--output", self.source, stdin=stream)
        self.assertEqual(result.returncode, 5)
        self.assertEqual(self.source.read_bytes(), self.example("A.json"))
        self.assertEqual(list(self.root.glob(".structural-safety-*.tmp")), [])

    def test_internal_failures_and_interrupts_are_not_unresolved_models(self):
        for error, expected in ((RuntimeError("PRIVATE_BUG_DETAIL"), 70), (KeyboardInterrupt(), 130)):
            with self.subTest(expected=expected):
                stdout, stderr = io.StringIO(), io.StringIO()
                with patch.object(cli, "analyze_json", side_effect=error):
                    with redirect_stdout(stdout), redirect_stderr(stderr):
                        code = cli.main(["analyze", str(self.source)])
                self.assertEqual(code, expected)
                self.assertEqual(stdout.getvalue(), "")
                self.assertNotIn("PRIVATE_BUG_DETAIL", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
