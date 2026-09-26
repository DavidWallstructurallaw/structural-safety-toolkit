"""CLI boundary checks: diagnostics, file preservation and result semantics."""

from contextlib import redirect_stderr, redirect_stdout
from importlib import resources
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import MappingProxyType, SimpleNamespace
import unittest
from unittest.mock import patch

from structural_safety import cli
from structural_safety.model import Diagnostic, Fact, Limits
from structural_safety.report import validation_to_dict, validation_to_markdown


class CLITests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    @staticmethod
    def example(name="A.json"):
        return resources.files("structural_safety").joinpath("examples", name).read_bytes()

    def source_file(self):
        path = self.root / "input.json"
        path.write_bytes(self.example())
        return path

    def command(self, *arguments, data=None, stdin=None):
        environment = os.environ.copy()
        # Source tests use the current package; installed-package checks are
        # separately run from a clean environment by the packaging workflow.
        package_parent = str(Path(cli.__file__).resolve().parents[1])
        environment["PYTHONPATH"] = package_parent
        return subprocess.run(
            [sys.executable, "-m", "structural_safety", *map(str, arguments)],
            input=data, stdin=stdin, capture_output=True, env=environment,
            cwd=self.root, check=False, timeout=20,
        )

    def test_file_and_stdin_produce_validation_reports_without_analysis(self):
        source = self.source_file()
        from_file = self.command("validate", source)
        from_stdin = self.command("validate", "-", data=source.read_bytes())
        self.assertEqual(from_file.returncode, 0, from_file.stderr)
        self.assertEqual(from_stdin.returncode, 0, from_stdin.stderr)
        self.assertEqual(from_file.stderr, b"")
        report = json.loads(from_file.stdout)
        self.assertEqual(report, json.loads(from_stdin.stdout))
        self.assertEqual(report["validation_status"], "valid")
        self.assertIs(report["analysis_performed"], False)
        self.assertNotIn("model", report)
        self.assertNotIn("safe", report)

    def test_invalid_json_is_an_input_result_without_raw_source(self):
        secret = b"PRIVATE_TOKEN_NOT_FOR_DIAGNOSTICS"
        result = self.command("validate", "-", data=b'{"broken":' + secret)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(json.loads(result.stdout)["validation_status"], "input_invalid")
        self.assertNotIn(secret, result.stdout + result.stderr)

    def test_explicit_unsupported_scope_remains_a_fact_in_cli_json(self):
        model = json.loads(self.example())
        action_id = model["actions"][0]["id"]
        for fact in (
            {"state": "known", "value": [{"collection": "actions", "id": action_id}], "evidence_refs": []},
            {"state": "unknown", "reason": "scope unavailable", "evidence_refs": []},
        ):
            with self.subTest(state=fact["state"]):
                model["context"]["unsupported_items"] = [{
                    "id": "unsupported:one", "reason": "Future operation semantics",
                    "affected_refs": fact,
                }]
                result = self.command("validate", "-", data=json.dumps(model).encode("utf-8"))
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                report = json.loads(result.stdout)
                self.assertIs(report["analysis_performed"], False)
                self.assertEqual(report["unsupported_items"][0]["affected_refs"], fact)
                self.assertNotIn(b'"_fields"', result.stdout)

    def test_input_read_is_bounded_before_json_parsing(self):
        result = self.command("validate", "-", data=b" " * (Limits().max_input_bytes + 31))
        self.assertEqual(result.returncode, 2)
        self.assertEqual(json.loads(result.stdout)["validation_status"], "resource_rejected")

    def test_missing_input_is_operational_error(self):
        result = self.command("validate", self.root / "absent.json")
        self.assertEqual(result.returncode, 5)
        self.assertEqual(result.stdout, b"")
        self.assertIn(b"Cannot read", result.stderr)

    def test_invalid_demo_cases_do_not_report_success(self):
        for scenario in ("G", "D-other", "E-other", "F-other", "ALL"):
            with self.subTest(scenario=scenario):
                result = self.command("demo", scenario)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, b"")
                self.assertIn(b"invalid choice", result.stderr)

    def test_help_and_version_identify_available_capability(self):
        help_result = self.command("--help")
        self.assertEqual(help_result.returncode, 0)
        self.assertIn(b"A-F", help_result.stdout)
        version = self.command("--version")
        self.assertEqual(version.returncode, 0)
        self.assertIn(b"0.1.0.dev0", version.stdout)

    def test_markdown_output_and_atomic_replacement(self):
        source = self.source_file()
        output = self.root / "report.md"
        output.write_text("previous report", encoding="utf-8")
        result = self.command("validate", source, "--format", "markdown", "--output", output)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b"")
        self.assertIn("input structure only", output.read_text(encoding="utf-8"))
        self.assertEqual(source.read_bytes(), self.example())
        self.assertEqual(list(self.root.glob(".structural-safety-*.tmp")), [])

    def test_input_cannot_be_output(self):
        source = self.source_file()
        result = self.command("validate", source, "--output", source)
        self.assertEqual(result.returncode, 5)
        self.assertEqual(source.read_bytes(), self.example())

    def test_hardlink_to_input_cannot_be_output(self):
        source = self.source_file()
        alias = self.root / "alias.json"
        os.link(source, alias)
        result = self.command("validate", source, "--output", alias)
        self.assertEqual(result.returncode, 5)
        self.assertEqual(source.read_bytes(), self.example())
        self.assertTrue(os.path.samefile(source, alias))

    def test_symlink_to_input_cannot_be_output(self):
        source = self.source_file()
        alias = self.root / "alias.json"
        try:
            alias.symlink_to(source)
        except (OSError, NotImplementedError) as error:
            self.skipTest(f"Symlinks unavailable in this environment: {type(error).__name__}")
        result = self.command("validate", source, "--output", alias)
        self.assertEqual(result.returncode, 5)
        self.assertEqual(source.read_bytes(), self.example())
        self.assertTrue(alias.is_symlink())

    def test_redirected_stdin_file_cannot_be_output(self):
        source = self.source_file()
        with source.open("rb") as stream:
            result = self.command("validate", "-", "--output", source, stdin=stream)
        self.assertEqual(result.returncode, 5)
        self.assertEqual(source.read_bytes(), self.example())

    def test_failed_replace_preserves_previous_report_and_cleans_temp_file(self):
        source = self.source_file()
        output = self.root / "report.json"
        output.write_bytes(b"previous report")
        with patch.object(cli.os, "replace", side_effect=OSError("PRIVATE_OS_DETAIL")):
            stdout, stderr = io.StringIO(), io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                code = cli.main(["validate", str(source), "--output", str(output)])
        self.assertEqual(code, 5)
        self.assertEqual(output.read_bytes(), b"previous report")
        self.assertNotIn("PRIVATE_OS_DETAIL", stderr.getvalue())
        self.assertEqual(list(self.root.glob(".structural-safety-*.tmp")), [])

    def test_internal_error_and_interruption_are_not_model_unknowns(self):
        source = self.source_file()
        for error, expected in ((RuntimeError("PRIVATE_BUG_DETAIL"), 70), (KeyboardInterrupt(), 130)):
            with self.subTest(expected=expected):
                stdout, stderr = io.StringIO(), io.StringIO()
                with patch.object(cli, "validate_json", side_effect=error):
                    with redirect_stdout(stdout), redirect_stderr(stderr):
                        code = cli.main(["validate", str(source)])
                self.assertEqual(code, expected)
                self.assertEqual(stdout.getvalue(), "")
                self.assertNotIn("PRIVATE_BUG_DETAIL", stderr.getvalue())


class ReportTests(unittest.TestCase):
    @staticmethod
    def result():
        hostile = "<script> ![x](https://example.invalid) |\n\x1b[31m \u202e"
        return SimpleNamespace(
            result_schema_version="sst.validation/0.1",
            validation_status="input_invalid",
            schema_version="sst.model/0.1",
            analysis_performed=False,
            supported_capabilities=("input_validation",),
            diagnostics=(Diagnostic("bad_field", "$.field", hostile),),
            effective_limits=Limits(),
            unsupported_items=(MappingProxyType({"id": "x", "reason": hostile,
                                               "affected_refs": ()}),),
            model=object(),
        )

    def test_json_result_excludes_internal_model_and_uses_standard_values(self):
        report = validation_to_dict(self.result())
        self.assertNotIn("model", report)
        self.assertIsInstance(report["diagnostics"], list)
        self.assertIsInstance(report["effective_limits"], dict)
        self.assertIsInstance(report["unsupported_items"][0], dict)
        json.dumps(report, allow_nan=False)

    def test_markdown_cannot_render_input_as_active_syntax_or_controls(self):
        output = validation_to_markdown(self.result())
        self.assertNotIn("<script>", output)
        self.assertNotIn("![x]", output)
        self.assertNotIn("https://", output)
        self.assertNotIn("\x1b", output)
        self.assertNotIn("\u202e", output)
        self.assertIn("&lt;script&gt;", output)
        self.assertIn("\\|", output)
        self.assertIn("input structure only", output)

    def test_fact_dataclass_keeps_fact_wire_shape_in_unsupported_records(self):
        for value in (
            {"state": "known", "value": [], "evidence_refs": []},
            {"state": "unknown", "reason": "scope unavailable", "evidence_refs": []},
        ):
            with self.subTest(state=value["state"]):
                result = self.result()
                result.unsupported_items = (MappingProxyType({
                    "id": "unsupported:one", "reason": "unsupported operation",
                    "affected_refs": Fact(value),
                }),)
                report = validation_to_dict(result)
                self.assertEqual(report["unsupported_items"][0]["affected_refs"], value)
                self.assertNotIn("_fields", json.dumps(report))


if __name__ == "__main__":
    unittest.main()
