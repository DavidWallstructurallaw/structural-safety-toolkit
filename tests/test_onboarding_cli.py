"""Business-model export and read-only configuration import at the CLI boundary."""

from importlib import resources
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from structural_safety import cli, get_template, import_claude_code_json, validate_json


TEMPLATE_NAMES = ("memory-handoff", "policy-self-modification", "human-oversight")
TEMPLATE_VARIANTS = ("exposed", "controlled")


class OnboardingCLITests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.configuration = self.root / ".mcp.json"
        self.bindings = self.root / "bindings.json"
        integrations = resources.files("structural_safety").joinpath("integrations")
        self.configuration.write_bytes(integrations.joinpath("claude-code-example.json").read_bytes())
        self.bindings.write_bytes(integrations.joinpath("claude-code-bindings.json").read_bytes())

    def invoke(self, *arguments, data=None, stdin=None):
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(Path(cli.__file__).resolve().parents[1])
        return subprocess.run(
            [sys.executable, "-m", "structural_safety", *map(str, arguments)],
            input=data, stdin=stdin, capture_output=True, env=environment,
            cwd=self.root, check=False, timeout=30,
        )

    def test_each_template_exports_the_editable_model_through_stdout_and_file(self):
        for name in TEMPLATE_NAMES:
            for variant in TEMPLATE_VARIANTS:
                with self.subTest(name=name, variant=variant):
                    expected = get_template(name, variant=variant)
                    command = self.invoke("template", name, "--variant", variant)
                    self.assertEqual(command.returncode, 0, command.stderr)
                    self.assertEqual(command.stderr, b"")
                    self.assertEqual(json.loads(command.stdout), expected)
                    self.assertEqual(validate_json(command.stdout).validation_status, "valid")
                    self.assertNotIn("analysis_status", expected)
                    target = self.root / f"{name}-{variant}.json"
                    saved = self.invoke("template", name, "--variant", variant, "--output", target)
                    self.assertEqual(saved.returncode, 0, saved.stderr)
                    self.assertEqual(saved.stdout, b"")
                    self.assertEqual(json.loads(target.read_bytes()), expected)

    def test_template_selection_cannot_read_arbitrary_files(self):
        for arguments in (("template", str(self.configuration)),
                          ("template", "memory-handoff", "--variant", "../../bindings")):
            with self.subTest(arguments=arguments):
                result = self.invoke(*arguments)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, b"")

    def test_inventory_does_not_become_a_model_or_a_safety_verdict(self):
        result = self.invoke("import-claude-code", self.configuration)
        expected = import_claude_code_json(self.configuration.read_bytes())
        self.assertEqual(result.returncode, 3, result.stderr)
        self.assertEqual(result.stderr, b"")
        report = json.loads(result.stdout)
        self.assertEqual(report, expected.to_dict())
        self.assertEqual(report["import_status"], "inventory_only")
        self.assertIsNone(report["model"])
        self.assertIs(report["analysis_performed"], False)
        self.assertIs(report["execution_performed"], False)
        self.assertNotIn("safe", report)
        self.assertNotIn("analysis_status", report)

    def test_explicit_bindings_create_a_valid_declared_model_and_separate_report(self):
        model_path, report_path = self.root / "model.json", self.root / "import.json"
        result = self.invoke("import-claude-code", self.configuration, "--bindings", self.bindings,
                             "--model-output", model_path, "--output", report_path)
        expected = import_claude_code_json(self.configuration.read_bytes(),
                                           bindings_document=self.bindings.read_bytes())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b"")
        report = json.loads(report_path.read_bytes())
        self.assertEqual(report, expected.to_dict())
        self.assertEqual(report["import_status"], "model_created")
        self.assertIs(report["analysis_performed"], False)
        self.assertIs(report["execution_performed"], False)
        self.assertEqual(json.loads(model_path.read_bytes()), report["model"])
        self.assertEqual(validate_json(model_path.read_bytes()).validation_status, "valid")
        self.assertNotIn("analysis_status", report)
        self.assertNotIn("safe", report)

    def test_invalid_bindings_or_configuration_leave_existing_model_intact(self):
        secret = b"PRIVATE_IMPORT_VALUE_MUST_NOT_APPEAR"
        model_path = self.root / "model.json"
        marker = b"existing model must survive"
        model_path.write_bytes(marker)
        for source in (self.bindings, self.configuration):
            original = source.read_bytes()
            try:
                with self.subTest(source=source.name):
                    source.write_bytes(b'{"broken":' + secret)
                    result = self.invoke("import-claude-code", self.configuration,
                                         "--bindings", self.bindings, "--model-output", model_path)
                    self.assertEqual(result.returncode, 2, result.stderr)
                    self.assertEqual(json.loads(result.stdout)["import_status"], "input_invalid")
                    self.assertEqual(model_path.read_bytes(), marker)
                    self.assertNotIn(secret, result.stdout + result.stderr)
            finally:
                source.write_bytes(original)
        self.bindings.write_bytes(b'{"unrecognized_binding":"' + secret + b'"}')
        result = self.invoke("import-claude-code", self.configuration, "--bindings", self.bindings,
                             "--model-output", model_path)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(json.loads(result.stdout)["import_status"], "input_invalid")
        self.assertEqual(model_path.read_bytes(), marker)
        self.assertNotIn(secret, result.stdout + result.stderr)

    def test_missing_bound_server_is_rejected_without_overwriting_existing_model(self):
        document = json.loads(self.bindings.read_bytes())
        document["servers"]["publish"] = "PRIVATE_SERVER_NOT_PRESENT"
        self.bindings.write_text(json.dumps(document), encoding="utf-8")
        model_path = self.root / "model.json"
        model_path.write_bytes(b"existing model")
        result = self.invoke("import-claude-code", self.configuration, "--bindings", self.bindings,
                             "--model-output", model_path)
        self.assertEqual(result.returncode, 2, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["import_status"], "input_invalid")
        self.assertIsNone(report["model"])
        self.assertIs(report["analysis_performed"], False)
        self.assertIs(report["execution_performed"], False)
        self.assertEqual(model_path.read_bytes(), b"existing model")
        self.assertNotIn(b"PRIVATE_SERVER_NOT_PRESENT", result.stdout + result.stderr)

    def test_inventory_cannot_write_model_and_two_documents_cannot_share_stdin(self):
        model_path = self.root / "existing.json"
        model_path.write_bytes(b"preserve")
        for arguments in (
            ("import-claude-code", self.configuration, "--model-output", model_path),
            ("import-claude-code", "-", "--bindings", "-", "--model-output", model_path),
        ):
            with self.subTest(arguments=arguments):
                result = self.invoke(*arguments, data=b"{}")
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertEqual(result.stdout, b"")
                self.assertEqual(model_path.read_bytes(), b"preserve")

    def test_both_outputs_refuse_aliases_of_either_input_and_stdin(self):
        originals = {path: path.read_bytes() for path in (self.configuration, self.bindings)}
        for source in originals:
            alias = self.root / (source.name + ".alias")
            os.link(source, alias)
            for target in (source, alias):
                for flag in ("--output", "--model-output"):
                    with self.subTest(source=source.name, target=target.name, flag=flag):
                        result = self.invoke("import-claude-code", self.configuration,
                                             "--bindings", self.bindings, flag, target)
                        self.assertEqual(result.returncode, 5, result.stderr)
                        self.assertEqual(result.stdout, b"")
                        for original, content in originals.items():
                            self.assertEqual(original.read_bytes(), content)
        with self.configuration.open("rb") as stream:
            result = self.invoke("import-claude-code", "-", "--bindings", self.bindings,
                                 "--model-output", self.configuration, stdin=stream)
        self.assertEqual(result.returncode, 5, result.stderr)
        self.assertEqual(self.configuration.read_bytes(), originals[self.configuration])
        self.assertEqual(list(self.root.glob(".structural-safety-*.tmp")), [])

    def test_report_and_model_outputs_cannot_alias_each_other(self):
        report = self.root / "report.json"
        alias = self.root / "report.alias"
        report.write_bytes(b"preserve both outputs")
        os.link(report, alias)
        for target in (report, alias):
            with self.subTest(target=target.name):
                result = self.invoke("import-claude-code", self.configuration,
                                     "--bindings", self.bindings,
                                     "--output", report, "--model-output", target)
                self.assertEqual(result.returncode, 5, result.stderr)
                self.assertEqual(result.stdout, b"")
                self.assertEqual(report.read_bytes(), b"preserve both outputs")
                self.assertEqual(alias.read_bytes(), b"preserve both outputs")

    def test_declared_server_command_is_not_executed_and_credentials_are_omitted(self):
        secret = "PRIVATE_MCP_CREDENTIAL_DO_NOT_ECHO"
        sentinel = self.root / "command-was-executed"
        document = {"mcpServers": {"local": {"command": sys.executable,
                    "args": ["-c", f"from pathlib import Path; Path({str(sentinel)!r}).write_text('executed')"],
                    "env": {"TOKEN": secret}}}}
        result = self.invoke("import-claude-code", "-", data=json.dumps(document).encode())
        self.assertEqual(result.returncode, 3, result.stderr)
        self.assertEqual(json.loads(result.stdout)["import_status"], "inventory_only")
        self.assertFalse(sentinel.exists())
        self.assertNotIn(secret.encode(), result.stdout + result.stderr)

    def test_operational_errors_keep_configuration_and_sensitive_paths_private(self):
        missing = self.root / "PRIVATE_PATH_NOT_FOR_DIAGNOSTICS" / "missing.json"
        result = self.invoke("import-claude-code", missing)
        self.assertEqual(result.returncode, 5)
        self.assertEqual(result.stdout, b"")
        self.assertNotIn(b"PRIVATE_PATH_NOT_FOR_DIAGNOSTICS", result.stderr)
        result = self.invoke("template", "memory-handoff", "--output", missing)
        self.assertEqual(result.returncode, 5)
        self.assertEqual(result.stdout, b"")
        self.assertNotIn(b"PRIVATE_PATH_NOT_FOR_DIAGNOSTICS", result.stderr)


if __name__ == "__main__":
    unittest.main()
