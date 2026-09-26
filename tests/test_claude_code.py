"""Read-only MCP import: redaction, bounded parsing and explicit model premises."""

from dataclasses import FrozenInstanceError
from importlib.resources import files
import json
import os
import socket
import subprocess
import unittest
from unittest.mock import patch
import urllib.request

from structural_safety.claude_code import import_claude_code_json
from structural_safety import Limits, analyze_json, validate_json


class ClaudeCodeImportTests(unittest.TestCase):
    @staticmethod
    def config():
        return json.loads(files("structural_safety").joinpath(
            "integrations", "claude-code-example.json").read_text())

    @staticmethod
    def bindings():
        return json.loads(files("structural_safety").joinpath(
            "integrations", "claude-code-bindings.json").read_text())

    def invoke(self, configuration=None, bindings=None, **kwargs):
        configuration = self.config() if configuration is None else configuration
        return import_claude_code_json(json.dumps(configuration), bindings_document=(
            json.dumps(bindings) if bindings is not None else None), **kwargs)

    def test_no_bindings_produces_redacted_inventory_without_analysis(self):
        result = self.invoke()
        self.assertEqual(result.import_status, "inventory_only")
        self.assertIsNone(result.model)
        report = result.to_dict()
        self.assertFalse(report["analysis_performed"])
        self.assertFalse(report["execution_performed"])
        self.assertNotIn("safe", report)
        self.assertEqual([item["server_name"] for item in report["inventory"]],
                         ["private-files", "shared-memory", "publisher"])
        self.assertEqual(report["inventory"][0]["transport"], "stdio")
        self.assertFalse(report["inventory"][0]["field_presence"]["type"])
        self.assertEqual(report["inventory"][0]["environment_entry_count"], 1)
        self.assertEqual(report["diagnostics"][0]["code"], "bindings_required")
        self.assertTrue(report["assumptions"])
        self.assertTrue(report["limitations"])

    def test_secret_values_are_never_returned_or_executed(self):
        config = self.config()
        config["mcpServers"]["private-files"].update({
            "command": "COMMAND_SECRET_RUN_ME", "args": ["ARG_SECRET"],
            "env": {"ENV_KEY_SECRET": "ENV_VALUE_SECRET"},
        })
        config["mcpServers"]["publisher"].update({
            "url": "https://URL_SECRET.invalid/mcp", "headers": {"HEADER_KEY_SECRET": "HEADER_VALUE_SECRET"},
            "headersHelper": "HELPER_SECRET_RUN_ME",
        })
        with patch.object(subprocess, "run", side_effect=AssertionError("command executed")), \
             patch.object(subprocess, "Popen", side_effect=AssertionError("process started")), \
             patch.object(os, "system", side_effect=AssertionError("shell executed")), \
             patch.object(os.path, "expandvars", side_effect=AssertionError("environment expanded")), \
             patch.object(socket, "create_connection", side_effect=AssertionError("network opened")), \
             patch.object(urllib.request, "urlopen", side_effect=AssertionError("URL opened")):
            result = self.invoke(config, self.bindings())
        self.assertEqual(result.import_status, "model_created")
        output = json.dumps(result.to_dict())
        for secret in ("COMMAND_SECRET", "ARG_SECRET", "ENV_KEY_SECRET", "ENV_VALUE_SECRET",
                       "URL_SECRET", "HEADER_KEY_SECRET", "HEADER_VALUE_SECRET", "HELPER_SECRET"):
            self.assertNotIn(secret, output)

    def test_supported_transports_and_unconfigured_remote_entry(self):
        servers = {transport: {"type": transport, "url": "${UNRESOLVED_ENDPOINT}",
                               "headers": {}, "headersHelper": "unexecuted helper"}
                   for transport in ("http", "streamable-http", "sse", "ws")}
        servers["empty"] = {"type": "http", "url": ""}
        report = self.invoke({"mcpServers": servers}).to_dict()
        self.assertEqual(report["import_status"], "inventory_only")
        inventory = {item["server_name"]: item for item in report["inventory"]}
        self.assertEqual(inventory["streamable-http"]["transport"], "http")
        self.assertEqual(inventory["empty"]["configuration_status"], "unconfigured")
        self.assertNotIn("UNRESOLVED_ENDPOINT", json.dumps(report))
        config = self.config()
        config["mcpServers"]["publisher"]["url"] = ""
        result = self.invoke(config, self.bindings())
        self.assertEqual(result.import_status, "input_invalid")
        self.assertEqual(result.diagnostics[0].code, "bindings_unconfigured")
        self.assertIsNone(result.model)

    def test_unknown_fields_types_and_shapes_fail_without_echoing_contents(self):
        configs = [
            {"mcpServers": {}, "PRIVATE_UNKNOWN_FIELD": "PRIVATE_CONTENT"},
            {"mcpServers": {"server": {"command": "private", "PRIVATE_UNKNOWN_FIELD": "PRIVATE_CONTENT"}}},
            {"mcpServers": {"server": {"type": "PRIVATE_CONTENT"}}},
            {"mcpServers": {"server": {"url": "https://PRIVATE_CONTENT.invalid"}}},
            {"mcpServers": {"server": {"type": "sdk", "command": "private"}}},
            {"mcpServers": {"server": {"type": "http", "url": "private", "oauth": {"secret": "PRIVATE_CONTENT"}}}},
            {"mcpServers": {"server": {"type": "http", "url": "private", "timeout": 5000}}},
            {"mcpServers": {"server": {"type": "http", "url": "private", "alwaysLoad": True}}},
            {"mcpServers": {"server": {"command": "private", "env": {"SECRET_FIELD": False}}}},
            {"mcpServers": {"server": {"command": "private", "args": "PRIVATE_CONTENT"}}},
        ]
        for config in configs:
            with self.subTest(config_index=configs.index(config)):
                result = self.invoke(config)
                self.assertEqual(result.import_status, "input_invalid")
                output = json.dumps(result.to_dict())
                for hidden in ("PRIVATE_UNKNOWN_FIELD", "PRIVATE_CONTENT", "SECRET_FIELD"):
                    self.assertNotIn(hidden, output)
                self.assertIsNone(result.model)

    def test_strict_json_duplicate_keys_unicode_and_nonfinite_values(self):
        for text in (
            '{"mcpServers":{},"mcpServers":{}}',
            '{"mcpServers":{"server":{"command":"x","env":{"SECRET_KEY":"a","SECRET_KEY":"b"}}}}',
            '{"mcpServers":{"server":{"command":"\\ud800"}}}',
            '{"mcpServers":{"server":{"command":"x","args":[NaN]}}}',
            '{"mcpServers":{"server":{"command":"x","args":[1e400]}}}',
            '{"mcpServers":{"server":{"command":"x","args":[Infinity]}}}',
            '{"mcpServers":{}} // PRIVATE_COMMENT',
            '{"mcpServers":{"server":{"command":"x"}},}',
            b'\xff',
            '{"mcpServers":{}' + chr(0xD800),
        ):
            with self.subTest(index=repr(text[:35])):
                result = import_claude_code_json(text)
                self.assertEqual(result.import_status, "input_invalid")
                self.assertNotIn("SECRET_KEY", json.dumps(result.to_dict()))
                self.assertNotIn("PRIVATE_COMMENT", json.dumps(result.to_dict()))

    def test_combined_input_bytes_depth_entries_and_generated_model_limits(self):
        configuration = json.dumps(self.config())
        bindings = json.dumps(self.bindings())
        result = import_claude_code_json(configuration, bindings_document=bindings,
                                       limits=Limits(max_input_bytes=len(configuration.encode())))
        self.assertEqual(result.import_status, "resource_rejected")
        self.assertEqual(result.diagnostics[0].code, "max_input_bytes")
        for limits, code in ((Limits(max_depth=2), "max_depth"),
                             (Limits(max_records=3), "max_records")):
            with self.subTest(code=code):
                result = import_claude_code_json(configuration, limits=limits)
                self.assertEqual(result.import_status, "resource_rejected")
                self.assertEqual(result.diagnostics[0].code, code)
        result = self.invoke(bindings=self.bindings(), limits=Limits(max_actions=1))
        self.assertEqual(result.import_status, "resource_rejected")
        self.assertEqual(result.diagnostics[0].code, "generated_model_limit")
        self.assertIsNone(result.model)

    def test_bindings_require_exact_schema_roles_existing_distinct_servers(self):
        cases = []
        for key, value in (("schema_version", "unknown"), ("template", "other"), ("variant", [])):
            value_to_test = self.bindings()
            value_to_test[key] = value
            cases.append(value_to_test)
        value = self.bindings()
        value["servers"]["publish"] = "SECRET_UNKNOWN_SERVER"
        cases.append(value)
        value = self.bindings()
        value["servers"]["publish"] = "shared-memory"
        cases.append(value)
        value = self.bindings()
        value["servers"]["SECRET_UNKNOWN_FIELD"] = "SECRET_VALUE"
        cases.append(value)
        value = self.bindings()
        del value["servers"]["memory"]
        cases.append(value)
        for bindings in cases:
            result = self.invoke(bindings=bindings)
            self.assertEqual(result.import_status, "input_invalid")
            self.assertIsNone(result.model)
            self.assertNotIn("SECRET", json.dumps(result.to_dict()))
        raw = '{"schema_version":"sst.claude-code-bindings/0.1","template":"memory-handoff","template":"other"}'
        result = import_claude_code_json(json.dumps(self.config()), bindings_document=raw)
        self.assertEqual(result.diagnostics[0].code, "duplicate_key")

    def test_models_validate_analyze_and_keep_configuration_separate_from_premises(self):
        for variant in ("exposed", "controlled"):
            bindings = self.bindings()
            bindings["variant"] = variant
            result = self.invoke(bindings=bindings)
            self.assertEqual(result.import_status, "model_created")
            model = result.to_dict()["model"]
            text = json.dumps(model)
            self.assertEqual(validate_json(text).validation_status, "valid")
            interfaces = {item["id"]: item for item in model["context"]["interfaces"]}
            for role in ("source", "memory", "publish"):
                self.assertIn("if:claude-code:" + role, interfaces)
            for old in ("if:crm-read", "if:handoff-memory", "if:customer-publish"):
                self.assertNotIn('"' + old + '"', text)
            evidence = {item["id"]: item for item in model["evidence"]}
            presence = evidence["ev:claude-code-config"]
            self.assertEqual(presence["acquisition"], "configuration_read")
            self.assertEqual(presence["scope"], [])
            self.assertEqual(evidence["ev:claude-code-bindings"]["acquisition"], "supplied_assertion")
            self.assertEqual(evidence["ev:template-premises"]["acquisition"], "supplied_assertion")
            for interface in interfaces.values():
                self.assertNotIn("ev:claude-code-config", interface["evidence_refs"])
            self.assertTrue(presence["limits"])
            analysis = analyze_json(text)
            self.assertEqual(analysis.analysis_status, "completed_for_supported_scope")
            violations = [item for item in analysis.findings if item["classification"] == "modeled_boundary_violation"]
            self.assertEqual(bool(violations), variant == "exposed")
            self.assertTrue(any(item["classification"] == "assurance_gap" for item in analysis.findings))
            self.assertTrue(all(item["observed_effect"] == "not_tested" for item in analysis.findings))

    def test_result_is_immutable_and_serialization_is_a_defensive_copy(self):
        result = self.invoke(bindings=self.bindings())
        with self.assertRaises(FrozenInstanceError):
            result.import_status = "other"
        with self.assertRaises(TypeError):
            result.model["context"]["snapshot_id"] = "changed"
        copied = result.to_dict()
        copied["model"]["context"]["snapshot_id"] = "changed"
        copied["inventory"][0]["field_presence"]["command"] = False
        self.assertNotEqual(result.to_dict()["model"]["context"]["snapshot_id"], "changed")
        self.assertTrue(result.to_dict()["inventory"][0]["field_presence"]["command"])

    def test_caller_misuse_is_not_reported_as_configuration_unknown(self):
        for arguments in (({}, {}), ("{}", {"bindings_document": {}}), ("{}", {"limits": {}})):
            with self.assertRaises(TypeError):
                import_claude_code_json(arguments[0], **arguments[1])


if __name__ == "__main__":
    unittest.main()
