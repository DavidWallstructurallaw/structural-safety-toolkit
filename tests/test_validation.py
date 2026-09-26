"""Input boundary tests: malformed data cannot silently become model facts."""

from dataclasses import FrozenInstanceError
from importlib.resources import files
import json
import unittest
from unittest.mock import patch

from structural_safety.model import Fact, Limits, Reference
from structural_safety.validation import validate_json


def minimal_document() -> dict:
    """A complete small snapshot, with no candidate actions or claims of safety."""
    return {
        "context": {
            "schema_version": "sst.model/0.1", "snapshot_id": "minimal",
            "as_of": "2026-09-26T12:00:00Z",
            "tasks": [{"id": "task", "parent_task": {
                "state": "known", "value": "not_applicable", "evidence_refs": []
            }, "evidence_refs": []}],
            "root_task": "task", "workflows": [], "interfaces": [],
            "operation_definitions": [], "purposes": [], "properties": [],
            "declared_scope": "No candidate actions supplied.", "known_limits": [],
            "completeness": [], "unsupported_items": [], "initial_conditions": [],
            "stopped_targets": [],
        },
        "nodes": [], "execution_contexts": [], "object_versions": [],
        "actions": [], "relations": [],
        "authorization": {"capabilities": [], "task_grants": [],
                          "approval_rights": [], "release_exceptions": []},
        "restrictions": [], "controls": [], "obligations": [], "evidence": [],
        "limits": {},
    }


class StrictInputTests(unittest.TestCase):
    def assert_issue(self, document, status, code, **kwargs):
        result = validate_json(document, **kwargs)
        self.assertEqual(result.validation_status, status, result.diagnostics)
        self.assertIn(code, [item.code for item in result.diagnostics])
        self.assertFalse(result.analysis_performed)
        self.assertIsNone(result.model)
        return result

    def test_valid_input_has_no_safety_analysis(self):
        result = validate_json(json.dumps(minimal_document()))
        self.assertEqual(result.validation_status, "valid", result.diagnostics)
        self.assertFalse(result.analysis_performed)
        self.assertEqual(result.supported_capabilities, ("input_validation",))
        self.assertEqual(result.model.to_dict(), minimal_document())
        self.assertNotIn("model", result.to_dict())
        self.assertNotIn("findings", result.to_dict())

    def test_decoded_dict_is_programmer_error(self):
        with self.assertRaises(TypeError):
            validate_json(minimal_document())
        with self.assertRaises(TypeError):
            validate_json("{}", limits={})

    def test_duplicate_key_preserves_escaped_location(self):
        result = self.assert_issue('{"a/b":{"x~y":1,"x~y":2}}', "input_invalid", "duplicate_key")
        self.assertEqual(result.diagnostics[0].path, "/a~1b/x~0y")

    def test_nonstandard_and_overflow_numbers_rejected(self):
        for token in ("NaN", "Infinity", "-Infinity", "1e999", "-1e999"):
            with self.subTest(token=token):
                result = validate_json('{"number":' + token + '}')
                self.assertEqual(result.validation_status, "input_invalid")
                self.assertIn(result.diagnostics[0].code, ("non_standard_number", "non_finite_number"))

    def test_strict_utf8_and_surrogates(self):
        for raw, code in ((b'\xff', "invalid_utf8"), ('"\ud800"', "invalid_utf8"),
                          ('"\\ud800"', "invalid_unicode")):
            with self.subTest(code=code):
                self.assert_issue(raw, "input_invalid", code)

    def test_surrogate_pair_is_valid_unicode(self):
        data = minimal_document()
        data["context"]["snapshot_id"] = "astral-\U0001f680"
        result = validate_json(json.dumps(data, ensure_ascii=True))
        self.assertEqual(result.validation_status, "valid", result.diagnostics)

    def test_syntax_and_root_failures_are_diagnostics(self):
        for raw, code in (("", "invalid_json"), ('{"a":1,}', "invalid_json"),
                          ("[]", "root_object"), ("null", "root_object")):
            with self.subTest(raw=raw):
                self.assert_issue(raw, "input_invalid", code)

    def test_schema_failure_is_separate_from_missing_schema(self):
        result = self.assert_issue('{"context":{"schema_version":"sst.model/9.0"}}',
                                   "unsupported_schema", "unsupported_schema")
        self.assertEqual(result.schema_version, "sst.model/9.0")
        self.assert_issue('{"context":{"schema_version":true}}', "input_invalid", "schema_version")

    def test_depth_prescan_respects_strings_and_escaped_quotes(self):
        data = minimal_document()
        data["context"]["declared_scope"] = '[{ " \\" ' * 40
        self.assertEqual(validate_json(json.dumps(data)).validation_status, "valid")
        self.assert_issue("[" * 33 + "0" + "]" * 33, "resource_rejected", "max_depth")

    def test_byte_limit_includes_utf8_bytes(self):
        data = minimal_document()
        data["context"]["declared_scope"] = "语义"
        raw = json.dumps(data, ensure_ascii=False)
        length = len(raw.encode("utf-8"))
        self.assertEqual(validate_json(raw, limits=Limits(max_input_bytes=length)).validation_status, "valid")
        self.assert_issue(raw, "resource_rejected", "max_input_bytes", limits=Limits(max_input_bytes=length - 1))

    def test_input_limit_cannot_raise_caller_policy(self):
        data = minimal_document()
        data["limits"]["max_states"] = 100_000
        result = validate_json(json.dumps(data), limits=Limits(max_states=5))
        self.assertEqual(result.effective_limits.max_states, 5)
        self.assertEqual(result.validation_status, "valid")

    def test_lower_input_hard_caps_rechecked_after_parse(self):
        for field, value in (("max_depth", 2), ("max_input_bytes", 20)):
            with self.subTest(field=field):
                data = minimal_document()
                data["limits"][field] = value
                self.assert_issue(json.dumps(data), "resource_rejected", field)

    def test_input_and_api_limits_are_strict_positive_integers(self):
        for value in (True, 0, -1, 1.0, "12", None):
            with self.subTest(value=value):
                data = minimal_document()
                data["limits"]["max_states"] = value
                self.assert_issue(json.dumps(data), "input_invalid", "invalid_limit")
                with self.assertRaises((ValueError, TypeError)):
                    Limits(max_states=value)
        data = minimal_document()
        data["limits"]["guess_limit"] = 10
        self.assert_issue(json.dumps(data), "input_invalid", "unknown_limit")

    def test_record_limit_counts_duplicates_before_validation(self):
        data = minimal_document()
        self.assertEqual(validate_json(json.dumps(data), limits=Limits(max_records=1)).validation_status, "valid")
        data["context"]["tasks"].append(data["context"]["tasks"][0])
        self.assert_issue(json.dumps(data), "resource_rejected", "max_records", limits=Limits(max_records=1))

    def test_raw_action_count_rejected_before_expensive_shape_checks(self):
        data = minimal_document()
        data["actions"] = [{}, {}]
        self.assert_issue(json.dumps(data), "resource_rejected", "max_actions", limits=Limits(max_actions=1))

    def test_atomic_receivers_also_consume_action_limit(self):
        data = json.loads(files("structural_safety").joinpath("examples/A.json").read_text(encoding="utf-8"))
        action = next(item for item in data["actions"] if item["id"] == "publish_s_main")
        action["group_id"] = "publish-batch"
        action["outputs"].append({"port_id": "out2", "object_version_id": "S:v1",
                                  "location_node_id": "result:internal", "context_id": "not_applicable"})
        action["effects"].append({"kind": "deliver", "id": "deliver2",
                                  "input_port_ids": ["in"], "output_port_id": "out2"})
        count = len(data["actions"])
        raw = json.dumps(data)
        self.assert_issue(raw, "resource_rejected", "max_actions", limits=Limits(max_actions=count))
        result = validate_json(raw, limits=Limits(max_actions=count + 1))
        self.assertEqual(result.validation_status, "valid", result.diagnostics)

    def test_unknown_and_conflict_survive_validation(self):
        for fact in (
            {"state": "unknown", "reason": "Not supplied.", "evidence_refs": []},
            {"state": "conflict", "candidates": [
                {"value": "not_applicable", "evidence_refs": []},
                {"value": "task", "evidence_refs": []}], "evidence_refs": []},
        ):
            with self.subTest(state=fact["state"]):
                data = minimal_document()
                data["context"]["tasks"][0]["parent_task"] = fact
                result = validate_json(json.dumps(data))
                self.assertEqual(result.validation_status, "valid", result.diagnostics)
                normalized = result.model.data["context"]["tasks"][0]["parent_task"]
                self.assertIsInstance(normalized, Fact)
                self.assertEqual(normalized.to_dict(), fact)
                self.assertEqual(normalized.evidence_basis, ())

    def test_unknown_cannot_carry_an_invented_value(self):
        data = minimal_document()
        data["context"]["tasks"][0]["parent_task"] = {
            "state": "unknown", "reason": "Missing", "value": "task", "evidence_refs": []}
        result = validate_json(json.dumps(data))
        self.assertEqual(result.validation_status, "input_invalid")

    def test_explicit_unsupported_preserved_without_analysis(self):
        data = minimal_document()
        data["context"]["unsupported_items"] = [{
            "id": "dynamic", "reason": "Dynamic route not enumerated.",
            "affected_refs": {"state": "unknown", "reason": "Scope unavailable.", "evidence_refs": []}}]
        result = validate_json(json.dumps(data))
        self.assertEqual(result.validation_status, "valid", result.diagnostics)
        self.assertFalse(result.analysis_performed)
        self.assertEqual(result.to_dict()["unsupported_items"], data["context"]["unsupported_items"])

    def test_unsupported_operation_has_identified_scope(self):
        data = minimal_document()
        data["context"]["operation_definitions"] = [{"id": "opaque", "semantic_kind": "unsupported",
            "unsupported_reason": "Opaque semantics.", "evidence_refs": []}]
        result = validate_json(json.dumps(data))
        self.assertEqual(result.validation_status, "valid", result.diagnostics)
        affected = result.to_dict()["unsupported_items"][0]["affected_refs"]["value"]
        self.assertEqual(affected, [{"collection": "operations", "id": "opaque"}])

    def test_external_policy_and_conflict_are_reported(self):
        def known(value):
            return {"state": "known", "value": value, "evidence_refs": []}

        unknown = {"state": "unknown", "reason": "Not supplied.", "evidence_refs": []}
        for decision in (known("external"), {"state": "conflict", "candidates": [
            {"value": "authorization", "evidence_refs": []},
            {"value": "unsupported", "evidence_refs": []}], "evidence_refs": []}):
            with self.subTest(state=decision["state"]):
                data = minimal_document()
                data["nodes"] = [{"id": "gate", "kind": "control", "owner": unknown, "evidence_refs": []}]
                data["context"]["properties"] = [{"id": "property", "description": "Boundary."}]
                data["controls"] = [{
                    "id": "gate", "node_id": "gate", "property_ids": ["property"],
                    "initial_policy": known("p1"), "modifiable_fields": known([]),
                    "responsible_principal": unknown, "modification_paths_complete": known(True),
                    "evidence_refs": [], "policy_versions": [{
                        "id": "p1", "coverage": known([]), "checked_parameters": known([]),
                        "binding": known("bound"), "timing": known("before_effect"),
                        "decision_mode": decision, "deny_clauses": known([]),
                        "failure_behavior": known("deny"), "unsupported_reason": "Requires external decision.",
                        "evidence_refs": [],
                    }],
                }]
                result = validate_json(json.dumps(data))
                self.assertEqual(result.validation_status, "valid", result.diagnostics)
                item = result.to_dict()["unsupported_items"][0]
                self.assertEqual(item["policy_id"], "p1")
                self.assertEqual(item["decision_state"], decision["state"])
                self.assertEqual(item["affected_refs"]["value"], [{"collection": "controls", "id": "gate"}])

    def test_model_and_facts_are_deeply_immutable(self):
        data = minimal_document()
        result = validate_json(json.dumps(data))
        model = result.model
        with self.assertRaises(TypeError):
            model.data["context"]["tasks"][0]["id"] = "changed"
        fact = model.data["context"]["tasks"][0]["parent_task"]
        self.assertEqual(fact.evidence_basis, ("supplied_assertion",))
        with self.assertRaises(TypeError):
            fact["value"] = "changed"
        with self.assertRaises(FrozenInstanceError):
            result.analysis_performed = True
        detached = model.to_dict()
        detached["context"]["tasks"][0]["id"] = "changed"
        self.assertEqual(model.data["context"]["tasks"][0]["id"], "task")
        self.assertEqual(data, minimal_document())

    def test_reference_namespaces_do_not_collapse(self):
        self.assertNotEqual(Reference("nodes", "shared"), Reference("actions", "shared"))

    def test_internal_failure_is_not_disguised_as_input_unknown(self):
        with patch("structural_safety.schema.validate_structure", side_effect=RuntimeError("bug")):
            with self.assertRaisesRegex(RuntimeError, "bug"):
                validate_json(json.dumps(minimal_document()))


if __name__ == "__main__":
    unittest.main()
