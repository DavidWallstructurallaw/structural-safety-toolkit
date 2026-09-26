"""Packaged finite-state examples remain model analysis, separate from demos."""

from copy import deepcopy
from importlib.resources import files
import json
import unittest

from structural_safety import Limits, analyze_json, validate_json
from structural_safety.experiment_cases import CASES


def example(name="P1-5-state"):
    return json.loads(files("structural_safety").joinpath("examples", name + ".json").read_text())


def analyze(document, **kwargs):
    return analyze_json(json.dumps(document), **kwargs).to_dict()


class PackagedStateExampleTests(unittest.TestCase):
    def test_packaged_memory_model_has_complete_version_path_and_only_model_evidence(self):
        document = example()
        self.assertEqual("valid", validate_json(json.dumps(document)).validation_status)
        result = analyze(document, limits=Limits(max_states=32))
        self.assertEqual("completed_for_supported_scope", result["analysis_status"])
        self.assertFalse(result["truncation"])
        finding = next(item for item in result["findings"] if item["rule_id"] == "SS001")
        self.assertEqual("modeled_boundary_violation", finding["classification"])
        self.assertEqual("not_tested", finding["observed_effect"])
        self.assertEqual(["read_s", "derive_s", "write_memory", "read_memory", "publish_derived"],
                         [step["action_id"] for step in finding["witness"]])
        produced = finding["witness"][1]["state_changes"]["source_details"]
        self.assertIn("S:v1", produced["ancestor_ids"])
        self.assertIn("restriction:S-v1", produced["restriction_ids"])
        stored, loaded = finding["witness"][2:4]
        self.assertEqual("D:v1", stored["output_port"]["object_version_id"])
        self.assertEqual("D:v1", loaded["input_ports"][0]["object_version_id"])
        self.assertEqual("result:internal", stored["output_port"]["location_node_id"])
        self.assertEqual("ctx:public", loaded["output_port"]["context_id"])
        self.assertFalse(any(item["rule_id"] == "SS004" for item in result["findings"]))
        for action in result["action_results"]:
            self.assertEqual("denied" if action["action_id"] == "publish_derived" else "allowed",
                             action["authorization"])

    def test_strict_variant_blocks_external_derived_version_after_memory_read(self):
        document = example()
        control = example("B")["controls"][0]
        control["policy_versions"][0]["coverage"]["value"] = [
            deepcopy(clause) for record in document["authorization"]["capabilities"] for clause in record["clauses"]]
        document["controls"] = [control]
        self.assertEqual("valid", validate_json(json.dumps(document)).validation_status)
        result = analyze(document)
        self.assertEqual("completed_for_supported_scope", result["analysis_status"])
        self.assertFalse(any(item["rule_id"] == "SS001" for item in result["findings"]))
        publish = next(item for item in result["action_results"] if item["action_id"] == "publish_derived")
        self.assertEqual("denied", publish["authorization"])
        self.assertEqual("blocked_in_model", publish["control_effect"])
        self.assertFalse(publish["witness"][-1]["committed"])
        self.assertTrue(all(item["witness"][-1]["committed"] for item in result["action_results"]
                            if item["action_id"] != "publish_derived"))

    def test_missing_output_declaration_does_not_erase_actual_source(self):
        document = example()
        output = next(item for item in document["object_versions"] if item["id"] == "D:v1")
        output["parents"]["value"] = []
        output["restriction_ids"]["value"] = []
        result = analyze(document)
        self.assertEqual("completed_for_supported_scope", result["analysis_status"])
        self.assertTrue(any(item["rule_id"] == "SS004" for item in result["findings"]))
        self.assertTrue(any(item["rule_id"] == "SS001" and item["authorization"] == "denied"
                            for item in result["findings"]))

    def test_budget_exhaustion_does_not_claim_completed_memory_model(self):
        result = analyze(example(), limits=Limits(max_states=3))
        self.assertEqual("partial", result["analysis_status"])
        self.assertTrue(result["truncation"])

    def test_analysis_examples_do_not_expand_the_fixed_demo_protocol(self):
        self.assertEqual(18, len(CASES))
        self.assertFalse(any(name.startswith("P1-5-") for name in CASES))

    def test_packaged_rule_example_identifies_declaration_gaps_without_inventing_execution(self):
        document = example("P1-5-rules")
        self.assertEqual("valid", validate_json(json.dumps(document)).validation_status)
        result = analyze(document)
        self.assertEqual("completed_for_supported_scope", result["analysis_status"])
        self.assertEqual({"SS002", "SS003", "SS004"}, {item["rule_id"] for item in result["findings"]})
        self.assertTrue(all(item["classification"] == "modeled_boundary_violation"
                            and item["observed_effect"] == "not_tested" for item in result["findings"]))
        delegated = [item for item in result["action_results"] if item["action_id"] == "delegate_expanded"]
        self.assertTrue(delegated)
        self.assertTrue(all(item["feasibility"] == "infeasible" for item in delegated))


if __name__ == "__main__":
    unittest.main()
