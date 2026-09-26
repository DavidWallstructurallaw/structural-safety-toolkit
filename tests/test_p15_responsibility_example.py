"""Packaged SS006 example through the complete public analysis API."""
from copy import deepcopy
from importlib.resources import files
import json
import unittest

from structural_safety import analyze_json
from structural_safety.model import Limits


def example():
    return json.loads(files("structural_safety").joinpath("examples/P1-5-responsibility.json").read_text())


def analyze(data, **kwargs):
    return analyze_json(json.dumps(data), **kwargs).to_dict()


class ResponsibilityExampleTests(unittest.TestCase):
    def test_packaged_review_is_scoped_and_stop_has_target_bound_authority(self):
        result = analyze(example())
        self.assertEqual(result["analysis_status"], "completed_for_supported_scope")
        self.assertEqual(result["unsupported_items"], [])
        obligation = next(item for item in result["obligations"] if item["obligation_id"] == "review:private")
        self.assertEqual(obligation["rule_id"], "SS006")
        self.assertEqual(obligation["obligation_status"], "satisfied_in_model")
        self.assertTrue(all(part["value"] for part in obligation["necessary_conditions"].values()))
        self.assertEqual(obligation["observed_effect"], "not_tested")
        self.assertFalse(any(item["rule_id"] == "SS006" for item in result["findings"]))
        stops = [item for item in result["action_results"] if item["action_id"] == "stop:private"]
        self.assertTrue(stops)
        self.assertTrue(all(item["feasibility"] == "feasible" and item["authorization"] == "allowed" for item in stops))
        self.assertTrue(all(item["query"]["management_targets"] == [["actions", "publish_s_main"]] for item in stops))

    def test_late_and_unknown_review_map_to_specific_findings(self):
        for kind, expected in (("late", "gap"), ("unknown", "unresolved")):
            with self.subTest(kind=kind):
                data = example()
                responsibility = data["obligations"][0]["responsibility"]
                if kind == "late":
                    responsibility["response"]["value"] = {"lower": 12, "upper": 14}
                else:
                    responsibility["verification_reliable"] = {"state": "unknown", "reason": "No validation basis", "evidence_refs": []}
                result = analyze(data)
                self.assertEqual(result["analysis_status"], "completed_for_supported_scope")
                finding, = [item for item in result["findings"] if item["rule_id"] == "SS006"]
                self.assertEqual(finding["obligation_status"], expected)
                self.assertEqual(finding["classification"], "responsibility_review_gap")
                self.assertEqual(finding["obligation_refs"], ["review:private"])
                self.assertEqual(finding["evidence_basis"], ["supplied_assertion", "model_deduction"])
                self.assertEqual(finding["observed_effect"], "not_tested")
                self.assertEqual(finding["witness"], [])
                self.assertEqual(bool([item for item in result["unresolved_items"] if item.get("rule_id") == "SS006"]), kind == "unknown")

    def test_clause_budget_leaves_unvisited_review_unchecked(self):
        result = analyze(example(), limits=Limits(max_clause_checks=1))
        self.assertEqual(result["analysis_status"], "partial")
        obligation = next(item for item in result["obligations"] if item["obligation_id"] == "review:private")
        self.assertEqual(obligation["check_status"], "not_checked")
        self.assertEqual(obligation["obligation_status"], "unresolved")
        self.assertTrue(any(item["reason"] == "max_clause_checks" for item in result["truncation"]))

    def test_finding_budget_preserves_checked_review_and_prior_finding(self):
        data = example()
        data["obligations"][0]["responsibility"]["reviewer_capable"]["value"] = False
        another = deepcopy(data["obligations"][0])
        another["id"] = "review:z"
        data["obligations"].append(another)
        result = analyze(data, limits=Limits(max_findings=1))
        self.assertEqual(result["analysis_status"], "partial")
        self.assertEqual(len(result["findings"]), 1)
        self.assertEqual(result["findings"][0]["obligation_refs"], ["review:private"])
        obligations = [item for item in result["obligations"] if item["obligation_id"].startswith("review:")]
        self.assertEqual(len(obligations), 2)
        self.assertTrue(all(item["check_status"] == "checked" and item["obligation_status"] == "gap" for item in obligations))
        self.assertTrue(any(item["reason"] == "max_findings" for item in result["truncation"]))


if __name__ == "__main__":
    unittest.main()
