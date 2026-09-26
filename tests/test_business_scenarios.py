"""Business starter pairs retain their risk, narrow intervention, and useful work."""

from copy import deepcopy
from importlib.resources import files
import json
import unittest

from structural_safety import analyze_json, validate_json


NAMES = ("memory-handoff", "policy-self-modification", "human-oversight")
VARIANTS = ("exposed", "controlled")


def load(name, variant):
    resource = files("structural_safety").joinpath("templates", f"{name}-{variant}.json")
    return json.loads(resource.read_text(encoding="utf-8"))


class BusinessScenarioTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.models = {(name, variant): load(name, variant) for name in NAMES for variant in VARIANTS}
        cls.reports = {key: analyze_json(json.dumps(model)).to_dict() for key, model in cls.models.items()}

    def test_all_six_templates_complete_model_checks_without_runtime_claims(self):
        for key, model in self.models.items():
            with self.subTest(template=key):
                self.assertEqual(validate_json(json.dumps(model)).validation_status, "valid")
                report = self.reports[key]
                self.assertEqual(report["analysis_status"], "completed_for_supported_scope")
                self.assertEqual(report["unresolved_items"], [])
                self.assertEqual(report["unsupported_items"], [])
                self.assertEqual(report["truncation"], [])
                self.assertTrue(all(item["observed_effect"] == "not_tested" for item in report["findings"]))
                self.assertTrue(all(item["runtime_status"] == "not_tested" for item in report["coverage"]))
                self.assertTrue(all(item["acquisition"] == "supplied_assertion" for item in model["evidence"]))

    def test_memory_gate_blocks_inherited_source_but_retains_internal_handoff_and_public_work(self):
        exposed = self.reports["memory-handoff", "exposed"]
        controlled = self.reports["memory-handoff", "controlled"]
        violation, = [finding for finding in exposed["findings"] if finding["rule_id"] == "SS001"]
        self.assertEqual([step["action_id"] for step in violation["witness"]],
                         ["read-crm-case", "summarize-case", "store-handoff", "load-handoff", "publish-case-summary"])
        self.assertFalse(any(finding["rule_id"] == "SS001" for finding in controlled["findings"]))
        for variant, report in (("exposed", exposed), ("controlled", controlled)):
            results = report["action_results"]
            private = [item for item in results if item["action_id"] == "publish-case-summary"]
            self.assertTrue(private)
            self.assertTrue(all(item["feasibility"] == "feasible" and item["authorization"] == "denied"
                                and item["control_effect"] == ("blocked_in_model" if variant == "controlled"
                                                              else "not_blocked_in_model") for item in private))
            for name in ("summarize-case", "store-handoff", "load-handoff", "publish-public-status"):
                useful = [item for item in results if item["action_id"] == name]
                self.assertTrue(useful)
                self.assertTrue(all(item["feasibility"] == "feasible" and item["authorization"] == "allowed"
                                    and item["control_effect"] == "not_blocked_in_model" for item in useful))
        changed = deepcopy(self.models["memory-handoff", "controlled"])
        changed["controls"] = []
        self.assertEqual(changed, self.models["memory-handoff", "exposed"])

    def test_policy_isolation_removes_only_the_exact_modification_capability(self):
        exposed = self.reports["policy-self-modification", "exposed"]
        controlled = self.reports["policy-self-modification", "controlled"]
        self.assertTrue(any(item["rule_id"] == "SS001" for item in exposed["findings"]))
        self.assertFalse(any(item["rule_id"] == "SS001" for item in controlled["findings"]))
        for variant, report in (("exposed", exposed), ("controlled", controlled)):
            selection = [item for item in report["action_results"]
                         if item["action_id"] == "select-permissive-publishing-policy"]
            self.assertTrue(selection)
            self.assertTrue(all(item["feasibility"] == ("feasible" if variant == "exposed" else "infeasible")
                                and item["authorization"] == "denied" for item in selection))
            public = [item for item in report["action_results"]
                      if item["action_id"] == "publish-approved-public-results"]
            self.assertTrue(public)
            self.assertTrue(all(item["feasibility"] == "feasible" and item["authorization"] == "allowed"
                                and item["control_effect"] == "not_blocked_in_model" for item in public))
        violation = next(item for item in exposed["findings"] if item["rule_id"] == "SS001")
        path = [step["action_id"] for step in violation["witness"]]
        self.assertLess(path.index("select-permissive-publishing-policy"), path.index("upload-forecast-after-policy-change"))
        changed = deepcopy(self.models["policy-self-modification", "exposed"])
        changed["authorization"]["capabilities"] = [item for item in changed["authorization"]["capabilities"]
            if item["id"] != "cap:select-permissive-publishing-policy"]
        self.assertEqual(changed, self.models["policy-self-modification", "controlled"])

    def test_human_oversight_requires_timely_response_and_the_same_exact_stop_authority(self):
        for variant in VARIANTS:
            model = self.models["human-oversight", variant]
            report = self.reports["human-oversight", variant]
            obligation = next(item for item in report["obligations"]
                              if item["obligation_id"] == "review:confidential-report-publication")
            self.assertEqual(obligation["obligation_status"], "gap" if variant == "exposed" else "satisfied_in_model")
            self.assertIs(obligation["necessary_conditions"]["timeliness"]["value"], variant == "controlled")
            self.assertTrue(obligation["necessary_conditions"]["stop_authority"]["value"])
            self.assertEqual(model["obligations"][0]["responsibility"]["consequence_window"]["value"],
                             {"lower": 5, "upper": 5})
            response = model["obligations"][0]["responsibility"]["response"]["value"]
            self.assertEqual(response, {"lower": 30, "upper": 30} if variant == "exposed" else {"lower": 3, "upper": 3})
            stops = [item for item in report["action_results"]
                     if item["action_id"] == "stop:confidential-report-publication"]
            self.assertTrue(stops)
            self.assertTrue(all(item["feasibility"] == "feasible" and item["authorization"] == "allowed"
                                and item["query"]["management_targets"] == [["actions", "publish-confidential-report"]]
                                for item in stops))
            self.assertEqual(bool([finding for finding in report["findings"] if finding["rule_id"] == "SS006"]),
                             variant == "exposed")
        changed = deepcopy(self.models["human-oversight", "exposed"])
        changed["obligations"][0]["responsibility"]["response"]["value"] = {"lower": 3, "upper": 3}
        next(item for item in changed["actions"] if item["id"] == "stop:confidential-report-publication")["effect_time"]["value"] = "2000-01-01T00:00:23Z"
        self.assertEqual(changed, self.models["human-oversight", "controlled"])

    def test_controlled_variants_retain_declared_evidence_limits(self):
        for name in NAMES:
            with self.subTest(template=name):
                report = self.reports[name, "controlled"]
                self.assertTrue(any(finding["rule_id"] == "SS005" and finding["classification"] == "assurance_gap"
                                    and finding["control_assurance"] == "declaration_only"
                                    for finding in report["findings"]))
                self.assertTrue(all(item["model_coverage"] == "covered_in_declared_model"
                                    for item in report["coverage"]))


if __name__ == "__main__":
    unittest.main()
