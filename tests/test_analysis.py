"""Integration regressions for claims that span search, semantics and reporting."""

import copy
from importlib.resources import files
import json
import unittest

from structural_safety import analyze_json, Limits


def fixture(name="A"):
    return json.loads(files("structural_safety").joinpath("examples", name + ".json").read_text())


def run(data, **kwargs):
    return analyze_json(json.dumps(data), **kwargs)


def unknown():
    return {"state": "unknown", "reason": "Not established", "evidence_refs": []}


def results_for(result, action):
    return [r for r in result.action_results if r["action_id"] == action]


class AnalysisIntegrationTests(unittest.TestCase):
    def test_ab_axes_and_normal_work_remain_separate_from_observation(self):
        for name, control in (("A", "not_blocked_in_model"), ("B", "blocked_in_model")):
            with self.subTest(name=name):
                result = run(fixture(name))
                private = results_for(result, "publish_s_main")
                self.assertTrue(private)
                self.assertEqual({(r["feasibility"], r["authorization"], r["control_effect"]) for r in private},
                                 {("feasible", "denied", control)})
                for action in ("copy_s_internal", "publish_p_main"):
                    self.assertTrue(any(r["authorization"] == "allowed" and r["control_effect"] == "not_blocked_in_model"
                                        for r in results_for(result, action)))
                violations = [f for f in result.findings if f["classification"] == "modeled_boundary_violation"]
                self.assertEqual(bool(violations), name == "A")
                self.assertTrue(all(f["observed_effect"] == "not_tested" for f in result.findings))
                self.assertEqual(result.scope["snapshot_id"], "snapshot:ab")
        violation = next(f for f in run(fixture()).findings if f["classification"] == "modeled_boundary_violation")
        self.assertEqual([p["action_id"] for p in violation["witness"]], ["read_s", "publish_s_main"])
        self.assertIn("input_ports", violation["witness"][-1])
        self.assertIn("output_port", violation["witness"][-1])

    def test_unknown_modification_paths_keep_current_block_but_limit_coverage(self):
        data = fixture("B")
        data["controls"][0]["modification_paths_complete"] = unknown()
        result = run(data)
        self.assertTrue(all(r["control_effect"] == "blocked_in_model" for r in results_for(result, "publish_s_main")))
        self.assertEqual(result.coverage[0]["model_coverage"], "unresolved")
        self.assertTrue(result.unresolved_items)
        self.assertTrue(any(o.get("has_unresolved") for o in result.obligations))

    def test_binding_unknown_makes_a_conditional_path_without_confirmed_violation(self):
        data = fixture("B")
        data["controls"][0]["policy_versions"][0]["binding"] = unknown()
        result = run(data)
        self.assertTrue(any(r["control_effect"] == "unresolved" for r in results_for(result, "publish_s_main")))
        self.assertFalse(any(f["classification"] == "modeled_boundary_violation" for f in result.findings))
        self.assertTrue(result.unresolved_items)

    def test_capability_absence_does_not_change_allowed_to_denied(self):
        data = fixture()
        data["authorization"]["capabilities"] = [c for c in data["authorization"]["capabilities"]
                                                   if "publish_p_main" not in c["id"]]
        result = run(data)
        self.assertTrue(any(r["feasibility"] == "infeasible" and r["authorization"] == "allowed"
                            for r in results_for(result, "publish_p_main")))

    def test_budget_stops_preserve_a_confirmed_finding_and_prevent_false_coverage(self):
        result = run(fixture(), limits=Limits(max_findings=1))
        self.assertEqual(result.analysis_status, "partial")
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0]["classification"], "modeled_boundary_violation")
        self.assertEqual(result.budget_usage["findings"], 1)
        self.assertTrue(result.truncation)
        self.assertEqual(result.coverage[0]["model_coverage"], "violated_in_model")
        self.assertEqual(result.coverage[0]["check_status"], "partial")
        early = run(fixture(), limits=Limits(max_clause_checks=1))
        self.assertEqual(early.analysis_status, "partial")
        self.assertEqual(early.coverage[0]["model_coverage"], "unresolved")

    def test_exact_work_budget_and_order_independent_report(self):
        original = fixture()
        result = run(original)
        capped = copy.deepcopy(original)
        capped["limits"] = {"max_" + k: v for k, v in result.budget_usage.items() if v}
        exact = run(capped)
        self.assertEqual(exact.analysis_status, "completed_for_supported_scope")
        self.assertFalse(exact.truncation)
        reordered = copy.deepcopy(original)
        for collection in ("nodes", "execution_contexts", "object_versions", "actions", "restrictions", "evidence"):
            reordered[collection].reverse()
        for records in reordered["authorization"].values():
            records.reverse()
        reordered["context"]["completeness"].reverse()
        self.assertEqual(run(reordered).to_dict(), result.to_dict())

    def test_missing_property_is_explicitly_unchecked(self):
        data = fixture()
        data["context"]["properties"] = []
        result = run(data)
        self.assertEqual(result.analysis_status, "partial")
        self.assertTrue(result.unsupported_items)
        self.assertEqual(result.coverage[0]["model_coverage"], "unresolved")

    def test_imported_verified_event_cannot_become_observed_violation(self):
        data = fixture()
        data["events"] = [{"id": "reported", "run_id": "claimed-run", "reported_event_kind": "effect_observed",
                           "action_id": "publish_s_main", "object_ids": ["S:v1"], "observer_id": "principal:owner",
                           "environment": "deployment", "occurred_at": unknown(),
                           "recorded_at": "2000-01-01T00:01:00Z", "details": "claimed success",
                           "verified": True, "claimed_origin": "tool_run", "evidence_refs": []}]
        result = run(data)
        self.assertEqual(result.analysis_status, "partial")
        self.assertTrue(any(i["affected_refs"]["value"][0]["collection"] == "events" for i in result.unsupported_items))
        self.assertFalse(any(f["classification"] in ("observed_boundary_violation", "demonstrated_control_bypass")
                             for f in result.findings))
        self.assertTrue(all(f["observed_effect"] == "not_tested" for f in result.findings))

    def test_source_consistency_rule_is_unchecked_but_inheritance_still_applies(self):
        data = fixture()
        obj = next(o for o in data["object_versions"] if o["id"] == "P:v1")
        obj["origin_kind"] = "derived"
        obj["parents"]["value"] = ["S:v1"]
        result = run(data)
        self.assertEqual(result.analysis_status, "partial")
        self.assertTrue(any(i.get("rule_id") == "SS004" for i in result.unsupported_items))
        self.assertTrue(any(r["authorization"] == "denied" for r in results_for(result, "publish_p_main")))

    def test_opaque_authority_scope_qualifies_path_and_survives_reporting(self):
        data = fixture()
        capability = next(c["id"] for c in data["authorization"]["capabilities"] if "publish_s_main" in c["id"])
        data["context"]["unsupported_items"] = [{"id": "opaque-authority", "reason": "External authority behavior",
             "affected_refs": {"state": "known", "value": [{"collection": "capabilities", "id": capability}], "evidence_refs": []}}]
        result = run(data)
        self.assertEqual(result.analysis_status, "partial")
        self.assertTrue(any(r["conditional"] for r in results_for(result, "publish_s_main")))
        self.assertFalse(any(f["classification"] == "modeled_boundary_violation" for f in result.findings))

    def test_invalid_input_never_enters_analysis(self):
        result = analyze_json('{"context": {"schema_version": "sst.model/0.1", "schema_version": "sst.model/0.1"}}')
        self.assertEqual(result.analysis_status, "input_invalid")
        self.assertFalse(result.analysis_performed)
        self.assertFalse(result.findings)
        self.assertFalse(result.budget_usage)


if __name__ == "__main__":
    unittest.main()
