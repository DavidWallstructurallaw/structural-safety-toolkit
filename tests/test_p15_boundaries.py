"""Exact management authority and imported-event evidence boundaries."""

from copy import deepcopy
from dataclasses import replace
import json
import unittest

from structural_safety import analyze_json, validate_json
from structural_safety.analysis_types import Budget, management_query
from structural_safety.model import Limits
from structural_safety.semantics import Evaluator
from test_state_effects import fixture, fact, unknown, named, scope


class ManagementBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.data = fixture()
        self.action = deepcopy(named(self.data["actions"], "publish_p_main"))
        self.action.update(id="manage", operation_id="delegate", inputs=[], outputs=[])
        self.effect = {"kind": "activate_authorizations", "capability_ids": ["cap:publish_p_main"],
                       "task_grant_ids": ["grant:publish_p_main"]}
        self.query = management_query(self.action, self.effect, self.data)
        self.evaluator = Evaluator(self.data, Budget(Limits()))

    def test_activation_requires_the_whole_compound_target_in_one_clause(self):
        complete = scope(self.action, targets=self.query.management_targets)
        self.assertIs(self.evaluator.match_scope(complete, self.query).value, True)
        partial = deepcopy(complete)
        partial["management_targets"]["value"].pop()
        self.assertIs(self.evaluator.match_scope(partial, self.query).value, False)
        other = deepcopy(complete)
        other["management_targets"]["value"].pop(0)
        self.assertIs(self.evaluator._clauses({"clauses": [partial, other]}, self.query).value, False)

    def test_empty_objects_and_other_management_operations_are_not_wildcards(self):
        clause = scope(self.action)
        self.assertIs(self.evaluator.match_scope(clause, self.query).value, False)
        clause["management_targets"] = fact([{"collection": c, "id": i}
                                           for c, i in self.query.management_targets])
        for operation in ("revoke", "stop"):
            self.assertIs(self.evaluator.match_scope(clause, replace(self.query, operation_id=operation)).value, False)
        clause["objects"] = fact(["P:v1"])
        self.assertIs(self.evaluator.match_scope(clause, self.query).value, False)

    def test_target_collection_and_unknown_target_inventory_stay_distinct(self):
        clause = scope(self.action, targets=self.query.management_targets)
        clause["management_targets"]["value"][0]["collection"] = "actions"
        self.assertIs(self.evaluator.match_scope(clause, self.query).value, False)
        clause["management_targets"] = unknown()
        self.assertIsNone(self.evaluator.match_scope(clause, self.query).value)

    def test_unknown_reactivation_cannot_disable_an_initially_active_capability(self):
        from test_semantics import AuthorizationTests
        helper = AuthorizationTests()
        helper.setUp()
        query = helper.query("publish_p_main")
        view = self.evaluator.with_state(activated=((("capabilities", "cap:publish_p_main"), None),))
        self.assertIs(view.capability(query).value, True)
        self.assertIs(self.evaluator.capability(query).value, True)

    def test_known_activation_and_unknown_initial_state_preserve_earlier_uncertainty(self):
        from test_semantics import AuthorizationTests
        helper = AuthorizationTests()
        helper.setUp()
        query = helper.query("publish_p_main")
        named(self.data["authorization"]["capabilities"], "cap:publish_p_main")["initially_active"] = unknown()
        evaluator = Evaluator(self.data, Budget(Limits()))
        view = evaluator.with_state(activated=((("capabilities", "cap:publish_p_main"), "2000-01-01T00:00:50Z"),))
        self.assertIsNone(view.capability(replace(query, effect_time="2000-01-01T00:00:40Z")).value)
        self.assertIs(view.capability(replace(query, effect_time="2000-01-01T00:00:50Z")).value, True)


class EventBoundaryTests(unittest.TestCase):
    def test_event_phases_time_and_object_discrepancies_do_not_mutate_analysis(self):
        data = fixture()
        baseline = analyze_json(json.dumps(data)).to_dict()
        data["events"] = [
            {"id": "event:" + kind, "run_id": "claimed-run", "reported_event_kind": kind,
             "action_id": "publish_s_main", "object_ids": ["P:v1"], "observer_id": "principal:owner",
             "environment": "deployment", "occurred_at": fact("2000-01-01T00:05:00Z"),
             "recorded_at": "2000-01-01T00:06:00Z", "details": "sensitive-untrusted-payload",
             "verified": True, "claimed_origin": "tool_run", "evidence_refs": []}
            for kind in ("proposal", "attempt", "execution", "effect_observed")]
        validation = validate_json(json.dumps(data))
        self.assertEqual(validation.validation_status, "valid", validation.diagnostics)
        result = analyze_json(json.dumps(data)).to_dict()
        self.assertEqual(result["action_results"], baseline["action_results"])
        self.assertEqual(result["findings"], baseline["findings"])
        self.assertEqual(result["coverage"], baseline["coverage"])
        self.assertEqual(len(result["event_reports"]), 4)
        for row in result["event_reports"]:
            self.assertEqual(row["evidence_basis"], ["external_report"])
            self.assertEqual(row["objects_outside_declared_action"], ["P:v1"])
            self.assertEqual(row["observed_effect"], "not_tested")
            self.assertFalse(row["direct_observation"])
            self.assertEqual(row["time_comparison"], "differs_from_declared_time" if
                             row["reported_event_kind"] in ("execution", "effect_observed")
                             else "not_applicable_to_effect_time")
        self.assertNotIn("sensitive-untrusted-payload", json.dumps(result))


if __name__ == "__main__":
    unittest.main()
