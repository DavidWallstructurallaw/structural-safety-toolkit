"""Controls must distinguish modeled refusal, policy isolation and observation."""

from copy import deepcopy
from importlib.resources import files
import json
import unittest

from structural_safety.analysis_types import Budget, Decision, Query, scalar_key
from structural_safety.controls import Controller
from structural_safety.model import Limits
from structural_safety.semantics import Evaluator
from structural_safety.validation import validate_json


def document(case="B"):
    return json.loads(files("structural_safety").joinpath("examples", case + ".json").read_text())


def known(value):
    return {"state": "known", "value": value, "evidence_refs": []}


def unknown(reason="Not established"):
    return {"state": "unknown", "reason": reason, "evidence_refs": []}


def query(data, action_id="publish_s_main", **changes):
    action = next(x for x in data["actions"] if x["id"] == action_id)
    output = action["outputs"][0]
    values = {key: action[key] for key in ("task_id", "actor_id", "operation_id", "interface_id", "purpose_id", "workflow_id")}
    values.update(object_version_id=output["object_version_id"], recipient_id=output["location_node_id"],
                  effect_time=action["effect_time"]["value"])
    values.update(changes)
    return Query(**values)


def controller(data):
    result = validate_json(json.dumps(data))
    if result.validation_status != "valid":
        raise AssertionError(result.diagnostics)
    return Controller(data, Evaluator(data, Budget(Limits())))


class ControlTests(unittest.TestCase):
    def test_ab_current_gate_and_public_task(self):
        a, b = document("A"), document("B")
        self.assertEqual(controller(a).evaluate(query(a)).status, "not_blocked_in_model")
        self.assertEqual(controller(b).evaluate(query(b)).status, "blocked_in_model")
        self.assertEqual(controller(b).evaluate(query(b, "publish_p_main")).status, "not_blocked_in_model")
        self.assertEqual(controller(b).evaluate(query(b, "read_s")).status, "not_blocked_in_model")

    def test_missing_control_inventory_cannot_prove_passage(self):
        data = document("A")
        for item in data["context"]["completeness"]:
            if item["collection"] == "controls":
                item["complete"] = known(False)
        self.assertEqual(controller(data).evaluate(query(data)).status, "unresolved")

    def test_current_known_refusal_survives_unknown_independence(self):
        data = document()
        data["controls"][0]["modification_paths_complete"] = unknown()
        value = controller(data)
        self.assertEqual(value.evaluate(query(data)).status, "blocked_in_model")
        obligation = value.obligations()[0]
        self.assertEqual(obligation["independence"]["status"], "unresolved")
        self.assertEqual(obligation["obligation_status"], "gap")
        self.assertTrue(obligation["has_unresolved"])
        self.assertIn("policy_modification_paths_incomplete", obligation["unresolved_reasons"])

    def test_conflicting_modification_claim_survives_known_evidence_gap(self):
        data = document()
        data["controls"][0]["modifiable_fields"] = {"state": "conflict", "candidates": [
            {"value": [], "evidence_refs": []}, {"value": ["binding"], "evidence_refs": []}], "evidence_refs": []}
        value = controller(data)
        self.assertEqual(value.evaluate(query(data)).status, "blocked_in_model")
        obligation = value.obligations()[0]
        self.assertTrue(obligation["has_unresolved"])
        self.assertIn("modifiable_fields_conflict", obligation["unresolved_reasons"])
        self.assertEqual(obligation["task_ids"], ("task:demo",))

    def test_contract_gap_retains_separate_unknown_criterion(self):
        data = document()
        policy = data["controls"][0]["policy_versions"][0]
        policy["binding"] = known("unbound")
        policy["decision_mode"] = unknown()
        obligation = controller(data).obligations()[0]
        self.assertEqual(obligation["model_contract"]["status"], "gap")
        self.assertTrue(obligation["has_unresolved"])
        self.assertIn("decision_mode_unknown", obligation["unresolved_reasons"])

    def test_comment_changes_preserve_modeled_independence(self):
        data = document()
        data["controls"][0]["modifiable_fields"] = known(["comment"])
        self.assertEqual(controller(data).obligations()[0]["independence"]["status"], "met")
        data["controls"][0]["modifiable_fields"] = known(["binding"])
        self.assertEqual(controller(data).obligations()[0]["independence"]["status"], "unresolved")
        self.assertEqual(controller(data).evaluate(query(data)).status, "blocked_in_model")

    def test_binding_and_actual_parameter_gaps_do_not_invent_passage(self):
        for name, value in (("binding", "unbound"), ("checked_parameters", ["task", "actor"])):
            with self.subTest(name=name):
                data = document()
                data["controls"][0]["policy_versions"][0][name] = known(value)
                result = controller(data)
                self.assertEqual(result.evaluate(query(data)).status, "unresolved")
                self.assertEqual(result.obligations()[0]["model_contract"]["status"], "gap")

    def test_after_effect_gate_cannot_prevent_this_effect(self):
        data = document()
        policy = data["controls"][0]["policy_versions"][0]
        policy["timing"] = known("after_effect")
        policy["decision_mode"] = unknown()
        self.assertEqual(controller(data).evaluate(query(data)).status, "not_blocked_in_model")

    def test_unknown_policy_does_not_borrow_known_failure_behavior(self):
        for field in ("initial_policy", "decision_mode"):
            with self.subTest(field=field):
                data = document()
                target = data["controls"][0] if field == "initial_policy" else data["controls"][0]["policy_versions"][0]
                target[field] = unknown()
                self.assertEqual(controller(data).evaluate(query(data)).status, "unresolved")

    def test_conflicting_initial_policy_never_selects_strict(self):
        data = document()
        control = data["controls"][0]
        other = deepcopy(control["policy_versions"][0])
        other["id"] = "weak"
        other["coverage"] = known([])
        control["policy_versions"].append(other)
        control["initial_policy"] = {"state": "conflict", "candidates": [
            {"value": "policy:strict", "evidence_refs": []}, {"value": "weak", "evidence_refs": []}], "evidence_refs": []}
        self.assertEqual(controller(data).evaluate(query(data)).status, "unresolved")

    def test_failure_policy_applies_to_unknown_authorization(self):
        for behavior, status in (("deny", "blocked_in_model"), ("pause", "blocked_in_model"), ("allow", "not_blocked_in_model")):
            with self.subTest(behavior=behavior):
                data = document()
                data["controls"][0]["policy_versions"][0]["failure_behavior"] = known(behavior)
                self.assertEqual(controller(data).evaluate(query(data), Decision(None)).status, status)

    def test_full_coverage_clauses_cannot_be_spliced(self):
        data = document()
        policy = data["controls"][0]["policy_versions"][0]
        first = deepcopy(policy["coverage"]["value"][0])
        second = deepcopy(first)
        first["objects"] = known(["S:v1"])
        first["recipients"] = known(["result:internal"])
        second["objects"] = known(["P:v1"])
        second["recipients"] = known(["sink:main"])
        policy["coverage"] = known([first, second])
        self.assertEqual(controller(data).evaluate(query(data)).status, "not_blocked_in_model")

    def test_expired_condition_scope_is_inapplicable(self):
        data = document()
        clause = data["controls"][0]["policy_versions"][0]["coverage"]["value"][0]
        clause["conditions"] = [{"key": "policy_window", "operator": "eq", "value": "active", "evidence_refs": []}]
        q = query(data, conditions=(("policy_window", (scalar_key("expired"),)),))
        self.assertEqual(controller(data).evaluate(q).status, "not_blocked_in_model")
        self.assertEqual(controller(data).evaluate(query(data)).status, "unresolved")

    def test_finite_deny_table_is_independent_of_task_authorization(self):
        data = document()
        policy = data["controls"][0]["policy_versions"][0]
        policy["decision_mode"] = known("deny_table")
        denied = deepcopy(policy["coverage"]["value"][0])
        denied["objects"] = known(["S:v1"])
        policy["deny_clauses"] = known([denied])
        self.assertEqual(controller(data).evaluate(query(data), Decision(True)).status, "blocked_in_model")
        self.assertEqual(controller(data).evaluate(query(data, "publish_p_main"), Decision(False)).status, "not_blocked_in_model")

    def test_unknown_gate_cannot_erase_independent_known_block(self):
        data = document()
        second = deepcopy(data["controls"][0])
        second["id"] = "other-gate"
        second["initial_policy"] = unknown()
        data["controls"].append(second)
        self.assertEqual(controller(data).evaluate(query(data)).status, "blocked_in_model")

    def test_declaration_gap_deduplicated_across_query_paths(self):
        data = document()
        value = controller(data)
        for action in data["actions"]:
            value.evaluate(query(data, action["id"]))
        obligations = value.obligations()
        self.assertEqual(len(obligations), 1)
        obligation = obligations[0]
        self.assertEqual(obligation["control_assurance"], "declaration_only")
        self.assertEqual(obligation["model_contract"]["status"], "satisfied_in_model")
        self.assertEqual(obligation["obligation_status"], "gap")
        self.assertEqual(obligation["runtime_status"], "not_tested")

    def test_imported_observation_remains_scoped_report(self):
        data = document()
        evidence = data["evidence"][0]
        evidence["acquisition"] = "runtime_observation"
        evidence["scope"] = [{"collection": "controls", "id": "gate:main"},
                             {"collection": "properties", "id": "P-CONF-01"}]
        obligation = controller(data).obligations()[0]
        self.assertEqual(obligation["control_assurance"], "scoped_evidence")
        self.assertEqual(obligation["runtime_status"], "not_tested")
        self.assertEqual(obligation["evidence_applicability"][0]["evidence_basis"], "external_report")
        evidence["snapshot_id"] = "older-snapshot"
        obligation = controller(data).obligations()[0]
        self.assertEqual(obligation["control_assurance"], "unresolved")
        self.assertEqual(obligation["evidence_applicability"][0]["applicability"], "configuration_changed")

    def test_expired_evidence_does_not_erase_declared_current_refusal(self):
        data = document()
        evidence = data["evidence"][0]
        evidence["acquisition"] = "external_report"
        evidence["scope"] = [{"collection": "controls", "id": "gate:main"},
                             {"collection": "properties", "id": "P-CONF-01"}]
        evidence["applicability"] = "expired"
        value = controller(data)
        self.assertEqual(value.obligations()[0]["control_assurance"], "unresolved")
        self.assertEqual(value.evaluate(query(data)).status, "blocked_in_model")


if __name__ == "__main__":
    unittest.main()
