"""SS003 counterexamples for scope containment and declared child authority."""
import copy
from importlib.resources import files
import json
import unittest

from structural_safety.analysis_types import Budget, BudgetExceeded
from structural_safety import analyze_json
from structural_safety.delegation import delegation_checks, delegation_decision
from structural_safety.model import Limits
from structural_safety.semantics import Evaluator


def fact(value):
    return {"state": "known", "value": value, "evidence_refs": []}


def unknown():
    return {"state": "unknown", "reason": "Not supplied", "evidence_refs": []}


def condition(key, *values):
    return {"key": key, "operator": "in", "value": list(values), "evidence_refs": []}


def fixture():
    doc = json.loads(files("structural_safety").joinpath("examples", "A.json").read_text())
    parent = copy.deepcopy(doc["authorization"]["task_grants"][1])
    child = copy.deepcopy(parent)
    child["id"] = "grant:child"
    child["initially_active"] = fact(False)
    child["clauses"][0]["tasks"] = fact(["task:child"])
    child["clauses"][0]["actors"] = fact(["actor:child"])
    doc["authorization"]["task_grants"] = [parent, child]
    owner = doc["authorization"]["approval_rights"][0]
    owner["clauses"][0]["tasks"]["value"].append("task:child")
    owner["clauses"][0]["actors"]["value"].append("actor:child")
    child_task = copy.deepcopy(doc["context"]["tasks"][0])
    child_task.update(id="task:child", parent_task=fact("task:demo"))
    doc["context"]["tasks"].append(child_task)
    actor = copy.deepcopy(next(item for item in doc["nodes"] if item["id"] == "actor:worker"))
    actor["id"] = "actor:child"
    doc["nodes"].append(actor)
    for row in tuple(doc["context"]["completeness"]):
        doc["context"]["completeness"].append(dict(copy.deepcopy(row), task_id="task:child"))
    relation = {"id": "delegation:test", "kind": "delegation", "parent_actor_id": "actor:worker",
                "child_actor_id": "actor:child", "parent_task_id": "task:demo",
                "child_task_id": "task:child", "action_id": "delegate:test",
                "parent_grant_ids": [parent["id"]], "child_grant_ids": [child["id"]],
                "capability_ids": [], "extension_approval_refs": fact([]),
                "conditions": [], "evidence_refs": []}
    action = copy.deepcopy(doc["actions"][1])
    action.update(id="delegate:test", operation_id="delegate", inputs=[], outputs=[],
                  success_dependencies=[], effects=[{"kind": "activate_authorizations", "id": "activate",
                                                       "task_grant_ids": [child["id"]], "capability_ids": []}])
    doc["context"]["operation_definitions"].append(
        {"id": "delegate", "semantic_kind": "delegate", "evidence_refs": []})
    next(item for item in doc["context"]["interfaces"] if item["id"] == action["interface_id"])["operation_ids"].append("delegate")
    doc["actions"] = [action]
    doc["relations"] = [relation]
    return doc, relation, parent, child


class DelegationTests(unittest.TestCase):
    def setUp(self):
        self.doc, self.relation, self.parent, self.child = fixture()

    def decision(self, **limits):
        budget = Budget(Limits(**limits))
        return delegation_decision(self.relation, Evaluator(self.doc, budget), budget)

    def records(self):
        budget = Budget(Limits())
        return list(delegation_checks(self.doc, Evaluator(self.doc, budget), budget))

    def test_legal_explicit_identity_mapping_does_not_grant_credentials(self):
        self.assertIs(self.decision().value, True)
        row = self.records()[0]
        self.assertEqual((row["rule_id"], row["obligation_status"], row["classification"]),
                         ("SS003", "satisfied_in_model", None))
        self.assertEqual(self.relation["capability_ids"], [])
        self.assertFalse(self.child["initially_active"]["value"])

    def test_expanded_inactive_child_is_violation_without_reachable_action(self):
        self.child["clauses"][0]["objects"]["value"].append("S:v2")
        self.doc["authorization"]["capabilities"] = []
        self.assertIs(self.decision().value, False)
        row = self.records()[0]
        self.assertEqual(row["classification"], "modeled_boundary_violation")
        self.assertEqual(row["witness"], [])
        result = analyze_json(json.dumps(self.doc))
        findings = [item for item in result.findings if item["rule_id"] == "SS003"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["classification"], "modeled_boundary_violation")
        self.assertEqual(findings[0]["observed_effect"], "not_tested")

    def test_unknown_parent_scope_or_inventory_retains_unresolved(self):
        self.parent["clauses"][0]["objects"] = unknown()
        self.assertIsNone(self.decision().value)
        self.parent["clauses"][0]["objects"] = fact(["S:v2"])
        for row in self.doc["context"]["completeness"]:
            if row["task_id"] == "task:demo" and row["collection"] == "task_grants":
                row["complete"] = fact(False)
        self.assertIsNone(self.decision().value)

    def test_unknown_child_scope_is_not_empty_authority(self):
        self.child["clauses"][0]["objects"] = unknown()
        self.assertEqual(self.records()[0]["obligation_status"], "unresolved")
        self.child["clauses"][0]["objects"] = fact(["S:v1"])
        self.child["validity"] = unknown()
        self.assertIsNone(self.decision().value)

    def test_unrelated_actor_or_task_cannot_be_substituted(self):
        for field, original in (("actors", "actor:worker"), ("tasks", "task:demo")):
            with self.subTest(field=field):
                self.setUp()
                self.child["clauses"][0][field]["value"].append(original)
                self.assertIs(self.decision().value, False)

    def test_complete_parent_clauses_cannot_be_spliced(self):
        second = copy.deepcopy(self.parent)
        second["id"] = "grant:second-parent"
        second["clauses"][0]["objects"] = fact(["S:v2"])
        second["clauses"][0]["recipients"] = fact(["sink:main"])
        self.doc["authorization"]["task_grants"].append(second)
        self.relation["parent_grant_ids"].append(second["id"])
        self.child["clauses"][0]["objects"] = fact(["S:v1", "S:v2"])
        self.child["clauses"][0]["recipients"] = fact(["result:internal", "sink:main"])
        self.assertIs(self.decision().value, False)
        first_clause = copy.deepcopy(self.child["clauses"][0])
        first_clause["objects"] = fact(["S:v1"])
        first_clause["recipients"] = fact(["result:internal"])
        second_clause = copy.deepcopy(first_clause)
        second_clause["objects"] = fact(["S:v2"])
        second_clause["recipients"] = fact(["sink:main"])
        self.child["clauses"] = [first_clause, second_clause]
        self.assertIs(self.decision().value, True)

    def test_only_parent_grants_named_in_the_relation_supply_coverage(self):
        other = copy.deepcopy(self.parent)
        other["id"] = "grant:unlisted"
        self.parent["clauses"][0]["objects"] = fact(["S:v2"])
        self.doc["authorization"]["task_grants"].append(other)
        self.assertIs(self.decision().value, False)

    def test_extension_requires_explicit_reference_scope_issuer_and_child_approval(self):
        self.child["clauses"][0]["objects"] = fact(["S:v2"])
        self.assertIs(self.decision().value, False)
        self.relation["extension_approval_refs"] = fact(["approval:owner-task"])
        self.assertIs(self.decision().value, True)
        self.child["issuer"] = fact("principal:outsider")
        self.assertIs(self.decision().value, False)
        self.child["issuer"] = fact("principal:owner")
        self.child["approval_refs"] = fact([])
        self.assertIs(self.decision().value, False)

    def test_release_right_cannot_expand_task_grant(self):
        self.child["clauses"][0]["objects"] = fact(["S:v2"])
        self.relation["extension_approval_refs"] = fact(["approval:owner-release"])
        self.assertIs(self.decision().value, False)
        self.relation["extension_approval_refs"] = unknown()
        self.assertIsNone(self.decision().value)

    def test_mapping_does_not_supply_child_issuer_approval(self):
        approval = self.doc["authorization"]["approval_rights"][0]
        approval["clauses"][0]["actors"] = fact(["actor:worker"])
        self.assertIs(self.decision().value, False)

    def test_full_child_time_window_and_half_open_endpoints(self):
        self.parent["validity"]["value"]["expires_at"] = "2000-01-01T00:01:00Z"
        self.assertIs(self.decision().value, False)
        self.child["validity"]["value"]["expires_at"] = "2000-01-01T00:01:00Z"
        self.assertIs(self.decision().value, True)
        self.parent["revocation"] = fact({"revoked": True, "at": "2000-01-01T00:00:59Z"})
        self.assertIs(self.decision().value, False)
        self.child["revocation"] = fact({"revoked": True, "at": "2000-01-01T00:00:59Z"})
        self.assertIs(self.decision().value, True)

    def test_time_coverage_can_use_independent_complete_successive_grants(self):
        later = copy.deepcopy(self.parent)
        later["id"] = "grant:later"
        later["validity"]["value"]["not_before"] = "2000-01-01T00:01:00Z"
        self.parent["validity"]["value"]["expires_at"] = "2000-01-01T00:01:00Z"
        self.doc["authorization"]["task_grants"].append(later)
        self.relation["parent_grant_ids"].append(later["id"])
        self.assertIs(self.decision().value, True)
        later["validity"]["value"]["not_before"] = "2000-01-01T00:01:01Z"
        self.assertIs(self.decision().value, False)

    def test_unbounded_window_rejects_finite_parent_and_approval(self):
        self.child["validity"]["value"]["expires_at"] = "unbounded"
        self.assertIs(self.decision().value, False)
        self.parent["validity"]["value"]["expires_at"] = "unbounded"
        self.doc["authorization"]["approval_rights"][0]["validity"]["value"]["expires_at"] = "unbounded"
        self.assertIs(self.decision().value, True)

    def test_unknown_revocation_is_unresolved_and_independent_parent_can_cover(self):
        self.parent["revocation"] = unknown()
        self.assertIsNone(self.decision().value)
        valid = copy.deepcopy(self.parent)
        valid["id"] = "grant:valid"
        valid["revocation"] = fact({"revoked": False, "at": "not_applicable"})
        self.doc["authorization"]["task_grants"].append(valid)
        self.relation["parent_grant_ids"].append(valid["id"])
        self.assertIs(self.decision().value, True)

    def test_inactive_parent_needs_explicit_activation_possibility(self):
        self.parent["initially_active"] = fact(False)
        self.assertIs(self.decision().value, False)
        self.doc["actions"][0]["effects"][0]["task_grant_ids"].append(self.parent["id"])
        self.assertIsNone(self.decision().value)
        self.parent["clauses"][0]["objects"] = fact(["S:v2"])
        self.assertIs(self.decision().value, False)

    def test_branch_revocation_boundary_limits_full_child_coverage(self):
        budget = Budget(Limits())
        evaluator = Evaluator(self.doc, budget).with_state(
            revoked=[(("task_grants", self.parent["id"]), "2000-01-01T00:01:00Z")])
        self.assertIs(delegation_decision(self.relation, evaluator, budget).value, False)

    def test_condition_union_keeps_complete_clauses_and_unrestricted_domain(self):
        self.parent["clauses"][0]["conditions"] = [condition("mode", "internal")]
        self.assertIs(self.decision().value, False)
        self.child["clauses"][0]["conditions"] = [condition("mode", "internal", "audit")]
        self.assertIs(self.decision().value, False)
        other = copy.deepcopy(self.parent["clauses"][0])
        other["conditions"] = [condition("mode", "audit")]
        self.parent["clauses"].append(other)
        self.assertIs(self.decision().value, True)
        self.child["clauses"][0]["conditions"] = []
        self.assertIs(self.decision().value, False)

    def test_mutually_exclusive_child_conditions_have_no_authority_combinations(self):
        self.child["clauses"][0]["conditions"] = [condition("mode", "internal"), condition("mode", "public")]
        self.parent["clauses"][0]["objects"] = fact(["S:v2"])
        self.assertIs(self.decision().value, True)

    def test_parent_and_child_approval_time_windows_are_checked(self):
        approval = self.doc["authorization"]["approval_rights"][0]
        approval["validity"]["value"]["expires_at"] = "2000-01-01T00:01:00Z"
        self.assertIs(self.decision().value, False)
        approval["validity"] = unknown()
        self.assertIsNone(self.decision().value)

    def test_management_targets_are_checked_as_one_complete_target_set(self):
        target = {"collection": "actions", "id": "read_s"}
        additional = {"collection": "actions", "id": "publish_s_main"}
        for record in (self.parent, self.child, self.doc["authorization"]["approval_rights"][0]):
            record["clauses"][0]["objects"] = fact([])
            record["clauses"][0]["management_targets"] = fact([target, additional])
        self.assertIs(self.decision().value, True)
        self.parent["clauses"][0]["management_targets"] = fact([target])
        other = copy.deepcopy(self.parent["clauses"][0])
        other["management_targets"] = fact([additional])
        self.parent["clauses"].append(other)
        self.assertIs(self.decision().value, False)
        self.parent["clauses"][0]["management_targets"] = unknown()
        self.assertIsNone(self.decision().value)

    def test_policy_fields_and_versions_stay_in_one_parent_target(self):
        target = {"control_id": "gate:main", "policy_version_id": "weak", "fields": ["decision_mode", "coverage"]}
        for record in (self.parent, self.child, self.doc["authorization"]["approval_rights"][0]):
            record["clauses"][0]["objects"] = fact([])
            record["clauses"][0]["policy_targets"] = fact([copy.deepcopy(target)])
        self.assertIs(self.decision().value, True)
        self.parent["clauses"][0]["policy_targets"]["value"][0]["fields"] = ["decision_mode"]
        other = copy.deepcopy(self.parent["clauses"][0])
        other["policy_targets"]["value"][0]["fields"] = ["coverage"]
        self.parent["clauses"].append(other)
        self.assertIs(self.decision().value, False)
        self.parent["clauses"][0]["policy_targets"] = fact([dict(target, policy_version_id="strict")])
        self.assertIs(self.decision().value, False)

    def test_scope_and_clause_budget_exhaustion_is_not_success(self):
        self.child["clauses"][0]["objects"]["value"].append("S:v2")
        with self.assertRaises(BudgetExceeded) as exhausted:
            self.decision(max_scope_combinations=1)
        self.assertEqual(exhausted.exception.resource, "scope_combinations")
        with self.assertRaises(BudgetExceeded) as exhausted:
            self.decision(max_clause_checks=1)
        self.assertEqual(exhausted.exception.resource, "clause_checks")

    def test_budget_retains_already_proved_child_violation(self):
        self.child["clauses"][0]["objects"] = fact(["S:v2", "S:v1"])
        budget = Budget(Limits(max_scope_combinations=1))
        records = delegation_checks(self.doc, Evaluator(self.doc, budget), budget)
        proved = next(records)
        self.assertEqual(proved["classification"], "modeled_boundary_violation")
        self.assertEqual(proved["check_status"], "partial")
        self.assertIn("max_scope_combinations", proved["unresolved_items"])
        with self.assertRaises(BudgetExceeded):
            next(records)
        result = analyze_json(json.dumps(self.doc), limits=Limits(max_scope_combinations=1))
        self.assertEqual(result.analysis_status, "partial")
        findings = [item for item in result.findings if item["rule_id"] == "SS003"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["classification"], "modeled_boundary_violation")
        self.assertEqual(findings[0]["check_status"], "partial")


if __name__ == "__main__":
    unittest.main()
