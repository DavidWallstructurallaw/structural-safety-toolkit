"""Direct semantic counterexamples for source loss and instruction authority."""

import copy
from importlib.resources import files
import json
import unittest

from structural_safety.analysis_types import Budget, BudgetExceeded, Decision, Query, scalar_key
from structural_safety.model import Limits
from structural_safety.semantics import Evaluator
from structural_safety.source_rules import influence_checks, source_check, source_checks


def fact(value):
    return {"state": "known", "value": value, "evidence_refs": []}


def unknown():
    return {"state": "unknown", "reason": "Not established", "evidence_refs": []}


class SourceRuleTests(unittest.TestCase):
    def setUp(self):
        self.doc = json.loads(files("structural_safety").joinpath("examples", "A.json").read_text())

    def evaluator(self, **limits):
        budget = Budget(Limits(**limits))
        return Evaluator(self.doc, budget), budget

    def derived(self, parents=("S:v1",), restrictions=()):
        output = next(obj for obj in self.doc["object_versions"] if obj["id"] == "P:v1")
        output["origin_kind"] = "derived"
        output["parents"] = fact(list(parents))
        output["restriction_ids"] = fact(list(restrictions))
        return output

    def source_rows(self):
        evaluator, budget = self.evaluator()
        return list(source_checks(self.doc, evaluator, budget))

    def influence(self, authority="none", approvals=()):
        obj = next(obj for obj in self.doc["object_versions"] if obj["id"] == "S:v1")
        obj["instruction_authority"].update(status=fact(authority), task_ids=fact(["task:demo"]),
                                           approval_refs=fact(list(approvals)))
        relation = {"id": "influence:private", "kind": "semantic_influence", "source_object_id": "S:v1",
                    "action_id": "publish_s_main", "slot": "recipient", "context_id": "ctx:restricted",
                    "conditions": [], "evidence_refs": []}
        self.doc["relations"].append(relation)
        return relation, obj

    def influence_rows(self, **row_overrides):
        evaluator, budget = self.evaluator()
        row = {"action_id": "publish_s_main", "effect_id": "send", "feasibility": "feasible",
               "authorization": "denied", "control_effect": "not_blocked_in_model", **row_overrides}
        return list(influence_checks(self.doc, evaluator, budget, [row]))

    def test_snapshot_derived_restriction_loss_is_not_a_disclosure_claim(self):
        self.derived()
        row = self.source_rows()[0]
        self.assertEqual(row["rule_id"], "SS004")
        self.assertEqual(row["classification"], "modeled_boundary_violation")
        self.assertEqual(row["necessary_conditions"]["missing_restriction_ids"], ["restriction:S-v1"])
        self.assertEqual(row["observed_effect"], "not_tested")
        self.assertEqual(row["witness"], [])

    def test_candidate_produce_contract_cannot_hide_the_explicit_input(self):
        output = self.derived(parents=())
        output["existence"] = "candidate_produced"
        output["initial_locations"] = []
        output["production"] = {"kind": "candidate_action", "action_id": "derive_private", "evidence_refs": []}
        action = copy.deepcopy(next(a for a in self.doc["actions"] if a["id"] == "publish_s_main"))
        action["id"] = "derive_private"
        action["effects"][0]["kind"] = "produce"
        action["outputs"][0]["object_version_id"] = "P:v1"
        self.doc["actions"].append(action)
        row = self.source_rows()[0]
        self.assertEqual(row["classification"], "modeled_boundary_violation")
        self.assertEqual(row["action_id"], "derive_private")
        self.assertEqual(row["necessary_conditions"]["missing_parents"], ["S:v1"])
        self.assertEqual(row["witness"], [])

    def test_parent_closure_does_not_require_every_ancestor_as_a_direct_parent(self):
        self.derived(parents=("S:v2",), restrictions=("restriction:S-v1", "restriction:S-v2"))
        parent = next(obj for obj in self.doc["object_versions"] if obj["id"] == "S:v2")
        parent["parents"] = fact(["S:v1"])
        parent["restriction_ids"] = fact(["restriction:S-v1", "restriction:S-v2"])
        rows = self.source_rows()
        self.assertTrue(all(row["obligation_status"] == "satisfied_in_model" for row in rows))

    def test_conditional_production_does_not_become_a_definite_violation(self):
        self.derived(parents=())
        evaluator, budget = self.evaluator()
        row = source_check(self.doc, evaluator, budget, "P:v1", "task:demo", ("S:v1", "P:v1"),
                           ("restriction:S-v1",), Decision(True), conditional=True)
        self.assertEqual(row["obligation_status"], "unresolved")
        self.assertEqual(row["classification"], "assurance_gap")
        self.assertEqual(row["witness"], [])
        self.assertEqual(row["observed_effect"], "not_tested")
        self.assertEqual(row["evidence_basis"], ["supplied_assertion", "model_deduction"])

    def test_matching_lineage_and_restrictions_are_satisfied(self):
        self.derived(restrictions=("restriction:S-v1",))
        row = self.source_rows()[0]
        self.assertEqual(row["obligation_status"], "satisfied_in_model")
        self.assertIsNone(row["classification"])

    def test_unknown_parentage_remains_unknown(self):
        output = self.derived(parents=())
        output["parents"] = unknown()
        row = self.source_rows()[0]
        self.assertEqual(row["obligation_status"], "unresolved")
        self.assertEqual(row["classification"], "assurance_gap")

    def test_branch_known_source_survives_unknown_extra_source(self):
        output = self.derived(parents=())
        evaluator, budget = self.evaluator()
        row = source_check(self.doc, evaluator, budget, output["id"], "task:demo", ("S:v1",),
                           ("restriction:S-v1",), Decision(None, ("another source is unknown",)))
        self.assertEqual(row["classification"], "modeled_boundary_violation")
        self.assertEqual(row["necessary_conditions"]["missing_parents"], ["S:v1"])
        self.assertEqual(row["necessary_conditions"]["missing_restriction_ids"], ["restriction:S-v1"])
        self.assertTrue(row["has_unresolved"])
        self.assertIn("another source is unknown", row["unresolved_reasons"])

    def test_incomplete_declaration_is_a_gap_without_false_definite_loss(self):
        output = self.derived(parents=())
        output["parents_complete"] = fact(False)
        output["restrictions_complete"] = unknown()
        evaluator, budget = self.evaluator()
        row = source_check(self.doc, evaluator, budget, "P:v1", "task:demo", ("S:v1",),
                           ("restriction:S-v1",), Decision(True))
        self.assertEqual(row["obligation_status"], "unresolved")

    def test_mere_shared_context_and_read_never_create_influence(self):
        self.doc["execution_contexts"][0]["initial_visible_objects"] = fact(["S:v1", "P:v1"])
        self.assertEqual(self.influence_rows(), [])
        self.assertEqual(self.source_rows(), [])

    def test_explicit_low_authority_influence_does_not_supply_capability_or_prove_adoption(self):
        self.influence()
        row = self.influence_rows(feasibility="infeasible")[0]
        self.assertEqual(row["obligation_status"], "satisfied_in_model")
        self.assertIsNone(row["classification"])
        self.assertFalse(row["necessary_conditions"]["grants_technical_capability"])
        self.assertEqual(row["necessary_conditions"]["influence_adopted"], "not_established")
        row = self.influence_rows()[0]
        self.assertEqual(row["classification"], "assurance_gap")
        self.assertEqual(row["witness"], [])

    def test_explicit_unapproved_instruction_authority_is_a_model_violation(self):
        self.influence(authority="task")
        row = self.influence_rows()[0]
        self.assertEqual(row["classification"], "modeled_boundary_violation")
        self.assertEqual(row["observed_effect"], "not_tested")

    def test_full_scoped_approval_is_legal_and_release_right_cannot_substitute(self):
        _, obj = self.influence(authority="task", approvals=("approval:owner-task",))
        row = self.influence_rows()[0]
        self.assertIsNone(row["classification"])
        obj["instruction_authority"]["approval_refs"] = fact(["approval:owner-release"])
        self.assertEqual(self.influence_rows()[0]["classification"], "modeled_boundary_violation")

    def test_approval_must_bind_source_and_recipient_in_one_clause(self):
        self.influence(authority="task", approvals=("approval:owner-task",))
        approval = next(a for a in self.doc["authorization"]["approval_rights"] if a["id"] == "approval:owner-task")
        template = copy.deepcopy(approval["clauses"][0])
        one, two = copy.deepcopy(template), copy.deepcopy(template)
        one["objects"] = fact(["S:v1"])
        one["recipients"] = fact(["result:internal"])
        two["objects"] = fact(["P:v1"])
        two["recipients"] = fact(["sink:main"])
        approval["clauses"] = [one, two]
        self.assertEqual(self.influence_rows()[0]["classification"], "modeled_boundary_violation")

    def test_unknown_authority_or_approval_never_becomes_legal(self):
        _, obj = self.influence(authority="task")
        obj["instruction_authority"]["approval_refs"] = unknown()
        self.assertEqual(self.influence_rows()[0]["obligation_status"], "unresolved")
        obj["instruction_authority"]["status"] = unknown()
        self.assertEqual(self.influence_rows()[0]["obligation_status"], "unresolved")

    def test_policy_authority_needs_exact_control_and_policy_target(self):
        self.doc = json.loads(files("structural_safety").joinpath("examples", "F-open.json").read_text())
        relation, obj = self.influence(authority="policy", approvals=("approval:owner-task",))
        relation.update(action_id="select_weak", slot="policy")
        obj["instruction_authority"]["control_ids"] = fact(["gate:main"])
        approval = next(item for item in self.doc["authorization"]["approval_rights"]
                        if item["id"] == "approval:owner-task")
        capability = next(item for item in self.doc["authorization"]["capabilities"]
                          if item["id"] == "cap:select_weak")
        approval["clauses"] = copy.deepcopy(capability["clauses"])
        evaluator, budget = self.evaluator()
        row = list(influence_checks(self.doc, evaluator, budget))[0]
        self.assertEqual(row["obligation_status"], "satisfied_in_model")
        approval["clauses"][0]["policy_targets"]["value"][0]["policy_version_id"] = "policy:strict"
        evaluator, budget = self.evaluator()
        self.assertEqual(list(influence_checks(self.doc, evaluator, budget))[0]["classification"],
                         "modeled_boundary_violation")

    def test_branch_revocation_does_not_reuse_initial_authority_approval(self):
        self.influence(authority="task", approvals=("approval:owner-task",))
        evaluator, budget = self.evaluator()
        view = evaluator.with_state(revoked=((('approval_rights', 'approval:owner-task'),
                                              '2000-01-01T00:00:20Z'),))
        row = list(influence_checks(self.doc, view, budget, action_id="publish_s_main"))[0]
        self.assertEqual(row["classification"], "modeled_boundary_violation")
        original = list(influence_checks(self.doc, evaluator, budget, action_id="publish_s_main"))[0]
        self.assertNotEqual(row["identity"], original["identity"])

    def test_static_source_contract_and_conditional_path_keep_separate_identities(self):
        self.derived(parents=())
        evaluator, budget = self.evaluator()
        arguments = (self.doc, evaluator, budget, "P:v1", "task:demo", ("S:v1",),
                     ("restriction:S-v1",), Decision(True))
        declaration = source_check(*arguments, action_id="derive")
        path = source_check(*arguments, action_id="derive", witness=[{"action_id": "derive", "committed": False}],
                            conditional=True)
        self.assertNotEqual(declaration["identity"], path["identity"])
        self.assertEqual(declaration["classification"], "modeled_boundary_violation")
        self.assertEqual(path["classification"], "assurance_gap")

    def test_influence_context_and_mutually_exclusive_conditions_are_exact(self):
        relation, _ = self.influence(authority="task")
        relation["context_id"] = "ctx:public"
        self.assertEqual(self.influence_rows()[0]["obligation_status"], "not_applicable")
        relation["context_id"] = "ctx:restricted"
        relation["conditions"] = [{"key": "mode", "operator": "eq", "value": "outside", "evidence_refs": []}]
        action = next(a for a in self.doc["actions"] if a["id"] == "publish_s_main")
        action["conditions"] = [{"key": "mode", "operator": "eq", "value": "inside", "evidence_refs": []}]
        self.assertEqual(self.influence_rows()[0]["obligation_status"], "not_applicable")
        action["conditions"] = []
        self.assertEqual(self.influence_rows()[0]["obligation_status"], "unresolved")
        evaluator, budget = self.evaluator()
        query = Query("task:demo", "actor:worker", "S:v1", "publish", "if:publish", "sink:main",
                      "external_demo", "2000-01-01T00:00:30Z", "workflow:restricted",
                      conditions=(("mode", (scalar_key("inside"),)),))
        row = list(influence_checks(self.doc, evaluator, budget, query=query,
                                   action_id="publish_s_main"))[0]
        self.assertEqual(row["obligation_status"], "not_applicable")

    def test_snapshot_authority_promotion_is_separate_from_external_release(self):
        output = self.derived(restrictions=("restriction:S-v1",))
        output["instruction_authority"].update(status=fact("task"), task_ids=fact(["task:demo"]))
        self.assertEqual(self.source_rows()[0]["classification"], "modeled_boundary_violation")
        output["instruction_authority"]["approval_refs"] = fact(["approval:owner-task"])
        self.assertEqual(self.source_rows()[0]["obligation_status"], "unresolved")

    def test_direct_checks_share_the_analysis_budget(self):
        self.derived()
        self.influence()
        evaluator, budget = self.evaluator(max_scope_combinations=1)
        self.assertEqual(len(list(source_checks(self.doc, evaluator, budget))), 1)
        with self.assertRaises(BudgetExceeded):
            list(influence_checks(self.doc, evaluator, budget))


if __name__ == "__main__":
    unittest.main()
