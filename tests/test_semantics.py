"""Counterexamples for complete authority clauses and inherited restrictions."""
import copy
from dataclasses import replace
from datetime import datetime
import json
from pathlib import Path
import unittest

from structural_safety.analysis_types import Budget, BudgetExceeded, Query, scalar_key
from structural_safety.model import Limits
from structural_safety.semantics import Evaluator


EXAMPLE = Path(__file__).parents[1] / "src/structural_safety/examples/A.json"


def fact(value):
    return {"state": "known", "value": value, "evidence_refs": []}


def unknown(reason="not supplied"):
    return {"state": "unknown", "reason": reason, "evidence_refs": []}


class AuthorizationTests(unittest.TestCase):
    def setUp(self):
        self.doc = json.loads(EXAMPLE.read_text(encoding="utf-8"))

    def evaluator(self, **limits):
        return Evaluator(self.doc, Budget(Limits(**limits)))

    def query(self, action_id="publish_s_main"):
        action = next(item for item in self.doc["actions"] if item["id"] == action_id)
        output = action["outputs"][0]
        return Query(action["task_id"], action["actor_id"], output["object_version_id"],
                     action["operation_id"], action["interface_id"], output["location_node_id"],
                     action["purpose_id"], action["effect_time"]["value"], action["workflow_id"])

    def grant_private(self):
        grant = copy.deepcopy(next(item for item in self.doc["authorization"]["capabilities"]
                                   if item["id"] == "cap:publish_s_main"))
        grant["id"] = "grant:publish_s_main"
        grant["approval_refs"] = fact(["approval:owner-task"])
        self.doc["authorization"]["task_grants"].append(grant)
        return grant

    def release(self, restriction_ids=("restriction:S-v1",)):
        cap = next(item for item in self.doc["authorization"]["capabilities"]
                   if item["id"] == "cap:publish_s_main")
        release = {key: copy.deepcopy(cap[key]) for key in
                   ("issuer", "clauses", "validity", "revocation", "evidence_refs")}
        release.update(id="release:test", restriction_ids=fact(list(restriction_ids)),
                       approval_refs=fact(["approval:owner-release"]))
        self.doc["authorization"]["release_exceptions"].append(release)
        return release

    def set_complete(self, collection, value):
        item = next(item for item in self.doc["context"]["completeness"]
                    if item["collection"] == collection)
        item["complete"] = fact(value)

    def test_technical_capability_does_not_supply_task_or_source_authority(self):
        evaluator = self.evaluator()
        self.assertIs(evaluator.capability(self.query()).value, True)
        self.assertIs(evaluator.authorization(self.query()).value, False)
        self.assertIs(evaluator.authorization(self.query("read_s")).value, True)
        self.assertIs(evaluator.authorization(self.query("publish_p_main")).value, True)

    def test_fields_from_different_grant_clauses_cannot_be_spliced(self):
        query = self.query("publish_p_main")
        template = copy.deepcopy(self.doc["authorization"]["task_grants"][-1])
        template["clauses"][0]["objects"] = fact(["S:v1"])
        other = copy.deepcopy(template)
        other["id"] = "grant:other"
        other["clauses"][0]["objects"] = fact(["P:v1"])
        other["clauses"][0]["recipients"] = fact(["result:internal"])
        self.doc["authorization"]["task_grants"] = [template, other]
        self.assertIs(self.evaluator().authorization(query).value, False)

    def test_missing_grant_inventory_is_unknown_not_denial(self):
        self.doc["authorization"]["task_grants"] = []
        self.set_complete("task_grants", False)
        self.assertIsNone(self.evaluator().authorization(self.query("publish_p_main")).value)

    def test_expired_grant_does_not_poison_an_independent_valid_grant(self):
        query = self.query("publish_p_main")
        grant = copy.deepcopy(self.doc["authorization"]["task_grants"][-1])
        grant["id"] = "grant:expired"
        grant["validity"]["value"]["expires_at"] = query.effect_time
        self.doc["authorization"]["task_grants"].append(grant)
        self.assertIs(self.evaluator().authorization(query).value, True)
        self.doc["authorization"]["task_grants"] = [grant]
        self.assertIs(self.evaluator().authorization(query).value, False)

    def test_revocation_effect_time_is_inclusive_and_unknown_order_stays_unknown(self):
        query = self.query("publish_p_main")
        grant = self.doc["authorization"]["task_grants"][-1]
        grant["revocation"] = fact({"revoked": True, "at": query.effect_time})
        self.assertIs(self.evaluator().authorization(query).value, False)
        self.assertIsNone(self.evaluator().authorization(replace(query, effect_time=None)).value)

    def test_release_requires_the_signers_right_and_exact_recipient(self):
        self.grant_private()
        release = self.release()
        self.assertIs(self.evaluator().authorization(self.query()).value, True)
        release["clauses"][0]["recipients"] = fact(["result:internal"])
        self.assertIs(self.evaluator().authorization(self.query()).value, False)
        release["clauses"][0]["recipients"] = fact(["sink:main"])
        release["issuer"] = fact("principal:outsider")
        self.assertIs(self.evaluator().authorization(self.query()).value, False)

    def test_exception_never_supplies_missing_task_grant(self):
        self.release()
        self.assertIs(self.evaluator().authorization(self.query()).value, False)

    def test_unknown_exception_inventory_prevents_premature_restriction_denial(self):
        self.grant_private()
        self.set_complete("release_exceptions", False)
        self.assertIsNone(self.evaluator().authorization(self.query()).value)

    def test_ancestor_restrictions_intersect_and_single_source_release_is_insufficient(self):
        query = self.query("publish_p_main")
        public = next(item for item in self.doc["object_versions"] if item["id"] == "P:v1")
        public["origin_kind"] = "derived"
        public["parents"] = fact(["S:v1", "S:v2"])
        release = self.release()
        grant = self.doc["authorization"]["task_grants"][-1]
        release["clauses"] = copy.deepcopy(grant["clauses"])
        evaluator = self.evaluator()
        self.assertEqual(evaluator.source_details("P:v1", query.task_id).restriction_ids,
                         ("restriction:S-v1", "restriction:S-v2"))
        self.assertIs(evaluator.authorization(query).value, False)
        release["restriction_ids"] = fact(["restriction:S-v1", "restriction:S-v2"])
        self.assertIs(self.evaluator().authorization(query).value, True)

    def test_known_denial_survives_unknown_ancestry(self):
        self.grant_private()
        private = next(item for item in self.doc["object_versions"] if item["id"] == "S:v1")
        private["parents"] = unknown()
        private["parents_complete"] = fact(False)
        result = self.evaluator().authorization(self.query())
        self.assertIs(result.value, False)
        self.assertTrue(any("parent identities" in reason for reason in result.reasons))

    def test_public_unchanged_version_does_not_inherit_unrelated_context_input(self):
        context = next(item for item in self.doc["execution_contexts"] if item["id"] == "ctx:public")
        context["initial_visible_objects"] = fact(["S:v1", "P:v1"])
        evaluator = self.evaluator()
        self.assertEqual(evaluator.source_details("P:v1", "task:demo").ancestor_ids, ("P:v1",))
        self.assertIs(evaluator.authorization(self.query("publish_p_main")).value, True)

    def test_cyclic_source_graph_terminates_preserving_restrictions_and_uncertainty(self):
        objects = {item["id"]: item for item in self.doc["object_versions"]}
        objects["S:v1"]["parents"] = fact(["P:v1"])
        objects["P:v1"]["parents"] = fact(["S:v1"])
        details = self.evaluator().source_details("P:v1", "task:demo")
        self.assertIsNone(details.completeness.value)
        self.assertIn("restriction:S-v1", details.restriction_ids)

    def test_condition_values_keep_booleans_distinct_and_numeric_equivalence(self):
        scope = copy.deepcopy(self.doc["authorization"]["task_grants"][-1]["clauses"][0])
        scope["conditions"] = [{"key": "mode", "operator": "eq", "value": True,
                                 "evidence_refs": []}]
        query = replace(self.query("publish_p_main"), conditions=(("mode", (scalar_key(1),)),))
        self.assertIs(self.evaluator().match_scope(scope, query).value, False)
        scope["conditions"][0]["value"] = 1.0
        self.assertIs(self.evaluator().match_scope(scope, query).value, True)

    def test_conflicting_scope_is_unknown_even_when_one_candidate_matches(self):
        grant = self.doc["authorization"]["task_grants"][-1]
        grant["clauses"][0]["recipients"] = {
            "state": "conflict", "candidates": [
                {"value": ["sink:main"], "evidence_refs": []},
                {"value": ["result:internal"], "evidence_refs": []}], "evidence_refs": []}
        self.assertIsNone(self.evaluator().authorization(self.query("publish_p_main")).value)

    def test_no_credential_interface_can_operate_without_a_grant(self):
        self.doc["authorization"]["capabilities"] = []
        interface = next(item for item in self.doc["context"]["interfaces"]
                         if item["id"] == "if:publish")
        interface["credential_required"] = fact(False)
        self.assertIs(self.evaluator().capability(self.query()).value, True)

    def test_clause_budget_is_shared_and_checked_before_the_next_match(self):
        evaluator = self.evaluator(max_clause_checks=1)
        clause = self.doc["authorization"]["task_grants"][-1]["clauses"][0]
        self.assertIs(evaluator.match_scope(clause, self.query("publish_p_main")).value, True)
        with self.assertRaises(BudgetExceeded):
            evaluator.match_scope(clause, self.query("publish_p_main"))
        self.assertEqual(evaluator.budget.usage["clause_checks"], 1)

    def test_unknown_effect_time_cannot_precede_its_only_capability_window(self):
        query = replace(self.query("read_s"), effect_time=None)
        capability = next(item for item in self.doc["authorization"]["capabilities"]
                          if item["id"] == "cap:read_s")
        capability["validity"]["value"]["not_before"] = "2000-01-01T00:00:40Z"
        start = datetime.fromisoformat("2000-01-01T00:00:00+00:00")
        end = datetime.fromisoformat("2000-01-01T00:00:30+00:00")
        decision, earliest = self.evaluator().capability_window(query, start, end)
        self.assertIs(decision.value, False)
        self.assertIsNone(earliest)
        decision, earliest = self.evaluator().capability_window(query, start, None)
        self.assertIs(decision.value, True)
        self.assertEqual(earliest.isoformat(), "2000-01-01T00:00:40+00:00")
        self.assertIsNone(query.effect_time)

    def test_time_window_uses_alternative_capabilities_and_exact_open_boundaries(self):
        query = replace(self.query("read_s"), effect_time=None)
        capability = next(item for item in self.doc["authorization"]["capabilities"]
                          if item["id"] == "cap:read_s")
        capability["validity"]["value"]["not_before"] = "2000-01-01T00:00:40Z"
        alternate = copy.deepcopy(capability)
        alternate["id"] = "cap:early"
        alternate["validity"]["value"] = {"not_before": "2000-01-01T00:00:20Z",
                                           "expires_at": "2000-01-01T00:00:30Z"}
        self.doc["authorization"]["capabilities"].append(alternate)
        start = datetime.fromisoformat("2000-01-01T00:00:00+00:00")
        twenty = datetime.fromisoformat("2000-01-01T00:00:20+00:00")
        thirty = datetime.fromisoformat("2000-01-01T00:00:30+00:00")
        decision, earliest = self.evaluator().capability_window(query, start, twenty)
        self.assertIs(decision.value, True)
        self.assertEqual(earliest, twenty)
        self.assertIs(self.evaluator().capability_in_window(query, start, twenty, True).value, False)
        self.assertIs(self.evaluator().capability_in_window(query, thirty, thirty).value, False)
        alternate["revocation"] = fact({"revoked": True, "at": "2000-01-01T00:00:20Z"})
        self.assertIs(self.evaluator().capability_in_window(query, start, thirty).value, False)

    def test_time_window_unknowns_stay_possible_without_erasing_known_impossibility(self):
        query = replace(self.query("read_s"), effect_time=None)
        capability = next(item for item in self.doc["authorization"]["capabilities"]
                          if item["id"] == "cap:read_s")
        start = datetime.fromisoformat("2000-01-01T00:00:00+00:00")
        end = datetime.fromisoformat("2000-01-01T00:00:30+00:00")
        capability["validity"] = unknown()
        decision, earliest = self.evaluator().capability_window(query, start, end)
        self.assertIsNone(decision.value)
        self.assertEqual(earliest, start)
        capability["revocation"] = fact({"revoked": True, "at": "2000-01-01T00:00:00Z"})
        self.assertIs(self.evaluator().capability_in_window(query, start, end).value, False)
        self.set_complete("capabilities", False)
        self.assertIsNone(self.evaluator().capability_in_window(query, start, end).value)
        self.doc["context"]["interfaces"][0]["credential_required"] = fact(False)
        self.assertIs(self.evaluator().capability_in_window(query, start, end).value, True)


if __name__ == "__main__":
    unittest.main()
