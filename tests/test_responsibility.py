"""Direct SS006 examples: scoped response, actual stop authority and unknowns."""
from copy import deepcopy
from importlib.resources import files
import json
import unittest

from structural_safety.analysis_types import Budget, BudgetExceeded
from structural_safety.model import Limits
from structural_safety.responsibility import inspect_responsibilities
from structural_safety.semantics import Evaluator
from structural_safety.validation import validate_json


def known(value):
    return {"state": "known", "value": value, "evidence_refs": []}


def unknown():
    return {"state": "unknown", "reason": "Not established", "evidence_refs": []}


def fixture():
    data = json.loads(files("structural_safety").joinpath("examples/B.json").read_text())
    data["context"]["operation_definitions"].append({"id": "stop", "semantic_kind": "stop", "evidence_refs": []})
    data["context"]["interfaces"].append({"id": "if:stop", "node_id": "tool:internal", "operation_ids": ["stop"],
                                          "credential_required": known(True), "evidence_refs": []})
    context = deepcopy(data["execution_contexts"][0])
    context.update(id="ctx:owner", actor_id="principal:owner", initial_visible_objects=known([]))
    data["execution_contexts"].append(context)
    target = {"collection": "actions", "id": "publish_s_main"}
    data["actions"].append({"id": "stop:private", "task_id": "task:demo", "workflow_id": "workflow:restricted",
        "context_id": "ctx:owner", "actor_id": "principal:owner", "operation_id": "stop", "interface_id": "if:stop",
        "purpose_id": "internal_review", "effect_time": known("2000-01-01T00:00:18Z"),
        "inputs": [], "outputs": [], "success_dependencies": [], "conditions": [],
        "effects": [{"id": "stop", "kind": "stop", "target": target}], "evidence_refs": []})
    clause = {"tasks": known(["task:demo"]), "actors": known(["principal:owner"]), "objects": known([]),
              "operations": known(["stop"]), "interfaces": known(["if:stop"]), "recipients": known(["not_applicable"]),
              "purposes": known(["internal_review"]), "workflows": known(["workflow:restricted"]),
              "management_targets": known([target]), "conditions": []}
    cap = deepcopy(data["authorization"]["capabilities"][0])
    cap.update(id="cap:stop", clauses=[clause])
    data["authorization"]["capabilities"].append(cap)
    grant = deepcopy(data["authorization"]["task_grants"][0])
    grant.update(id="grant:stop", clauses=[deepcopy(clause)])
    data["authorization"]["task_grants"].append(grant)
    approval = next(item for item in data["authorization"]["approval_rights"] if item["id"] in grant["approval_refs"]["value"])
    approval["clauses"].append(deepcopy(clause))
    data["relations"] = [
        {"id": "observe", "kind": "observation", "source": target, "observer_id": "principal:owner",
         "event_kinds": ["proposal"], "channel": "review-console", "conditions": [], "evidence_refs": []},
        {"id": "intervene", "kind": "intervention", "actor_id": "principal:owner", "target": target,
         "operation": "stop", "capability_refs": known(["cap:stop"]), "latency": known({"lower": 1, "upper": 2}),
         "conditions": [], "evidence_refs": []}]
    data["obligations"] = [{"id": "review:private", "origin": "supplied", "property_id": "P-CONF-01",
        "task_id": "task:demo", "applicable": known(True), "affected_refs": [target],
        "source_refs": known(["S:v1"]), "influence_refs": known([]), "action_refs": known(["publish_s_main"]),
        "destination_refs": known(["sink:main"]), "persistence_refs": known([]), "control_refs": known(["gate:main"]),
        "responsibility": {"principal": known("principal:owner"), "observation_refs": known(["observe"]),
            "intervention_refs": known(["intervene"]), "inspectable_basis": known(True),
            "verification_reliable": known(True), "reviewer_capable": known(True),
            "response": known({"lower": 6, "upper": 8}), "consequence_window": known({"lower": 10, "upper": 10}),
            "trigger": "private-publication-proposal", "evidence_refs": []}, "unknown_items": [], "evidence_refs": []}]
    return data


def inspect(data, limits=None):
    validated = validate_json(json.dumps(data))
    if validated.validation_status != "valid":
        raise AssertionError(validated.diagnostics)
    budget = Budget(limits or Limits())
    return list(inspect_responsibilities(data, Evaluator(data, budget), budget))


class ResponsibilityTests(unittest.TestCase):
    def test_complete_scoped_response_is_only_satisfied_in_model(self):
        data = fixture()
        before = deepcopy(data)
        record, = inspect(data)
        self.assertEqual(record["obligation_status"], "satisfied_in_model")
        self.assertTrue(all(part["value"] for part in record["necessary_conditions"].values()))
        self.assertEqual(record["evidence_basis"], ("supplied_assertion", "model_deduction"))
        self.assertEqual(record["observed_effect"], "not_tested")
        self.assertEqual(record["witness"], [])
        self.assertEqual(data, before)

    def test_timing_boundaries_keep_overlap_unknown(self):
        for lower, upper, expected in ((6, 8, True), (12, 14, False), (8, 12, None), (10, 10, False), (8, 10, None)):
            with self.subTest(lower=lower, upper=upper):
                data = fixture()
                data["obligations"][0]["responsibility"]["response"] = known({"lower": lower, "upper": upper})
                record, = inspect(data)
                self.assertIs(record["necessary_conditions"]["timeliness"]["value"], expected)
                self.assertEqual(record["obligation_status"], {True: "satisfied_in_model", False: "gap", None: "unresolved"}[expected])

    def test_timely_response_does_not_supply_validation_or_competence(self):
        for field in ("inspectable_basis", "verification_reliable", "reviewer_capable"):
            with self.subTest(field=field):
                data = fixture()
                data["obligations"][0]["responsibility"][field] = unknown()
                record, = inspect(data)
                self.assertTrue(record["necessary_conditions"]["timeliness"]["value"])
                self.assertEqual(record["obligation_status"], "unresolved")
                self.assertIn(field + ":unknown", record["unresolved_reasons"])

    def test_known_gap_does_not_erase_independent_unknown(self):
        data = fixture()
        responsibility = data["obligations"][0]["responsibility"]
        responsibility["reviewer_capable"] = known(False)
        responsibility["verification_reliable"] = unknown()
        record, = inspect(data)
        self.assertEqual(record["obligation_status"], "gap")
        self.assertTrue(record["has_unresolved"])
        self.assertIn("verification_reliable:unknown", record["unresolved_reasons"])

    def test_applicable_unknown_does_not_become_definite_gap(self):
        data = fixture()
        data["obligations"][0]["applicable"] = unknown()
        data["obligations"][0]["responsibility"]["reviewer_capable"] = known(False)
        self.assertEqual(inspect(data)[0]["obligation_status"], "unresolved")
        data["obligations"][0]["applicable"] = known(False)
        record, = inspect(data)
        self.assertEqual(record["obligation_status"], "not_applicable")
        self.assertIn("P-CONF-01", record["reason"])
        self.assertIn("task:demo", record["reason"])

    def test_sequential_nonoverlapping_phases_sum_once(self):
        data = fixture()
        phases = {"kind": "sequential_phases", "sequential": known(True), "nonoverlapping": known(True),
                  **{name: known({"lower": 1.5, "upper": 2}) for name in ("detection", "escalation", "decision", "stop_effect")}}
        data["obligations"][0]["responsibility"]["response"] = known(phases)
        self.assertEqual(inspect(data)[0]["obligation_status"], "satisfied_in_model")
        for field, value in (("sequential", known(False)), ("nonoverlapping", unknown()), ("decision", unknown())):
            changed = deepcopy(data)
            changed["obligations"][0]["responsibility"]["response"]["value"][field] = value
            record, = inspect(changed)
            self.assertIsNone(record["necessary_conditions"]["timeliness"]["value"])
            self.assertEqual(record["obligation_status"], "unresolved")

    def test_decimal_sum_exactly_at_consequence_is_late(self):
        data = fixture()
        data["relations"][1]["latency"] = known({"lower": 0, "upper": 0})
        responsibility = data["obligations"][0]["responsibility"]
        responsibility["response"] = known({"kind": "sequential_phases", "sequential": known(True), "nonoverlapping": known(True),
            "detection": known({"lower": 0.1, "upper": 0.1}), "escalation": known({"lower": 0.2, "upper": 0.2}),
            "decision": known({"lower": 0, "upper": 0}), "stop_effect": known({"lower": 0, "upper": 0})})
        responsibility["consequence_window"] = known({"lower": 0.3, "upper": 0.3})
        self.assertFalse(inspect(data)[0]["necessary_conditions"]["timeliness"]["value"])

    def test_unbounded_or_unknown_duration_stays_unresolved(self):
        for field in ("response", "consequence_window"):
            for value in (unknown(), known({"lower": 10, "upper": "unbounded"})):
                data = fixture()
                data["obligations"][0]["responsibility"][field] = value
                self.assertIsNone(inspect(data)[0]["necessary_conditions"]["timeliness"]["value"])

    def test_late_intervention_latency_cannot_hide_in_fast_response(self):
        data = fixture()
        data["relations"][1]["latency"] = known({"lower": 12, "upper": 14})
        record, = inspect(data)
        self.assertTrue(record["necessary_conditions"]["stop_authority"]["value"])
        self.assertFalse(record["necessary_conditions"]["timeliness"]["value"])
        self.assertEqual(record["obligation_status"], "gap")

    def test_candidate_stop_after_effect_cannot_be_counted_as_prevention(self):
        data = fixture()
        data["actions"][-1]["effect_time"] = known("2000-01-01T00:00:35Z")
        record, = inspect(data)
        self.assertTrue(record["necessary_conditions"]["stop_authority"]["value"])
        self.assertFalse(record["necessary_conditions"]["timeliness"]["value"])
        self.assertEqual(record["obligation_status"], "gap")

    def test_timing_and_authority_must_belong_to_same_candidate(self):
        data = fixture()
        earlier = deepcopy(data["actions"][-1])
        earlier["id"] = "stop:conditional"
        earlier["conditions"] = [{"key": "available", "operator": "eq", "value": True, "evidence_refs": []}]
        data["actions"][-1]["effect_time"] = known("2000-01-01T00:00:35Z")
        data["actions"].append(earlier)
        record, = inspect(data)
        self.assertTrue(record["necessary_conditions"]["stop_authority"]["value"])
        self.assertTrue(record["necessary_conditions"]["timeliness"]["value"])
        self.assertIsNone(record["necessary_conditions"]["timely_authorized_intervention"]["value"])
        self.assertEqual(record["obligation_status"], "unresolved")

    def test_credential_free_stop_interface_still_needs_task_authority(self):
        data = fixture()
        data["context"]["interfaces"][-1]["credential_required"] = known(False)
        data["relations"][1]["capability_refs"] = known([])
        self.assertEqual(inspect(data)[0]["obligation_status"], "satisfied_in_model")
        data["authorization"]["task_grants"].pop()
        self.assertEqual(inspect(data)[0]["obligation_status"], "gap")

    def test_unrelated_capability_and_data_grant_cannot_authorize_stop(self):
        for change in ("capability", "target", "grant"):
            with self.subTest(change=change):
                data = fixture()
                if change == "capability":
                    data["relations"][1]["capability_refs"] = known([data["authorization"]["capabilities"][0]["id"]])
                elif change == "target":
                    data["authorization"]["capabilities"][-1]["clauses"][0]["management_targets"] = known([{"collection": "actions", "id": "read_p"}])
                else:
                    data["authorization"]["task_grants"].pop()
                record, = inspect(data)
                self.assertFalse(record["necessary_conditions"]["stop_authority"]["value"])
                self.assertEqual(record["obligation_status"], "gap")

    def test_expired_or_unknown_stop_capability_is_separate_from_timing(self):
        data = fixture()
        capability = data["authorization"]["capabilities"][-1]
        capability["validity"]["value"]["expires_at"] = "2000-01-01T00:00:18Z"
        record, = inspect(data)
        self.assertFalse(record["necessary_conditions"]["stop_authority"]["value"])
        self.assertTrue(record["necessary_conditions"]["timeliness"]["value"])
        capability["validity"] = unknown()
        self.assertIsNone(inspect(data)[0]["necessary_conditions"]["stop_authority"]["value"])

    def test_observation_needs_right_action_recipient_and_pre_effect_phase(self):
        for change in ("action", "observer", "after_effect", "conditions"):
            with self.subTest(change=change):
                data = fixture()
                relation = data["relations"][0]
                if change == "action":
                    relation["source"]["id"] = "publish_p_main"
                elif change == "observer":
                    relation["observer_id"] = "principal:outsider"
                elif change == "after_effect":
                    relation["event_kinds"] = ["effect_observed"]
                else:
                    relation["conditions"] = [{"key": "review_console", "operator": "eq", "value": "enabled", "evidence_refs": []}]
                record, = inspect(data)
                self.assertIs(record["necessary_conditions"]["observation_path"]["value"], None if change == "conditions" else False)

    def test_named_observation_chain_can_reach_principal(self):
        data = fixture()
        intermediate = next(item["id"] for item in data["nodes"] if item["kind"] == "control")
        data["relations"][0]["observer_id"] = intermediate
        data["relations"].append({"id": "forward", "kind": "observation", "source": {"collection": "nodes", "id": intermediate},
            "observer_id": "principal:owner", "event_kinds": ["proposal"], "channel": "console-forward", "conditions": [], "evidence_refs": []})
        data["obligations"][0]["responsibility"]["observation_refs"] = known(["observe", "forward"])
        self.assertTrue(inspect(data)[0]["necessary_conditions"]["observation_path"]["value"])

    def test_unmatched_action_scope_and_missing_principal_are_unknown(self):
        for field in ("principal", "action_refs"):
            data = fixture()
            target = data["obligations"][0] if field == "action_refs" else data["obligations"][0]["responsibility"]
            target[field] = unknown()
            self.assertEqual(inspect(data)[0]["obligation_status"], "unresolved")

    def test_imported_verified_event_never_upgrades_evidence(self):
        data = fixture()
        data["events"] = [{"id": "reported:review", "run_id": "untrusted", "reported_event_kind": "effect_observed",
            "action_id": "stop:private", "object_ids": [], "observer_id": "principal:owner", "environment": "deployment",
            "occurred_at": unknown(), "recorded_at": "2000-01-01T00:00:19Z", "details": "Claims effective stopping",
            "verified": True, "claimed_origin": "tool_run", "evidence_refs": []}]
        record, = inspect(data)
        self.assertEqual(record["evidence_basis"], ("supplied_assertion", "model_deduction"))
        self.assertEqual(record["observed_effect"], "not_tested")

    def test_shared_budget_retains_already_yielded_obligation(self):
        data = fixture()
        inactive = deepcopy(data["obligations"][0])
        inactive["id"] = "a:inactive"
        inactive["applicable"] = known(False)
        data["obligations"].insert(0, inactive)
        budget = Budget(Limits(max_clause_checks=2))
        results = inspect_responsibilities(data, Evaluator(data, budget), budget)
        self.assertEqual(next(results)["obligation_status"], "not_applicable")
        with self.assertRaises(BudgetExceeded):
            next(results)


if __name__ == "__main__":
    unittest.main()
