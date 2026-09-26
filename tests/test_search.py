"""Direct checks for graph joins, branch assumptions, and bounded work."""

import copy
import json
from pathlib import Path
import unittest

from structural_safety.analysis_types import Budget, Decision
from structural_safety.controls import ControlDecision, Controller
from structural_safety.model import Limits
from structural_safety.search import explore
from structural_safety.semantics import Evaluator


EXAMPLES = Path(__file__).parents[1] / "src" / "structural_safety" / "examples"


def fixture(name="A"):
    return json.loads((EXAMPLES / (name + ".json")).read_text(encoding="utf-8"))


def fact(value):
    return {"state": "known", "value": value, "evidence_refs": []}


def unknown():
    return {"state": "unknown", "reason": "not supplied", "evidence_refs": []}


class _Evaluator:
    """Independent always-capable collaborator isolates transition semantics."""

    def capability(self, query):
        return Decision(True)

    def authorization(self, query):
        return Decision(False)

    def capability_window(self, query, lower, upper, upper_exclusive=False):
        return Decision(True), lower


class _Controller:
    def __init__(self, decisions=None):
        self.decisions = decisions or {}

    def evaluate(self, query, authorization=None, policies=None):
        return ControlDecision(self.decisions.get(query.recipient_id, "not_blocked_in_model"))


def run(document, *, controller=None, limits=None, real=False):
    budget = Budget(limits or Limits())
    evaluator = Evaluator(document, budget) if real else _Evaluator()
    controller = controller or (Controller(document, evaluator) if real else _Controller())
    steps = []
    outcome = explore(document, evaluator, controller, budget, steps.append)
    return outcome, steps, budget


class SearchTests(unittest.TestCase):
    def test_a_b_current_control_preserves_technical_authorization_distinctions(self):
        for name, expected in (("A", "not_blocked_in_model"), ("B", "blocked_in_model")):
            with self.subTest(name=name):
                outcome, steps, _ = run(fixture(name), real=True)
                self.assertTrue(outcome.completed)
                private = [step for step in steps if step["action_id"] == "publish_s_main"]
                self.assertTrue(private)
                self.assertTrue(all(step["technical"].value is True for step in private))
                self.assertTrue(all(step["authorization"].value is False for step in private))
                self.assertTrue(all(step["control"].status == expected for step in private))
                self.assertIn("copy_s_internal", outcome.reached_actions)
                self.assertIn("publish_p_main", outcome.reached_actions)
                self.assertEqual(name == "A", "publish_s_main" in outcome.reached_actions)
                self.assertEqual(["read_s", "publish_s_main"],
                                 [item["action_id"] for item in private[0]["path"]])
                self.assertEqual("S:v1", private[0]["path"][-1]["output_port"]["object_version_id"])

    def test_same_actor_context_and_same_logical_object_do_not_join(self):
        for field, value in (("context_id", "ctx:public"), ("object_version_id", "S:v2")):
            with self.subTest(field=field):
                document = fixture()
                publish = next(item for item in document["actions"] if item["id"] == "publish_s_main")
                publish["inputs"][0][field] = value
                if field == "context_id":
                    publish["context_id"] = value
                    publish["workflow_id"] = "workflow:public"
                else:
                    publish["outputs"][0][field] = value
                outcome, steps, _ = run(document)
                self.assertNotIn("publish_s_main", outcome.reached_actions)
                self.assertFalse(any(step["action_id"] == "publish_s_main" for step in steps))

    def test_allowed_public_request_without_capability_is_still_authorized(self):
        document = fixture()
        document["authorization"]["capabilities"] = [record for record in
            document["authorization"]["capabilities"] if record["id"] != "cap:publish_p_main"]
        outcome, steps, _ = run(document, real=True)
        self.assertNotIn("publish_p_main", outcome.reached_actions)
        public = [step for step in steps if step["action_id"] == "publish_p_main"]
        self.assertTrue(public)
        self.assertTrue(all(step["technical"].value is False for step in public))
        self.assertTrue(all(step["authorization"].value is True for step in public))
        self.assertTrue(all(step["committed"] is False for step in public))

    def test_visible_object_does_not_invent_a_held_position(self):
        document = fixture()
        document["actions"] = [item for item in document["actions"] if item["id"] == "publish_s_main"]
        document["actions"][0]["success_dependencies"] = []
        document["execution_contexts"][0]["initial_visible_objects"] = fact(["S:v1"])
        outcome, steps, _ = run(document)
        self.assertEqual((), outcome.reached_actions)
        self.assertEqual([], steps)

    def test_success_dependency_cycle_cannot_start_itself(self):
        document = fixture()
        read = next(item for item in document["actions"] if item["id"] == "read_s")
        read["success_dependencies"] = ["publish_s_main"]
        outcome, steps, _ = run(document)
        self.assertNotIn("read_s", outcome.reached_actions)
        self.assertNotIn("publish_s_main", outcome.reached_actions)
        self.assertIn("publish_p_main", outcome.reached_actions)

    def test_condition_intersections_keep_bool_distinct_from_number(self):
        for before, after in (("internal", "public"), (True, 1)):
            with self.subTest(before=before, after=after):
                document = fixture()
                for action in document["actions"]:
                    if action["id"] in ("read_s", "publish_s_main"):
                        action["conditions"] = [{"key": "mode", "operator": "eq",
                                                 "value": before if action["id"] == "read_s" else after,
                                                 "evidence_refs": []}]
                outcome, _, _ = run(document)
                self.assertIn("read_s", outcome.reached_actions)
                self.assertNotIn("publish_s_main", outcome.reached_actions)

    def test_unknown_and_conflicting_conditions_do_not_become_certain(self):
        for binding in (unknown(), {"state": "conflict", "evidence_refs": [],
                                   "candidates": [{"value": "private", "evidence_refs": []},
                                                  {"value": "public", "evidence_refs": []}]}):
            document = fixture()
            document["context"]["initial_conditions"] = [{"key": "mode", "value": binding}]
            document["actions"][0]["conditions"] = [{"key": "mode", "operator": "eq",
                                                      "value": "private", "evidence_refs": []}]
            _, steps, _ = run(document)
            publishes = [step for step in steps if step["action_id"] == "publish_s_main"]
            self.assertTrue(publishes)
            self.assertTrue(all(step["conditional"] and step["technical"].value is None for step in publishes))

    def test_conditional_control_assumptions_reach_descendants(self):
        document = fixture()
        outcome, steps, _ = run(document, controller=_Controller({"actor:worker": "unresolved"}))
        self.assertIn("publish_s_main", outcome.reached_actions)
        private = [step for step in steps if step["action_id"] == "publish_s_main"]
        self.assertTrue(all(step["technical"].value is None for step in private))
        self.assertTrue(all(any(reason.startswith("control_not_blocking_assumed:read_s:")
                                for reason in step["assumptions"]) for step in private))

    def test_partial_atomic_success_cannot_satisfy_whole_action_dependency(self):
        document = fixture()
        read = next(item for item in document["actions"] if item["id"] == "read_s")
        second = copy.deepcopy(read["outputs"][0])
        second.update(port_id="external", location_node_id="sink:main", context_id="not_applicable")
        read["outputs"].append(second)
        read["effects"].append({"kind": "deliver", "id": "second", "input_port_ids": ["in"],
                                "output_port_id": "external"})
        outcome, steps, _ = run(document, controller=_Controller({"sink:main": "blocked_in_model"}))
        self.assertNotIn("read_s", outcome.reached_actions)
        self.assertNotIn("copy_s_internal", outcome.reached_actions)
        self.assertTrue(any(step["action_id"] == "read_s" and step["effect_id"] == "deliver"
                            and step["committed"] for step in steps))
        self.assertTrue(any(step["action_id"] == "read_s" and step["effect_id"] == "second"
                            and not step["committed"] for step in steps))

    def test_atomic_effect_only_requires_its_own_input_ports(self):
        document = fixture()
        read = document["actions"][0]
        read["inputs"].append({"port_id": "missing", "object_version_id": "S:v2",
                               "location_node_id": "sink:main", "context_id": "not_applicable"})
        read["outputs"].append({"port_id": "second", "object_version_id": "S:v2",
                                "location_node_id": "actor:worker", "context_id": "ctx:restricted"})
        read["effects"].append({"kind": "deliver", "id": "second", "input_port_ids": ["missing"],
                                "output_port_id": "second"})
        outcome, steps, _ = run(document)
        reads = [step for step in steps if step["action_id"] == "read_s"]
        self.assertTrue(reads)
        self.assertTrue(all(step["effect_id"] == "deliver" and step["committed"] for step in reads))
        self.assertNotIn("read_s", outcome.reached_actions)
        self.assertNotIn("copy_s_internal", outcome.reached_actions)

    def test_stops_apply_at_effect_time_and_do_not_undo_prior_outputs(self):
        for second, blocked in ((10, True), (31, False)):
            document = fixture()
            document["context"]["stopped_targets"] = [
                {"target": {"collection": "actions", "id": "publish_s_main"},
                 "effective_at": fact(f"2000-01-01T00:00:{second:02}Z"), "evidence_refs": []}]
            outcome, _, _ = run(document)
            self.assertEqual(not blocked, "publish_s_main" in outcome.reached_actions)

    def test_time_reversal_is_impossible_but_unknown_time_is_conditional(self):
        document = fixture()
        publish = next(item for item in document["actions"] if item["id"] == "publish_s_main")
        publish["effect_time"] = fact("2000-01-01T00:00:05Z")
        outcome, _, _ = run(document)
        self.assertNotIn("publish_s_main", outcome.reached_actions)
        document["actions"][0]["effect_time"] = unknown()
        outcome, steps, _ = run(document)
        self.assertIn("publish_s_main", outcome.reached_actions)
        self.assertTrue(all(step["conditional"] for step in steps if step["action_id"] == "publish_s_main"))
        self.assertTrue(all(step["path"][0]["effect_time"] is None for step in steps
                            if step["action_id"] == "publish_s_main"))

    def test_unknown_time_jointly_respects_capability_and_successor_windows(self):
        document = fixture()
        document["actions"][0]["effect_time"] = unknown()
        cap = document["authorization"]["capabilities"][0]
        cap["validity"]["value"]["not_before"] = "2000-01-01T00:00:40Z"
        outcome, steps, _ = run(document, real=True)
        self.assertIn("read_s", outcome.reached_actions)
        self.assertNotIn("publish_s_main", outcome.reached_actions)
        self.assertFalse(any(step["action_id"] == "publish_s_main" for step in steps))
        alternate = copy.deepcopy(cap)
        alternate["id"] = "cap:early-read"
        alternate["validity"]["value"].update(not_before="2000-01-01T00:00:05Z",
                                                expires_at="2000-01-01T00:00:20Z")
        document["authorization"]["capabilities"].append(alternate)
        outcome, steps, _ = run(document, real=True)
        self.assertIn("publish_s_main", outcome.reached_actions)
        private = next(step for step in steps if step["action_id"] == "publish_s_main")
        self.assertTrue(private["conditional"])
        self.assertIsNone(private["path"][0]["effect_time"])
        window = private["path"][-1]["time_constraints"]["windows"][0]
        self.assertEqual("2000-01-01T00:00:05Z", window["not_before"])
        self.assertEqual("2000-01-01T00:00:30Z", window["not_after"])
        json.dumps(private["path"])

    def test_unknown_predecessor_times_propagate_capability_lower_bounds(self):
        document = fixture()
        document["actions"][0]["effect_time"] = unknown()
        publish = next(action for action in document["actions"] if action["id"] == "publish_s_main")
        publish["effect_time"] = unknown()
        read_cap = document["authorization"]["capabilities"][0]
        read_cap["validity"]["value"]["not_before"] = "2000-01-01T00:00:40Z"
        publish_cap = next(cap for cap in document["authorization"]["capabilities"]
                           if cap["id"] == "cap:publish_s_main")
        publish_cap["validity"]["value"]["expires_at"] = "2000-01-01T00:00:20Z"
        outcome, steps, _ = run(document, real=True)
        self.assertNotIn("publish_s_main", outcome.reached_actions)
        self.assertFalse(any(step["action_id"] == "publish_s_main" for step in steps))

    def test_later_conditions_recheck_previous_conditional_capability(self):
        document = fixture()
        cap = document["authorization"]["capabilities"][0]
        cap["clauses"][0]["conditions"] = [{"key": "mode", "operator": "eq",
                                            "value": "private", "evidence_refs": []}]
        publish = next(action for action in document["actions"] if action["id"] == "publish_s_main")
        publish["conditions"] = [{"key": "mode", "operator": "eq", "value": "public", "evidence_refs": []}]
        outcome, steps, _ = run(document, real=True)
        self.assertIn("read_s", outcome.reached_actions)
        self.assertNotIn("publish_s_main", outcome.reached_actions)
        self.assertFalse(any(step["action_id"] == "publish_s_main" for step in steps))

    def test_later_conditions_recheck_previous_unresolved_control_coverage(self):
        document = fixture("B")
        policy = document["controls"][0]["policy_versions"][0]
        clause = copy.deepcopy(document["authorization"]["capabilities"][0]["clauses"][0])
        clause["conditions"] = [{"key": "mode", "operator": "eq", "value": "public", "evidence_refs": []}]
        policy["coverage"] = fact([clause])
        policy["decision_mode"] = fact("deny_table")
        policy["deny_clauses"] = fact([copy.deepcopy(clause)])
        publish = next(action for action in document["actions"] if action["id"] == "publish_s_main")
        publish["conditions"] = [{"key": "mode", "operator": "eq", "value": "public", "evidence_refs": []}]
        outcome, steps, _ = run(document, real=True)
        self.assertIn("read_s", outcome.reached_actions)
        self.assertNotIn("publish_s_main", outcome.reached_actions)
        self.assertFalse(any(step["action_id"] == "publish_s_main" for step in steps))

    def test_unexecuted_unsupported_effect_is_not_an_identity_transition(self):
        document = fixture()
        document["context"]["operation_definitions"][0]["semantic_kind"] = "persist_read"
        outcome, steps, _ = run(document)
        self.assertEqual(("read_p", "read_s"), outcome.unsupported_actions)
        self.assertEqual((), outcome.reached_actions)
        self.assertEqual([], steps)

    def test_opaque_extension_affecting_a_path_preserves_assumptions(self):
        document = fixture()
        document["context"]["unsupported_items"] = [{"id": "opaque", "reason": "external mechanism",
                                                       "affected_refs": fact([{"collection": "actions", "id": "read_s"}])}]
        _, steps, _ = run(document)
        private = [step for step in steps if step["action_id"] == "publish_s_main"]
        self.assertTrue(all("unsupported_context_assumption:opaque" in step["assumptions"] for step in private))
        public = [step for step in steps if step["action_id"] == "read_p" and len(step["path"]) == 1]
        self.assertTrue(public)
        self.assertTrue(all(not step["conditional"] for step in public))

    def test_opaque_authority_or_inherited_source_extension_is_not_ignored(self):
        for collection, identifier in (("capabilities", "cap:publish_s_main"),
                                       ("restrictions", "restriction:S-v1")):
            document = fixture()
            if collection == "restrictions":
                identifier = document["object_versions"][0]["restriction_ids"]["value"][0]
            document["context"]["unsupported_items"] = [
                {"id": "opaque", "reason": "unmodeled qualification",
                 "affected_refs": fact([{"collection": collection, "id": identifier}])}]
            _, steps, _ = run(document)
            publishes = [step for step in steps if step["action_id"] == "publish_s_main"]
            self.assertTrue(publishes)
            self.assertTrue(all(step["conditional"] for step in publishes))

    def test_state_limit_keeps_the_discovered_step_before_registration(self):
        document = fixture()
        outcome, steps, budget = run(document, limits=Limits(max_states=1))
        self.assertFalse(outcome.completed)
        self.assertEqual("max_states", outcome.truncation_reason)
        self.assertEqual(1, outcome.state_count)
        self.assertEqual(1, len(steps))
        self.assertEqual(1, budget.usage["states"])

    def test_exact_budget_completion_and_atomic_transition_count(self):
        document = fixture()
        document["actions"] = [document["actions"][0]]
        outcome, steps, budget = run(document, limits=Limits(max_states=2, max_transition_checks=2))
        self.assertTrue(outcome.completed)
        self.assertEqual(2, budget.usage["states"])
        self.assertEqual(2, budget.usage["transition_checks"])
        self.assertEqual(1, len(steps))
        document["actions"][0]["effects"].append(
            {"kind": "deliver", "id": "second", "input_port_ids": ["in"], "output_port_id": "out"})
        outcome, steps, budget = run(document, limits=Limits(max_transition_checks=1))
        self.assertFalse(outcome.completed)
        self.assertEqual("max_transition_checks", outcome.truncation_reason)
        self.assertEqual(1, len(steps))
        self.assertEqual(1, budget.usage["transition_checks"])


if __name__ == "__main__":
    unittest.main()
