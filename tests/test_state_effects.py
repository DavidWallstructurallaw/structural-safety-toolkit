"""Direct state-effect checks: lineage, exact storage, authority, and time."""

from copy import deepcopy
from dataclasses import replace
from importlib.resources import files
import json
import unittest

from structural_safety import Limits, validate_json
from structural_safety.analysis_types import Budget
from structural_safety.controls import Controller, ControlDecision
from structural_safety.search import explore
from structural_safety.semantics import Evaluator


def fact(value):
    return {"state": "known", "value": value, "evidence_refs": []}


def unknown():
    return {"state": "unknown", "reason": "Not established", "evidence_refs": []}


def fixture(case="A"):
    return json.loads(files("structural_safety").joinpath("examples", case + ".json").read_text())


def named(rows, name):
    return next(row for row in rows if row["id"] == name)


def instant(second):
    return fact(f"2000-01-01T00:00:{second:02}Z")


def run(document, controller=None):
    budget = Budget(Limits())
    evaluator = Evaluator(document, budget)
    steps = []
    outcome = explore(document, evaluator, controller or Controller(document, evaluator), budget, steps.append)
    return outcome, steps


def add_operation(document, operation):
    if not any(item["id"] == operation for item in document["context"]["operation_definitions"]):
        document["context"]["operation_definitions"].append(
            {"id": operation, "semantic_kind": operation, "evidence_refs": []})
        named(document["context"]["interfaces"], "if:internal")["operation_ids"].append(operation)


def scope(action, output=None, targets=()):
    result = {field: fact([value]) for field, value in {
        "tasks": action["task_id"], "actors": action["actor_id"],
        "operations": action["operation_id"], "interfaces": action["interface_id"],
        "recipients": output["location_node_id"] if output else "not_applicable",
        "purposes": action["purpose_id"], "workflows": action["workflow_id"],
    }.items()}
    result["objects"] = fact([output["object_version_id"]] if output else [])
    result["conditions"] = []
    if targets:
        result["management_targets"] = fact([{"collection": c, "id": i} for c, i in targets])
    return result


def allow(document, action, *, targets=(), capability=True, grant=True):
    clause = scope(action, action["outputs"][0] if action["outputs"] else None, targets)
    for collection, prefix, enabled in (("capabilities", "cap:", capability),
                                         ("task_grants", "grant:", grant)):
        if enabled:
            record = deepcopy(document["authorization"][collection][0])
            record.update(id=prefix + action["id"], clauses=[deepcopy(clause)])
            document["authorization"][collection].append(record)
    named(document["authorization"]["approval_rights"], "approval:owner-task")["clauses"].append(deepcopy(clause))
    if document["controls"]:
        document["controls"][0]["policy_versions"][0]["coverage"]["value"].append(deepcopy(clause))


def management(document, identifier, kind, target, second, dependencies=()):
    add_operation(document, "delegate" if kind == "activate_authorizations" else kind)
    action = deepcopy(document["actions"][0])
    action.update(id=identifier, operation_id="delegate" if kind == "activate_authorizations" else kind,
                  interface_id="if:internal", inputs=[], outputs=[], success_dependencies=list(dependencies),
                  effect_time=instant(second))
    effect = {"id": "change", "kind": kind}
    if kind == "activate_authorizations":
        effect.update(capability_ids=[i for c, i in target if c == "capabilities"],
                      task_grant_ids=[i for c, i in target if c == "task_grants"])
        targets = tuple(target)
        document["relations"].append({
            "id": "delegation:" + identifier, "kind": "delegation", "action_id": identifier,
            "parent_actor_id": action["actor_id"], "child_actor_id": action["actor_id"],
            "parent_task_id": action["task_id"], "child_task_id": action["task_id"],
            "parent_grant_ids": [], "child_grant_ids": list(effect["task_grant_ids"]),
            "capability_ids": list(effect["capability_ids"]), "extension_approval_refs": fact([]),
            "conditions": [], "evidence_refs": [],
        })
    else:
        effect["authorization_ref" if kind == "revoke" else "target"] = {
            "collection": target[0], "id": target[1]}
        targets = (target,)
    action["effects"] = [effect]
    document["actions"].append(action)
    allow(document, action, targets=targets)
    return action


def memory_document(case="A"):
    document = fixture(case)
    read = named(document["actions"], "read_s")
    document["actions"] = [read]
    for operation in ("derive", "persist_write", "persist_read"):
        add_operation(document, operation)
    derived = deepcopy(named(document["object_versions"], "P:v1"))
    derived.update(id="D:v1", logical_id="D", origin_kind="derived", existence="candidate_produced",
                   initial_locations=[], production={"kind": "candidate_action", "action_id": "derive_s",
                                                     "evidence_refs": []})
    # The declaration omits S. The executed inputs must still supply its restriction.
    document["object_versions"].append(derived)
    action = deepcopy(read)
    action.update(id="derive_s", operation_id="derive", interface_id="if:internal",
                  effect_time=instant(15), success_dependencies=["read_s"])
    action["inputs"][0].update(location_node_id="actor:worker", context_id="ctx:restricted")
    action["outputs"][0]["object_version_id"] = "D:v1"
    action["effects"][0].update(kind="produce", id="produce")
    document["actions"].append(action)
    write = deepcopy(action)
    write.update(id="write_memory", operation_id="persist_write", effect_time=instant(20),
                 success_dependencies=["derive_s"])
    write["inputs"][0]["object_version_id"] = "D:v1"
    write["outputs"][0].update(location_node_id="result:internal", context_id="not_applicable")
    write["effects"][0].update(kind="deliver", id="deliver")
    document["actions"].append(write)
    load = deepcopy(write)
    load.update(id="read_memory", operation_id="persist_read", effect_time=instant(25),
                context_id="ctx:public", workflow_id="workflow:public", success_dependencies=["write_memory"])
    load["inputs"][0].update(location_node_id="result:internal", context_id="not_applicable")
    load["outputs"][0].update(location_node_id="actor:worker", context_id="ctx:public")
    document["actions"].append(load)
    publish = deepcopy(load)
    publish.update(id="publish_derived", operation_id="publish", interface_id="if:publish",
                   purpose_id="external_demo", effect_time=instant(30), success_dependencies=["read_memory"])
    publish["inputs"][0].update(location_node_id="actor:worker", context_id="ctx:public")
    publish["outputs"][0].update(location_node_id="sink:main", context_id="not_applicable")
    document["actions"].append(publish)
    for action in document["actions"][1:]:
        allow(document, action)
    for restriction in document["restrictions"]:
        restriction["applies_to_operations"]["value"].extend(["derive", "persist_write", "persist_read"])
        for action in document["actions"][1:-1]:
            clause = scope(action, action["outputs"][0])
            restriction["allowed_clauses"].append({k: v for k, v in clause.items()
                                                 if k not in ("tasks", "actors", "objects")})
    return document


class StateEffectTests(unittest.TestCase):
    def test_derived_restriction_survives_exact_store_and_explicit_new_context(self):
        for case in ("A", "B"):
            with self.subTest(case=case):
                document = memory_document(case)
                self.assertEqual("valid", validate_json(json.dumps(document)).validation_status)
                outcome, steps = run(document)
                self.assertTrue(outcome.completed)
                rows = [step for step in steps if step["action_id"] == "publish_derived"]
                self.assertTrue(rows)
                self.assertTrue(all(step["authorization"].value is False for step in rows))
                self.assertTrue(all(step["committed"] == (case == "A") for step in rows))
                path = rows[0]["path"]
                self.assertEqual(["read_s", "derive_s", "write_memory", "read_memory", "publish_derived"],
                                 [step["action_id"] for step in path])
                sources = rows[0]["evaluator"].source_details("D:v1", "task:demo")
                self.assertIn("S:v1", sources.ancestor_ids)
                self.assertIn("restriction:S-v1", sources.restriction_ids)
                self.assertIs(sources.completeness.value, True)
                self.assertEqual("ctx:public", path[-2]["output_port"]["context_id"])
                json.dumps(path)

    def test_wrong_store_or_version_cannot_join_memory_chain(self):
        for field, value in (("location_node_id", "sink:main"), ("object_version_id", "S:v2")):
            document = memory_document()
            named(document["actions"], "read_memory")["inputs"][0][field] = value
            outcome, _ = run(document)
            self.assertIn("write_memory", outcome.reached_actions)
            self.assertNotIn("read_memory", outcome.reached_actions)
            self.assertNotIn("publish_derived", outcome.reached_actions)

    def test_blocked_production_does_not_create_an_output_or_success_dependency(self):
        document = memory_document()

        class BlockProducer:
            def evaluate(self, query, authorization=None, policies=None):
                return ControlDecision("blocked_in_model" if query.operation_id == "derive"
                                       else "not_blocked_in_model")

        outcome, steps = run(document, BlockProducer())
        self.assertNotIn("derive_s", outcome.reached_actions)
        self.assertNotIn("write_memory", outcome.reached_actions)
        self.assertTrue(all(not step["committed"] for step in steps if step["action_id"] == "derive_s"))

    def test_strict_gate_checks_actual_lineage_before_direct_derived_output(self):
        document = memory_document("B")
        document["actions"] = document["actions"][:2]
        action = document["actions"][1]
        action["outputs"][0].update(location_node_id="sink:main", context_id="not_applicable")
        # Cover the actual external tuple but deliberately grant no new source exception.
        clause = scope(action, action["outputs"][0])
        for collection, prefix in (("capabilities", "cap:"), ("task_grants", "grant:")):
            named(document["authorization"][collection], prefix + "derive_s")["clauses"] = [deepcopy(clause)]
        named(document["authorization"]["approval_rights"], "approval:owner-task")["clauses"].append(deepcopy(clause))
        document["controls"][0]["policy_versions"][0]["coverage"]["value"].append(clause)
        outcome, steps = run(document)
        rows = [step for step in steps if step["action_id"] == "derive_s"]
        self.assertTrue(rows)
        self.assertTrue(all(step["authorization"].value is False and not step["committed"] for step in rows))
        self.assertNotIn("derive_s", outcome.reached_actions)

    def test_context_sources_apply_to_generation_but_not_unchanged_public_bytes(self):
        document = memory_document()
        production = named(document["actions"], "derive_s")
        production["inputs"][0].update(object_version_id="P:v1", location_node_id="source:public",
                                       context_id="not_applicable")
        _, steps = run(document)
        generation = next(step for step in steps if step["action_id"] == "derive_s")
        self.assertIn("S:v1", generation["visible_sources"])
        self.assertIn("S:v1", generation["source_details"].ancestor_ids)
        self.assertIn("P:v1", generation["source_details"].ancestor_ids)
        ordinary = fixture()
        ordinary["execution_contexts"][1]["initial_visible_objects"] = fact(["S:v1"])
        _, rows = run(ordinary)
        self.assertTrue(all(row["authorization"].value is True for row in rows
                            if row["action_id"] == "publish_p_main"))

    def test_unknown_visibility_retains_known_private_restriction(self):
        document = memory_document()
        document["execution_contexts"][0]["visibility_complete"] = unknown()
        _, steps = run(document)
        generation = next(step for step in steps if step["action_id"] == "derive_s")
        self.assertFalse(generation["visibility_complete"])
        self.assertIsNone(generation["source_details"].completeness.value)
        self.assertIn("restriction:S-v1", generation["source_details"].restriction_ids)
        self.assertTrue(all(row["authorization"].value is False for row in steps
                            if row["action_id"] == "publish_derived"))

    def test_activation_changes_only_explicit_records_and_requires_committed_parent(self):
        for activate_capability in (False, True):
            document = fixture()
            document["actions"] = [named(document["actions"], "read_p")]
            cap = named(document["authorization"]["capabilities"], "cap:read_p")
            grant = named(document["authorization"]["task_grants"], "grant:read_p")
            cap["initially_active"] = grant["initially_active"] = fact(False)
            targets = [("task_grants", "grant:read_p")]
            if activate_capability:
                targets.append(("capabilities", "cap:read_p"))
            action = management(document, "activate", "activate_authorizations", targets, 5)
            document["actions"][0]["success_dependencies"] = [action["id"]]
            self.assertEqual("valid", validate_json(json.dumps(document)).validation_status)
            outcome, steps = run(document)
            reads = [step for step in steps if step["action_id"] == "read_p"]
            self.assertTrue(reads)
            self.assertTrue(all(step["authorization"].value is True for step in reads))
            self.assertTrue(all(step["capability"].value == activate_capability for step in reads))
            self.assertEqual(activate_capability, "read_p" in outcome.reached_actions)

    def test_blocked_activation_cannot_supply_capability_to_a_later_attempt(self):
        document = fixture()
        document["actions"] = [named(document["actions"], "read_p")]
        named(document["authorization"]["capabilities"], "cap:read_p")["initially_active"] = fact(False)
        management(document, "activate", "activate_authorizations", [("capabilities", "cap:read_p")], 5)

        class BlockActivation:
            def evaluate(self, query, authorization=None, policies=None):
                return ControlDecision("blocked_in_model" if query.operation_id == "delegate"
                                       else "not_blocked_in_model")

        outcome, steps = run(document, BlockActivation())
        self.assertNotIn("activate", outcome.reached_actions)
        self.assertNotIn("read_p", outcome.reached_actions)
        self.assertTrue(all(step["capability"].value is False for step in steps if step["action_id"] == "read_p"))
        self.assertTrue(all(not step["path"][-1]["state_changes"]["activated"] for step in steps))

    def test_revocation_at_same_time_blocks_later_capability_and_keeps_earlier_effect(self):
        document = fixture()
        document["actions"] = [named(document["actions"], "read_p"),
                               named(document["actions"], "publish_p_main")]
        document["actions"][0]["effect_time"] = instant(10)
        document["actions"][1]["effect_time"] = instant(20)
        revoke = management(document, "revoke_publish", "revoke", ("capabilities", "cap:publish_p_main"),
                            20, ["read_p"])
        document["actions"][1]["success_dependencies"].append(revoke["id"])
        outcome, steps = run(document)
        self.assertIn("read_p", outcome.reached_actions)
        self.assertIn("revoke_publish", outcome.reached_actions)
        self.assertNotIn("publish_p_main", outcome.reached_actions)
        publishes = [step for step in steps if step["action_id"] == "publish_p_main"]
        self.assertTrue(publishes)
        self.assertTrue(all(step["authorization"].value is True and step["capability"].value is False
                            for step in publishes))

    def test_unknown_revocation_is_conditional_and_does_not_disable_independent_capability(self):
        for independent in (False, True):
            document = fixture()
            document["actions"] = [named(document["actions"], "read_p"),
                                   named(document["actions"], "publish_p_main")]
            document["actions"][0]["effect_time"] = instant(10)
            revoke = management(document, "revoke_publish", "revoke", ("capabilities", "cap:publish_p_main"),
                                20, ["read_p"])
            revoke["effect_time"] = unknown()
            document["actions"][1]["success_dependencies"].append(revoke["id"])
            if independent:
                cap = deepcopy(named(document["authorization"]["capabilities"], "cap:publish_p_main"))
                cap["id"] = "cap:independent"
                document["authorization"]["capabilities"].append(cap)
            _, steps = run(document)
            rows = [step for step in steps if step["action_id"] == "publish_p_main"]
            self.assertTrue(rows)
            self.assertTrue(all(step["conditional"] for step in rows))
            self.assertTrue(all(step["capability"].value is (True if independent else None) for step in rows))

    def test_multiple_revocation_times_keep_unknown_and_known_constraints(self):
        document = fixture()
        _, steps = run(document)
        query = next(step["query"] for step in steps if step["action_id"] == "read_p")
        evaluator = Evaluator(document, Budget(Limits())).with_state(revoked=(
            (("capabilities", "cap:read_p"), "2000-01-01T00:00:50Z"),
            (("capabilities", "cap:read_p"), None),
        ))
        self.assertIsNone(evaluator.capability(query).value)
        self.assertIs(evaluator.capability(replace(query, effect_time="2000-01-01T00:00:50Z")).value, False)

        document["actions"] = [named(document["actions"], "read_p")]
        first = management(document, "revoke_known", "revoke", ("capabilities", "cap:read_p"), 10)
        second = management(document, "revoke_unknown", "revoke", ("capabilities", "cap:read_p"),
                            20, [first["id"]])
        second["effect_time"] = unknown()
        document["actions"][0]["success_dependencies"] = [second["id"]]
        _, steps = run(document)
        rows = [step for step in steps if step["action_id"] == "read_p"]
        self.assertTrue(rows)
        self.assertTrue(all(step["capability"].value is False for step in rows))
        unknown_changes = next(step for step in steps if step["action_id"] == "revoke_unknown")["path"][-1]["state_changes"]["revoked"]
        self.assertIn((("capabilities", "cap:read_p"), None), unknown_changes)

    def test_stops_cover_exact_action_actor_or_interface_without_undoing_earlier_data(self):
        for target in (("actions", "publish_p_main"), ("nodes", "actor:worker"),
                       ("interfaces", "if:publish")):
            document = fixture()
            document["actions"] = [named(document["actions"], "read_p"),
                                   named(document["actions"], "publish_p_main")]
            document["actions"][0]["effect_time"] = instant(10)
            stop = management(document, "stop_now", "stop", target, 20, ["read_p"])
            document["actions"][1]["success_dependencies"].append(stop["id"])
            outcome, steps = run(document)
            self.assertIn("read_p", outcome.reached_actions)
            self.assertIn("stop_now", outcome.reached_actions)
            self.assertNotIn("publish_p_main", outcome.reached_actions)
            self.assertFalse(any(step["action_id"] == "publish_p_main" for step in steps))
            stopped = next(step for step in steps if step["action_id"] == "stop_now")
            self.assertEqual(target, stopped["path"][-1]["state_changes"]["stopped"][0][0])

    def test_post_effect_stop_retains_prior_publication(self):
        document = fixture()
        document["actions"] = [named(document["actions"], "read_p"),
                               named(document["actions"], "publish_p_main")]
        management(document, "late_stop", "stop", ("interfaces", "if:publish"), 55, ["publish_p_main"])
        outcome, steps = run(document)
        self.assertIn("late_stop", outcome.reached_actions)
        row = next(step for step in steps if step["action_id"] == "late_stop")
        self.assertEqual(["read_p", "publish_p_main", "late_stop"], [x["action_id"] for x in row["path"]])
        self.assertEqual("sink:main", row["path"][-2]["output_port"]["location_node_id"])

    def test_unknown_stop_time_does_not_prove_unconditional_suppression_or_execution(self):
        document = fixture()
        document["actions"] = [named(document["actions"], "read_p"),
                               named(document["actions"], "publish_p_main")]
        document["actions"][0]["effect_time"] = instant(10)
        stop = management(document, "stop_time_unknown", "stop", ("interfaces", "if:publish"), 20, ["read_p"])
        stop["effect_time"] = unknown()
        document["actions"][1]["success_dependencies"].append(stop["id"])
        _, steps = run(document)
        rows = [step for step in steps if step["action_id"] == "publish_p_main"]
        self.assertTrue(rows)
        self.assertTrue(all(step["technical"].value is None and step["conditional"] for step in rows))
        self.assertTrue(all("stop_time_unresolved:interfaces:if:publish" in step["assumptions"] for step in rows))

    def test_historical_conditional_capability_uses_pre_revocation_state(self):
        document = fixture()
        document["actions"] = [named(document["actions"], "read_p"),
                               named(document["actions"], "publish_p_main")]
        document["actions"][0]["effect_time"] = unknown()
        revoke = management(document, "revoke_read", "revoke", ("capabilities", "cap:read_p"), 20, ["read_p"])
        document["actions"][1]["success_dependencies"].append(revoke["id"])
        outcome, steps = run(document)
        self.assertIn("publish_p_main", outcome.reached_actions)
        publishes = [step for step in steps if step["action_id"] == "publish_p_main"]
        self.assertTrue(publishes)
        self.assertTrue(all(step["conditional"] for step in publishes))
        self.assertEqual(["read_p", "revoke_read", "publish_p_main"],
                         [step["action_id"] for step in publishes[0]["path"]])


if __name__ == "__main__":
    unittest.main()
