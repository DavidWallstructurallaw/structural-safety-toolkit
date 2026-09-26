"""Joint acceptance regressions for authority changes and SS003 reporting."""

from copy import deepcopy
import json
import unittest

from structural_safety import analyze_json, validate_json
from test_delegation import fixture as delegation_fixture, fact
from test_state_effects import allow, fixture, instant, management, unknown


def analyze(document):
    validated = validate_json(json.dumps(document))
    if validated.validation_status != "valid":
        raise AssertionError(validated.diagnostics)
    return analyze_json(json.dumps(document))


def branch_rows(result):
    return [row for row in result.obligations if row["rule_id"] == "SS003" and row["witness"]]


class DelegationStateIntegrationTests(unittest.TestCase):
    def test_revoked_parent_cannot_support_later_activation_or_false_coverage(self):
        document, _, parent, child = delegation_fixture()
        action = document["actions"][0]
        action["effect_time"] = instant(10)
        allow(document, action, targets=[("task_grants", child["id"])])
        revoke = management(document, "revoke_parent", "revoke", ("task_grants", parent["id"]), 5)
        action["success_dependencies"] = [revoke["id"]]
        result = analyze(document)
        self.assertEqual(result.analysis_status, "completed_for_supported_scope")
        initial = [row for row in result.obligations if row["rule_id"] == "SS003" and not row["witness"]]
        self.assertEqual(initial[0]["obligation_status"], "satisfied_in_model")
        rows = branch_rows(result)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["classification"], "modeled_boundary_violation")
        self.assertEqual([step["action_id"] for step in rows[0]["witness"]], ["revoke_parent", "delegate:test"])
        self.assertTrue(rows[0]["witness"][-1]["committed"])
        self.assertEqual(rows[0]["necessary_conditions"]["remaining_from"], "2000-01-01T00:00:10Z")
        self.assertEqual(next(row for row in result.coverage if row["task_id"] == "task:child")["model_coverage"],
                         "violated_in_model")

    def test_initially_active_child_is_rechecked_after_parent_revocation(self):
        document, _, parent, child = delegation_fixture()
        child["initially_active"] = fact(True)
        management(document, "revoke_parent", "revoke", ("task_grants", parent["id"]), 5)
        result = analyze(document)
        rows = branch_rows(result)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["obligation_status"], "gap")
        self.assertEqual([step["action_id"] for step in rows[0]["witness"]], ["revoke_parent"])
        self.assertFalse(any(row["action_id"] == "delegate:test" and row["feasibility"] == "feasible"
                             for row in result.action_results))

    def test_revoking_child_first_leaves_no_future_scope_for_parent_revocation(self):
        document, _, parent, child = delegation_fixture()
        child["initially_active"] = fact(True)
        revoke_child = management(document, "revoke_child", "revoke", ("task_grants", child["id"]), 3)
        management(document, "revoke_parent", "revoke", ("task_grants", parent["id"]), 5,
                   [revoke_child["id"]])
        result = analyze(document)
        rows = branch_rows(result)
        self.assertEqual(len(rows), 2)
        self.assertTrue(all(row["obligation_status"] == "satisfied_in_model" for row in rows))
        self.assertFalse(any(row["rule_id"] == "SS003" for row in result.findings))

    def test_blocked_revocation_has_no_successor_delegation_gap(self):
        document, _, parent, child = delegation_fixture()
        child["initially_active"] = fact(True)
        strict = fixture("B")
        document["controls"] = deepcopy(strict["controls"])
        existing = {row["id"] for row in document["nodes"]}
        document["nodes"].extend(deepcopy(row) for row in strict["nodes"] if row["id"] not in existing)
        revoke = management(document, "revoke_parent", "revoke", ("task_grants", parent["id"]), 5)
        document["authorization"]["task_grants"] = [row for row in document["authorization"]["task_grants"]
                                                     if row["id"] != "grant:" + revoke["id"]]
        document["controls"][0]["policy_versions"][0]["checked_parameters"]["value"].append("management_targets")
        result = analyze(document)
        rows = [row for row in result.action_results if row["action_id"] == revoke["id"]]
        self.assertTrue(rows)
        self.assertTrue(all(row["control_effect"] == "blocked_in_model" for row in rows))
        self.assertEqual(branch_rows(result), [])
        self.assertFalse(any(row["rule_id"] == "SS003" for row in result.findings))

    def test_conditional_revocation_never_establishes_a_definite_branch_violation(self):
        for condition in (False, True):
            with self.subTest(condition=condition):
                document, _, parent, child = delegation_fixture()
                action = document["actions"][0]
                action["effect_time"] = instant(10)
                allow(document, action, targets=[("task_grants", child["id"])])
                revoke = management(document, "revoke_parent", "revoke", ("task_grants", parent["id"]), 5)
                if condition:
                    revoke["conditions"] = [{"key": "revoke_requested", "operator": "eq", "value": True,
                                             "evidence_refs": []}]
                else:
                    revoke["effect_time"] = unknown()
                action["success_dependencies"] = [revoke["id"]]
                result = analyze(document)
                rows = branch_rows(result)
                self.assertTrue(rows)
                self.assertTrue(all(row["obligation_status"] == "unresolved" for row in rows))
                self.assertFalse(any(row["rule_id"] == "SS003" and row["classification"] == "modeled_boundary_violation"
                                     for row in result.findings))

    def test_later_revocation_preserves_the_earlier_activation_check(self):
        document, _, parent, child = delegation_fixture()
        action = document["actions"][0]
        action["effect_time"] = instant(3)
        allow(document, action, targets=[("task_grants", child["id"])])
        management(document, "revoke_parent", "revoke", ("task_grants", parent["id"]), 5, [action["id"]])
        result = analyze(document)
        rows = {row["witness"][-1]["action_id"]: row for row in branch_rows(result)}
        self.assertEqual(rows["delegate:test"]["obligation_status"], "satisfied_in_model")
        self.assertEqual(rows["revoke_parent"]["obligation_status"], "gap")
        self.assertNotEqual(rows["delegate:test"]["obligation_id"], rows["revoke_parent"]["obligation_id"])

    def test_revoked_child_issuer_approval_is_checked_in_branch_state(self):
        document, _, _, child = delegation_fixture()
        child["initially_active"] = fact(True)
        management(document, "revoke_approval", "revoke", ("approval_rights", child["approval_refs"]["value"][0]), 5)
        result = analyze(document)
        rows = branch_rows(result)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["obligation_status"], "gap")
        self.assertEqual(rows[0]["witness"][-1]["action_id"], "revoke_approval")


if __name__ == "__main__":
    unittest.main()
