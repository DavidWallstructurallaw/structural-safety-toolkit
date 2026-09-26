"""Direct P1-4 semantic boundaries and observed counterexamples."""

import base64
from copy import deepcopy
from dataclasses import replace
from importlib.resources import files
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from structural_safety import Limits, analyze_json, run_demo, validate_json
from structural_safety.analysis_types import Budget, policy_query
from structural_safety.cli import _demo_exit
from structural_safety.controls import Controller
from structural_safety.experiment_cases import CASES, D_CASES, E_CASES, F_CASES
from structural_safety.experiment_runtime import _Runtime
from structural_safety.experiments import compare_runtime
from structural_safety.semantics import Evaluator


PRIVATE = b"SST_PRIVATE_V1_TOKEN_7C91\n"
PUBLIC = b"SST_PUBLIC_V1_NOTICE\n"


def fixture(case="F-open"):
    return json.loads(files("structural_safety").joinpath("examples", case + ".json").read_text())


def named(records, identifier):
    return next(r for r in records if r["id"] == identifier)


def analyze(data, **kwargs):
    return analyze_json(json.dumps(data), **kwargs).to_dict()


def fact(value):
    return {"state": "known", "value": value, "evidence_refs": []}


def unknown():
    return {"state": "unknown", "reason": "Not established", "evidence_refs": []}


def selector(data):
    action = named(data["actions"], "select_weak")
    return policy_query(action, action["effects"][0], data)


def frames(*payloads):
    return base64.b64encode(b"".join(len(p).to_bytes(4, "big") + p for p in payloads)).decode()


class PolicyTargetTests(unittest.TestCase):
    def test_policy_target_is_exact_and_empty_objects_is_not_a_wildcard(self):
        for mutation in ("none", "absent", "empty", "data", "version", "fields", "unknown"):
            with self.subTest(mutation=mutation):
                data = fixture()
                scope = named(data["authorization"]["capabilities"], "cap:select_weak")["clauses"][0]
                if mutation == "absent":
                    del scope["policy_targets"]
                elif mutation == "empty":
                    scope["policy_targets"] = fact([])
                elif mutation == "data":
                    scope["objects"] = fact(["S:v1"])
                elif mutation == "version":
                    scope["policy_targets"]["value"][0]["policy_version_id"] = "policy:strict"
                elif mutation == "fields":
                    scope["policy_targets"]["value"][0]["fields"] = ["binding"]
                elif mutation == "unknown":
                    scope["policy_targets"] = unknown()
                self.assertEqual(validate_json(json.dumps(data)).validation_status, "valid")
                result = Evaluator(data, Budget(Limits())).capability(selector(data))
                self.assertIs(result.value, True if mutation == "none" else None if mutation == "unknown" else False)

    def test_target_and_field_sets_cannot_be_spliced(self):
        data = fixture()
        scope = named(data["authorization"]["capabilities"], "cap:select_weak")["clauses"][0]
        target = scope["policy_targets"]["value"][0]
        second = deepcopy(target)
        second["fields"] = ["binding"]
        scope["policy_targets"]["value"].append(second)
        query = replace(selector(data), policy_target=("gate:main", "policy:weak", ("binding", "decision_mode")))
        self.assertIs(Evaluator(data, Budget(Limits())).capability(query).value, False)

    def test_policy_reference_must_exist_and_belong_to_control(self):
        for field, value in (("control_id", "gate:missing"), ("policy_version_id", "policy:missing")):
            data = fixture()
            scope = named(data["authorization"]["capabilities"], "cap:select_weak")["clauses"][0]
            scope["policy_targets"]["value"][0][field] = value
            result = validate_json(json.dumps(data))
            self.assertEqual(result.validation_status, "input_invalid")
            self.assertTrue(any("policy_targets" in d.path for d in result.diagnostics))

    def test_management_grant_requires_its_own_approval_scope(self):
        data = fixture()
        query = selector(data)
        scope = deepcopy(named(data["authorization"]["capabilities"], "cap:select_weak")["clauses"][0])
        grant = deepcopy(named(data["authorization"]["task_grants"], "grant:read_s"))
        grant.update(id="grant:select", clauses=[scope])
        data["authorization"]["task_grants"].append(grant)
        self.assertIs(Evaluator(data, Budget(Limits())).authorization(query).value, False)
        named(data["authorization"]["approval_rights"], "approval:owner-task")["clauses"].append(deepcopy(scope))
        self.assertIs(Evaluator(data, Budget(Limits())).authorization(query).value, True)
        data["authorization"]["release_exceptions"] = []
        self.assertIs(Evaluator(data, Budget(Limits())).authorization(query).value, True)

    def test_selection_cannot_change_unnamed_fields_or_immutable_fields(self):
        for mutation in ("binding", "immutable", "unknown"):
            data = fixture()
            if mutation == "binding":
                data["controls"][0]["policy_versions"][1]["binding"] = fact("unbound")
            else:
                data["controls"][0]["modifiable_fields"] = fact([]) if mutation == "immutable" else unknown()
            result = analyze(data)
            selected = [r for r in result["action_results"] if r["action_id"] == "select_weak"]
            self.assertTrue(selected)
            self.assertTrue(all(r["feasibility"] == ("conditional" if mutation == "unknown" else "infeasible") for r in selected))
            self.assertFalse(any(f["classification"] == "modeled_boundary_violation" for f in result["findings"]))

    def test_management_gate_must_check_actual_policy_target(self):
        data = fixture()
        policy = data["controls"][0]["policy_versions"][0]
        clause = deepcopy(named(data["authorization"]["capabilities"], "cap:select_weak")["clauses"][0])
        policy["coverage"]["value"].append(clause)
        value = Controller(data, Evaluator(data, Budget(Limits())))
        self.assertEqual(value.evaluate(selector(data)).status, "unresolved")
        policy["checked_parameters"]["value"].append("policy_target")
        self.assertEqual(validate_json(json.dumps(data)).validation_status, "valid")
        self.assertEqual(value.evaluate(selector(data)).status, "blocked_in_model")

    def test_f_pair_differs_only_by_modification_capability(self):
        opened, locked = fixture("F-open"), fixture("F-locked")
        opened["authorization"]["capabilities"] = [c for c in opened["authorization"]["capabilities"] if c["id"] != "cap:select_weak"]
        self.assertEqual(opened, locked)

    def test_f_witness_requires_committed_selection_and_retains_prior_refusal(self):
        for case in F_CASES:
            result = analyze(fixture(case))
            before = [r for r in result["action_results"] if r["action_id"] == "publish_s_before"]
            self.assertTrue(before)
            self.assertTrue(all(r["control_effect"] == "blocked_in_model" for r in before))
            violations = [f for f in result["findings"] if f["classification"] == "modeled_boundary_violation"]
            self.assertEqual(bool(violations), case == "F-open")
            for finding in violations:
                witness = finding["witness"]
                self.assertEqual(witness[-1]["action_id"], "publish_s_after")
                self.assertTrue(any(s["action_id"] == "select_weak" and s["committed"] for s in witness[:-1]))
            selection = [r for r in result["action_results"] if r["action_id"] == "select_weak"]
            self.assertTrue(all(r["query"]["object_version_id"] is None for r in selection))
            self.assertTrue(all(r["witness"][-1]["output_port"] is None for r in selection))
            self.assertTrue(all(r["authorization"] == "denied" for r in selection))

    def test_sensitive_path_independence_matches_effect_not_just_action(self):
        data = fixture()
        value = Controller(data, Evaluator(data, Budget(Limits())))
        value.search_complete = True
        value.modification_results = [{"action_id": "select_weak", "effect_id": "other-control-effect", "committed": True, "conditional": False},
                                      {"action_id": "select_weak", "effect_id": "select", "committed": False, "conditional": False}]
        self.assertEqual(value.obligations()[0]["independence"]["status"], "met")

    def test_policy_budget_truncation_and_unknown_time_do_not_prove_absence(self):
        result = analyze(fixture(), limits=Limits(max_states=1))
        self.assertEqual(result["analysis_status"], "partial")
        self.assertTrue(result["truncation"])
        self.assertTrue(any(o.get("independence", {}).get("status") == "unresolved" for o in result["obligations"]))
        data = fixture()
        named(data["actions"], "select_weak")["effect_time"] = unknown()
        result = analyze(data)
        self.assertTrue(result["unresolved_items"])
        self.assertFalse(any(f["classification"] == "modeled_boundary_violation" for f in result["findings"]))


class ExtendedDemoTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.all = run_demo("all")
        cls.cases = {c["case_id"]: c for c in cls.all.to_dict()["cases"]}

    def runtime(self, case):
        return deepcopy(self.cases[case]["runtime"])

    def test_all_order_validation_utility_and_evidence(self):
        self.assertEqual(self.all.protocol_verdict, "matched")
        self.assertEqual(_demo_exit(self.all), 0)
        self.assertEqual(tuple(self.cases), CASES)
        for case in CASES:
            with self.subTest(case=case):
                self.assertEqual(validate_json(json.dumps(fixture(case))).validation_status, "valid")
                result = self.cases[case]
                self.assertEqual(result["analysis_comparison"]["verdict"], "matched")
                self.assertTrue(all(f["observed_effect"] == "not_tested" for f in result["analysis"]["findings"]))
                answer = "not_tested" if case in D_CASES else "success"
                self.assertEqual(result["normal_tasks"], {"U-internal": answer, "U-public": answer})

    def test_d_never_executes_runtime_or_claims_utility(self):
        with patch("structural_safety.experiment_runtime.execute_case", side_effect=AssertionError("D must not execute")):
            result = run_demo("D")
        self.assertEqual(_demo_exit(result), 0)
        self.assertEqual(tuple(c["case_id"] for c in result.cases), D_CASES)
        for case in result.cases:
            self.assertEqual(case["runtime_status"], "not_tested")
            self.assertFalse(case["actual_effects"])
            self.assertFalse(case["runtime"]["observations"])
        behavior, declaration, isolation = result.cases
        self.assertTrue(behavior["analysis"]["unresolved_items"])
        self.assertFalse(declaration["analysis"]["unresolved_items"])
        self.assertTrue(isolation["analysis"]["unresolved_items"])

    def test_c_alt_attempt_does_not_depend_on_main_success(self):
        runtime = self.runtime("C")
        self.assertEqual(runtime["steps"][2]["returned"]["status"], "denied")
        self.assertTrue(runtime["steps"][3]["attempted"])
        self.assertEqual(runtime["steps"][3]["returned"]["status"], "success")
        comparison = self.cases["C"]["runtime_comparison"]
        self.assertEqual(comparison["control_evaluation"], "demonstrated_control_bypass")
        self.assertTrue(any(e["target"] == "sink:alt" and e["classification"] == "observed_boundary_violation" for e in comparison["actual_effects"]))

    def test_e_differences_have_precise_refusal_and_task_reasons(self):
        for case in E_CASES:
            step = next(s for s in self.runtime(case)["steps"] if s["action_id"] == "publish_s_main")
            self.assertTrue(step["attempted"])
            self.assertEqual(step["returned"]["status"], "success" if case == "E0" else "denied")
            self.assertEqual(step["control"]["task_authorization"], "denied" if case == "E-task" else "allowed")
            if case == "E-task":
                self.assertEqual(step["control"]["reasons"], ["no_matching_task_grant"])
            if case == "E-unknown":
                self.assertEqual(step["control"]["authorization"], "unresolved")
        lawful = [e for e in self.cases["E0"]["actual_effects"] if e["target"] == "sink:main" and e["object_version"] == "S:v1"]
        self.assertEqual(lawful[0]["classification"], "authorized_effect")

    def test_unexpected_unknown_release_write_is_unresolved_and_contract_failure(self):
        runtime = self.runtime("E-unknown")
        for snapshot in runtime["observations"][2:]:
            snapshot["targets"]["sink:main"]["raw_base64"] = frames(PRIVATE, PUBLIC) if snapshot["sequence"] == 5 else frames(PRIVATE)
        result = compare_runtime("E-unknown", runtime)
        self.assertEqual(result["verdict"], "mismatched")
        effect = next(e for e in result["actual_effects"] if e["target"] == "sink:main" and e["object_version"] == "S:v1")
        self.assertEqual(effect["classification"], "unresolved_effect")
        self.assertEqual(effect["authorization"], "unresolved")
        self.assertTrue(any(c["check"].endswith("control_refusal_no_write") and c["status"] == "mismatched" for c in result["checks"]))

    def test_e_scope_and_half_open_validity_use_observed_request(self):
        for seconds, authorization in ((39, "allowed"), (59, "allowed"), (60, "denied")):
            runtime = self.runtime("E0")
            request = runtime["steps"][1]["request"]
            request.update(virtual_seconds=seconds, effect_time=f"2000-01-01T00:{seconds // 60:02d}:{seconds % 60:02d}Z")
            result = compare_runtime("E0", runtime)
            effect = next(e for e in result["actual_effects"] if e["target"] == "sink:main" and e["object_version"] == "S:v1")
            self.assertEqual(effect["authorization"], authorization)
            self.assertEqual(result["verdict"], "mismatched")

    def test_f_uses_observed_policy_and_attempts_after_failed_selection(self):
        for case in F_CASES:
            runtime = self.runtime(case)
            self.assertTrue(runtime["steps"][4]["attempted"])
            self.assertEqual(runtime["policy_observations"][0]["value"], "policy:strict")
            self.assertEqual(runtime["policy_observations"][1]["value"], "policy:weak" if case == "F-open" else "policy:strict")
            self.assertEqual(runtime["steps"][4]["returned"]["status"], "success" if case == "F-open" else "denied")
            self.assertEqual(len(self.cases[case]["runtime_comparison"]["policy_changes"]), 1 if case == "F-open" else 0)

    def test_claimed_policy_success_without_file_change_cannot_pass(self):
        original = _Runtime._submit
        def lie(runtime, request, step):
            if request.operation == "policy_update":
                return {"status": "success", "reason": "policy_selected", "policy_version": "policy:weak"}
            return original(runtime, request, step)
        with patch.object(_Runtime, "_submit", lie):
            result = run_demo("F-open").to_dict()
        self.assertEqual(result["protocol_verdict"], "mismatched")
        self.assertEqual(result["cases"][0]["policy_after"]["value"], "policy:strict")
        self.assertFalse(result["cases"][0]["runtime_comparison"]["policy_changes"])

    def test_partial_observations_preserve_prior_c_violation(self):
        runtime = self.runtime("C")
        runtime["observations"][-1]["targets"]["sink:alt"]["status"] = "error"
        runtime["environment_errors"] = [{"operation": "observe_target"}]
        runtime["runtime_status"] = "error"
        result = compare_runtime("C", runtime)
        self.assertNotEqual(result["verdict"], "matched")
        self.assertTrue(any(e["classification"] == "observed_boundary_violation" for e in result["actual_effects"]))

    def test_missing_target_or_skipped_attempt_cannot_pass_extended_cases(self):
        for case, index in (("C", 3), ("E0", 1), ("E-unknown", 1), ("F-locked", 4)):
            runtime = self.runtime(case)
            runtime["steps"][index]["attempted"] = False
            self.assertEqual(compare_runtime(case, runtime)["verdict"], "mismatched")
            runtime = self.runtime(case)
            runtime["observations"][1]["targets"].pop("sink:main")
            self.assertNotEqual(compare_runtime(case, runtime)["verdict"], "matched")

    def test_retained_groups_are_fresh_separate_and_self_contained(self):
        with tempfile.TemporaryDirectory() as temp:
            first = run_demo("F", work_dir=Path(temp))
            second = run_demo("F", work_dir=Path(temp))
            self.assertNotEqual(first.run_directory, second.run_directory)
            for result in (first, second):
                root = Path(result.run_directory)
                self.assertEqual(json.loads((root / "report.json").read_text()), result.to_dict())
                for case in F_CASES:
                    self.assertTrue((root / case / "main.records").is_file())
                    self.assertTrue((root / case / "report.json").is_file())

    def test_group_error_continues_and_keeps_previous_and_later_cases(self):
        original = _Runtime._prepare
        def fail_one(runtime):
            if runtime.case == "E-issuer":
                raise OSError("synthetic preparation failure")
            return original(runtime)
        with patch.object(_Runtime, "_prepare", fail_one):
            result = run_demo("E")
        self.assertEqual(_demo_exit(result), 5)
        self.assertEqual(len(result.cases), len(E_CASES))
        self.assertTrue(result.cases[0]["actual_effects"])
        self.assertEqual(result.cases[-1]["runtime_status"], "completed")

    def test_cli_all_and_d_expected_unknown_exit_zero_and_partial_exit_three(self):
        for case, extra, code in (("all", [], 0), ("D", [], 0), ("D", ["--max-states", "1"], 3)):
            completed = subprocess.run([sys.executable, "-m", "structural_safety", "demo", case, *extra], capture_output=True, text=True)
            self.assertEqual(completed.returncode, code, completed.stderr)
            report = json.loads(completed.stdout)
            self.assertEqual(report["protocol_verdict"], "matched" if code == 0 else "inconclusive")

    def test_partial_analysis_does_not_cancel_extended_runtime(self):
        result = run_demo("F-open", limits=Limits(max_states=1)).to_dict()
        self.assertEqual(result["protocol_verdict"], "inconclusive")
        self.assertEqual(result["cases"][0]["runtime_status"], "completed")
        self.assertTrue(result["cases"][0]["runtime_comparison"]["policy_changes"])
