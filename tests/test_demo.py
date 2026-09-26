"""Direct experiment acceptance and counterexamples to false acceptance."""

import base64
import copy
from dataclasses import FrozenInstanceError
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from structural_safety import Limits
from structural_safety.experiments import compare_analysis, compare_runtime, run_demo
from structural_safety.experiment_runtime import _Runtime


PRIVATE = b"SST_PRIVATE_V1_TOKEN_7C91\n"
PUBLIC = b"SST_PUBLIC_V1_NOTICE\n"


def raw_records(*payloads):
    return base64.b64encode(b"".join(struct.pack(">I", len(p)) + p for p in payloads)).decode("ascii")


class DemoTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.baselines = {case: run_demo(case).to_dict() for case in ("A", "B")}

    def runtime(self, case="B"):
        return copy.deepcopy(self.baselines[case]["cases"][0]["runtime"])

    def test_ab_model_runtime_utility_and_scoped_assurance(self):
        for case, report in self.baselines.items():
            with self.subTest(case=case):
                self.assertEqual(report["protocol_verdict"], "matched")
                record = report["cases"][0]
                self.assertEqual(record["analysis_comparison"]["verdict"], "matched")
                self.assertEqual(record["runtime_status"], "completed")
                self.assertEqual(record["normal_tasks"], {"U-internal": "success", "U-public": "success"})
                violations = [e for e in record["actual_effects"] if e["classification"] == "observed_boundary_violation"]
                self.assertEqual(bool(violations), case == "A")
                self.assertTrue(all(f["observed_effect"] == "not_tested" for f in record["analysis"]["findings"]))
                if case == "B":
                    self.assertEqual(record["runtime_comparison"]["control_assurance"], "scoped_evidence")
                    self.assertTrue(any(f.get("control_assurance") == "declaration_only" for f in record["analysis"]["findings"]))

    def test_skipped_forbidden_request_cannot_pass_b(self):
        runtime = self.runtime()
        runtime["steps"][2]["attempted"] = False
        runtime["steps"][2]["returned"]["status"] = "skipped"
        runtime["steps"][2]["control"]["invoked"] = False
        runtime["runtime_status"] = "incomplete"
        self.assertEqual(compare_runtime("B", runtime)["verdict"], "mismatched")

    def test_disabled_tools_cannot_pass_b(self):
        with patch("structural_safety.experiment_runtime._CAPABILITIES", frozenset()):
            report = run_demo("B").to_dict()
        self.assertEqual(report["protocol_verdict"], "mismatched")
        self.assertNotEqual(report["cases"][0]["normal_tasks"]["U-public"], "success")

    def test_lying_gate_preserves_actual_violation_and_contract_failure(self):
        runtime = self.runtime()
        for observation in runtime["observations"][3:]:
            payloads = (PRIVATE, PUBLIC) if observation["sequence"] == 5 else (PRIVATE,)
            observation["targets"]["sink:main"]["raw_base64"] = raw_records(*payloads)
        result = compare_runtime("B", runtime)
        self.assertEqual(result["verdict"], "mismatched")
        self.assertTrue(any(e["classification"] == "observed_boundary_violation" for e in result["actual_effects"]))
        self.assertTrue(any(c["check"] == "control_refusal_no_prohibited_write" and c["status"] == "mismatched"
                            for c in result["checks"]))

    def test_exact_bytes_order_count_and_destination_are_required(self):
        for mutation in ("truncated_payload", "extra_record", "wrong_order", "wrong_target", "public_label"):
            with self.subTest(mutation=mutation):
                runtime = self.runtime("A")
                snapshot = runtime["observations"][-1]
                if mutation == "truncated_payload":
                    snapshot["targets"]["sink:main"]["raw_base64"] = raw_records(PRIVATE[:-1], PUBLIC)
                elif mutation == "extra_record":
                    snapshot["targets"]["sink:main"]["raw_base64"] = raw_records(PRIVATE, PUBLIC, PUBLIC)
                elif mutation == "wrong_order":
                    snapshot["targets"]["sink:main"]["raw_base64"] = raw_records(PUBLIC, PRIVATE)
                elif mutation == "wrong_target":
                    snapshot["targets"]["sink:other"] = snapshot["targets"].pop("sink:main")
                else:
                    runtime["steps"][2]["request"]["object_version"] = "P:v1"
                result = compare_runtime("A", runtime)
                self.assertEqual(result["verdict"], "mismatched")

    def test_malformed_external_observation_cannot_claim_absence(self):
        runtime = self.runtime()
        runtime["observations"][3]["targets"]["sink:main"]["raw_base64"] = base64.b64encode(b"\x00").decode()
        result = compare_runtime("B", runtime)
        self.assertEqual(result["verdict"], "mismatched")
        self.assertEqual(result["property_observation"], "unknown")

    def test_missing_observation_is_inconclusive_even_when_return_says_denied(self):
        runtime = self.runtime()
        runtime["observations"][3]["targets"]["sink:main"]["status"] = "error"
        runtime["steps"][2]["after"] = copy.deepcopy(runtime["observations"][3])
        runtime["steps"][3]["before"] = copy.deepcopy(runtime["observations"][3])
        runtime["runtime_status"] = "error"
        runtime["environment_errors"] = [{"error": "observer failed"}]
        result = compare_runtime("B", runtime)
        self.assertEqual(result["verdict"], "inconclusive")
        self.assertEqual(result["control_assurance"], "unresolved")

    def test_skipped_utility_with_existing_bytes_does_not_become_success(self):
        runtime = self.runtime()
        runtime["steps"][4]["attempted"] = False
        runtime["steps"][4]["returned"]["status"] = "skipped"
        result = compare_runtime("B", runtime)
        self.assertEqual(result["normal_tasks"]["U-public"], "not_tested")
        self.assertEqual(result["verdict"], "mismatched")

    def test_full_observed_grant_checked_separately_from_fixed_schedule(self):
        for second, purpose, authorization in ((16, "internal_review", "allowed"),
                                               (120, "internal_review", "denied"),
                                               (15, "external_demo", "denied")):
            with self.subTest(second=second, purpose=purpose):
                runtime = self.runtime()
                request = runtime["steps"][1]["request"]
                request.update(virtual_seconds=second, purpose=purpose,
                               effect_time="2000-01-01T00:02:00Z" if second == 120 else f"2000-01-01T00:00:{second:02d}Z")
                result = compare_runtime("B", runtime)
                effect = next(e for e in result["actual_effects"] if e["target"] == "result:internal")
                self.assertEqual(effect["authorization"], authorization)
                self.assertEqual(result["verdict"], "mismatched")

    def test_late_error_retains_earlier_violation_and_completed_internal_utility(self):
        original = _Runtime._submit
        def fail_public_read(runtime, request, step):
            if request.action_id == "read_p":
                raise OSError("injected late read failure")
            return original(runtime, request, step)
        with patch.object(_Runtime, "_submit", fail_public_read):
            report = run_demo("A").to_dict()
        record = report["cases"][0]
        self.assertEqual(report["demo_status"], "error")
        self.assertEqual(record["runtime_status"], "error")
        self.assertEqual(record["normal_tasks"]["U-internal"], "success")
        self.assertNotEqual(record["normal_tasks"]["U-public"], "success")
        self.assertTrue(any(e["classification"] == "observed_boundary_violation" for e in record["actual_effects"]))

    def test_partial_analysis_executes_entire_driver_and_stays_inconclusive(self):
        report = run_demo("A", limits=Limits(max_states=1)).to_dict()
        record = report["cases"][0]
        self.assertEqual(record["analysis"]["analysis_status"], "partial")
        self.assertEqual(record["runtime_status"], "completed")
        self.assertEqual(len(record["runtime"]["steps"]), 5)
        self.assertEqual(record["runtime_comparison"]["verdict"], "matched")
        self.assertEqual(report["protocol_verdict"], "inconclusive")

    def test_hard_model_budget_rejection_does_not_skip_fixed_driver(self):
        report = run_demo("A", limits=Limits(max_input_bytes=1)).to_dict()
        self.assertEqual(report["demo_status"], "resource_rejected")
        self.assertEqual(report["cases"][0]["runtime_status"], "completed")
        self.assertEqual(report["protocol_verdict"], "inconclusive")

    def test_decisive_model_mismatch_dominates_partial_analysis(self):
        analysis = copy.deepcopy(self.baselines["B"]["cases"][0]["analysis"])
        analysis["analysis_status"] = "partial"
        next(r for r in analysis["action_results"] if r["action_id"] == "publish_s_main")["authorization"] = "allowed"
        self.assertEqual(compare_analysis("B", analysis)["verdict"], "mismatched")

    def test_wrong_witness_destination_fails_analysis_comparison(self):
        analysis = copy.deepcopy(self.baselines["A"]["cases"][0]["analysis"])
        for finding in analysis["findings"]:
            if finding["rule_id"] == "SS001":
                finding["witness"][-1]["output_port"]["location_node_id"] = "result:internal"
        self.assertEqual(compare_analysis("A", analysis)["verdict"], "mismatched")

    def test_reserved_and_invalid_names_do_not_run(self):
        for scenario in ("C", "D", "E", "F", "all", "D-behavior", "E-unknown", "F-open", "unknown", "../A", "a"):
            with self.subTest(scenario=scenario), patch("structural_safety.experiment_runtime.execute_case") as execute:
                result = run_demo(scenario)
                self.assertEqual(result.protocol_verdict, "not_tested")
                self.assertTrue(result.diagnostics)
                self.assertFalse(result.cases)
                execute.assert_not_called()

    def test_retained_runs_are_fresh_and_report_self_contained(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = run_demo("A", work_dir=root)
            second = run_demo("A", work_dir=root)
            self.assertNotEqual(first.run_directory, second.run_directory)
            self.assertTrue((Path(first.run_directory) / "report.json").is_file())
            self.assertTrue((Path(second.run_directory) / "main.records").is_file())
        self.assertEqual(first.cases[0]["normal_tasks"]["U-public"], "success")
        self.assertTrue(first.to_dict()["cases"][0]["runtime"]["observations"])

    def test_deep_immutable_results_and_fresh_serialization(self):
        result = run_demo("A")
        with self.assertRaises(FrozenInstanceError):
            result.scenario = "B"
        with self.assertRaises(TypeError):
            result.cases[0]["normal_tasks"]["U-public"] = "failure"
        mutable = result.to_dict()
        mutable["cases"][0]["runtime"]["observations"].clear()
        self.assertEqual(len(result.to_dict()["cases"][0]["runtime"]["observations"]), 6)

    def test_late_cleanup_failure_preserves_observed_effects(self):
        real = tempfile.TemporaryDirectory()
        class FailingCleanup:
            name = real.name
            def cleanup(self):
                real.cleanup()
                raise OSError("cleanup failed after result")
        with patch("structural_safety.experiments.tempfile.TemporaryDirectory", return_value=FailingCleanup()):
            result = run_demo("A")
        self.assertEqual(result.demo_status, "error")
        self.assertEqual(result.environment_errors[-1]["operation"], "cleanup_run_directory")
        self.assertTrue(any(e["classification"] == "observed_boundary_violation" for e in result.cases[0]["actual_effects"]))

    def test_internal_errors_propagate(self):
        with patch("structural_safety.experiments.analyze_json", side_effect=RuntimeError("broken invariant")):
            with self.assertRaisesRegex(RuntimeError, "broken invariant"):
                run_demo("B")


if __name__ == "__main__":
    unittest.main()
