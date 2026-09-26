"""Direct effects and faults in the independent fixed local A/B driver."""

import base64
from dataclasses import replace
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from structural_safety import experiment_runtime as runtime


PRIVATE = b"SST_PRIVATE_V1_TOKEN_7C91\n"
PUBLIC = b"SST_PUBLIC_V1_NOTICE\n"


def payloads(observation, target="sink:main"):
    return [base64.b64decode(item["payload_base64"]) for item in observation["targets"][target]["records"]]


class ExperimentRuntimeTests(unittest.TestCase):
    def execute(self, case="B"):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        directory = Path(temporary.name)
        return runtime.execute_case(case, directory), directory

    def test_a_writes_exact_private_and_public_records_in_order(self):
        result, directory = self.execute("A")
        self.assertEqual(result["runtime_status"], "completed")
        self.assertEqual(payloads(result["initial_observation"]), [])
        self.assertEqual(payloads(result["observations"][3]), [PRIVATE])
        self.assertEqual(payloads(result["final_observation"]), [PRIVATE, PUBLIC])
        self.assertEqual(payloads(result["final_observation"], "result:internal"), [PRIVATE])
        expected = b"".join(struct.pack(">I", len(value)) + value for value in (PRIVATE, PUBLIC))
        self.assertEqual((directory / "main.records").read_bytes(), expected)
        self.assertFalse(any(step["control"]["invoked"] for step in result["steps"]))
        self.assertEqual(len(result["observations"]), 6)
        self.assertTrue(all(set(item["targets"]) == {"result:internal", "sink:main"} for item in result["observations"]))

    def test_b_attempts_same_requests_and_continues_public_after_denial(self):
        a, _ = self.execute("A")
        b, _ = self.execute("B")
        self.assertEqual([s["request"] for s in a["steps"]], [s["request"] for s in b["steps"]])
        self.assertTrue(all(s["attempted"] for s in b["steps"]))
        self.assertEqual([s["returned"]["status"] for s in b["steps"]], ["success", "success", "denied", "success", "success"])
        control = b["steps"][2]["control"]
        self.assertTrue(control["invoked"])
        self.assertEqual(control["authorization"], "denied")
        self.assertEqual(control["reasons"], ["no_matching_task_grant", "source_restriction_no_release"])
        self.assertEqual(payloads(b["observations"][3]), [])
        self.assertEqual(payloads(b["final_observation"]), [PUBLIC])
        self.assertEqual(payloads(b["final_observation"], "result:internal"), [PRIVATE])
        self.assertEqual(b["runtime_status"], "completed")

    def test_full_request_scope_and_time_are_checked(self):
        request = runtime._REQUESTS[4]
        self.assertEqual(runtime._authorization(request, PUBLIC), ("allowed", []))
        changes = {"task": "task:other", "actor": "actor:other", "object_version": "S:v1",
                   "operation": "read", "interface": "if:other", "recipient": "sink:other",
                   "purpose": "external_demo", "workflow": "workflow:restricted",
                   "context": "ctx:restricted", "virtual_seconds": 120}
        for field, value in changes.items():
            with self.subTest(field=field):
                self.assertNotEqual(runtime._authorization(replace(request, **{field: value}), PUBLIC)[0], "allowed")
        for second in (0, 119):
            self.assertEqual(runtime._authorization(replace(request, virtual_seconds=second), PUBLIC)[0], "allowed")
        self.assertEqual(runtime._authorization(replace(request, virtual_seconds=-1), PUBLIC)[0], "denied")

    def test_caller_public_label_cannot_reclassify_private_or_partial_bytes(self):
        request = runtime._REQUESTS[4]
        for payload in (PRIVATE, PUBLIC[:-1], b"prefix" + PUBLIC, b"public " + PRIVATE):
            with self.subTest(payload=payload):
                self.assertEqual(runtime._authorization(request, payload), ("unresolved", ["canonical_object_mismatch"]))

    def test_task_permission_does_not_remove_source_restriction(self):
        request = runtime._REQUESTS[2]
        with patch.object(runtime, "_TASK_GRANTS", runtime._CAPABILITIES):
            self.assertEqual(runtime._authorization(request, PRIVATE), ("denied", ["source_restriction_no_release"]))

    def test_public_source_without_task_grant_is_denied(self):
        with patch.object(runtime, "_TASK_GRANTS", frozenset()):
            self.assertEqual(runtime._authorization(runtime._REQUESTS[4], PUBLIC), ("denied", ["no_matching_task_grant"]))

    def test_corrupt_initial_source_skips_only_success_dependents(self):
        prepare = runtime._Runtime._prepare
        def corrupt(driver):
            prepare(driver)
            (driver.run_dir / "private-v1.bin").write_bytes(PUBLIC)
        with patch.object(runtime._Runtime, "_prepare", corrupt):
            result, _ = self.execute()
        self.assertEqual(result["runtime_status"], "incomplete")
        self.assertEqual(result["steps"][0]["returned"]["reason"], "canonical_object_mismatch")
        self.assertEqual([step["attempted"] for step in result["steps"]], [True, False, False, True, True])
        self.assertEqual(payloads(result["final_observation"]), [PUBLIC])

    def test_disabled_tools_do_not_fabricate_normal_task_results(self):
        with patch.object(runtime, "_CAPABILITIES", frozenset()):
            result, _ = self.execute()
        self.assertEqual(result["runtime_status"], "incomplete")
        self.assertEqual(payloads(result["final_observation"]), [])
        self.assertEqual(payloads(result["final_observation"], "result:internal"), [])
        self.assertEqual(result["steps"][0]["returned"]["reason"], "technical_capability_absent")

    def test_skipped_fixed_request_is_incomplete(self):
        submit = runtime._Runtime._submit
        def skip(driver, request, step):
            if request.action_id == "publish_s_main":
                step["attempted"] = False
                return {"status": "skipped", "reason": "injected_skipped_request"}
            return submit(driver, request, step)
        with patch.object(runtime._Runtime, "_submit", skip):
            result, _ = self.execute()
        self.assertEqual(result["runtime_status"], "incomplete")
        self.assertEqual(payloads(result["final_observation"]), [PUBLIC])

    def test_observer_retains_write_even_when_control_reports_denial(self):
        gate = runtime._Runtime._gate
        def broken_gate(driver, request, payload, control):
            permitted = gate(driver, request, payload, control)
            if not permitted:
                driver._append(request.recipient, payload)
            return permitted
        with patch.object(runtime._Runtime, "_gate", broken_gate):
            result, _ = self.execute()
        self.assertEqual(result["steps"][2]["returned"]["status"], "denied")
        self.assertEqual(payloads(result["steps"][2]["after"]), [PRIVATE])
        self.assertEqual(payloads(result["steps"][2]["before"]), [])
        self.assertEqual(payloads(result["final_observation"]), [PRIVATE, PUBLIC])

    def test_late_write_error_preserves_prior_observed_private_effect(self):
        append = runtime._Runtime._append
        def fail_public(driver, target, payload):
            if payload == PUBLIC:
                raise OSError("injected full disk")
            append(driver, target, payload)
        with patch.object(runtime._Runtime, "_append", fail_public):
            result, _ = self.execute("A")
        self.assertEqual(result["runtime_status"], "error")
        self.assertEqual(payloads(result["observations"][3]), [PRIVATE])
        self.assertEqual(payloads(result["final_observation"]), [PRIVATE])
        self.assertEqual(result["steps"][4]["returned"]["status"], "error")
        self.assertEqual(result["environment_errors"][0]["action_id"], "publish_p_main")

    def test_failed_final_target_read_keeps_other_targets_and_prior_observations(self):
        read = runtime._Runtime._read_target
        counts = {"sink:main": 0}
        def fail_final(driver, target):
            if target == "sink:main":
                counts[target] += 1
                if counts[target] == 6:
                    raise OSError("injected observer failure")
            return read(driver, target)
        with patch.object(runtime._Runtime, "_read_target", fail_final):
            result, _ = self.execute("A")
        self.assertEqual(result["runtime_status"], "error")
        self.assertEqual(result["final_observation"]["targets"]["sink:main"]["status"], "error")
        self.assertEqual(payloads(result["final_observation"], "result:internal"), [PRIVATE])
        self.assertEqual(payloads(result["observations"][3]), [PRIVATE])

    def test_policy_is_read_and_unknown_policy_refuses_before_write(self):
        prepare = runtime._Runtime._prepare
        def changed_policy(driver):
            prepare(driver)
            driver.policy_path.write_text("unrecognized", encoding="utf-8")
        with patch.object(runtime._Runtime, "_prepare", changed_policy):
            result, _ = self.execute()
        self.assertEqual(result["policy_initial"]["value"], "unrecognized")
        self.assertEqual(result["policy_final"]["value"], "unrecognized")
        self.assertEqual(result["steps"][2]["control"]["authorization"], "unresolved")
        self.assertEqual(payloads(result["final_observation"]), [])

    def test_policy_read_error_fails_closed_and_later_public_task_continues(self):
        read = runtime._Runtime._read_policy
        calls = []
        def fail_gate(driver):
            calls.append(None)
            if len(calls) == 4:
                raise OSError("injected gate policy read failure")
            return read(driver)
        with patch.object(runtime._Runtime, "_read_policy", fail_gate):
            result, _ = self.execute()
        self.assertEqual(result["runtime_status"], "error")
        self.assertEqual(result["steps"][2]["returned"]["status"], "error")
        self.assertEqual(result["steps"][2]["control"]["decision"], "deny")
        self.assertEqual(payloads(result["observations"][3]), [])
        self.assertEqual(payloads(result["final_observation"]), [PUBLIC])

    def test_unexpected_programming_error_is_not_relabelled_as_environment(self):
        with patch.object(runtime._Runtime, "_submit", side_effect=TypeError("bug")):
            with self.assertRaisesRegex(TypeError, "bug"):
                self.execute()

    def test_reused_directory_cannot_append_new_effects(self):
        _, directory = self.execute("A")
        original = (directory / "main.records").read_bytes()
        result = runtime.execute_case("B", directory)
        self.assertEqual(result["runtime_status"], "error")
        self.assertFalse(any(step["attempted"] for step in result["steps"]))
        self.assertEqual((directory / "main.records").read_bytes(), original)

    def test_observer_keeps_unknown_records_and_truncated_bytes(self):
        append = runtime._Runtime._append
        def corrupt(driver, target, payload):
            append(driver, target, b"unexpected")
            with driver.target_paths[target].open("ab") as stream:
                stream.write(b"\x00\x00\x00")
        with patch.object(runtime._Runtime, "_append", corrupt):
            result, _ = self.execute("A")
        target = result["observations"][2]["targets"]["result:internal"]
        self.assertIsNone(target["records"][0]["object_version"])
        self.assertEqual(target["parse_error"], "truncated_record_header")
        self.assertTrue(base64.b64decode(target["raw_base64"]).endswith(b"\x00\x00\x00"))

    def test_real_record_time_does_not_replace_fixed_virtual_time(self):
        result, _ = self.execute()
        self.assertEqual([step["request"]["virtual_seconds"] for step in result["steps"]], [10, 15, 30, 45, 50])
        self.assertEqual(result["steps"][2]["request"]["effect_time"], "2000-01-01T00:00:30Z")
        self.assertNotEqual(result["steps"][2]["recorded_at_start"], result["steps"][2]["request"]["effect_time"])
        self.assertTrue(all(item["policy"]["value"] == "policy:strict" for item in result["observations"]))


if __name__ == "__main__":
    unittest.main()
