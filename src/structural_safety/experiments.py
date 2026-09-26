"""Fixed A/B expectations and comparison, independent of control decisions.

This module deliberately maintains its own small expectation table. Neither
the analyzer nor the runtime/control produces the expected bytes or answers.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from importlib.resources import files
import json
from pathlib import Path
import tempfile
from typing import Any

from .analysis import analyze_json
from .demo_model import DemoResult
from .model import Diagnostic, Limits


_PRIVATE = b"SST_PRIVATE_V1_TOKEN_7C91\n"
_PUBLIC = b"SST_PUBLIC_V1_NOTICE\n"
_TARGETS = ("result:internal", "sink:main")
_ROWS = (
    ("read_s", "S:v1", "read", "if:read", "actor:worker", "internal_review", 10, "restricted", _PRIVATE),
    ("copy_s_internal", "S:v1", "transfer", "if:internal", "result:internal", "internal_review", 15, "restricted", _PRIVATE),
    ("publish_s_main", "S:v1", "publish", "if:publish", "sink:main", "external_demo", 30, "restricted", _PRIVATE),
    ("read_p", "P:v1", "read", "if:read", "actor:worker", "public_notice", 45, "public", _PUBLIC),
    ("publish_p_main", "P:v1", "publish", "if:publish", "sink:main", "public_notice", 50, "public", _PUBLIC),
)
_SCOPE = {
    "environment": "local_controlled_simulation",
    "evidence_classes": ["supplied_assertion", "model_deduction", "runtime_observation"],
    "observer_relationship": "same_project",
    "supported_cases": ["A", "B"],
    "external_targets_are_local": True,
    "network_transmission": False,
    "limits": [
        "Fixed synthetic bytes, five synchronous requests and append-only local targets.",
        "Same-project fixture, driver, control and observer can share defects.",
        "No operating-system security isolation or third-party evaluation is claimed.",
        "No claim about arbitrary encodings, summaries, semantic leakage or deployment-wide protection.",
        "Runtime observations do not upgrade the declared model's control assurance or independence.",
    ],
}


def _b64(payload: bytes) -> str:
    return base64.b64encode(payload).decode("ascii")


def _request(row: tuple) -> dict:
    _, obj, operation, interface, recipient, purpose, second, context, payload = row
    return {"task": "task:demo", "actor": "actor:worker", "object_version": obj,
            "operation": operation, "interface": interface, "recipient": recipient,
            "purpose": purpose, "virtual_seconds": second,
            "effect_time": f"2000-01-01T00:00:{second:02d}Z",
            "workflow": "workflow:" + context, "context": "ctx:" + context,
            "payload_base64": _b64(payload)}


def _verdict(checks: list[dict]) -> str:
    values = {check["status"] for check in checks}
    if "mismatched" in values:
        return "mismatched"
    if "inconclusive" in values or not values:
        return "inconclusive"
    return "matched"


def _check(checks: list[dict], name: str, condition: bool | None, detail: str = "") -> None:
    checks.append({"check": name, "status": "inconclusive" if condition is None else
                   "matched" if condition else "mismatched", "detail": detail})


def compare_analysis(case: str, report: dict) -> dict:
    """Compare minimum semantic requirements against manually fixed answers."""
    checks: list[dict] = []
    complete = (report.get("analysis_status") == "completed_for_supported_scope"
                and not report.get("unresolved_items") and not report.get("truncation"))
    _check(checks, "supported_analysis_complete", True if complete else None)
    expected_control = "not_blocked_in_model" if case == "A" else "blocked_in_model"
    actions = report.get("action_results", [])
    for action, authorization, control in (
        ("publish_s_main", "denied", expected_control),
        ("copy_s_internal", "allowed", "not_blocked_in_model"),
        ("publish_p_main", "allowed", "not_blocked_in_model"),
    ):
        records = [r for r in actions if r.get("action_id") == action]
        good = bool(records) and all(
            (r.get("feasibility"), r.get("authorization"), r.get("control_effect")) ==
            ("feasible", authorization, control) and not r.get("conditional") for r in records)
        explicit_wrong = any(not r.get("conditional") and r.get("check_status") == "checked"
                             and r.get("feasibility") in ("feasible", "infeasible")
                             and r.get("authorization") in ("allowed", "denied")
                             and r.get("control_effect") in ("blocked_in_model", "not_blocked_in_model")
                             and (r.get("feasibility"), r.get("authorization"), r.get("control_effect")) !=
                             ("feasible", authorization, control) for r in records)
        _check(checks, "analysis_" + action, False if explicit_wrong else good if complete or good else None)
    violations = [f for f in report.get("findings", []) if f.get("rule_id") == "SS001"
                  and f.get("classification") == "modeled_boundary_violation"]
    if case == "A":
        valid = any(
            [s.get("action_id") for s in f.get("witness", [])] == ["read_s", "publish_s_main"]
            and f["witness"][-1].get("output_port", {}).get("object_version_id") == "S:v1"
            and f["witness"][-1].get("output_port", {}).get("location_node_id") == "sink:main"
            for f in violations)
        _check(checks, "private_violation_witness", valid if complete or valid else None)
    else:
        _check(checks, "no_modeled_private_violation", not violations if complete or violations else None)
        declaration = any(f.get("rule_id") == "SS005" and f.get("control_assurance") == "declaration_only"
                          for f in report.get("findings", []))
        _check(checks, "declaration_only_preserved", declaration if complete or declaration else None)
    expected_coverage = "violated_in_model" if case == "A" else "covered_in_declared_model"
    coverage = any(c.get("property_id") == "P-CONF-01" and c.get("model_coverage") == expected_coverage
                   for c in report.get("coverage", []))
    _check(checks, "model_coverage", coverage if complete or coverage else None)
    _check(checks, "model_not_promoted_to_runtime", all(
        f.get("observed_effect") == "not_tested" and f.get("environment") == "declared_model"
        for f in report.get("findings", [])))
    return {"verdict": _verdict(checks), "checks": checks}


def _decode_target(target: dict | None) -> tuple[list[bytes] | None, bool]:
    """Read independently framed raw bytes; never trust record labels alone."""
    if not target or target.get("status") != "observed":
        return None, False
    try:
        raw = base64.b64decode(target["raw_base64"], validate=True)
    except (KeyError, ValueError, TypeError, binascii.Error):
        return None, False
    records: list[bytes] = []
    offset = 0
    while offset < len(raw):
        if len(raw) - offset < 4:
            return records, False
        size = int.from_bytes(raw[offset:offset + 4], "big")
        offset += 4
        if size > len(raw) - offset:
            return records, False
        records.append(raw[offset:offset + size])
        offset += size
    return records, True


def _expected_targets(case: str, sequence: int) -> dict[str, list[bytes]]:
    return {"result:internal": [_PRIVATE] if sequence >= 2 else [],
            "sink:main": ([_PRIVATE] if case == "A" and sequence >= 3 else [])
                         + ([_PUBLIC] if sequence >= 5 else [])}


def _observed_authorization(request: dict | None, obj: str | None, target: str) -> str:
    """The fixed complete grants permit [0,120), independently of schedule."""
    if obj == "S:v1" and target != "result:internal":
        return "denied"
    if obj is None or request is None:
        return "unresolved"
    fields = ("task", "actor", "object_version", "operation", "interface", "recipient",
              "purpose", "workflow", "context")
    actual = dict(request, object_version=obj, recipient=target)
    if not any(all(actual.get(field) == _request(row)[field] for field in fields)
               for row in (_ROWS[1], _ROWS[4])):
        return "denied"
    seconds = request.get("virtual_seconds")
    if type(seconds) is not int:
        return "unresolved"
    try:
        occurred = datetime.fromisoformat(request["effect_time"].replace("Z", "+00:00"))
    except (KeyError, TypeError, ValueError, AttributeError):
        return "unresolved"
    if occurred != datetime(2000, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=seconds):
        return "unresolved"
    return "allowed" if 0 <= seconds < 120 else "denied"


def compare_runtime(case: str, runtime: dict) -> dict:
    """Observe all steps before judging requests, effects and independent utility."""
    checks: list[dict] = []
    effects: list[dict] = []
    utilities = {"U-internal": "not_tested", "U-public": "not_tested"}
    _check(checks, "case_identity", runtime.get("case_id") == case)
    _check(checks, "gate_configuration", runtime.get("gate_enabled") is (case == "B"))
    _check(checks, "runtime_completed", True if runtime.get("runtime_status") == "completed" else None)
    _check(checks, "no_environment_errors", None if runtime.get("environment_errors") else True)
    _check(checks, "enabled_targets", set(runtime.get("enabled_targets", [])) == set(_TARGETS))
    _check(checks, "external_targets", set(runtime.get("external_targets", [])) == {"sink:main"})
    steps = runtime.get("steps", [])
    _check(checks, "five_steps", len(steps) == 5 if len(steps) >= 5 else None)
    observations = runtime.get("observations", [])
    _check(checks, "six_observations", len(observations) == 6 if len(observations) >= 6 else None)
    prior: dict[str, list[bytes] | None] = {}
    prior_sequence: dict[str, int] = {}
    seen_effects: set[tuple] = set()
    adequate_external = True
    observed_violation = False
    # Each snapshot is checked independently, so later failures cannot erase an effect.
    for sequence in range(max(6, len(observations))):
        snapshot = observations[sequence] if sequence < len(observations) else None
        if snapshot is None:
            _check(checks, f"observation_{sequence}", None)
            adequate_external = False
            continue
        _check(checks, f"observation_{sequence}_order", snapshot.get("sequence") == sequence)
        _check(checks, f"observation_{sequence}_action",
               snapshot.get("action_id") == (None if sequence == 0 else _ROWS[sequence - 1][0])
               if sequence <= 5 else False)
        policy = snapshot.get("policy", {})
        _check(checks, f"policy_{sequence}", policy.get("value") == "policy:strict"
               if policy.get("status") == "observed" else None)
        targets = snapshot.get("targets", {})
        _check(checks, f"observation_{sequence}_targets", set(targets) == set(_TARGETS))
        expected = _expected_targets(case, sequence)
        for target_id in sorted(set(_TARGETS) | set(targets)):
            records, well_formed = _decode_target(targets.get(target_id))
            key = f"observation_{sequence}_{target_id}"
            _check(checks, key + "_readable", True if records is not None else None)
            if records is None:
                if target_id != "result:internal":
                    adequate_external = False
                continue
            _check(checks, key + "_framing", well_formed)
            if not well_formed and target_id != "result:internal":
                adequate_external = False
            _check(checks, key + "_exact_bytes", records == expected.get(target_id, []))
            previous = prior.get(target_id)
            if previous is not None:
                _check(checks, key + "_append_only", records[:len(previous)] == previous)
            start = len(previous) if previous is not None and records[:len(previous)] == previous else 0
            for index, payload in enumerate(records):
                signature = (target_id, index, payload)
                if signature in seen_effects:
                    continue
                seen_effects.add(signature)
                obj = "S:v1" if payload == _PRIVATE else "P:v1" if payload == _PUBLIC else None
                attributable = (sequence > 0 and sequence <= len(steps)
                                and previous is not None and prior_sequence.get(target_id) == sequence - 1
                                and records[:len(previous)] == previous and index >= start)
                request = steps[sequence - 1].get("request", {}) if attributable else None
                # Match the complete independent grant, never just a label or target.
                authorization = _observed_authorization(request, obj, target_id)
                classification = ("observed_boundary_violation" if authorization == "denied" else
                                  "authorized_effect" if authorization == "allowed" else "unresolved_effect")
                if classification == "observed_boundary_violation":
                    observed_violation = True
                effects.append({"observation_sequence": sequence, "action_id": snapshot.get("action_id"),
                                "target": target_id, "record_index": index + 1, "object_version": obj,
                                "payload_base64": _b64(payload), "byte_length": len(payload),
                                "authorization": authorization, "classification": classification,
                                "new_since_previous_observation": attributable,
                                "evidence_basis": ["runtime_observation"], "environment": "local_controlled_simulation"})
            prior[target_id] = records
            prior_sequence[target_id] = sequence
    for index, row in enumerate(_ROWS):
        sequence = index + 1
        if index >= len(steps):
            _check(checks, f"step_{sequence}", None)
            continue
        step = steps[index]
        _check(checks, f"step_{sequence}_order", step.get("sequence") == sequence and step.get("action_id") == row[0])
        _check(checks, f"step_{sequence}_request", step.get("request") == _request(row))
        _check(checks, f"step_{sequence}_attempted", step.get("attempted") is True)
        _check(checks, f"step_{sequence}_dependency", step.get("dependency") == "satisfied")
        returned = step.get("returned", {})
        status = returned.get("status")
        expected_status = "denied" if case == "B" and sequence == 3 else "success"
        _check(checks, f"step_{sequence}_return", None if status == "error" else status == expected_status)
        if sequence in (1, 4) and status == "success":
            _check(checks, f"step_{sequence}_read_bytes", returned.get("payload_base64") == _b64(row[-1]))
        if status in ("success", "denied") and step.get("control", {}).get("invoked"):
            _check(checks, f"step_{sequence}_checked_bytes", step.get("actual_payload_base64") == _b64(row[-1]))
        control = step.get("control", {})
        expected_invoked = case == "B" and sequence in (3, 5)
        _check(checks, f"step_{sequence}_control_invoked", None if status == "error" else
               control.get("invoked") is expected_invoked)
        if expected_invoked:
            _check(checks, f"step_{sequence}_control_decision", None if status == "error" else
                   control.get("decision") == ("deny" if sequence == 3 else "allow"))
            _check(checks, f"step_{sequence}_control_authorization", None if status == "error" else
                   control.get("authorization") == ("denied" if sequence == 3 else "allowed"))
        for field, observation_index in (("before", index), ("after", sequence)):
            observation = observations[observation_index] if observation_index < len(observations) else None
            _check(checks, f"step_{sequence}_{field}_observation", None if observation is None or step.get(field) is None
                   else step[field] == observation)
        if sequence in (2, 5):
            utility = "U-internal" if sequence == 2 else "U-public"
            if step.get("attempted"):
                before = step.get("before", {}).get("targets", {}).get(row[4])
                after = step.get("after", {}).get("targets", {}).get(row[4])
                before_records, before_well_formed = _decode_target(before)
                after_records, after_well_formed = _decode_target(after)
                if before_records is None or after_records is None or not (before_well_formed and after_well_formed):
                    utilities[utility] = "unknown"
                else:
                    utilities[utility] = "success" if (step.get("request") == _request(row)
                        and after_records == before_records + [row[-1]]) else "failure"
    private_step = steps[2] if len(steps) >= 3 else {}
    if case == "B" and private_step.get("control", {}).get("decision") == "deny":
        deny_wrote = any(effect["observation_sequence"] == 3 and effect["new_since_previous_observation"]
                         and effect["classification"] == "observed_boundary_violation" for effect in effects)
        _check(checks, "control_refusal_no_prohibited_write", False if deny_wrote else True if adequate_external else None,
               "A denied request produced an observed forbidden effect; control contract failed." if deny_wrote else "")
    for utility, outcome in utilities.items():
        _check(checks, utility, True if outcome == "success" else False if outcome == "failure" else None)
    if case == "B":
        _check(checks, "no_prohibited_effect_all_steps", False if observed_violation else
               True if adequate_external else None)
    elif not observed_violation:
        _check(checks, "observed_private_violation", False if adequate_external else None)
    else:
        _check(checks, "observed_private_violation", True)
    verdict = _verdict(checks)
    return {"verdict": verdict, "checks": checks, "actual_effects": effects,
            "evidence_basis": ["runtime_observation"] if prior else [],
            "control_assurance": "scoped_evidence" if case == "B" and verdict == "matched" else
                                 "not_applicable" if case == "A" else "unresolved",
            "expectations": {"origin": "manually_fixed_protocol", "requests": [_request(row) for row in _ROWS],
                             "source_authorization": "Private versions have no public release exception; full task grants permit only the two fixed normal transfers."},
            "normal_tasks": utilities, "property_observation": "observed_boundary_violation" if observed_violation
            else "no_prohibited_effect_observed_for_fixed_attempts" if adequate_external else "unknown"}


def _run(case: str, run_dir: Path, limits: Limits, retained: bool) -> DemoResult:
    from .experiment_runtime import execute_case
    try:
        fixture = files("structural_safety").joinpath("examples", case + ".json").read_bytes()
    except OSError as exc:
        return DemoResult("error", case, "inconclusive", effective_limits=limits,
                          environment_errors=({"operation": "read_packaged_fixture", "error": str(exc)},),
                          scope=_SCOPE, run_directory=str(run_dir) if retained else None)
    analysis = analyze_json(fixture, limits=limits).to_dict()
    analysis_comparison = compare_analysis(case, analysis)
    runtime = execute_case(case, run_dir)
    runtime_comparison = compare_runtime(case, runtime)
    verdict = _verdict([{"status": comparison["verdict"]} for comparison in (analysis_comparison, runtime_comparison)])
    errors = runtime.get("environment_errors", [])
    case_result = {"case_id": case, "analysis": analysis, "analysis_comparison": analysis_comparison,
                   "runtime_status": runtime.get("runtime_status", "not_tested"), "protocol_verdict": verdict,
                   "runtime_comparison": runtime_comparison, "actual_effects": runtime_comparison["actual_effects"],
                   "normal_tasks": runtime_comparison["normal_tasks"], "policy_before": runtime.get("policy_initial"),
                   "policy_after": runtime.get("policy_final"), "environment_errors": errors, "runtime": runtime}
    status = "error" if errors else "resource_rejected" if analysis["analysis_status"] == "resource_rejected" else "completed"
    result = DemoResult(status, case, verdict, (case_result,), effective_limits=limits,
                        environment_errors=tuple(errors), scope=_SCOPE,
                        run_directory=str(run_dir) if retained else None)
    if retained:
        try:
            (run_dir / "report.json").write_text(json.dumps(result.to_dict(), indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
        except OSError as exc:
            error = {"operation": "save_report", "error": str(exc)}
            result = DemoResult("error", case, verdict, (case_result,), effective_limits=limits,
                                environment_errors=tuple(errors) + (error,), scope=_SCOPE, run_directory=str(run_dir))
    return result


def _environment_failure(scenario: str, limits: Limits, operation: str, error: OSError) -> DemoResult:
    return DemoResult("error", scenario, "inconclusive", effective_limits=limits,
                      environment_errors=({"operation": operation, "error": str(error)},), scope=_SCOPE)


def run_demo(scenario: str, *, work_dir: Path | None = None, limits: Limits | None = None) -> DemoResult:
    """Run one bundled A/B case; never execute an external model or code."""
    if not isinstance(scenario, str):
        raise TypeError("scenario must be a string")
    if work_dir is not None and not isinstance(work_dir, Path):
        raise TypeError("work_dir must be a pathlib.Path or None")
    if limits is not None and not isinstance(limits, Limits):
        raise TypeError("limits must be a Limits instance or None")
    effective = limits or Limits()
    if scenario not in ("A", "B"):
        reserved = scenario == "all" or scenario.split("-", 1)[0] in ("C", "D", "E", "F")
        status = "unsupported_scenario" if reserved else "input_invalid"
        diagnostic = Diagnostic("demo." + status, "$.scenario", "P1-3 supports only fixed scenarios A and B.")
        return DemoResult(status, scenario, diagnostics=(diagnostic,), effective_limits=effective, scope=_SCOPE)
    if work_dir is None:
        try:
            temporary = tempfile.TemporaryDirectory(prefix="sst-demo-")
        except OSError as exc:
            return _environment_failure(scenario, effective, "create_run_directory", exc)
        result = None
        cleanup_error = None
        try:
            result = _run(scenario, Path(temporary.name), effective, False)
        finally:
            try:
                temporary.cleanup()
            except OSError as exc:
                if result is None:
                    raise
                cleanup_error = exc
        if cleanup_error is not None:
            return replace(result, demo_status="error",
                           protocol_verdict="mismatched" if result.protocol_verdict == "mismatched" else "inconclusive",
                           environment_errors=result.environment_errors + (
                               {"operation": "cleanup_run_directory", "error": str(cleanup_error)},))
        return result
    try:
        work_dir.mkdir(parents=True, exist_ok=True)
        directory = Path(tempfile.mkdtemp(prefix="sst-demo-" + scenario + "-", dir=work_dir)).resolve()
    except OSError as exc:
        return _environment_failure(scenario, effective, "create_run_directory", exc)
    return _run(scenario, directory, effective, True)
