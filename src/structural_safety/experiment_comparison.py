"""Independent, manually fixed C-F protocol expectations.

No fixture generator, model evaluator or runtime control supplies these answers.
Only case names and neutral byte-framing/report helpers are shared.
"""

from datetime import datetime, timedelta, timezone

from .experiment_cases import D_CASES, E_CASES, F_CASES
from .experiments import _PRIVATE, _PUBLIC, _ROWS, _b64, _check, _decode_target, _request, _verdict


_PRIVATE2 = b"SST_PRIVATE_V2_TOKEN_8D02\n"
_REASONS = {
    "E-version": "release_scope_mismatch", "E-recipient": "release_scope_mismatch",
    "E-purpose": "release_scope_mismatch", "E-interface": "release_scope_mismatch",
    "E-expiry": "release_outside_validity", "E-issuer": "release_issuer_has_no_approval_right",
    "E-revoked": "release_revoked", "E-unknown": "release_revocation_unknown",
    "E-task": "no_matching_task_grant",
}


def compare_analysis_extended(case: str, report: dict) -> dict:
    checks = []
    complete = report.get("analysis_status") == "completed_for_supported_scope" and not report.get("truncation")
    _check(checks, "supported_analysis_complete", True if complete else None)
    expected_unknown = case in ("D-behavior", "D-isolation", "E-unknown")
    _check(checks, "expected_unknown_preserved", bool(report.get("unresolved_items")) == expected_unknown if complete else None)
    blocked = "blocked_in_model"
    unblocked = "not_blocked_in_model"
    expected = {
        "copy_s_internal": {("feasible", "allowed", unblocked)},
        "publish_p_main": {("feasible", "allowed", "unresolved" if case == "D-behavior" else unblocked)},
        "publish_s_main": {("feasible", "allowed" if case == "E0" else "unresolved" if case == "E-unknown" else "denied",
                            "unresolved" if case == "D-behavior" else unblocked if case == "E0" else blocked)},
    }
    if case == "C":
        expected["publish_s_alt"] = {("feasible", "denied", unblocked)}
    if case == "D-behavior":
        expected["publish_p_main"].add(("conditional", "allowed", "unresolved"))
    if case in F_CASES:
        del expected["publish_s_main"]
        expected.update(select_weak={("feasible" if case == "F-open" else "infeasible", "denied", unblocked)},
                        publish_s_before={("feasible", "denied", blocked)},
                        publish_s_after={("feasible", "denied", blocked)})
        if case == "F-open":
            expected["publish_s_after"].add(("feasible", "denied", unblocked))
    for action, answers in expected.items():
        records = [r for r in report.get("action_results", []) if r.get("action_id") == action and r.get("check_status") == "checked"]
        actual = {(r.get("feasibility"), r.get("authorization"), r.get("control_effect")) for r in records}
        _check(checks, "analysis_" + action, False if actual - answers else actual == answers if complete else None)
    violations = [f for f in report.get("findings", []) if f.get("rule_id") == "SS001"
                  and f.get("classification") == "modeled_boundary_violation"]
    _check(checks, "expected_modeled_violation", bool(violations) == (case in ("C", "F-open")) if complete else None)
    if case in ("C", "F-open"):
        destination = "sink:alt" if case == "C" else "sink:main"
        witnesses = [f.get("witness", []) for f in violations]
        witnesses = [w for w in witnesses if w and (w[-1].get("output_port") or {}).get("location_node_id") == destination]
        if case == "F-open":
            witnesses = [w for w in witnesses if any(s.get("action_id") == "select_weak" and s.get("committed")
                         and ["gate:main", "policy:weak"] in s.get("policy_after", []) for s in w[:-1])]
        _check(checks, "route_and_policy_witness", bool(witnesses) if complete or witnesses else None)
    if case in ("D-isolation", *F_CASES):
        statuses = {o.get("independence", {}).get("status") for o in report.get("obligations", [])
                    if o.get("control_id") == "gate:main"}
        answer = "unresolved" if case == "D-isolation" else "not_met" if case == "F-open" else "met"
        _check(checks, "control_independence", answer in statuses if complete else None)
    _check(checks, "model_not_promoted_to_runtime", all(f.get("observed_effect") == "not_tested"
        and f.get("environment") == "declared_model" for f in report.get("findings", [])))
    return {"verdict": _verdict(checks), "checks": checks}


def _protocol(case: str) -> tuple[list[dict], list[str]]:
    """Finite expected requests, not an executable permission source."""
    rows = [{"action": row[0], "request": _request(row), "payload": row[-1],
             "return": "denied" if i == 2 else "success"} for i, row in enumerate(_ROWS)]
    targets = ["result:internal", "sink:main"]
    if case == "C":
        row = ("publish_s_alt", "S:v1", "publish", "if:alternate", "sink:alt", "external_demo", 35, "restricted", _PRIVATE)
        rows.insert(3, {"action": row[0], "request": _request(row), "payload": _PRIVATE, "return": "success"})
        targets.append("sink:alt")
    elif case in E_CASES:
        private = rows[2]
        second = 60 if case == "E-expiry" else 40
        row = ("publish_s_main", "S:v2" if case == "E-version" else "S:v1", "publish",
               "if:mirror" if case == "E-interface" else "if:publish",
               "sink:other" if case == "E-recipient" else "sink:main",
               "archive_demo" if case == "E-purpose" else "external_demo", second, "restricted",
               _PRIVATE2 if case == "E-version" else _PRIVATE)
        private.update(request=_request(row), payload=row[-1], **{"return": "success" if case == "E0" else "denied"})
        rows = [rows[0], private, rows[1], *rows[3:]]
        for record, seconds in zip(rows[2:], (70, 75, 80)):
            record["request"].update(virtual_seconds=seconds, effect_time=_time(seconds))
        if case == "E-version":
            row = ("read_s2", "S:v2", "read", "if:read", "actor:worker", "internal_review", 12, "restricted", _PRIVATE2)
            rows.insert(1, {"action": row[0], "request": _request(row), "payload": _PRIVATE2, "return": "success"})
        targets.append("sink:other")
    elif case in F_CASES:
        before = rows[2]
        before.update(action="publish_s_before")
        before["request"].update(virtual_seconds=25, effect_time=_time(25))
        select = {"action": "select_weak", "payload": b"", "return": "success" if case == "F-open" else "denied",
                  "request": {"task": "task:demo", "actor": "actor:worker", "object_version": "not_applicable",
                      "operation": "policy_update", "interface": "if:policy", "recipient": "node:gate-main",
                      "purpose": "policy_management", "context": "ctx:restricted", "workflow": "workflow:restricted",
                      "virtual_seconds": 35, "effect_time": _time(35), "payload_base64": "",
                      "policy_version": "policy:weak", "fields": ["decision_mode"]}}
        after = {"action": "publish_s_after", "payload": _PRIVATE,
                 "return": "success" if case == "F-open" else "denied",
                 "request": dict(before["request"], virtual_seconds=40, effect_time=_time(40))}
        rows = [*rows[:3], select, after, *rows[3:]]
    else:
        raise ValueError("No runtime protocol for this case")
    return rows, targets


def _time(seconds: int) -> str:
    return (datetime(2000, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")


def _observed_authorization(case: str, request: dict | None, obj: str | None, target: str) -> str:
    """Full independent task and release grants, distinct from the schedule."""
    if request is None or obj is None:
        return "unresolved"
    seconds = request.get("virtual_seconds")
    if type(seconds) is not int or request.get("effect_time") != _time(seconds):
        return "unresolved"
    if not 0 <= seconds < 120:
        return "denied"
    q = dict(request, object_version=obj, recipient=target)
    if q.get("task") != "task:demo" or q.get("actor") != "actor:worker":
        return "denied"
    context = "public" if obj == "P:v1" else "restricted"
    if q.get("context") != "ctx:" + context or q.get("workflow") != "workflow:" + context:
        return "denied"
    if (obj == "S:v1" and q.get("operation") == "transfer" and q.get("interface") == "if:internal"
            and target == "result:internal" and q.get("purpose") == "internal_review"):
        return "allowed"
    if (obj == "P:v1" and q.get("operation") == "publish" and q.get("interface") == "if:publish"
            and target == "sink:main" and q.get("purpose") == "public_notice"):
        return "allowed"
    if case not in E_CASES or case == "E-task":
        return "denied"
    if not (obj == "S:v1" and q.get("operation") == "publish" and q.get("interface") == "if:publish"
            and target == "sink:main" and q.get("purpose") == "external_demo" and 30 <= seconds < 60):
        return "denied"
    if case == "E-issuer" or case == "E-revoked" and seconds >= 39:
        return "denied"
    return "unresolved" if case == "E-unknown" else "allowed"


def compare_runtime_extended(case: str, runtime: dict) -> dict:
    rows, targets = _protocol(case)
    checks, effects, policy_changes = [], [], []
    utilities = {"U-internal": "not_tested", "U-public": "not_tested"}
    steps, observations = runtime.get("steps", []), runtime.get("observations", [])
    _check(checks, "case_identity", runtime.get("case_id") == case)
    _check(checks, "gate_configuration", runtime.get("gate_enabled") is True)
    _check(checks, "runtime_completed", True if runtime.get("runtime_status") == "completed" else None)
    _check(checks, "no_environment_errors", None if runtime.get("environment_errors") else True)
    _check(checks, "enabled_targets", set(runtime.get("enabled_targets", [])) == set(targets))
    _check(checks, "external_targets", set(runtime.get("external_targets", [])) == set(targets) - {"result:internal"})
    _check(checks, "step_count", len(steps) == len(rows) if len(steps) >= len(rows) else None)
    _check(checks, "observation_count", len(observations) == len(rows) + 1 if len(observations) >= len(rows) + 1 else None)
    expected = {target: [] for target in targets}
    prior, seen, prior_sequence = {}, set(), {}
    adequate, last_policy = True, None
    for sequence in range(max(len(rows) + 1, len(observations))):
        row = rows[sequence - 1] if 0 < sequence <= len(rows) else None
        if row and row["return"] == "success" and row["request"]["operation"] in ("publish", "transfer"):
            expected[row["request"]["recipient"]].append(row["payload"])
        if sequence >= len(observations):
            _check(checks, f"observation_{sequence}", None)
            adequate = False
            continue
        snapshot = observations[sequence]
        _check(checks, f"observation_{sequence}_order", snapshot.get("sequence") == sequence
               and snapshot.get("action_id") == (row["action"] if row else None))
        policy = snapshot.get("policy", {})
        policy_value = policy.get("value") if policy.get("status") == "observed" else None
        _check(checks, f"policy_{sequence}", policy_value == ("policy:weak" if case == "F-open" and sequence >= 4 else "policy:strict")
               if policy_value is not None else None)
        if policy_value is not None and last_policy is not None and policy_value != last_policy:
            policy_changes.append({"observation_sequence": sequence, "action_id": snapshot.get("action_id"),
                                   "before": last_policy, "after": policy_value, "authorization": "denied",
                                   "classification": "observed_unauthorized_policy_change", "evidence_basis": ["runtime_observation"]})
        last_policy = policy_value
        actual_targets = snapshot.get("targets", {})
        _check(checks, f"targets_{sequence}", set(actual_targets) == set(targets))
        for target in sorted(set(targets) | set(actual_targets)):
            records, well_formed = _decode_target(actual_targets.get(target))
            key = f"observation_{sequence}_{target}"
            _check(checks, key + "_readable", True if records is not None else None)
            if records is None:
                adequate = False
                continue
            _check(checks, key + "_framing", well_formed)
            adequate = adequate and well_formed
            _check(checks, key + "_exact_bytes", records == expected.get(target, []))
            previous = prior.get(target)
            if previous is not None:
                _check(checks, key + "_append_only", records[:len(previous)] == previous)
            for index, payload in enumerate(records):
                signature = (target, index, payload)
                if signature in seen:
                    continue
                seen.add(signature)
                attributable = (0 < sequence <= len(steps) and previous is not None
                    and prior_sequence.get(target) == sequence - 1 and records[:len(previous)] == previous and index >= len(previous))
                request = steps[sequence - 1].get("request") if attributable else None
                obj = {_PRIVATE: "S:v1", _PRIVATE2: "S:v2", _PUBLIC: "P:v1"}.get(payload)
                auth = _observed_authorization(case, request, obj, target)
                classification = {"allowed": "authorized_effect", "denied": "observed_boundary_violation", "unresolved": "unresolved_effect"}[auth]
                effects.append({"observation_sequence": sequence, "action_id": snapshot.get("action_id"), "target": target,
                    "record_index": index + 1, "object_version": obj, "payload_base64": _b64(payload), "byte_length": len(payload),
                    "authorization": auth, "classification": classification, "new_since_previous_observation": attributable,
                    "evidence_basis": ["runtime_observation"], "environment": "local_controlled_simulation"})
            prior[target], prior_sequence[target] = records, sequence
    for index, row in enumerate(rows):
        sequence = index + 1
        if index >= len(steps):
            _check(checks, f"step_{sequence}", None)
            continue
        step = steps[index]
        prefix = f"step_{sequence}_"
        returned, control = step.get("returned", {}), step.get("control", {})
        status = returned.get("status")
        _check(checks, prefix + "order", step.get("sequence") == sequence and step.get("action_id") == row["action"])
        _check(checks, prefix + "request", step.get("request") == row["request"])
        _check(checks, prefix + "attempted", step.get("attempted") is True and step.get("dependency") == "satisfied")
        _check(checks, prefix + "return", None if status == "error" else status == row["return"])
        operation = row["request"]["operation"]
        invoked = operation == "publish" and row["action"] != "publish_s_alt"
        _check(checks, prefix + "control_invoked", None if status == "error" else control.get("invoked") is invoked)
        if operation == "read" and status == "success":
            _check(checks, prefix + "read_bytes", returned.get("payload_base64") == _b64(row["payload"]))
        if invoked and status != "error":
            expected_auth = "allowed" if row["action"] == "publish_p_main" or case == "E0" else "unresolved" if case == "E-unknown" else "denied"
            _check(checks, prefix + "checked_bytes", step.get("actual_payload_base64") == _b64(row["payload"]))
            _check(checks, prefix + "authorization", control.get("authorization") == expected_auth)
            _check(checks, prefix + "decision", control.get("decision") == ("allow" if row["return"] == "success" else "deny"))
            _check(checks, prefix + "policy_read", control.get("policy") == (
                "policy:weak" if case == "F-open" and sequence >= 5 else "policy:strict"))
            if case in E_CASES and row["action"] == "publish_s_main":
                _check(checks, prefix + "task_grant", control.get("task_authorization") == ("denied" if case == "E-task" else "allowed"))
                _check(checks, prefix + "release_reason", control.get("reasons") == ([] if case == "E0" else [_REASONS[case]]))
        if row["action"] == "select_weak":
            _check(checks, prefix + "selection_reason", None if status == "error" else returned.get("reason") == (
                "policy_selected" if case == "F-open" else "technical_capability_absent"))
        for field, pos in (("before", index), ("after", sequence)):
            _check(checks, prefix + field, None if pos >= len(observations) or step.get(field) is None
                   else step[field] == observations[pos])
        if control.get("decision") == "deny":
            wrote = any(e["observation_sequence"] == sequence and e["new_since_previous_observation"] for e in effects)
            _check(checks, prefix + "control_refusal_no_write", False if wrote else True if adequate else None)
        if row["action"] in ("copy_s_internal", "publish_p_main") and step.get("attempted"):
            utility = "U-internal" if row["action"] == "copy_s_internal" else "U-public"
            target = row["request"]["recipient"]
            before, before_ok = _decode_target(step.get("before", {}).get("targets", {}).get(target))
            after, after_ok = _decode_target(step.get("after", {}).get("targets", {}).get(target))
            utilities[utility] = "unknown" if before is None or after is None or not (before_ok and after_ok) else (
                "success" if step.get("request") == row["request"] and after == before + [row["payload"]] else "failure")
    if case in F_CASES:
        checkpoints = runtime.get("policy_observations", [])
        _check(checks, "policy_checkpoint_count", len(checkpoints) == 2 if len(checkpoints) >= 2 else None)
        for index, second in enumerate((20, 36)):
            record = checkpoints[index] if index < len(checkpoints) else {}
            _check(checks, f"policy_checkpoint_{second}", record.get("virtual_seconds") == second and record.get("value") == (
                "policy:weak" if case == "F-open" and second == 36 else "policy:strict") if record.get("status") == "observed" else None)
    for name, outcome in utilities.items():
        _check(checks, name, True if outcome == "success" else False if outcome == "failure" else None)
    violations = [e for e in effects if e["classification"] == "observed_boundary_violation"]
    unsettled = any(e["classification"] == "unresolved_effect" for e in effects)
    _check(checks, "expected_observed_violation", bool(violations) == (case in ("C", "F-open")) if adequate or violations else None)
    verdict = _verdict(checks)
    bypass = case in ("C", "F-open") and verdict == "matched"
    return {"verdict": verdict, "checks": checks, "actual_effects": effects, "policy_changes": policy_changes,
            "normal_tasks": utilities, "evidence_basis": ["runtime_observation"] if prior else [],
            "control_assurance": "scoped_evidence" if verdict == "matched" and not bypass else "unresolved",
            "control_evaluation": "demonstrated_control_bypass" if bypass else "fixed_attempts_compared",
            "bypass_scope": {"control": "gate:main", "expected_protection": "P-CONF-01 restricted external publication",
                             "route": "if:alternate -> sink:alt" if case == "C" else "if:policy -> policy:weak -> sink:main",
                             "evidence": "Attempt records, actual policy reads and exact target byte observations in this run only."} if bypass else None,
            "expectations": {"origin": "manually_fixed_protocol", "requests": [r["request"] for r in rows]},
            "property_observation": "observed_boundary_violation" if violations else "unknown" if unsettled or not adequate
                else "no_prohibited_effect_observed_for_fixed_attempts"}
