"""Declared current-policy effects and separately scoped control assurance.

This module evaluates a finite input model. It never executes a control, trusts
an imported observation as a local experiment, or selects a favorable value
from a conflicting Fact.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import json
from typing import Any

from .analysis_types import Decision, Query, decision_and, decision_or


REQUIRED_PARAMETERS = frozenset({
    "task", "actor", "object_version", "operation", "interface", "recipient",
    "purpose", "effect_time", "workflow_conditions",
})
SENSITIVE_FIELDS = frozenset({
    "decision_mode", "deny_clauses", "coverage", "checked_parameters",
    "binding", "timing", "failure_behavior",
})


@dataclass(frozen=True, slots=True)
class ControlDecision:
    status: str
    details: tuple[dict, ...] = ()
    reasons: tuple[str, ...] = ()
    evidence_refs: tuple[str, ...] = ()


def _refs(value: Any) -> tuple[str, ...]:
    """Retain all submitted references, including conflicting candidates."""
    result: set[str] = set()
    if isinstance(value, Mapping):
        result.update(value.get("evidence_refs", ()))
        for key, child in value.items():
            if key != "evidence_refs":
                result.update(_refs(child))
    elif isinstance(value, (tuple, list)):
        for child in value:
            result.update(_refs(child))
    return tuple(sorted(result))


def _known(fact: Mapping) -> Any:
    return fact["value"] if fact["state"] == "known" else None


def _field(fact: Mapping, expected: Any, name: str) -> Decision:
    if fact["state"] != "known":
        return Decision(None, (name + "_" + fact["state"],), _refs(fact))
    matched = fact["value"] == expected
    return Decision(matched, () if matched else (name + "_not_met",), _refs(fact))


def _as_dict(value: Decision) -> dict:
    return {"value": value.value, "reasons": value.reasons,
            "evidence_refs": value.evidence_refs}


class Controller:
    def __init__(self, document: Mapping, evaluator: Any):
        self.document = document
        self.evaluator = evaluator
        self.controls = tuple(sorted(document["controls"], key=lambda x: x["id"]))
        self.evidence = {item["id"]: item for item in document["evidence"]}
        self.modification_results = None
        self.search_complete = False

    def _policy(self, control: Mapping, policies: Mapping | None = None) -> Mapping | None:
        selected = policies.get(control["id"]) if policies is not None else _known(control["initial_policy"])
        return next((p for p in control["policy_versions"] if p["id"] == selected), None)

    def _clauses(self, fact: Mapping, query: Query, name: str) -> Decision:
        if fact["state"] != "known":
            return Decision(None, (name + "_" + fact["state"],), _refs(fact))
        # Each full clause is matched intact and charged to the shared budget.
        matches = tuple(self.evaluator.match_scope(clause, query)
                        for clause in fact["value"])
        result = decision_or(matches)
        reasons = result.reasons
        if result.value is False:
            reasons += (name + "_no_match",)
        return Decision(result.value, reasons, result.evidence_refs + _refs(fact))

    @staticmethod
    def _parameters(policy: Mapping, query: Query | None = None) -> Decision:
        fact = policy["checked_parameters"]
        if fact["state"] != "known":
            return Decision(None, ("checked_parameters_" + fact["state"],), _refs(fact))
        required = ((REQUIRED_PARAMETERS - {"object_version"}) | {"policy_target"}
                    if query is not None and query.policy_target is not None else REQUIRED_PARAMETERS)
        if query is not None and query.management_targets:
            required = (REQUIRED_PARAMETERS - {"object_version"}) | {"management_targets"}
        missing = sorted(required.difference(fact["value"]))
        return Decision(not missing, tuple("parameter_unchecked:" + x for x in missing), _refs(fact))

    @staticmethod
    def _failure(policy: Mapping) -> Decision:
        fact = policy["failure_behavior"]
        value = _known(fact)
        if value is None:
            return Decision(None, ("failure_behavior_" + fact["state"],), _refs(fact))
        blocks = value in ("deny", "pause")
        return Decision(blocks, ("failure_behavior:" + value,), _refs(fact))

    def _refusal(self, policy: Mapping, query: Query,
                 authorization: Decision | None) -> Decision:
        mode = _known(policy["decision_mode"])
        refs = _refs(policy["decision_mode"])
        if mode == "authorization":
            auth = authorization if authorization is not None else self.evaluator.authorization(query)
            if auth.value is not None:
                return Decision(not auth.value,
                                ("authorization_denied" if not auth.value else "authorization_allowed",),
                                auth.evidence_refs + refs)
            failure = self._failure(policy)
            return Decision(failure.value, auth.reasons + failure.reasons,
                            auth.evidence_refs + failure.evidence_refs + refs)
        if mode == "deny_table":
            denied = self._clauses(policy["deny_clauses"], query, "deny_table")
            if denied.value is not None:
                return denied
            failure = self._failure(policy)
            return Decision(failure.value, denied.reasons + failure.reasons,
                            denied.evidence_refs + failure.evidence_refs + refs)
        reason = "decision_mode_" + (mode or policy["decision_mode"]["state"])
        return Decision(None, (reason,), refs)

    def _evaluate_control(self, control: Mapping, query: Query,
                          authorization: Decision | None, policies: Mapping | None = None) -> tuple[Decision, dict]:
        policy = self._policy(control, policies)
        detail = {"control_id": control["id"], "property_ids": tuple(control["property_ids"]),
                  "policy_version_id": policy["id"] if policy else None,
                  "runtime_status": "not_tested"}
        if policy is None:
            result = Decision(None, ("initial_policy_" + control["initial_policy"]["state"],),
                              _refs(control["initial_policy"]))
        else:
            coverage = self._clauses(policy["coverage"], query, "control_coverage")
            parameters = self._parameters(policy, query)
            binding = _field(policy["binding"], "bound", "parameter_binding")
            timing = _field(policy["timing"], "before_effect", "control_timing")
            # A control outside this query's scope or running after this effect
            # cannot prevent it. Irrelevant unknown policy facts do not taint it.
            if coverage.value is False or timing.value is False:
                result = decision_and(coverage, timing)
                refusal = Decision(None, ("decision_not_needed",))
            else:
                refusal = self._refusal(policy, query, authorization)
                # An unchecked or unbound actual parameter does not establish
                # what the gate checked. Neither refusal nor passage is known.
                if parameters.value is False:
                    parameters = Decision(None, parameters.reasons, parameters.evidence_refs)
                if binding.value is False:
                    binding = Decision(None, binding.reasons, binding.evidence_refs)
                prerequisites = decision_and(coverage, timing, parameters, binding)
                if prerequisites.value is None:
                    result = Decision(None, prerequisites.reasons + refusal.reasons,
                                      prerequisites.evidence_refs + refusal.evidence_refs)
                else:
                    result = decision_and(prerequisites, refusal)
            detail.update({"coverage": _as_dict(coverage), "parameters": _as_dict(parameters),
                           "binding": _as_dict(binding), "timing": _as_dict(timing),
                           "refusal": _as_dict(refusal)})
        detail.update({"control_effect": self._status(result.value),
                       "reasons": result.reasons, "evidence_refs": result.evidence_refs})
        return result, detail

    @staticmethod
    def _status(value: bool | None) -> str:
        return {True: "blocked_in_model", False: "not_blocked_in_model",
                None: "unresolved"}[value]

    def evaluate(self, query: Query, authorization: Decision | None = None,
                 policies: Mapping | None = None) -> ControlDecision:
        evaluated = tuple(self._evaluate_control(c, query, authorization, policies) for c in self.controls)
        result = decision_or(tuple(item[0] for item in evaluated))
        if result.value is False:
            complete = self.evaluator.complete(query.task_id, "controls")
            if complete.value is not True:
                result = Decision(None, complete.reasons + ("control_inventory_incomplete",),
                                  result.evidence_refs + complete.evidence_refs)
        return ControlDecision(self._status(result.value), tuple(item[1] for item in evaluated),
                               result.reasons, result.evidence_refs)

    def selection(self, effect: Mapping, policies: Mapping) -> Decision:
        """A version selection must expose every changed policy field."""
        control = next(c for c in self.controls if c["id"] == effect["control_id"])
        permitted = control["modifiable_fields"]
        fields = set(effect["fields"])
        if permitted["state"] == "known" and not fields <= set(permitted["value"]):
            return Decision(False, ("policy_fields_not_modifiable",), _refs(permitted))
        before = self._policy(control, policies)
        after = next(p for p in control["policy_versions"] if p["id"] == effect["policy_version_id"])
        if before is None or permitted["state"] != "known":
            return Decision(None, ("policy_selection_fields_unresolved",), _refs(permitted))
        def facts(value):
            if isinstance(value, Mapping):
                return {k: facts(v) for k, v in value.items() if k != "evidence_refs"}
            if isinstance(value, (tuple, list)):
                return [facts(v) for v in value]
            return value
        changed = {key for key in SENSITIVE_FIELDS if facts(before.get(key)) != facts(after.get(key))}
        return Decision(changed <= fields, () if changed <= fields else ("policy_change_outside_named_fields",))

    def _independence(self, control: Mapping) -> dict:
        fields = _known(control["modifiable_fields"])
        paths = _known(control["modification_paths_complete"])
        modification_actions = tuple(sorted(action["id"] for action in self.document["actions"]
            if any(effect["kind"] == "select_policy" and effect["control_id"] == control["id"]
                   and set(effect["fields"]).intersection(SENSITIVE_FIELDS)
                   for effect in action["effects"])))
        if modification_actions and self.modification_results is not None:
            targets = {(a["id"], e["id"]) for a in self.document["actions"] for e in a["effects"]
                       if e["kind"] == "select_policy" and e["control_id"] == control["id"]
                       and set(e["fields"]).intersection(SENSITIVE_FIELDS)}
            rows = [r for r in self.modification_results if (r["action_id"], r["effect_id"]) in targets]
            reached = any(r["committed"] and not r["conditional"] for r in rows)
            uncertain = any(r["committed"] and r["conditional"] for r in rows)
            complete = self.search_complete and paths is True and fields is not None
            status = "not_met" if reached else "met" if complete and not uncertain else "unresolved"
            reasons = ("reachable_policy_modification",) if reached else () if status == "met" else ("policy_modification_unresolved",)
            return {"status": status, "check_status": "checked" if complete else "partial",
                    "reasons": reasons, "modification_action_refs": modification_actions}
        if fields is not None and not set(fields).intersection(SENSITIVE_FIELDS) and paths is True:
            # Without search results, declared immutability cannot dismiss an
            # explicit contradicting update candidate as already checked.
            if not modification_actions:
                return {"status": "met", "check_status": "checked", "reasons": (),
                        "modification_action_refs": ()}
        reasons = []
        if fields is None:
            reasons.append("modifiable_fields_" + control["modifiable_fields"]["state"])
        elif set(fields).intersection(SENSITIVE_FIELDS):
            reasons.append("sensitive_policy_fields_modifiable")
        if paths is not True:
            reasons.append("policy_modification_paths_incomplete")
        if modification_actions:
            reasons.append("policy_modification_transitions_not_checked")
        return {"status": "unresolved", "check_status": "not_checked" if modification_actions else "checked",
                "reasons": tuple(reasons), "modification_action_refs": modification_actions}

    def _assurance(self, control: Mapping, property_id: str, policy: Mapping | None) -> dict:
        selected_claims = {key: control[key] for key in (
            "initial_policy", "modifiable_fields", "modification_paths_complete",
            "responsible_principal", "evidence_refs")}
        refs = tuple(sorted(set(_refs(selected_claims) + (_refs(policy) if policy else ()))))
        applicability = []
        scoped = False
        unsettled = False
        for ref in refs:
            evidence = self.evidence[ref]
            scope = {(item["collection"], item["id"]) for item in evidence["scope"]}
            control_match = ("controls", control["id"]) in scope
            property_match = ("properties", property_id) in scope
            full_scope = control_match and property_match
            snapshot_match = evidence["snapshot_id"] == self.document["context"]["snapshot_id"]
            status = evidence["applicability"]
            if status == "current" and not snapshot_match:
                status = "configuration_changed"
            if status == "current" and evidence["recorded_at"]["state"] != "known":
                status = "unresolved"
            reported = evidence["acquisition"]
            # Submitted runtime records remain reports even when perfectly
            # scoped; only the separate local experiment can observe effects.
            effective_basis = "supplied_assertion" if reported == "supplied_assertion" else "external_report"
            applicability.append({"evidence_ref": ref, "reported_acquisition": reported,
                                  "evidence_basis": effective_basis,
                                  "declared_applicability": evidence["applicability"],
                                  "applicability": status, "control_scope_matches": control_match,
                                  "property_scope_matches": property_match,
                                  "snapshot_matches": snapshot_match,
                                  "limits": tuple(evidence["limits"]),
                                  "runtime_status": "not_tested"})
            if full_scope and status == "current" and reported != "supplied_assertion":
                scoped = True
            if full_scope and status in ("conflict", "unresolved", "expired", "configuration_changed"):
                unsettled = True
        assurance = "unresolved" if unsettled else "scoped_evidence" if scoped else "declaration_only"
        return {"control_assurance": assurance, "evidence_applicability": tuple(applicability),
                "evidence_refs": refs, "runtime_status": "not_tested"}

    @staticmethod
    def _contract(policy: Mapping | None) -> dict:
        if policy is None:
            return {"status": "unresolved", "reasons": ("initial_policy_unresolved",),
                    "unresolved_reasons": ("initial_policy_unresolved",)}
        failure = Controller._failure(policy)
        if failure.value is True:
            failure = Decision(True, evidence_refs=failure.evidence_refs)
        checks = [Controller._parameters(policy), _field(policy["binding"], "bound", "parameter_binding"),
                  _field(policy["timing"], "before_effect", "control_timing"), failure]
        mode = _known(policy["decision_mode"])
        if mode in ("authorization", "deny_table"):
            checks.append(Decision(True))
        else:
            checks.append(Decision(None, ("decision_mode_" + (mode or policy["decision_mode"]["state"]),)))
        coverage = _known(policy["coverage"])
        if coverage is None:
            checks.append(Decision(None, ("control_coverage_" + policy["coverage"]["state"],)))
        elif not coverage:
            checks.append(Decision(False, ("control_coverage_empty",)))
        else:
            unresolved = tuple("control_coverage_" + field + "_" + fact["state"]
                               for clause in coverage for field, fact in clause.items()
                               if field != "conditions" and fact["state"] != "known")
            if unresolved:
                checks.append(Decision(None, unresolved))
        # Unknown scope members remain local query questions. Merely possessing
        # coverage clauses is never a proof that all property routes are covered.
        if mode == "deny_table" and policy["deny_clauses"]["state"] != "known":
            checks.append(Decision(None, ("deny_table_" + policy["deny_clauses"]["state"],)))
        value = decision_and(checks)
        return {"status": {True: "satisfied_in_model", False: "gap", None: "unresolved"}[value.value],
                "reasons": value.reasons,
                "unresolved_reasons": tuple(sorted({reason for check in checks if check.value is None
                                                     for reason in check.reasons}))}

    def _tasks(self, control: Mapping, policy: Mapping | None) -> tuple[str, ...]:
        all_tasks = {task["id"] for task in self.document["context"]["tasks"]}
        coverage = _known(policy["coverage"]) if policy is not None else None
        if coverage is None:
            return tuple(sorted(all_tasks))
        tasks = set()
        for clause in coverage:
            value = _known(clause["tasks"])
            tasks.update(all_tasks if value is None else value)
        # A supplied obligation can require this control even when its current
        # declared coverage is empty or fails to cover that task.
        for obligation in self.document["obligations"]:
            refs = _known(obligation["control_refs"])
            if refs is not None and control["id"] in refs:
                tasks.add(obligation["task_id"])
        return tuple(sorted(tasks))

    def obligations(self) -> tuple[dict, ...]:
        """One SS005 assurance obligation per control, property and snapshot."""
        result = []
        context = self.document["context"]
        for control in self.controls:
            policy = self._policy(control)
            independence = self._independence(control)
            contract = self._contract(policy)
            task_ids = self._tasks(control, policy)
            for property_id in sorted(control["property_ids"]):
                assurance = self._assurance(control, property_id, policy)
                reasons = list(contract["reasons"] + independence["reasons"])
                unresolved = list(contract["unresolved_reasons"])
                if independence["status"] == "unresolved":
                    unresolved.extend(independence["reasons"])
                if assurance["control_assurance"] == "declaration_only":
                    reasons.append("control_effectiveness_has_only_model_declarations")
                elif assurance["control_assurance"] == "unresolved":
                    reasons.append("control_evidence_applicability_unresolved")
                    unresolved.append("control_evidence_applicability_unresolved")
                if contract["status"] == "gap" or independence["status"] == "not_met" or assurance["control_assurance"] == "declaration_only":
                    status = "gap"
                elif contract["status"] == "unresolved" or independence["status"] == "unresolved" or assurance["control_assurance"] == "unresolved":
                    status = "unresolved"
                else:
                    status = "satisfied_in_model"
                identity = json.dumps([context["snapshot_id"], control["id"], property_id],
                                      ensure_ascii=True, separators=(",", ":"))
                result.append({"obligation_id": "SS005:" + identity,
                               "rule_id": "SS005", "control_id": control["id"], "property_id": property_id,
                               "snapshot_id": context["snapshot_id"],
                               "task_id": task_ids[0] if len(task_ids) == 1 else None,
                               "task_ids": task_ids,
                               "obligation_status": status, "check_status": "checked",
                               "model_contract": contract, "independence": independence,
                               "reasons": tuple(sorted(set(reasons))),
                               "has_unresolved": bool(unresolved),
                               "unresolved_reasons": tuple(sorted(set(unresolved))),
                               "evidence_basis": ("supplied_assertion", "model_deduction"),
                               "environment": "declared_model", **assurance})
        return tuple(result)
