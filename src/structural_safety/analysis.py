"""Coordinate supported model analysis without executing candidate actions."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import fields, is_dataclass
import hashlib
import json
from typing import Any

from .analysis_model import AnalysisResult
from .analysis_types import Budget, BudgetExceeded
from .model import Limits
from .validation import validate_json


OPERATIONS = ("read", "transfer", "derive", "persist_write", "persist_read", "delegate", "policy_update", "revoke", "stop")
SUPPORTED = ("input_validation", *OPERATIONS, "event_reports", "SS001", "SS002", "SS003", "SS004", "SS005", "SS006")
PROPERTY = "P-CONF-01"


def _plain(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _plain(item) for key, item in value.items()}
    if is_dataclass(value):
        return {field.name: _plain(getattr(value, field.name)) for field in fields(value)}
    if isinstance(value, (tuple, list)):
        return [_plain(item) for item in value]
    return value


def _key(value: Any) -> str:
    return json.dumps(_plain(value), sort_keys=True, ensure_ascii=True,
                      separators=(",", ":"), allow_nan=False)


def _identifier(prefix: str, identity: Any) -> str:
    return prefix + ":" + hashlib.sha256(_key(identity).encode()).hexdigest()[:16]


def _query_record(query: Any) -> dict:
    record = _plain(query)
    record["conditions"] = [
        {"key": key, "possible_values": [json.loads(v) for v in domain]}
        for key, domain in query.conditions
    ]
    return record


def _unsupported(document: dict, validation_items: tuple) -> list[dict]:
    items = [_plain(item) for item in validation_items]
    operations = {item["id"]: item["semantic_kind"]
                  for item in document["context"]["operation_definitions"]}

    def add(identifier, reason, collection, ref, rule=None):
        item = {"id": identifier, "reason": reason, "check_status": "not_checked",
                "affected_refs": {"state": "known", "value": [
                    {"collection": collection, "id": ref}], "evidence_refs": []}}
        if rule:
            item["rule_id"] = rule
        items.append(item)

    for action in sorted(document["actions"], key=lambda x: x["id"]):
        semantic = operations[action["operation_id"]]
        if semantic not in OPERATIONS:
            add("operation:" + action["id"],
                "The current analyzer does not execute " + semantic + " effects.",
                "actions", action["id"])
    for prop in sorted(document["context"]["properties"], key=lambda x: x["id"]):
        if prop["id"] != PROPERTY:
            add("property:" + prop["id"],
                "No semantic checker is defined for this property identifier.",
                "properties", prop["id"])
    if not any(p["id"] == PROPERTY for p in document["context"]["properties"]):
        add("property:missing-supported-property",
            "The supported P-CONF-01 property is not declared; no protected-property check is available.",
            "tasks", document["context"]["root_task"])
    return sorted(items, key=_key)


def analyze_json(document: str | bytes, *, limits: Limits | None = None) -> AnalysisResult:
    """Analyze finite read/transfer/policy effects within supplied model premises."""
    validated = validate_json(document, limits=limits)
    if validated.validation_status != "valid":
        return AnalysisResult(
            analysis_status=validated.validation_status,
            schema_version=validated.schema_version,
            analysis_performed=False,
            diagnostics=validated.diagnostics,
            effective_limits=validated.effective_limits,
            supported_capabilities=SUPPORTED,
        )

    from .controls import Controller
    from .search import explore
    from .semantics import Evaluator
    from .source_rules import source_checks, source_check, influence_checks
    from .delegation import delegation_checks
    from .responsibility import inspect_responsibilities
    from .event_reports import import_reports

    data = validated.model.to_dict()
    budget = Budget(validated.effective_limits)
    evaluator = Evaluator(data, budget)
    controller = Controller(data, evaluator)
    snapshot = data["context"]["snapshot_id"]
    property_present = any(x["id"] == PROPERTY for x in data["context"]["properties"])
    unsupported = _unsupported(data, validated.unsupported_items)
    findings: dict[str, dict] = {}
    unresolved: dict[str, dict] = {}
    obligations: dict[str, dict] = {}
    action_results: dict[str, dict] = {}
    truncation: list[dict] = []
    outcome = None
    modification_results = []
    influence_actions = set()
    supplied_ids = {item["id"] for item in data["obligations"]}
    derived_ids = {}

    def derived_obligation_id(identifier):
        if identifier not in derived_ids:
            candidate = identifier
            while candidate in supplied_ids or candidate in derived_ids.values():
                candidate = "derived:" + candidate
            derived_ids[identifier] = candidate
        return derived_ids[identifier]

    def add_unresolved(item: dict) -> None:
        unresolved.setdefault(_key(item), item)

    def add_finding(identity: dict, record: dict) -> None:
        key = _key(identity)
        if key in findings:
            return
        budget.consume("findings")
        record["finding_id"] = _identifier(record["rule_id"], identity)
        findings[key] = record

    def record_rule(item: dict) -> None:
        record = _plain(item)
        rule = record["rule_id"]
        identity = record.pop("identity", {"obligation_id": record.get("obligation_id")})
        oid = (record["obligation_id"] if rule == "SS006" else
               derived_obligation_id(record.get("obligation_id") or _identifier(rule + "-obligation", identity)))
        record.update(obligation_id=oid, snapshot_id=snapshot)
        record.setdefault("origin", "derived")
        record.setdefault("evidence_basis", ["supplied_assertion", "model_deduction"])
        record.setdefault("environment", "declared_model")
        record.setdefault("observed_effect", "not_tested")
        record.setdefault("witness", [])
        record.setdefault("unresolved_items", record.get("unresolved_reasons", []))
        obligations[oid] = record
        unsettled = record.get("unresolved_reasons", record.get("unresolved_items", []))
        if record["obligation_status"] == "unresolved" or record.get("has_unresolved") or unsettled:
            add_unresolved({"kind": "rule_obligation", "rule_id": rule, "obligation_id": oid,
                            "task_id": record["task_id"], "reasons": unsettled or record.get("reasons", []),
                            "affected_refs": record.get("affected_refs", [])})
        if record["obligation_status"] in ("gap", "unresolved"):
            finding = dict(record)
            finding.pop("obligation_id", None)
            finding.update(obligation_refs=[oid])
            finding["classification"] = finding.get("classification") or (
                "responsibility_review_gap" if rule == "SS006" else "assurance_gap")
            finding.setdefault("affected_objects", [])
            finding.setdefault("affected_refs", [])
            finding.setdefault("feasibility", "not_applicable")
            finding.setdefault("authorization", "not_applicable")
            finding.setdefault("control_effect", "not_applicable")
            finding.setdefault("control_assurance", "unresolved")
            finding.setdefault("repair_locations", finding["affected_refs"])
            finding.setdefault("suggested_verification", "Establish the missing or contradictory conditions within this obligation's scope.")
            add_finding({"rule_id": rule, "obligation_id": oid}, finding)

    def on_step(step: dict) -> None:
        query = step["query"]
        technical = step["technical"]
        authorization = step["authorization"]
        control = step["control"]
        assumptions = tuple(sorted(set(step.get("assumptions", ()))))
        feasibility = {True: "feasible", False: "infeasible", None: "conditional"}[technical.value]
        authorization_status = {True: "allowed", False: "denied", None: "unresolved"}[authorization.value]
        conditional = bool(step.get("conditional", False))
        refs = tuple(sorted(set(technical.evidence_refs + authorization.evidence_refs +
                                tuple(control.evidence_refs) + tuple(step.get("evidence_refs", ())))))
        identity = {
            "task": query.task_id, "action": step["action_id"], "effect": step["effect_id"],
            "query": _query_record(query), "feasibility": feasibility,
            "authorization": authorization_status, "control": control.status,
            "assumptions": assumptions,
        }
        result = {
            "action_id": step["action_id"], "effect_id": step["effect_id"],
            "query": identity["query"], "feasibility": feasibility,
            "authorization": authorization_status, "control_effect": control.status,
            "control_details": _plain(control.details), "check_status": "checked",
            "conditional": conditional, "assumptions": assumptions,
            "necessary_conditions": {"technical": _plain(technical),
                                     "authorization": _plain(authorization)},
            "evidence_refs": refs, "evidence_basis": ("supplied_assertion", "model_deduction"),
            "environment": "declared_model", "observed_effect": "not_tested",
            "witness": _plain(step["path"]),
        }
        action_results.setdefault(_key(identity), result)
        if property_present and step.get("source_details") is not None:
            sources = step["source_details"]
            record_rule(source_check(data, step.get("evaluator", evaluator), budget,
                query.object_version_id, query.task_id, sources.ancestor_ids, sources.restriction_ids,
                sources.completeness, action_id=step["action_id"], witness=result["witness"],
                conditional=conditional or not step["committed"], query=query))
        if property_present:
            for item in influence_checks(data, step.get("evaluator", evaluator), budget, (result,),
                    action_id=step["action_id"], query=query, conditional=conditional):
                record_rule(item)
            influence_actions.add(step["action_id"])
        if query.policy_target is not None:
            modification_results.append({"action_id": step["action_id"], "effect_id": step["effect_id"],
                                         "committed": step["committed"], "conditional": conditional})
        reasons = set()
        if technical.value is None:
            reasons.update(technical.reasons)
        if authorization.value is None:
            reasons.update(authorization.reasons)
        if control.status == "unresolved":
            reasons.update(control.reasons)
        if conditional:
            reasons.update(assumptions)
        if technical.value is not False and (reasons or technical.value is None or authorization.value is None or control.status == "unresolved"):
            add_unresolved({"kind": "action_conditions", "task_id": query.task_id,
                            "action_id": step["action_id"], "effect_id": step["effect_id"],
                            "reasons": tuple(sorted(reasons)), "assumptions": assumptions,
                            "affected_refs": [{"collection": "actions", "id": step["action_id"]}]})

        if not property_present or technical.value is False:
            return
        if query.object_version_id is None:
            if authorization.value is not True and control.status != "blocked_in_model":
                oid = derived_obligation_id(_identifier("policy-boundary", identity))
                obligations[oid] = {"obligation_id": oid, "rule_id": "SS005", "origin": "derived",
                                    "task_id": query.task_id, "property_id": PROPERTY, "snapshot_id": snapshot,
                                    "check_status": "checked", "obligation_status": "unresolved" if conditional or authorization.value is None else "gap"}
                add_finding({**identity, "rule_id": "SS005"}, {
                    "rule_id": "SS005", "classification": "assurance_gap", "property_id": PROPERTY,
                    "task_id": query.task_id, "snapshot_id": snapshot, "affected_objects": [],
                    "affected_refs": ([{"collection": "controls", "id": query.policy_target[0]}]
                                      if query.policy_target else [{"collection": c, "id": i} for c, i in query.management_targets])
                                      + [{"collection": "actions", "id": step["action_id"]}],
                    "obligation_refs": [oid], "necessary_conditions": result["necessary_conditions"],
                    "feasibility": feasibility, "authorization": authorization_status,
                    "control_effect": control.status, "control_assurance": "unresolved",
                    "evidence_basis": ["supplied_assertion", "model_deduction"], "evidence_refs": refs,
                    "environment": "declared_model", "observed_effect": "not_tested",
                    "unresolved_items": tuple(sorted(reasons)), "assumptions": assumptions,
                    "witness": result["witness"], "query": result["query"],
                    "repair_locations": [{"collection": "interfaces", "id": query.interface_id}],
                    "suggested_verification": "Bind the management request to every exact typed target and separately verify its authorization and execution boundary."})
            return
        definite = (technical.value is True and not conditional and authorization.value is False
                    and control.status == "not_blocked_in_model")
        uncertain_boundary = (authorization.value is not True and
                              control.status != "blocked_in_model" and not definite)
        obligation_id = derived_obligation_id(_identifier("path", identity))
        obligation = {
            "obligation_id": obligation_id, "origin": "derived", "rule_id": "SS001",
            "property_id": PROPERTY, "task_id": query.task_id, "snapshot_id": snapshot,
            "action_id": step["action_id"], "effect_id": step["effect_id"],
            "obligation_status": "gap" if definite else "unresolved" if uncertain_boundary else "satisfied_in_model",
            "check_status": "checked", "evidence_refs": refs,
        }
        obligations.setdefault(obligation_id, obligation)
        if definite or uncertain_boundary:
            finding = {
                "rule_id": "SS001",
                "classification": "modeled_boundary_violation" if definite else "assurance_gap",
                "property_id": PROPERTY, "task_id": query.task_id, "snapshot_id": snapshot,
                "affected_objects": [query.object_version_id],
                "affected_refs": [{"collection": "actions", "id": step["action_id"]},
                                  {"collection": "object_versions", "id": query.object_version_id}],
                "obligation_refs": [obligation_id],
                "necessary_conditions": result["necessary_conditions"],
                "feasibility": feasibility, "authorization": authorization_status,
                "control_effect": control.status,
                "evidence_basis": ["supplied_assertion", "model_deduction"],
                "evidence_refs": refs, "environment": "declared_model", "observed_effect": "not_tested",
                "unresolved_items": tuple(sorted(reasons)), "assumptions": assumptions,
                "witness": result["witness"], "query": result["query"],
                "repair_locations": [{"collection": "actions", "id": step["action_id"]},
                                     {"collection": "interfaces", "id": query.interface_id}],
                "suggested_verification": "Check exact task grants, inherited restrictions and pre-effect control against this object and recipient.",
            }
            add_finding({**identity, "rule_id": "SS001", "classification": finding["classification"]}, finding)
        if authorization.value is False and control.status != "blocked_in_model":
            control_obligation = {**obligation, "obligation_id": derived_obligation_id(_identifier("control-path", identity)),
                                  "rule_id": "SS005",
                                  "obligation_status": "gap" if definite else "unresolved"}
            obligations.setdefault(control_obligation["obligation_id"], control_obligation)
            finding = {
                "rule_id": "SS005", "classification": "assurance_gap", "property_id": PROPERTY,
                "task_id": query.task_id, "snapshot_id": snapshot,
                "affected_objects": [query.object_version_id],
                "affected_refs": [{"collection": "actions", "id": step["action_id"]}],
                "obligation_refs": [control_obligation["obligation_id"]],
                "necessary_conditions": {"control": _plain(control.details)},
                "feasibility": feasibility, "authorization": authorization_status,
                "control_effect": control.status, "control_assurance": "unresolved",
                "evidence_basis": ["supplied_assertion", "model_deduction"], "evidence_refs": refs,
                "environment": "declared_model", "observed_effect": "not_tested",
                "unresolved_items": tuple(sorted(reasons)), "assumptions": assumptions,
                "witness": result["witness"], "query": result["query"],
                "repair_locations": [{"collection": "interfaces", "id": query.interface_id}],
                "suggested_verification": "Verify a control covers and binds the actual effect before its recipient receives this version.",
            }
            add_finding({**identity, "rule_id": "SS005", "classification": "assurance_gap"}, finding)

    def record_controls():
        for item in controller.obligations():
            record = _plain(item)
            oid = derived_obligation_id(record["obligation_id"])
            record["obligation_id"] = oid
            obligations[oid] = record
            if record.get("obligation_status") == "unresolved" or record.get("has_unresolved", False):
                add_unresolved({"kind": "control_obligation", "obligation_id": oid,
                                "reasons": record.get("unresolved_reasons", record.get("reasons", ())),
                                "task_ids": record.get("task_ids", ()),
                                "affected_refs": [{"collection": "controls", "id": record["control_id"]}]})
            if record.get("obligation_status") in ("gap", "unresolved"):
                finding = {
                    "rule_id": "SS005", "classification": "assurance_gap",
                    "property_id": record["property_id"], "task_id": record.get("task_id"),
                    "task_ids": record.get("task_ids", ()),
                    "snapshot_id": snapshot, "affected_objects": [],
                    "affected_refs": [{"collection": "controls", "id": record["control_id"]}],
                    "obligation_refs": [oid], "necessary_conditions": record,
                    "feasibility": "not_applicable", "authorization": "not_applicable",
                    "control_effect": "not_applicable", "control_assurance": record.get("control_assurance", "unresolved"),
                    "evidence_basis": ["supplied_assertion", "model_deduction"],
                    "evidence_refs": record.get("evidence_refs", ()),
                    "environment": "declared_model", "observed_effect": "not_tested",
                    "unresolved_items": record.get("unresolved_reasons", ()),
                    "witness": [], "witness_applicability": "Control assurance is an obligation check, not an executed path.",
                    "repair_locations": [{"collection": "controls", "id": record["control_id"]}],
                    "suggested_verification": "Establish property- and snapshot-scoped control evidence and policy-modification isolation.",
                }
                add_finding({"rule_id": "SS005", "obligation_id": oid}, finding)
    try:
        if property_present:
            for item in source_checks(data, evaluator, budget):
                record_rule(item)
            for item in delegation_checks(data, evaluator, budget):
                record_rule(item)
        for item in inspect_responsibilities(data, evaluator, budget):
            record_rule(item)
        outcome = explore(data, evaluator, controller, budget, on_step)
        if not outcome.completed:
            truncation.append({"reason": outcome.truncation_reason, "scope": "remaining_supported_search",
                               "check_status": "partial"})
        controller.modification_results = modification_results
        controller.search_complete = outcome.completed
        record_controls()
        if property_present:
            for action_id in sorted({r["action_id"] for r in data["relations"]
                                     if r["kind"] == "semantic_influence"} - influence_actions):
                for item in influence_checks(data, evaluator, budget, action_id=action_id):
                    record_rule(item)
    except BudgetExceeded as error:
        truncation.append({"reason": error.reason, "scope": "remaining_supported_checks", "check_status": "partial"})

    for supplied in sorted(data["obligations"], key=lambda x: x["id"]):
        if supplied["id"] in obligations:
            continue
        inactive = supplied["applicable"]["state"] == "known" and supplied["applicable"]["value"] is False
        obligations[supplied["id"]] = {
            "obligation_id": supplied["id"], "origin": supplied["origin"], "rule_id": "SS006",
            "task_id": supplied["task_id"], "property_id": supplied["property_id"],
            "check_status": "not_applicable" if inactive else "not_checked",
            "obligation_status": "not_applicable" if inactive else "unresolved",
            "reason": "Declared inapplicable." if inactive else "Responsibility check was not reached within the shared analysis budget.",
            "evidence_refs": supplied["evidence_refs"],
            "evidence_basis": ["supplied_assertion"], "environment": "declared_model",
            "observed_effect": "not_tested", "snapshot_id": snapshot,
        }

    operations = {x["id"]: x["semantic_kind"] for x in data["context"]["operation_definitions"]}
    evaluated = {(x["action_id"], x["effect_id"]) for x in action_results.values()}
    for action in sorted(data["actions"], key=lambda x: x["id"]):
        for effect in sorted(action["effects"], key=lambda x: x["id"]):
            if (action["id"], effect["id"]) in evaluated:
                continue
            unchecked = bool(truncation or unsupported or operations[action["operation_id"]] not in OPERATIONS)
            record = {"action_id": action["id"], "effect_id": effect["id"],
                      "feasibility": "conditional" if unchecked else "infeasible",
                      "authorization": "not_checked", "control_effect": "not_checked",
                      "check_status": "not_checked" if unchecked else "checked",
                      "checked_axes": [] if unchecked else ["feasibility"],
                      "unchecked_axes": ["authorization", "control_effect"],
                      "reason": "Not reached within completed supported search." if not unchecked else "Remaining or unsupported scope was not exhausted.",
                      "witness": [], "environment": "declared_model", "observed_effect": "not_tested"}
            action_results[_key((action["id"], effect["id"], "unreached"))] = record

    coverage = []
    required_collections = ("nodes", "actions", "capabilities", "task_grants", "approval_rights",
                            "release_exceptions", "sources", "restrictions", "controls", "policy_change_paths",
                            "relations", "execution_contexts", "object_versions")
    for task in sorted(data["context"]["tasks"], key=lambda x: x["id"]):
        incomplete = []
        for collection in required_collections:
            decision = evaluator.complete(task["id"], collection)
            if decision.value is not True:
                incomplete.append(collection)
                add_unresolved({"kind": "inventory_completeness", "task_id": task["id"],
                                "collection": collection, "reasons": decision.reasons,
                                "evidence_refs": decision.evidence_refs})
        violations = [f["finding_id"] for f in findings.values()
                      if f["task_id"] == task["id"] and f.get("property_id") == PROPERTY
                      and f["classification"] == "modeled_boundary_violation"]
        disclosure_paths = [f["finding_id"] for f in findings.values()
                            if f["finding_id"] in violations and f["rule_id"] == "SS001"]
        task_unknown = any(
            task["id"] in x["task_ids"] if x.get("task_ids") else x.get("task_id", task["id"]) == task["id"]
            for x in unresolved.values())
        limited = bool(incomplete or truncation or unsupported or task_unknown or not property_present)
        coverage.append({"task_id": task["id"], "snapshot_id": snapshot, "property_id": PROPERTY if property_present else None,
                         "model_coverage": "violated_in_model" if violations else "unresolved" if limited else "covered_in_declared_model",
                         "check_status": "partial" if truncation or unsupported else "checked",
                         "violation_refs": sorted(violations), "incomplete_collections": incomplete,
                         "disclosure_path_refs": sorted(disclosure_paths),
                         "evidence_basis": ["supplied_assertion", "model_deduction"],
                         "environment": "declared_model", "runtime_status": "not_tested"})

    return AnalysisResult(
        analysis_status="partial" if truncation or unsupported else "completed_for_supported_scope",
        schema_version=validated.schema_version, analysis_performed=True,
        findings=tuple(sorted(findings.values(), key=lambda x: x["finding_id"])),
        unresolved_items=tuple(sorted(unresolved.values(), key=_key)),
        obligations=tuple(sorted(obligations.values(), key=_key)),
        input_completeness=tuple(sorted(data["context"]["completeness"], key=_key)),
        supported_capabilities=SUPPORTED, unsupported_items=tuple(unsupported),
        effective_limits=validated.effective_limits, budget_usage=budget.usage,
        truncation=tuple(truncation), action_results=tuple(sorted(action_results.values(), key=_key)),
        coverage=tuple(coverage), scope={key: data["context"][key] for key in
            ("snapshot_id", "as_of", "root_task", "declared_scope", "known_limits")},
        event_reports=tuple(import_reports(data)),
    )
