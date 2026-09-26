"""Bounded, complete-clause containment of explicitly delegated task grants.

The comparison maps only the parent and child identities in one relation. It
checks declared child authority even when no action can acquire credentials.
Finite condition partitions and validity endpoints make universal coverage
checkable without combining unrelated fields from separate parent clauses.
"""
from __future__ import annotations

from dataclasses import replace
from itertools import product

from .analysis_types import BudgetExceeded, Decision, Query, decision_and, decision_or, scalar_key
from .semantics import _refs, _time


_DIMENSIONS = ("tasks", "actors", "operations", "interfaces", "recipients",
               "purposes", "workflows")


class _PartialDelegation(BudgetExceeded):
    """Carry a proved counterexample through exhaustion of remaining scope."""

    def __init__(self, resource, decision):
        super().__init__(resource)
        self.decision = decision


def _conditions(conditions):
    domains = {}
    for condition in conditions:
        values = condition["value"] if condition["operator"] == "in" else [condition["value"]]
        current = {scalar_key(value) for value in values}
        key = condition["key"]
        domains[key] = domains[key] & current if key in domains else current
    return domains


def _condition_domains(child_clause, relation, records):
    """Partition unrestricted scalar domains by all mentioned equality values."""
    child = _conditions([*child_clause["conditions"], *relation["conditions"]])
    mentioned = {}
    for record in records:
        for clause in record["clauses"]:
            for key, values in _conditions(clause["conditions"]).items():
                mentioned.setdefault(key, set()).update(values)
    for key, values in mentioned.items():
        if key not in child:
            other = "__sst_other_condition_value__"
            while scalar_key(other) in values:
                other += "_"
            child[key] = values | {scalar_key(other)}
    return tuple((key, tuple(sorted(values))) for key, values in sorted(child.items()))


def _instants(child, records, state_times=()):
    """One representative at every change in the half-open validity window."""
    interval = child["validity"]["value"]
    lower = _time(interval["not_before"])
    upper = None if interval["expires_at"] == "unbounded" else _time(interval["expires_at"])
    revocation = child["revocation"]
    if revocation["state"] == "known" and revocation["value"]["revoked"]:
        when = revocation["value"]["at"]
        if when != "not_applicable":
            revoked = _time(when)
            upper = revoked if upper is None else min(upper, revoked)
    if upper is not None and upper <= lower:
        return ()
    points = {lower}
    points.update(_time(value) for value in state_times if value is not None)
    for record in records:
        validity = record["validity"]
        if validity["state"] == "known":
            value = validity["value"]
            points.add(_time(value["not_before"]))
            if value["expires_at"] != "unbounded":
                points.add(_time(value["expires_at"]))
        revoked = record["revocation"]
        if revoked["state"] == "known" and revoked["value"]["revoked"]:
            when = revoked["value"]["at"]
            if when != "not_applicable":
                points.add(_time(when))
    return tuple(point.isoformat() for point in sorted(points)
                 if point >= lower and (upper is None or point < upper))


def _targets(clause):
    """Return data versions or one compound target from a management clause."""
    objects = clause["objects"]
    if objects["state"] != "known":
        return None
    values = [(item, None, None) for item in objects["value"]]
    for field in ("policy_targets", "management_targets"):
        targets = clause.get(field)
        if targets is None:
            continue
        if targets["state"] != "known":
            return None
        # Typed management authorization always requires an empty data scope.
        if objects["value"]:
            continue
        if field == "policy_targets":
            values.extend((None, (item["control_id"], item["policy_version_id"],
                                  tuple(sorted(item["fields"]))), None)
                          for item in targets["value"])
        elif targets["value"]:
            values.append((None, None, tuple(sorted((item["collection"], item["id"])
                                                   for item in targets["value"]))))
    return tuple(values)


def _extension(child, relation, query, evaluator):
    refs = relation["extension_approval_refs"]
    # Only references explicitly attached to this delegation can extend it.
    proxy = dict(child, approval_refs=refs)
    return evaluator._approval(proxy, query, "issue_task_grant")


def _parent_temporal(parent, query, evaluator, activatable):
    active = parent["initially_active"]
    if active["state"] == "known" and active["value"] is False and parent["id"] in activatable:
        # A candidate effect is a possible state transition, not a successful
        # activation. Preserve the uncertainty without removing other denials.
        possible = dict(parent, initially_active={
            "state": "unknown", "reason": "Declared activation has not been established",
            "evidence_refs": list(_refs(active))})
        return decision_and(evaluator._temporal(possible, query),
                            evaluator._state_liveness(parent, query))
    return evaluator._temporal(parent, query)


def _child_decisions(child, relation, evaluator, budget):
    parents = [record for record in evaluator.authorities["task_grants"]
               if record["id"] in relation["parent_grant_ids"]]
    approvals = evaluator.authorities["approval_rights"]
    records = (*parents, *approvals)
    if child["validity"]["state"] != "known":
        yield Decision(None, (f"{child['id']}: child validity unresolved",),
                       _refs(child["validity"]))
        return
    state_times = (instant for table in (evaluator._activated, evaluator._revoked)
                   for values in table.values() for instant in values)
    instants = _instants(child, records, state_times)
    activatable = {identifier for action in evaluator.document["actions"]
                   for effect in action["effects"] if effect["kind"] == "activate_authorizations"
                   for identifier in effect["task_grant_ids"]}
    # Activation is checked in the state machine. Inactive declarations still
    # carry a scope that must be contained before or after their activation.
    temporal_child = dict(child, initially_active={"state": "known", "value": True,
                                                   "evidence_refs": []})
    for clause in child["clauses"]:
        targets = _targets(clause)
        unknown = [field for field in _DIMENSIONS if clause[field]["state"] != "known"]
        if unknown or targets is None:
            yield Decision(None, (f"{child['id']}: child scope unresolved",),
                           tuple(ref for field in (*_DIMENSIONS, "objects")
                                 for ref in _refs(clause[field])))
            continue
        condition_domains = _condition_domains(clause, relation, records)
        dimensions = [tuple(clause[field]["value"]) for field in _DIMENSIONS]
        conditions = product(*(values for _, values in condition_domains))
        # Enumerate conditions outside the scope product without materializing
        # the Cartesian set; every actual combination consumes shared budget.
        for condition_values in conditions:
            concrete_conditions = tuple((key, (value,)) for (key, _), value
                                        in zip(condition_domains, condition_values))
            for scope_values in product(*dimensions, targets, instants):
                budget.consume("scope_combinations")
                task, actor, operation, interface, recipient, purpose, workflow, target, instant = scope_values
                object_id, policy_target, management_targets = target
                query = Query(task, actor, object_id, operation, interface, recipient,
                              purpose, instant, workflow, concrete_conditions, policy_target)
                if management_targets is not None:
                    query = replace(query, management_targets=management_targets)
                child_time = evaluator._temporal(temporal_child, query)
                if child_time.value is False:
                    continue
                if task != relation["child_task_id"] or actor != relation["child_actor_id"]:
                    covered = Decision(False, ("child actor/task outside explicit delegation mapping",))
                else:
                    parent_query = replace(query, task_id=relation["parent_task_id"],
                                           actor_id=relation["parent_actor_id"])
                    candidate = [decision_and(evaluator._clauses(parent, parent_query),
                                              _parent_temporal(parent, parent_query, evaluator, activatable),
                                              evaluator._approval(parent, parent_query,
                                                                  "issue_task_grant"))
                                 for parent in parents]
                    covered = evaluator._inventory_or(candidate, relation["parent_task_id"],
                                                       "task_grants")
                    covered = decision_or(covered, _extension(child, relation, query, evaluator))
                    covered = decision_and(covered,
                                           evaluator._approval(child, query, "issue_task_grant"))
                if child_time.value is None and covered.value is not True:
                    covered = Decision(None, tuple(sorted(set((*covered.reasons,
                                                               *child_time.reasons)))),
                                       (*covered.evidence_refs, *child_time.evidence_refs))
                if covered.value is False:
                    covered = Decision(False, (*covered.reasons,
                                               f"{child['id']}: uncovered complete child combination at {instant}"),
                                       covered.evidence_refs)
                yield covered


def _child_decision(child, relation, evaluator, budget):
    results = []
    try:
        for decision in _child_decisions(child, relation, evaluator, budget):
            results.append(decision)
    except BudgetExceeded as error:
        if any(result.value is False for result in results):
            raise _PartialDelegation(error.resource, decision_and(results)) from error
        raise
    return decision_and(results)


def delegation_decision(relation, evaluator, budget):
    """Compare all declared child grants; never supply technical credentials."""
    children = {record["id"]: record for record in evaluator.authorities["task_grants"]}
    return decision_and(_child_decision(children[child_id], relation, evaluator, budget)
                        for child_id in relation["child_grant_ids"])


def delegation_checks(document, evaluator, budget):
    """Yield SS003 obligations independently of runtime reachability."""
    children = {record["id"]: record for record in evaluator.authorities["task_grants"]}
    for relation in sorted(document["relations"], key=lambda value: value["id"]):
        if relation["kind"] != "delegation":
            continue
        for child_id in sorted(relation["child_grant_ids"]):
            child = children[child_id]
            truncated = None
            try:
                decision = _child_decision(child, relation, evaluator, budget)
            except _PartialDelegation as error:
                decision, truncated = error.decision, error
            objects = sorted({value for clause in child["clauses"]
                              if clause["objects"]["state"] == "known"
                              for value in clause["objects"]["value"]})
            status = "satisfied_in_model" if decision.value is True else "gap" if decision.value is False else "unresolved"
            yield {"rule_id": "SS003", "identity": f"{relation['id']}:{child_id}",
                   "obligation_status": status, "check_status": "partial" if truncated else "checked",
                   "classification": "modeled_boundary_violation" if decision.value is False
                   else "assurance_gap" if decision.value is None else None,
                   "task_id": relation["child_task_id"], "property_id": "P-CONF-01",
                   "affected_objects": objects,
                   "affected_refs": [{"collection": "relations", "id": relation["id"]},
                                     {"collection": "task_grants", "id": child_id}],
                   "necessary_conditions": {"relation_conditions": relation["conditions"],
                                              "scope_comparison": "complete_child_combinations"},
                   "reasons": list(decision.reasons),
                   "unresolved_items": [truncated.reason] if truncated else
                   list(decision.reasons) if decision.value is None else [],
                   "evidence_refs": sorted(set((*relation["evidence_refs"],
                                                *child["evidence_refs"], *decision.evidence_refs))),
                   "witness": []}
            if truncated:
                # Yield the proved violation before signalling that remaining
                # supported work was not exhausted to the shared orchestrator.
                raise truncated
