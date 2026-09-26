"""Obligation-scoped review and preventive intervention in a declared snapshot.

The checker consumes submitted premises. It neither certifies a reviewer nor
converts an imported event, evidence label, or successful call into observation.
"""
from __future__ import annotations

from dataclasses import asdict
from datetime import datetime
from decimal import Decimal

from .analysis_types import Decision, decision_and, decision_or, scalar_key


def _refs(value):
    if isinstance(value, dict):
        return tuple(sorted(set(value.get("evidence_refs", ())) | {
            ref for key, item in value.items() if key != "evidence_refs" for ref in _refs(item)}))
    if isinstance(value, (list, tuple)):
        return tuple(sorted({ref for item in value for ref in _refs(item)}))
    return ()


def _fact(fact, label, predicate=lambda value: value is True):
    if fact["state"] != "known":
        return Decision(None, (label + ":" + fact["state"],), _refs(fact))
    value = predicate(fact["value"])
    return Decision(value, () if value else (label + ":missing_or_mismatched",), _refs(fact))


def _bounds(fact, label, budget):
    budget.consume("clause_checks")
    if fact["state"] != "known":
        return None, Decision(None, (label + ":" + fact["state"],), _refs(fact))
    value = fact["value"]
    if value["upper"] == "unbounded":
        return None, Decision(None, (label + ":unbounded",), _refs(fact))
    return (Decimal(str(value["lower"])), Decimal(str(value["upper"]))), Decision(True, evidence_refs=_refs(fact))


def _response(responsibility, budget):
    response = responsibility["response"]
    if response["state"] != "known" or "kind" not in response["value"]:
        return _bounds(response, "response", budget)
    phases = response["value"]
    budget.consume("clause_checks", 2)
    order = [_fact(phases[field], "response_" + field) for field in ("sequential", "nonoverlapping")]
    durations = [_bounds(phases[field], "response_" + field, budget)
                 for field in ("detection", "escalation", "decision", "stop_effect")]
    refs = _refs(response)
    if any(part.value is not True for part in order) or any(bounds is None for bounds, _ in durations):
        reasons = tuple(reason for part in order + [part for _, part in durations] for reason in part.reasons)
        return None, Decision(None, reasons or ("response_phase_sum_unestablished",), refs)
    return (sum(bounds[0] for bounds, _ in durations), sum(bounds[1] for bounds, _ in durations)), Decision(True, evidence_refs=refs)


def _timing(response, consequence, latency=None):
    response_bounds, response_known = response
    consequence_bounds, consequence_known = consequence
    refs = response_known.evidence_refs + consequence_known.evidence_refs + _refs(latency)
    if response_bounds is None or consequence_bounds is None:
        return Decision(None, response_known.reasons + consequence_known.reasons, refs)
    lower, upper = response_bounds
    if latency is not None and latency["state"] == "known":
        # The end-to-end response already includes stop-effect time. Latency is
        # a lower bound on that response, never another term added to it.
        lower = max(lower, Decimal(str(latency["value"]["lower"])))
    if lower >= consequence_bounds[1]:
        return Decision(False, ("response_too_late",), refs)
    if lower > upper:
        return Decision(None, ("response_intervention_intervals_inconsistent",), refs)
    if upper < consequence_bounds[0]:
        return Decision(True, evidence_refs=refs)
    return Decision(None, ("response_consequence_intervals_overlap",), refs)


def _domains(document, action):
    domains = {item["key"]: {scalar_key(item["value"]["value"])}
               for item in document["context"]["initial_conditions"] if item["value"]["state"] == "known"}
    for condition in action["conditions"]:
        values = condition["value"] if condition["operator"] == "in" else [condition["value"]]
        allowed = {scalar_key(value) for value in values}
        key = condition["key"]
        domains[key] = domains[key] & allowed if key in domains else allowed
    return tuple((key, tuple(sorted(values))) for key, values in sorted(domains.items()))


def _conditions(conditions, action, principal, document, evaluator):
    domains = dict(_domains(document, action))
    if any(not values for values in domains.values()):
        return Decision(False, ("incompatible_action_conditions",))
    results = []
    for condition in conditions:
        evaluator.budget.consume("clause_checks")
        values = condition["value"] if condition["operator"] == "in" else [condition["value"]]
        allowed = {scalar_key(value) for value in values}
        domain = domains.get(condition["key"])
        value = None if domain is None else False if not set(domain) & allowed else True if set(domain) <= allowed else None
        results.append(Decision(value, () if value is True else ("condition_unestablished:" + condition["key"],), _refs(condition)))
    return decision_and(results)


def _observation(action, principal, relations, document, evaluator, budget):
    interface = evaluator.interfaces[action["interface_id"]]
    starts = {("actions", action["id"]), ("nodes", action["actor_id"]), ("nodes", interface["node_id"])}
    reachable = {source: Decision(True) for source in starts}
    observations = {}
    # Each node can improve at most twice (unknown to true). This checks the
    # named observation path, with each edge charged to the shared budget.
    pending = list(sorted(starts))
    while pending:
        source = pending.pop(0)
        for relation in relations:
            budget.consume("clause_checks")
            if (relation["source"]["collection"], relation["source"]["id"]) != source:
                continue
            phase = Decision(True)
            if source in starts:
                kinds = set(relation["event_kinds"])
                if not kinds & {"proposal", "attempt", "policy_decision"}:
                    phase = Decision(None, ("observation_before_effect_unestablished",)) if "execution" in kinds else Decision(False, ("observation_after_protected_effect",))
            path = decision_and(reachable[source], phase,
                                _conditions(relation["conditions"], action, principal, document, evaluator),
                                Decision(True, evidence_refs=_refs(relation)))
            target = ("nodes", relation["observer_id"])
            observations[target] = decision_or(observations.get(target, Decision(False)), path)
            old = reachable.get(target, Decision(False))
            value = decision_or(old, path)
            if value.value != old.value:
                reachable[target] = value
                if value.value is not False:
                    pending.append(target)
    result = observations.get(("nodes", principal))
    if result is not None:
        return result
    return Decision(False, ("no_preventive_observation_path:" + action["id"],), _refs(relations))


def _covers(target, action, evaluator):
    return ((target["collection"] == "actions" and target["id"] == action["id"])
            or (target["collection"] == "interfaces" and target["id"] == action["interface_id"])
            or (target["collection"] == "nodes" and target["id"] in
                (action["actor_id"], evaluator.interfaces[action["interface_id"]]["node_id"])))


def _intervention_authority(relation, protected, principal, document, evaluator, budget):
    from .analysis_types import management_query

    budget.consume("clause_checks")
    if relation["actor_id"] != principal:
        result = Decision(None, ("intervention_principal_path_unestablished",), _refs(relation))
        return result, Decision(True), result
    if relation["operation"] == "revoke":
        # Removing one credential does not establish that all alternative
        # technical paths are stopped. State search retains that distinction.
        result = Decision(None, ("revocation_prevention_requires_path_check",), _refs(relation))
        return result, Decision(True), result
    if not _covers(relation["target"], protected, evaluator):
        result = Decision(False, ("intervention_target_mismatch",), _refs(relation))
        return result, Decision(True), result
    selected = relation["capability_refs"]
    outcomes, orders, ordered_authorities = [], [], []
    for action in sorted(document["actions"], key=lambda item: item["id"]):
        budget.consume("clause_checks")
        if action["actor_id"] != principal or action["task_id"] != protected["task_id"]:
            continue
        for effect in action["effects"]:
            budget.consume("clause_checks")
            if effect["kind"] != "stop" or effect["target"] != relation["target"]:
                continue
            query = management_query(action, effect, document, _domains(document, protected))
            capabilities = []
            if selected["state"] == "known":
                for capability in evaluator.authorities["capabilities"]:
                    budget.consume("clause_checks")
                    if capability["id"] in selected["value"]:
                        capabilities.append(decision_and(evaluator._clauses(capability, query),
                            evaluator._temporal(capability, query),
                            _fact(capability["issuer"], "intervention_capability_issuer", lambda value: bool(value))))
                if not capabilities:
                    capabilities.append(Decision(False, ("intervention_capabilities_empty",), _refs(selected)))
            else:
                capabilities.append(Decision(None, ("intervention_capabilities:" + selected["state"],), _refs(selected)))
            free_interface = _fact(evaluator.interfaces[action["interface_id"]]["credential_required"],
                                   "intervention_interface_requires_credential", lambda value: value is False)
            availability = Decision(None, ("intervention_action_prerequisites_unresolved",)) if action["inputs"] or action["success_dependencies"] else Decision(True)
            authority = decision_and(decision_or(free_interface, decision_or(capabilities)), evaluator.task_grant(query), availability,
                _conditions(action["conditions"] + relation["conditions"], protected, principal, document, evaluator))
            outcomes.append(authority)
            order = Decision(True)
            if authority.value is not False:
                stop_at, protected_at = action["effect_time"], protected["effect_time"]
                if stop_at["state"] == protected_at["state"] == "known":
                    before = datetime.fromisoformat(stop_at["value"]) < datetime.fromisoformat(protected_at["value"])
                    order = Decision(before, () if before else ("intervention_action_not_before_protected_effect",), _refs([stop_at, protected_at]))
                # Relative intervals use the declared trigger; absolute times
                # additionally reject contradictory fixed candidate timings.
                orders.append(order)
            ordered_authorities.append(decision_and(authority, order))
    if not outcomes:
        complete = evaluator.complete(protected["task_id"], "actions")
        result = Decision(False if complete.value is True else None,
                          ("intervention_action_unavailable" if complete.value is True else "intervention_action_unestablished",), _refs(relation))
        return result, Decision(True), result
    return (decision_and(decision_or(outcomes), Decision(True, evidence_refs=_refs(relation))),
            decision_or(orders) if orders else Decision(True), decision_or(ordered_authorities))


def inspect_responsibilities(document, evaluator, budget):
    """Yield checked SS006 obligation records; the caller creates findings.

    Capability checks apply to the declared initial snapshot. Any unestablished
    prerequisite remains unknown; no executed intervention is inferred.
    """
    relations = {item["id"]: item for item in document["relations"]}
    actions = {item["id"]: item for item in document["actions"]}
    for obligation in sorted(document["obligations"], key=lambda item: item["id"]):
        budget.consume("clause_checks")
        responsibility = obligation["responsibility"]
        applicable = _fact(obligation["applicable"], "applicability")
        base = {"obligation_id": obligation["id"], "origin": obligation["origin"], "rule_id": "SS006",
                "task_id": obligation["task_id"], "property_id": obligation["property_id"],
                "snapshot_id": document["context"]["snapshot_id"], "affected_refs": obligation["affected_refs"],
                "evidence_basis": ("supplied_assertion", "model_deduction"), "environment": "declared_model",
                "observed_effect": "not_tested", "witness": [],
                "witness_applicability": "Responsibility checks use scoped premises and no executed action witness."}
        if applicable.value is False:
            yield {**base, "check_status": "not_applicable", "obligation_status": "not_applicable",
                   "reason": "Declared inapplicable to property " + obligation["property_id"] + " and task " + obligation["task_id"] + ".",
                   "necessary_conditions": {"applicable": asdict(applicable)}, "evidence_refs": _refs(obligation),
                   "has_unresolved": False, "reasons": (), "unresolved_reasons": ()}
            continue
        checks = {"applicable": applicable,
                  "principal": _fact(responsibility["principal"], "responsible_principal", lambda value: bool(value))}
        for field in ("inspectable_basis", "verification_reliable", "reviewer_capable"):
            budget.consume("clause_checks")
            checks[field] = _fact(responsibility[field], field)
        response = _response(responsibility, budget)
        consequence = _bounds(responsibility["consequence_window"], "consequence_window", budget)
        checks["timeliness"] = _timing(response, consequence)
        scoped = obligation["action_refs"]
        known_scope = scoped["state"] == "known" and bool(scoped["value"])
        checks["protected_action_scope"] = Decision(True, evidence_refs=_refs(scoped)) if known_scope else Decision(None, ("protected_action_scope_unestablished",), _refs(scoped))
        principal = responsibility["principal"].get("value")
        observation_results, authority_results, ready_results, timing_results = [], [], [], []
        details = []
        if known_scope and checks["principal"].value is True:
            for identifier in sorted(scoped["value"]):
                budget.consume("clause_checks")
                protected = actions[identifier]
                if protected["task_id"] != obligation["task_id"]:
                    checks["protected_action_scope"] = Decision(False, ("protected_action_task_mismatch",), _refs(scoped))
                observed = responsibility["observation_refs"]
                observation_results.append(_observation(protected, principal, [relations[ref] for ref in observed["value"]], document, evaluator, budget)
                                           if observed["state"] == "known" else Decision(None, ("observation_refs:" + observed["state"],), _refs(observed)))
                interventions = responsibility["intervention_refs"]
                authority, ready, timing = [], [], []
                if interventions["state"] == "known":
                    for ref in sorted(interventions["value"]):
                        relation = relations[ref]
                        auth, order, ordered_authority = _intervention_authority(relation, protected, principal, document, evaluator, budget)
                        duration = _timing(response, consequence, relation["latency"])
                        timely = decision_and(duration, order)
                        authority.append(auth)
                        ready.append(decision_and(ordered_authority, duration))
                        if auth.value is not False:
                            timing.append(timely)
                        details.append({"action_id": identifier, "relation_id": ref,
                                        "stop_authority": asdict(auth), "timeliness": asdict(timely)})
                    authority_results.append(decision_or(authority) if authority else Decision(False, ("intervention_refs_empty",)))
                    ready_results.append(decision_or(ready) if ready else Decision(False, ("intervention_refs_empty",)))
                    timing_results.append(decision_or(timing) if timing else checks["timeliness"])
                else:
                    missing = Decision(None, ("intervention_refs:" + interventions["state"],), _refs(interventions))
                    authority_results.append(missing)
                    ready_results.append(missing)
        else:
            missing = Decision(None, ("responsibility_scope_or_principal_unestablished",))
            observation_results.append(missing)
            authority_results.append(missing)
            ready_results.append(missing)
        checks["observation_path"] = decision_and(observation_results)
        checks["stop_authority"] = decision_and(authority_results)
        checks["timely_authorized_intervention"] = decision_and(ready_results)
        if timing_results:
            checks["timeliness"] = decision_and(timing_results)
        if obligation["unknown_items"]:
            checks["declared_unknown_items"] = Decision(None, tuple(obligation["unknown_items"]))
        unresolved = tuple(sorted({reason for value in checks.values() if value.value is None for reason in value.reasons}))
        reasons = tuple(sorted({reason for value in checks.values() if value.value is not True for reason in value.reasons}))
        status = ("unresolved" if applicable.value is None else "gap" if any(value.value is False for value in checks.values())
                  else "unresolved" if any(value.value is None for value in checks.values()) else "satisfied_in_model")
        yield {**base, "check_status": "checked", "obligation_status": status,
               "necessary_conditions": {name: asdict(value) for name, value in checks.items()},
               "interventions": details, "has_unresolved": bool(unresolved), "reasons": reasons,
               "unresolved_reasons": unresolved,
               "evidence_refs": tuple(sorted(set(_refs(obligation)) | {ref for part in checks.values() for ref in part.evidence_refs})),
               "scope_limit": "Declared responsibility and initial authority for these actions; no runtime response, personnel certification, or organization-wide capacity test."}
