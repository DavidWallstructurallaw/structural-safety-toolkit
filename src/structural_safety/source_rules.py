"""Narrow source consistency and explicit semantic-influence checks.

These checks inspect model declarations. They neither infer influence from
shared context nor turn a supplied event or evidence label into an observation.
Search can supply branch-local ancestry to ``source_check`` after a production.
"""

from dataclasses import asdict, replace

from .analysis_types import Decision, Query, decision_and, decision_or, management_query, scalar_key


PROPERTY = "P-CONF-01"


def _refs(fact):
    return tuple(sorted(set(fact.get("evidence_refs", ())) | {
        ref for candidate in fact.get("candidates", ()) for ref in candidate["evidence_refs"]}))


def _known(fact, label, predicate=lambda value: True):
    if fact["state"] != "known":
        return Decision(None, (label + ": " + fact["state"],), _refs(fact))
    value = predicate(fact["value"])
    return Decision(value, () if value else (label,), _refs(fact))


def _as_record(rule, identity, task_id, decision, affected_objects, affected_refs,
               *, classification=None, witness=(), necessary=None, action_id=None,
               applicability="applicable"):
    return {
        "rule_id": rule, "identity": identity, "task_id": task_id, "property_id": PROPERTY,
        "obligation_status": "not_applicable" if applicability == "not_applicable" else
        {True: "satisfied_in_model", False: "gap", None: "unresolved"}[decision.value],
        "check_status": "not_applicable" if applicability == "not_applicable" else "checked",
        "classification": classification if decision.value is not True else None,
        "affected_objects": sorted(set(affected_objects)), "affected_refs": affected_refs,
        "necessary_conditions": necessary or {}, "reasons": list(decision.reasons),
        "unresolved_items": list(decision.reasons) if decision.value is None else [],
        "evidence_refs": list(decision.evidence_refs),
        "evidence_basis": ["supplied_assertion", "model_deduction"],
        "environment": "declared_model", "observed_effect": "not_tested",
        "feasibility": "not_applicable", "authorization": "not_applicable",
        "control_effect": "not_applicable", "witness": list(witness),
        "witness_applicability": "Declaration consistency does not establish an executed effect."
        if not witness else "Finite model path; execution was not observed.",
        "action_id": action_id,
        "repair_locations": affected_refs,
        "suggested_verification": "Check declared lineage and authority against exact inputs, context and scoped approvals.",
    }


def _queries(action, document):
    outputs = {port["port_id"]: port for port in action["outputs"]}
    for effect in sorted(action["effects"], key=lambda item: item["id"]):
        if effect["kind"] in ("select_policy", "activate_authorizations", "revoke", "stop"):
            yield management_query(action, effect, document)
        elif effect.get("output_port_id") in outputs:
            port = outputs[effect["output_port_id"]]
            yield Query(action["task_id"], action["actor_id"], port["object_version_id"],
                        action["operation_id"], action["interface_id"], port["location_node_id"],
                        action["purpose_id"], action["effect_time"].get("value"), action["workflow_id"])


def authority_approval(authority, object_id, query, evaluator):
    """Check a referenced instruction approval against one whole action tuple.

    The current model uses ``issue_task_grant`` for task/policy instruction
    approval. Release rights cannot supply it. Snapshot declarations without an
    action tuple cannot establish a scoped approval merely by naming a record.
    """
    status = authority["status"]
    if status["state"] != "known":
        return _known(status, "instruction authority status")
    if status["value"] == "none":
        return Decision(True, (), _refs(status))
    refs = authority["approval_refs"]
    if refs["state"] == "known" and not refs["value"]:
        return Decision(False, ("instruction authority has no approval references",), _refs(refs))
    if query is None:
        return Decision(None, ("instruction approval action scope is unavailable",), _refs(refs))
    scope = _known(authority["task_ids"], "instruction authority task scope",
                   lambda ids: query.task_id in ids)
    if status["value"] == "policy":
        control = query.policy_target[0] if query.policy_target else None
        scope = decision_and(scope, _known(authority["control_ids"],
                             "instruction authority control scope", lambda ids: control in ids))
        if query.policy_target is None:
            return Decision(None, ("instruction policy target is unavailable",), scope.evidence_refs)
    elif query.policy_target is not None:
        return Decision(False, ("task instruction authority cannot select a policy",), scope.evidence_refs)
    approval_query = query if query.object_version_id is None else replace(query, object_version_id=object_id)
    candidates = []
    for approval in evaluator.authorities["approval_rights"]:
        evaluator.budget.consume("scope_combinations")
        listed = _known(refs, "instruction approval reference", lambda ids: approval["id"] in ids)
        if listed.value is False:
            continue
        candidates.append(decision_and(
            listed, scope, Decision("issue_task_grant" in approval["rights"],
                                    () if "issue_task_grant" in approval["rights"] else
                                    ("approval does not authorize task instructions",),
                                    tuple(approval["evidence_refs"])),
            evaluator._clauses(approval, approval_query), evaluator._temporal(approval, approval_query)))
    decision = evaluator._inventory_or(candidates, query.task_id, "approval_rights")
    if decision.value is False:
        return Decision(False, decision.reasons + ("instruction authority lacks a valid scoped approval",),
                        decision.evidence_refs)
    return decision


def _inherits_authority(output, ancestors, objects):
    """A transform cannot increase any known parent's instruction authority."""
    authority = output["instruction_authority"]
    status = authority["status"]
    if status["state"] != "known":
        return _known(status, "output instruction authority")
    if status["value"] == "none":
        return Decision(True)
    decisions = []
    for ancestor in sorted(set(ancestors) - {output["id"]}):
        parent = objects[ancestor]["instruction_authority"]
        decisions.append(_known(parent["status"], ancestor + ": instruction authority promotion",
                                lambda value: value == status["value"]))
        for field in ("task_ids", "control_ids"):
            child_scope = authority[field]
            if child_scope["state"] != "known":
                decisions.append(_known(child_scope, "output " + field))
            else:
                decisions.append(_known(parent[field], ancestor + ": instruction scope expansion",
                                        lambda ids, scope=child_scope["value"]: set(scope) <= set(ids)))
    # Root declarations have no inherited instruction authority to compare.
    return decision_and(decisions) if decisions else Decision(True)


def source_check(document, evaluator, budget, object_id, task_id, expected_ancestors,
                 expected_restrictions, completeness, *, action_id=None, witness=(),
                 conditional=False, query=None):
    """Compare one declared output with certain sources from a specific state.

    Known discrepancies survive an additional unknown source. ``completeness``
    concerns the expected source set; a false or unknown value cannot certify an
    otherwise matching output. Unknown declaration fields remain unresolved.
    """
    budget.consume("scope_combinations")
    objects = evaluator.objects
    output = objects[object_id]
    required = set(expected_ancestors) - {object_id}
    decisions, details = [], {}
    declared = set()
    if output["parents"]["state"] == "known":
        for parent in output["parents"]["value"]:
            source = evaluator.source_details(parent, task_id)
            declared.update(source.ancestor_ids)
    for field, complete_field, wanted, actual in (
        ("parents", "parents_complete", required, declared),
        ("restriction_ids", "restrictions_complete", set(expected_restrictions),
         set(output["restriction_ids"].get("value", ()))
         if output["restriction_ids"]["state"] == "known" else set()),
    ):
        value = output[field]
        missing = sorted(wanted - actual)
        details["missing_" + field] = missing
        if value["state"] != "known":
            decisions.append(_known(value, "declared " + field))
        elif missing:
            declared_complete = output[complete_field]
            certain = declared_complete["state"] == "known" and declared_complete["value"] is True
            decisions.append(Decision(False if certain else None,
                                      ("declared " + field + " omits " + ", ".join(missing),),
                                      _refs(value) + _refs(declared_complete)))
        else:
            declared_complete = output[complete_field]
            decisions.append(Decision(True) if declared_complete["state"] == "known" and
                             declared_complete["value"] is True else
                             Decision(None, ("declared " + field + " completeness unresolved",),
                                      _refs(declared_complete)))
    inheritance = _inherits_authority(output, required, objects)
    if inheritance.value is not True:
        approved = authority_approval(output["instruction_authority"], object_id, query, evaluator)
        decisions.append(decision_or(inheritance, approved))
        details["authority_inheritance"] = {"value": inheritance.value, "reasons": inheritance.reasons}
        details["authority_approval"] = {"value": approved.value, "reasons": approved.reasons}
    if completeness.value is not True:
        decisions.append(Decision(None, completeness.reasons or ("expected source inventory incomplete",),
                                  completeness.evidence_refs))
    decisions.append(Decision(True, (), tuple(output["evidence_refs"])))
    result = decision_and(decisions)
    result = Decision(result.value, result.reasons,
                      tuple(ref for part in decisions for ref in part.evidence_refs))
    # Conditional production does not establish that the discrepancy occurs.
    if conditional and result.value is False:
        result = Decision(None, result.reasons + ("production path is conditional",), result.evidence_refs)
    details.update(expected_ancestors=sorted(required), expected_restrictions=sorted(expected_restrictions),
                   source_completeness={"value": completeness.value, "reasons": completeness.reasons})
    refs = [{"collection": "object_versions", "id": object_id}]
    if action_id:
        refs.append({"collection": "actions", "id": action_id})
    record = _as_record("SS004", {"object_id": object_id, "action_id": action_id,
                               "expected_ancestors": sorted(required), "details": details,
                               "scope": "candidate_path" if witness else "declaration",
                               "query": asdict(query) if query is not None else None,
                               "conditional": conditional,
                               "decision": {"value": result.value, "reasons": result.reasons}},
                      task_id, result, [object_id, *required], refs,
                      classification="modeled_boundary_violation" if result.value is False else "assurance_gap",
                      witness=witness, necessary=details, action_id=action_id)
    unresolved = {reason for part in decisions if part.value is None for reason in part.reasons}
    if conditional:
        unresolved.add("production path is conditional")
    record.update(has_unresolved=bool(unresolved), unresolved_reasons=sorted(unresolved),
                  unresolved_items=sorted(unresolved))
    return record


def source_checks(document, evaluator, budget):
    """Check snapshot lineage and finite declared production input consistency."""
    actions = {action["id"]: action for action in document["actions"]}
    for obj in sorted(document["object_versions"], key=lambda item: item["id"]):
        parents = obj["parents"]
        if obj["origin_kind"] != "derived" and not (parents["state"] == "known" and parents["value"]):
            continue
        action = actions.get(obj["production"].get("action_id"))
        task_id = action["task_id"] if action else document["context"]["root_task"]
        details = evaluator.source_details(obj["id"], task_id)
        ancestors, restrictions = set(details.ancestor_ids), set(details.restriction_ids)
        completeness = details.completeness
        query = None
        if action:
            output_ports = {port["port_id"]: port for port in action["outputs"]}
            effects = [effect for effect in action["effects"] if effect["kind"] == "produce" and
                       output_ports.get(effect["output_port_id"], {}).get("object_version_id") == obj["id"]]
            input_ids = {port_id for effect in effects for port_id in effect["input_port_ids"]}
            expected = {port["object_version_id"] for port in action["inputs"] if port["port_id"] in input_ids}
            # Context retention can change before production. Only the search
            # callback supplies its actual branch-local generation visibility.
            for object_id in sorted(expected):
                budget.consume("scope_combinations")
                source = evaluator.source_details(object_id, task_id)
                ancestors.update(source.ancestor_ids)
                restrictions.update(source.restriction_ids)
                completeness = decision_and(completeness, source.completeness)
            query = next((q for q in _queries(action, document) if q.object_version_id == obj["id"]), None)
        yield source_check(document, evaluator, budget, obj["id"], task_id, ancestors, restrictions,
                           completeness, action_id=action["id"] if action else None, query=query)


def _relation_conditions(document, action, relation, budget, state_conditions=None):
    domains = {}
    unknown = set()
    for binding in document["context"]["initial_conditions"]:
        if binding["value"]["state"] == "known":
            domains[binding["key"]] = {scalar_key(binding["value"]["value"])}
    if state_conditions is not None:
        for key, domain in state_conditions:
            values = set(domain)
            domains[key] = domains[key] & values if key in domains else values
            if not domains[key]:
                return Decision(False, ("semantic influence state conditions are incompatible",)), ()
    for item in [*action["conditions"], *relation["conditions"]]:
        budget.consume("scope_combinations")
        values = item["value"] if item["operator"] == "in" else [item["value"]]
        values = {scalar_key(value) for value in values}
        if item["key"] not in domains:
            unknown.add(item["key"])
            domains[item["key"]] = values
        else:
            if not domains[item["key"]] <= values:
                unknown.add(item["key"])
            domains[item["key"]] &= values
        if not domains[item["key"]]:
            return Decision(False, ("semantic influence conditions are incompatible",)), ()
    normalized = tuple((key, tuple(sorted(values))) for key, values in sorted(domains.items()))
    return Decision(None if unknown else True,
                    tuple("semantic influence condition unresolved: " + key for key in sorted(unknown))), normalized


def influence_checks(document, evaluator, budget, action_results=(), *, action_id=None,
                     query=None, conditional=False):
    """Inspect explicit influence relations without inferring adoption or success."""
    actions = {action["id"]: action for action in document["actions"]}
    for relation in sorted(document["relations"], key=lambda item: item["id"]):
        if relation["kind"] != "semantic_influence" or (action_id is not None and
                                                        relation["action_id"] != action_id):
            continue
        budget.consume("scope_combinations")
        action = actions[relation["action_id"]]
        obj = evaluator.objects[relation["source_object_id"]]
        refs = [{"collection": "relations", "id": relation["id"]},
                {"collection": "actions", "id": action["id"]},
                {"collection": "object_versions", "id": obj["id"]}]
        conditions, domains = _relation_conditions(document, action, relation, budget,
                                                   query.conditions if query is not None else None)
        matches_context = relation["context_id"] == action["context_id"]
        necessary = {"source_object_id": obj["id"], "action_id": action["id"],
                     "context_id": relation["context_id"], "slot": relation["slot"],
                     "influence_adopted": "not_established", "grants_technical_capability": False}
        if not matches_context or conditions.value is False:
            result = Decision(True, ("Influence does not apply to this action context or condition set.",),
                              tuple(relation["evidence_refs"]))
            yield _as_record("SS002", {"relation_id": relation["id"], "applicability": "not_applicable",
                                      "query": asdict(query) if query is not None else None}, action["task_id"], result,
                             [obj["id"]], refs, necessary=necessary, action_id=action["id"],
                             applicability="not_applicable")
            continue
        authority = obj["instruction_authority"]
        status = authority["status"]
        claim_scope = authority["task_ids"]
        outside_task = claim_scope["state"] == "known" and action["task_id"] not in claim_scope["value"]
        claims_authority = status["state"] == "known" and status["value"] != "none" and not outside_task
        rows = [row for row in action_results if row["action_id"] == action["id"]]
        necessary["action_constraints"] = [
            {key: row.get(key) for key in ("effect_id", "feasibility", "authorization", "control_effect")}
            for row in rows]
        if claims_authority:
            queries = [query] if query is not None else [replace(item, conditions=domains)
                                                       for item in _queries(action, document)]
            approvals = [authority_approval(authority, obj["id"], item, evaluator) for item in queries]
            result = decision_and(approvals) if approvals else authority_approval(authority, obj["id"], None, evaluator)
            result = decision_and(result, conditions)
            if result.value is False and (conditions.value is None or conditional):
                result = Decision(None, result.reasons + conditions.reasons, result.evidence_refs)
            classification = "modeled_boundary_violation" if result.value is False else "assurance_gap"
        elif status["state"] != "known":
            result = decision_and(_known(status, "influence source authority"), conditions)
            classification = "assurance_gap"
        else:
            # Potential content influence is not adoption as task/policy authority.
            # A concrete unconstrained unauthorized action leaves an obligation gap.
            risky = [row for row in rows if row.get("feasibility") != "infeasible" and
                     row.get("authorization") == "denied" and
                     row.get("control_effect") != "blocked_in_model"]
            uncertain = [row for row in rows if row.get("feasibility") == "conditional" or
                         row.get("authorization") in ("unresolved", "not_checked") or
                         row.get("control_effect") in ("unresolved", "not_checked")]
            if risky:
                result = Decision(False, ("explicit low-authority influence reaches an unconstrained decision surface; adoption is unproved",))
            elif uncertain or not rows or conditions.value is None:
                result = Decision(None, ("consequential action constraints remain unresolved",) + conditions.reasons)
            else:
                result = Decision(True, ("explicit content influence supplies no instruction authority or technical capability",))
            classification = "assurance_gap"
        result = Decision(result.value, result.reasons,
                          result.evidence_refs + tuple(obj["evidence_refs"]) + tuple(relation["evidence_refs"]))
        record = _as_record("SS002", {"relation_id": relation["id"], "conditions": necessary,
                                     "query": asdict(query) if query is not None else None,
                                     "conditional": conditional,
                                     "decision": {"value": result.value, "reasons": result.reasons}},
                            action["task_id"], result, [obj["id"]], refs, classification=classification,
                            necessary=necessary, action_id=action["id"])
        unresolved = set(result.reasons if result.value is None else ())
        if claims_authority:
            unresolved.update(reason for part in approvals if part.value is None for reason in part.reasons)
        if conditions.value is None:
            unresolved.update(conditions.reasons)
        if conditional:
            unresolved.add("influenced action path is conditional")
        record.update(has_unresolved=bool(unresolved), unresolved_reasons=sorted(unresolved),
                      unresolved_items=sorted(unresolved))
        yield record
