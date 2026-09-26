"""Finite state effects over exact ports, authority targets, and local assumptions.

Only the declared candidate effects are explored. A state shares immutable
authorization, lineage, and control declarations with every other state; their
finite effects are branch-local and cannot rewrite those records. Witnesses use predecessor links rather than
copying all histories into the state key.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable

from .analysis_types import BudgetExceeded, Decision, Query, scalar_key, management_query, decision_and


@dataclass(frozen=True, slots=True)
class SearchOutcome:
    completed: bool
    truncation_reason: str | None
    reached_actions: tuple[str, ...]
    evaluated_effects: tuple[tuple[str, str], ...]
    unsupported_actions: tuple[str, ...]
    state_count: int


@dataclass(frozen=True, slots=True)
class _Window:
    """Bounds for one unknown action time, never an invented timestamp."""

    action_id: str
    lower: datetime
    upper: datetime | None = None
    upper_exclusive: bool = False


@dataclass(frozen=True, slots=True)
class _State:
    held: frozenset[tuple[str, str, str]]
    committed: frozenset[tuple[str, str]]
    conditions: tuple[tuple[str, tuple[str, ...]], ...]
    assumptions: tuple[str, ...]
    last_known_time: datetime
    unknown_times: tuple[_Window, ...]
    unknown_order: frozenset[tuple[str, str]]
    conditional_effects: frozenset[tuple[str, str]]
    # Visibility does not imply a location. It is retained separately for
    # future operations; raw transfer requires an exact held input port.
    visible: frozenset[tuple[str, str]]
    visibility_unknown: frozenset[str]
    policies: tuple[tuple[str, str | None], ...]
    activated: tuple
    revoked: tuple
    stopped: tuple
    sources: tuple
    # Every conditional execution retains the view in which it happened.
    # Later revocations, policy changes, or derivations cannot rewrite history.
    conditional_views: tuple[tuple[tuple[str, str], tuple], ...]


@dataclass(slots=True)
class _Node:
    state: _State
    predecessor: int | None
    witness: dict[str, Any] | None


def _time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _fact_refs(fact: Any) -> tuple[str, ...]:
    refs = tuple(fact.get("evidence_refs", ()))
    if fact["state"] == "conflict":
        refs += tuple(ref for candidate in fact["candidates"]
                      for ref in candidate["evidence_refs"])
    return refs


def _condition_domains(conditions: Any) -> dict[str, set[str]] | None:
    domains: dict[str, set[str]] = {}
    for condition in conditions:
        values = (condition["value"],) if condition["operator"] == "eq" else condition["value"]
        domain = {scalar_key(value) for value in values}
        key = condition["key"]
        domains[key] = domains[key] & domain if key in domains else domain
        if not domains[key]:
            return None
    return domains


def _merge_conditions(state: _State, action: Any, initial_known: frozenset[str]):
    requirements = _condition_domains(action["conditions"])
    if requirements is None:
        return None
    domains = {key: set(values) for key, values in state.conditions}
    reasons = set()
    for key, required in requirements.items():
        domains[key] = domains[key] & required if key in domains else required
        if not domains[key]:
            return None
        if key not in initial_known:
            reasons.add("condition_assumed:" + key + "=" + ",".join(sorted(domains[key])))
    normalized = tuple((key, tuple(sorted(values))) for key, values in sorted(domains.items()))
    return normalized, reasons


def _window_valid(window: _Window) -> bool:
    return (window.upper is None or window.lower < window.upper or
            (window.lower == window.upper and not window.upper_exclusive))


def _upper(window: _Window, value: datetime, exclusive: bool = False) -> _Window:
    if window.upper is None or value < window.upper:
        return _Window(window.action_id, window.lower, value, exclusive)
    if value == window.upper and exclusive:
        return _Window(window.action_id, window.lower, value, True)
    return window


def _temporal(state: _State, action: Any, stops: Any):
    """Return consistent chronological bounds, or no feasible transition."""
    fact = action["effect_time"]
    known = fact["state"] == "known"
    effect_time = _time(fact["value"]) if known else None
    refs = set(_fact_refs(fact))
    reasons = set()
    windows = {window.action_id: window for window in state.unknown_times}
    order = state.unknown_order
    floor = state.last_known_time
    if known:
        if effect_time < floor:
            return None
        windows = {key: _upper(window, effect_time) for key, window in windows.items()}
        floor = effect_time
    else:
        order = order | {(identifier, action["id"]) for identifier in windows
                         if identifier != action["id"]}
        previous = windows.get(action["id"])
        current = _Window(action["id"], floor)
        if previous is not None:
            current = _Window(action["id"], max(floor, previous.lower),
                              previous.upper, previous.upper_exclusive)
        windows[action["id"]] = current
        reasons.add("effect_time_unresolved:" + action["id"])
    targets = {("actions", action["id"]), ("nodes", action["actor_id"]),
               ("interfaces", action["interface_id"])}
    for stop in stops:
        if (stop["target"]["collection"], stop["target"]["id"]) not in targets:
            continue
        stopped_at = stop["effective_at"]
        refs.update(stop["evidence_refs"])
        refs.update(_fact_refs(stopped_at))
        if stopped_at["state"] == "known":
            bound = _time(stopped_at["value"])
            if known and effect_time >= bound:
                return None
            if not known:
                windows[action["id"]] = _upper(windows[action["id"]], bound, True)
                reasons.add("effect_precedes_stop:" + action["id"])
        else:
            reasons.add("stop_time_unresolved:" + stop["target"]["collection"] +
                        ":" + stop["target"]["id"])
    if not all(_window_valid(window) for window in windows.values()):
        return None
    return (floor, tuple(windows[key] for key in sorted(windows)), order, reasons, refs)


def _query(action: Any, effect: Any, conditions: Any, document: Any = None) -> Query:
    if effect["kind"] not in ("deliver", "produce"):
        return management_query(action, effect, document, conditions)
    output = next(port for port in action["outputs"] if port["port_id"] == effect["output_port_id"])
    return Query(task_id=action["task_id"], actor_id=action["actor_id"],
                 object_version_id=output["object_version_id"], operation_id=action["operation_id"],
                 interface_id=action["interface_id"], recipient_id=output["location_node_id"],
                 purpose_id=action["purpose_id"], workflow_id=action["workflow_id"],
                 effect_time=action["effect_time"].get("value")
                 if action["effect_time"]["state"] == "known" else None,
                 conditions=conditions)


def _view(evaluator: Any, activated: tuple, revoked: tuple, sources: tuple):
    if activated or revoked or sources:
        return evaluator.with_state(activated=activated, revoked=revoked, sources=sources)
    return evaluator


def _execution_view(state: _State, key: tuple[str, str], evaluator: Any):
    stored = dict(state.conditional_views).get(key)
    if stored is None:
        return _view(evaluator, state.activated, state.revoked, state.sources), dict(state.policies)
    activated, revoked, sources, policies = stored
    return _view(evaluator, activated, revoked, sources), dict(policies)


def _add_timed(rows: tuple, targets: tuple, timestamp: str | None) -> tuple:
    accumulated: dict[tuple, set] = {}
    for target, at in (*rows, *((target, timestamp) for target in targets)):
        accumulated.setdefault(target, set()).add(at)
    result = []
    for target, times in accumulated.items():
        known = [at for at in times if at is not None]
        if known:
            result.append((target, min(known, key=_time)))
        if None in times:
            result.append((target, None))
    return tuple(sorted(result, key=lambda row: (*row[0], row[1] or "")))


def _stop_rows(rows: tuple):
    return tuple({"target": {"collection": target[0], "id": target[1]},
                  "effective_at": ({"state": "known", "value": timestamp,
                                    "evidence_refs": []} if timestamp is not None else
                                   {"state": "unknown", "reason": "stop effect time unresolved",
                                    "evidence_refs": []}),
                  "evidence_refs": []} for target, timestamp in rows)


def _consistent_history(state: _State, execution_id: tuple[str, str], conditions: Any,
                        windows: tuple[_Window, ...], order: frozenset[tuple[str, str]],
                        candidates: dict, evaluator: Any, controller: Any, document: Any):
    """Intersect earlier conditional premises with the new branch constraints.

    Lower bounds are the earliest *possible* times, not observations or chosen
    execution timestamps. Monotone propagation handles complete-capability OR
    intervals, precedence, and multiple atomic effects of the same action.
    """
    bounds = {window.action_id: window for window in windows}
    executions = state.committed | {execution_id}
    timed = tuple(sorted(key for key in executions if key[0] in bounds))
    changed = True
    while changed:
        changed = False
        for key in timed:
            action, effect = candidates[key]
            window = bounds[key[0]]
            historical_evaluator, _ = _execution_view(state, key, evaluator)
            decision, earliest = historical_evaluator.capability_window(
                _query(action, effect, conditions, document), window.lower, window.upper, window.upper_exclusive)
            if decision.value is False or earliest is None:
                return None
            if earliest > window.lower:
                bounds[key[0]] = _Window(window.action_id, earliest, window.upper, window.upper_exclusive)
                changed = True
        for before, after in sorted(order):
            previous, following = bounds[before], bounds[after]
            if previous.lower > following.lower:
                bounds[after] = _Window(following.action_id, previous.lower,
                                       following.upper, following.upper_exclusive)
                changed = True
        if not all(_window_valid(window) for window in bounds.values()):
            return None
    for key in sorted(state.conditional_effects):
        action, effect = candidates[key]
        query = _query(action, effect, conditions, document)
        historical_evaluator, historical_policies = _execution_view(state, key, evaluator)
        if key[0] not in bounds and historical_evaluator.capability(query).value is False:
            return None
        if controller.evaluate(query, historical_evaluator.authorization(query),
                               historical_policies).status == "blocked_in_model":
            return None
    return tuple(bounds[key] for key in sorted(bounds))


def _time_constraints(windows: tuple[_Window, ...], order: frozenset[tuple[str, str]]) -> dict:
    return {
        "windows": tuple({"action_id": window.action_id,
                          "not_before": window.lower.isoformat().replace("+00:00", "Z"),
                          "not_after": window.upper.isoformat().replace("+00:00", "Z")
                          if window.upper is not None else None,
                          "upper_exclusive": window.upper_exclusive} for window in windows),
        "no_later_than": tuple(sorted(order)),
    }


def _path(nodes: list[_Node], index: int, current: dict[str, Any]):
    path = [current]
    while nodes[index].predecessor is not None:
        path.append(nodes[index].witness)
        index = nodes[index].predecessor
    return tuple(reversed(path))


def _unsupported_assumptions(document: Any, action: Any, query: Query) -> set[str]:
    relevant = {("actions", action["id"]), ("tasks", query.task_id),
                ("workflows", query.workflow_id), ("execution_contexts", action["context_id"]),
                ("nodes", query.actor_id), ("nodes", query.recipient_id),
                ("interfaces", query.interface_id), ("operations", query.operation_id),
                ("purposes", query.purpose_id), ("object_versions", query.object_version_id)}
    relevant.update(("object_versions", port["object_version_id"])
                    for port in action["inputs"])
    relevant.update(("controls", control["id"]) for control in document["controls"])
    # An opaque change to an authority record can affect the record's scope
    # itself. Keep task-level uncertainty instead of using the other fields
    # of that affected record to prove the current request unaffected.
    for collection, records in document["authorization"].items():
        for record in records:
            if any(clause["tasks"]["state"] != "known" or
                   query.task_id in clause["tasks"]["value"] for clause in record["clauses"]):
                relevant.add((collection, record["id"]))
    objects = {item["id"]: item for item in document["object_versions"]}
    pending = [query.object_version_id] if query.object_version_id is not None else []
    visited = set()
    while pending:
        identifier = pending.pop()
        if identifier in visited:
            continue
        visited.add(identifier)
        relevant.add(("object_versions", identifier))
        obj = objects[identifier]
        for name, collection in (("parents", "object_versions"), ("restriction_ids", "restrictions")):
            fact = obj[name]
            values = fact["value"] if fact["state"] == "known" else ()
            if fact["state"] == "conflict":
                values = tuple(value for candidate in fact["candidates"] for value in candidate["value"])
            relevant.update((collection, value) for value in values)
            if name == "parents":
                pending.extend(values)
    result = set()
    for item in document["context"]["unsupported_items"]:
        scope = item["affected_refs"]
        if (scope["state"] != "known" or
                any((ref["collection"], ref["id"]) in relevant for ref in scope["value"])):
            result.add("unsupported_context_assumption:" + item["id"])
    return result


def explore(document: Any, evaluator: Any, controller: Any, budget: Any,
            on_step: Callable[[dict[str, Any]], None]) -> SearchOutcome:
    """Enumerate supported atomic effects and retain partial work on a cap.

    ``on_step`` receives each effect with available inputs and consistent
    conditions/time before state deduplication, including capability failures
    and blocked attempts. Its decisions are model
    deductions, never runtime observations. A callback budget failure stops
    the same search and preserves all previously delivered records.
    """
    operations = {item["id"]: item["semantic_kind"]
                  for item in document["context"]["operation_definitions"]}
    actions = sorted(document["actions"], key=lambda item: item["id"])
    supported = [action for action in actions if
                 operations[action["operation_id"]] in
                 ("read", "transfer", "derive", "persist_write", "persist_read",
                  "delegate", "policy_update", "revoke", "stop")]
    unsupported = tuple(action["id"] for action in actions if action not in supported)
    candidates = [(action, effect) for action in supported
                  for effect in sorted(action["effects"], key=lambda item: item["id"])]
    candidate_index = {(action["id"], effect["id"]): (action, effect) for action, effect in candidates}
    requirements = {action["id"]: frozenset((action["id"], effect["id"])
                                           for effect in action["effects"])
                    for action in actions}
    contexts = {item["id"]: item for item in document["execution_contexts"]}
    held = frozenset((obj["id"], location["node_id"], location["context_id"])
                     for obj in document["object_versions"]
                     for location in obj["initial_locations"])
    visible = set()
    visibility_unknown = set()
    for context in contexts.values():
        fact = context["initial_visible_objects"]
        if fact["state"] == "known":
            visible.update((context["id"], identifier) for identifier in fact["value"])
        if (fact["state"] != "known" or
                context["visibility_complete"]["state"] != "known" or
                context["visibility_complete"].get("value") is not True):
            visibility_unknown.add(context["id"])
    initial_domains = {}
    initial_known = set()
    for binding in document["context"]["initial_conditions"]:
        fact = binding["value"]
        if fact["state"] == "known":
            initial_domains[binding["key"]] = (scalar_key(fact["value"]),)
            initial_known.add(binding["key"])
    state = _State(held, frozenset(), tuple(sorted(initial_domains.items())), (),
                   _time(document["context"]["as_of"]), (), frozenset(), frozenset(),
                   frozenset(visible), frozenset(visibility_unknown),
                   tuple((c["id"], c["initial_policy"].get("value") if c["initial_policy"]["state"] == "known" else None)
                         for c in sorted(document["controls"], key=lambda c: c["id"])),
                   (), (), (), (), ())
    nodes: list[_Node] = []
    reached: set[str] = set()
    evaluated: set[tuple[str, str]] = set()
    try:
        budget.consume("states")
        nodes.append(_Node(state, None, None))
        seen = {state}
        queue = deque([0])
        while queue:
            index = queue.popleft()
            state = nodes[index].state
            complete = {identifier for identifier, effects in requirements.items()
                        if effects and effects <= state.committed}
            for action, effect in candidates:
                budget.consume("transition_checks")
                execution_id = (action["id"], effect["id"])
                if execution_id in state.committed:
                    continue
                if not set(action["success_dependencies"]) <= complete:
                    continue
                inputs = tuple(port for port in action["inputs"]
                               if port["port_id"] in effect.get("input_port_ids", ()))
                if any((port["object_version_id"], port["location_node_id"], port["context_id"])
                       not in state.held for port in inputs):
                    continue
                merged = _merge_conditions(state, action, frozenset(initial_known))
                if merged is None:
                    continue
                conditions, condition_assumptions = merged
                temporal = _temporal(state, action,
                                     (*document["context"]["stopped_targets"], *_stop_rows(state.stopped)))
                if temporal is None:
                    continue
                floor, windows, order, time_assumptions, time_refs = temporal
                windows = _consistent_history(state, execution_id, conditions, windows, order,
                                              candidate_index, evaluator, controller, document)
                if windows is None:
                    continue
                management = effect["kind"] not in ("deliver", "produce")
                output = None if management else next(port for port in action["outputs"]
                              if port["port_id"] == effect["output_port_id"])
                query = _query(action, effect, conditions, document)
                current_evaluator = _view(evaluator, state.activated, state.revoked, state.sources)
                visible_sources = tuple(sorted(identifier for context_id, identifier in state.visible
                                               if context_id == action["context_id"]))
                visibility_complete = action["context_id"] not in state.visibility_unknown
                source_details = None
                query_sources = state.sources
                if effect["kind"] == "produce":
                    source_details = current_evaluator.derive_sources(
                        output["object_version_id"], tuple(port["object_version_id"] for port in inputs),
                        visible_sources, visibility_complete, action["task_id"])
                    query_sources = tuple(sorted({**dict(state.sources),
                                                  output["object_version_id"]: source_details}.items()))
                    current_evaluator = _view(evaluator, state.activated, state.revoked, query_sources)
                capability = current_evaluator.capability(query)
                if effect["kind"] == "select_policy":
                    capability = decision_and(capability, controller.selection(effect, dict(state.policies)))
                assumptions = set(state.assumptions) | condition_assumptions | time_assumptions
                assumptions.update(_unsupported_assumptions(document, action, query))
                if capability.value is None:
                    assumptions.add("capability_unresolved:" + action["id"] + ":" + effect["id"])
                    assumptions.update(capability.reasons)
                evidence = (set(action["evidence_refs"]) | time_refs |
                            set(capability.evidence_refs))
                evidence.update(ref for condition in action["conditions"] for ref in condition["evidence_refs"])
                technical = Decision(False if capability.value is False else
                                     None if assumptions else True,
                                     tuple(sorted(assumptions | set(capability.reasons))), tuple(sorted(evidence)))
                authorization = current_evaluator.authorization(query)
                control = controller.evaluate(query, authorization, dict(state.policies))
                if control.status == "unresolved":
                    assumptions.add("control_not_blocking_assumed:" + action["id"] + ":" + effect["id"])
                    assumptions.update(control.reasons)
                evidence.update(authorization.evidence_refs)
                evidence.update(control.evidence_refs)
                assumptions_tuple = tuple(sorted(assumptions))
                committed = capability.value is not False and control.status != "blocked_in_model"
                next_policies = dict(state.policies)
                next_activated, next_revoked, next_stopped = state.activated, state.revoked, state.stopped
                targets = query.management_targets
                if effect["kind"] == "select_policy" and committed:
                    next_policies[effect["control_id"]] = effect["policy_version_id"]
                elif effect["kind"] == "activate_authorizations" and committed:
                    next_activated = _add_timed(state.activated, targets, query.effect_time)
                elif effect["kind"] == "revoke" and committed:
                    next_revoked = _add_timed(state.revoked, targets, query.effect_time)
                elif effect["kind"] == "stop" and committed:
                    next_stopped = _add_timed(state.stopped, targets, query.effect_time)
                witness = {
                    "action_id": action["id"], "effect_id": effect["id"],
                    "task_id": action["task_id"], "context_id": action["context_id"],
                    "input_ports": tuple(dict(port) for port in inputs),
                    "output_port": dict(output) if output is not None else None, "effect_time": query.effect_time,
                    "policy_before": state.policies, "policy_after": tuple(sorted(next_policies.items())),
                    "policy_target": query.policy_target,
                    "management_targets": targets,
                    "state_changes": {
                        "activated": tuple(row for row in next_activated if row not in state.activated),
                        "revoked": tuple(row for row in next_revoked if row not in state.revoked),
                        "stopped": tuple(row for row in next_stopped if row not in state.stopped),
                        "source_details": None if source_details is None else {
                            "ancestor_ids": source_details.ancestor_ids,
                            "restriction_ids": source_details.restriction_ids,
                            "complete": source_details.completeness.value,
                            "reasons": source_details.completeness.reasons,
                            "committed": committed,
                        },
                    },
                    "conditions": conditions, "control_status": control.status,
                    "time_constraints": _time_constraints(windows, order),
                    "control_details": control.details,
                    "assumptions": assumptions_tuple, "committed": committed,
                    "evidence_refs": tuple(sorted(evidence)),
                }
                evaluated.add(execution_id)
                on_step({"action_id": action["id"], "effect_id": effect["id"],
                         "query": query, "capability": capability, "technical": technical,
                         "authorization": authorization, "control": control,
                         "conditional": bool(assumptions_tuple), "assumptions": assumptions_tuple,
                         "conditions": conditions, "committed": committed,
                         "evaluator": current_evaluator,
                         "source_details": source_details,
                         "visible_sources": visible_sources,
                         "visibility_complete": visibility_complete,
                         "path": _path(nodes, index, witness),
                         "evidence_refs": tuple(sorted(evidence))})
                if not committed:
                    continue
                new_visible = set(state.visible)
                new_visibility_unknown = set(state.visibility_unknown)
                context = contexts[action["context_id"]]
                visibility = context["input_visibility"]
                retention = context["retain_inputs"]
                if (visibility["state"] == "known" and visibility["value"] == "visible" and
                        retention["state"] == "known" and retention["value"] is True):
                    new_visible.update((context["id"], port["object_version_id"])
                                       for port in inputs)
                elif visibility["state"] != "known" or retention["state"] != "known":
                    new_visibility_unknown.add(context["id"])
                if output is not None and output["context_id"] != "not_applicable":
                    receiving = contexts[output["context_id"]]
                    visibility, retention = receiving["input_visibility"], receiving["retain_inputs"]
                    if (visibility["state"] == "known" and visibility["value"] == "visible" and
                            retention["state"] == "known" and retention["value"] is True):
                        new_visible.add((receiving["id"], output["object_version_id"]))
                    elif visibility["state"] != "known" or retention["state"] != "known":
                        new_visibility_unknown.add(receiving["id"])
                successor = _State(
                    state.held | ({(output["object_version_id"], output["location_node_id"], output["context_id"])}
                                  if output is not None else set()),
                    state.committed | {execution_id}, conditions, assumptions_tuple,
                    floor, windows, order,
                    state.conditional_effects | ({execution_id} if assumptions_tuple else set()),
                    frozenset(new_visible), frozenset(new_visibility_unknown),
                    tuple(sorted(next_policies.items())),
                    next_activated, next_revoked, next_stopped, query_sources,
                    state.conditional_views if not assumptions_tuple else
                    tuple(sorted((*state.conditional_views, (execution_id,
                                 (state.activated, state.revoked, query_sources, state.policies))))))
                if requirements[action["id"]] <= successor.committed:
                    reached.add(action["id"])
                if successor not in seen:
                    budget.consume("states")
                    seen.add(successor)
                    nodes.append(_Node(successor, index, witness))
                    queue.append(len(nodes) - 1)
    except BudgetExceeded as exc:
        return SearchOutcome(False, exc.reason, tuple(sorted(reached)),
                             tuple(sorted(evaluated)), unsupported, len(nodes))
    return SearchOutcome(True, None, tuple(sorted(reached)), tuple(sorted(evaluated)),
                         unsupported, len(nodes))
