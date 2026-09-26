"""Finite, three-valued authorization and immutable source semantics.

Every permission is matched as a complete clause. Technical capabilities,
task grants and source-release exceptions remain separate kinds of authority.
The evaluator consumes validated input and never executes supplied content.
"""
from __future__ import annotations

from dataclasses import dataclass
from copy import copy
from datetime import datetime

from .analysis_types import Decision, scalar_key


def _decision(value, reason="", evidence=()):
    return Decision(value, (reason,) if reason else (), tuple(sorted(set(evidence))))


def _combine(items, *, conjunction):
    items = tuple(items)
    values = [item.value for item in items]
    if conjunction:
        value = False if False in values else None if None in values else True
    else:
        value = True if True in values else None if None in values else False
        if value is True:
            items = tuple(item for item in items if item.value is True)
        elif value is None:
            items = tuple(item for item in items if item.value is None)
    return Decision(
        value,
        tuple(sorted({reason for item in items for reason in item.reasons})),
        tuple(sorted({ref for item in items for ref in item.evidence_refs})),
    )


def _and(*items):
    return _combine(items, conjunction=True)


def _or(*items):
    return _combine(items, conjunction=False)


def _refs(fact):
    refs = set(fact.get("evidence_refs", ()))
    for candidate in fact.get("candidates", ()):
        refs.update(candidate.get("evidence_refs", ()))
    return tuple(sorted(refs))


def _fact(fact, predicate, label):
    if fact["state"] != "known":
        return _decision(None, f"{label}: {fact['state']}", _refs(fact))
    value = predicate(fact["value"])
    return _decision(value, f"{label}: does not match" if value is False else "", _refs(fact))


def _known(fact, label):
    return _fact(fact, lambda value: True, label)


def _complete(fact, label):
    result = _fact(fact, lambda value: value is True, label)
    if result.value is False:
        return _decision(None, f"{label}: inventory incomplete", result.evidence_refs)
    return result


def _time(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


@dataclass(frozen=True)
class SourceDetails:
    ancestor_ids: tuple[str, ...]
    restriction_ids: tuple[str, ...]
    completeness: Decision


class Evaluator:
    """Evaluate fixed read/transfer queries against one validated snapshot."""

    _dimensions = {
        "tasks": "task_id", "actors": "actor_id", "objects": "object_version_id",
        "operations": "operation_id", "interfaces": "interface_id",
        "recipients": "recipient_id", "purposes": "purpose_id", "workflows": "workflow_id",
    }

    def __init__(self, document, budget):
        self.document = document
        self.budget = budget
        self.authorities = {
            collection: tuple(sorted(records, key=lambda item: item["id"]))
            for collection, records in document["authorization"].items()
        }
        self.objects = {item["id"]: item for item in document["object_versions"]}
        self.restrictions = {item["id"]: item for item in document["restrictions"]}
        self.interfaces = {item["id"]: item for item in document["context"]["interfaces"]}
        self.completeness = {
            (item["task_id"], item["collection"]): item["complete"]
            for item in document["context"]["completeness"]
        }
        self._source_cache: dict[tuple[str, str], SourceDetails] = {}
        self._sources = {}
        self._activated = {}
        self._revoked = {}
        self._record_keys = {id(record): (collection, record["id"])
                             for collection, records in self.authorities.items() for record in records}

    def with_state(self, *, activated=(), revoked=(), sources=()):
        """Create a read-only view of branch-local authority and ancestry."""
        if not activated and not revoked and not sources:
            return self
        view = copy(self)
        def times(rows):
            grouped = {}
            for key, instant in rows:
                grouped.setdefault(key, set()).add(instant)
            return {key: tuple(sorted(values, key=lambda value: value or ""))
                    for key, values in grouped.items()}
        view._activated, view._revoked, view._sources = times(activated), times(revoked), dict(sources)
        for collection, records in self.authorities.items():
            for record in records:
                key = (collection, record["id"])
                if key not in view._activated:
                    continue
                initial = record.get("initially_active", {})
                if initial.get("state") == "known" and initial["value"] is True:
                    del view._activated[key]
                elif initial.get("state") != "known":
                    view._activated[key] = tuple({None, *view._activated[key]})
        view._source_cache = {}
        view.authorities = {}
        for collection, records in self.authorities.items():
            view.authorities[collection] = tuple(
                dict(record, initially_active={"state": "known", "value": True, "evidence_refs": []})
                if (collection, record["id"]) in view._activated and "initially_active" in record else record
                for record in records)
        view._record_keys = {id(record): (collection, record["id"])
                             for collection, records in view.authorities.items() for record in records}
        return view

    def derive_sources(self, output_id, input_ids, visible_ids, visibility_complete, task_id):
        """Retain actual inputs and context sources alongside output declarations."""
        parents = sorted(set(input_ids) | set(visible_ids))
        parts = [self.source_details(identifier, task_id) for identifier in parents]
        declared = self.source_details(output_id, task_id)
        ancestry = {output_id, *declared.ancestor_ids}
        restrictions = set(declared.restriction_ids)
        decisions = [declared.completeness]
        for part in parts:
            ancestry.update(part.ancestor_ids)
            restrictions.update(part.restriction_ids)
            decisions.append(part.completeness)
        if not visibility_complete:
            decisions.append(_decision(None, "generation_context_sources_incomplete"))
        return SourceDetails(tuple(sorted(ancestry)), tuple(sorted(restrictions)), _and(*decisions))

    def _state_liveness(self, record, query):
        key = self._record_keys.get(id(record))
        decisions = []
        for table, is_activation in ((self._activated, True), (self._revoked, False)):
            if key not in table:
                continue
            changes = []
            for at in table[key]:
                if at is None or query.effect_time is None:
                    changes.append(_decision(None, f"{record['id']}: state change time unknown"))
                else:
                    enabled = _time(query.effect_time) >= _time(at) if is_activation else _time(query.effect_time) < _time(at)
                    changes.append(_decision(enabled, "" if enabled else f"{record['id']}: inactive at effect time"))
            decisions.append(_or(*changes) if is_activation else _and(*changes))
        return _and(*decisions)

    def complete(self, task_id, collection):
        """Return the explicit completeness claim, including known false."""
        fact = self.completeness.get((task_id, collection))
        label = f"completeness {task_id}/{collection}"
        if fact is None:
            return _decision(None, f"{label}: missing")
        return _fact(fact, lambda value: value is True, label)

    def _inventory_or(self, items, task_id, collection):
        result = _or(*items)
        if result.value is True:
            return result
        complete = self.complete(task_id, collection)
        if complete.value is not True:
            return _or(result, _decision(None, f"{collection}: inventory completeness unresolved",
                                          complete.evidence_refs))
        if result.value is False:
            return _and(result, _decision(False, f"{collection}: no complete valid clause",
                                          complete.evidence_refs))
        return _and(result, _decision(True, evidence=complete.evidence_refs))

    def match_scope(self, clause, query):
        """Match one complete scope; restriction clauses use their five dimensions."""
        self.budget.consume("clause_checks")
        decisions = [
            _fact(clause[field], lambda values, value=getattr(query, attribute): value in values,
                  f"scope {field}")
            for field, attribute in self._dimensions.items() if field in clause
            and not (field == "objects" and query.object_version_id is None)
        ]
        if query.policy_target is not None:
            # Management scopes use an explicit typed target. An empty object
            # list, a data grant, or an unlisted version never grants control.
            control, policy, fields = query.policy_target
            target = clause.get("policy_targets")
            decisions.append(_fact(clause["objects"], lambda values: not values,
                                   "management scope objects must be empty"))
            decisions.append(_decision(False, "policy target not granted") if target is None else
                             _fact(target, lambda values: any(
                                 value["control_id"] == control and value["policy_version_id"] == policy
                                 and set(fields) <= set(value["fields"]) for value in values), "policy target"))
        elif query.object_version_id is None:
            target = clause.get("management_targets")
            decisions.append(_fact(clause["objects"], lambda values: not values, "management scope objects must be empty"))
            decisions.append(_decision(False, "management target not granted") if target is None or not query.management_targets else
                             _fact(target, lambda values: set(query.management_targets) <= {
                                 (item["collection"], item["id"]) for item in values}, "management targets"))
        domains = dict(query.conditions)
        for condition in clause["conditions"]:
            key = condition["key"]
            values = condition["value"] if condition["operator"] == "in" else [condition["value"]]
            allowed = {scalar_key(value) for value in values}
            domain = domains.get(key)
            if domain is None:
                value, reason = None, f"condition {key}: value unknown"
            elif not set(domain) & allowed:
                value, reason = False, f"condition {key}: incompatible values"
            elif set(domain) <= allowed:
                value, reason = True, ""
            else:
                value, reason = None, f"condition {key}: only part of domain matches"
            decisions.append(_decision(value, reason, condition["evidence_refs"]))
        return _and(*decisions)

    def _clauses(self, record, query):
        return _or(*(self.match_scope(clause, query) for clause in record["clauses"]))

    def _temporal(self, record, query):
        label = record["id"]
        validity = record["validity"]
        revocation = record["revocation"]
        if query.effect_time is None:
            valid = _decision(None, f"{label}: effect time unknown", _refs(validity))
        else:
            instant = _time(query.effect_time)
            valid = _fact(
                validity,
                lambda interval: _time(interval["not_before"]) <= instant
                and (interval["expires_at"] == "unbounded" or instant < _time(interval["expires_at"])),
                f"{label} validity",
            )
        if revocation["state"] != "known":
            live = _decision(None, f"{label} revocation: {revocation['state']}", _refs(revocation))
        elif not revocation["value"]["revoked"]:
            live = _decision(True, evidence=_refs(revocation))
        elif query.effect_time is None or revocation["value"]["at"] == "not_applicable":
            live = _decision(None, f"{label}: revocation order unknown", _refs(revocation))
        else:
            live = _decision(_time(query.effect_time) < _time(revocation["value"]["at"]),
                             f"{label}: revoked at effect time" if _time(query.effect_time) >=
                             _time(revocation["value"]["at"]) else "", _refs(revocation))
        active = (_fact(record["initially_active"], lambda value: value is True,
                        f"{label} activation") if "initially_active" in record else _decision(True))
        return _and(valid, live, active, self._state_liveness(record, query), _decision(True, evidence=record["evidence_refs"]))

    def capability(self, query):
        """Technical capability does not imply task or source authorization."""
        interface = self.interfaces[query.interface_id]
        no_credential = _fact(interface["credential_required"], lambda value: value is False,
                              f"interface {query.interface_id} requires credential")
        candidates = [
            _and(self._clauses(record, query), self._temporal(record, query),
                 _known(record["issuer"], f"{record['id']} issuer"))
            for record in self.authorities["capabilities"]
        ]
        return _or(no_credential, self._inventory_or(candidates, query.task_id, "capabilities"))

    def _temporal_window(self, record, lower, upper, upper_exclusive):
        """Intersect known temporal premises without filling unknown facts."""
        decisions = [_decision(True, evidence=record["evidence_refs"])]
        key = self._record_keys.get(id(record))
        for table, activation in ((self._activated, True), (self._revoked, False)):
            if key not in table:
                continue
            instants = table[key]
            known = [_time(value) for value in instants if value is not None]
            if None in instants:
                decisions.append(_decision(None, f"{record['id']}: state change time unknown"))
            if activation:
                if known and None not in instants:
                    lower = max(lower, min(known))
            elif known and (upper is None or min(known) <= upper):
                upper, upper_exclusive = min(known), True
        validity = record["validity"]
        if validity["state"] == "known":
            lower = max(lower, _time(validity["value"]["not_before"]))
            expires = validity["value"]["expires_at"]
            if expires != "unbounded":
                endpoint = _time(expires)
                if upper is None or endpoint <= upper:
                    upper, upper_exclusive = endpoint, True
            decisions.append(_decision(True, evidence=_refs(validity)))
        else:
            decisions.append(_decision(None, f"{record['id']} validity: {validity['state']}",
                                       _refs(validity)))
        revocation = record["revocation"]
        if revocation["state"] != "known":
            decisions.append(_decision(None, f"{record['id']} revocation: {revocation['state']}",
                                       _refs(revocation)))
        elif revocation["value"]["revoked"]:
            if revocation["value"]["at"] == "not_applicable":
                decisions.append(_decision(None, f"{record['id']}: revocation order unknown",
                                           _refs(revocation)))
            else:
                endpoint = _time(revocation["value"]["at"])
                if upper is None or endpoint <= upper:
                    upper, upper_exclusive = endpoint, True
                decisions.append(_decision(True, evidence=_refs(revocation)))
        else:
            decisions.append(_decision(True, evidence=_refs(revocation)))
        decisions.append(_fact(record["initially_active"], lambda value: value is True,
                               f"{record['id']} activation"))
        if upper is not None and (lower > upper or (lower == upper and upper_exclusive)):
            decisions.append(_decision(False, f"{record['id']}: no valid time in execution window"))
        result = _and(*decisions)
        return result, None if result.value is False else lower

    def capability_window(self, query, lower: datetime, upper: datetime | None,
                          upper_exclusive: bool = False):
        """Return feasibility and the earliest possible bound in a time window.

        The bound is only an existential lower bound, never a supplied timestamp.
        Unknown scope or temporal facts remain unknown. Independent capabilities
        form a union of intervals; unrelated records are never intersected.
        """
        if query.effect_time is not None:
            instant = _time(query.effect_time)
            if instant < lower or (upper is not None and
                    (instant > upper or (instant == upper and upper_exclusive))):
                return _decision(False, "effect time outside execution window"), None
            lower = upper = instant
            upper_exclusive = False
        if upper is not None and (lower > upper or (lower == upper and upper_exclusive)):
            return _decision(False, "execution window is empty"), None
        interface = self.interfaces[query.interface_id]
        no_credential = _fact(interface["credential_required"], lambda value: value is False,
                              f"interface {query.interface_id} requires credential")
        candidates, earliest = [], []
        if no_credential.value is not False:
            earliest.append(lower)
        for record in self.authorities["capabilities"]:
            temporal, first = self._temporal_window(record, lower, upper, upper_exclusive)
            result = _and(self._clauses(record, query), temporal,
                          _known(record["issuer"], f"{record['id']} issuer"))
            candidates.append(result)
            if result.value is not False:
                earliest.append(first)
        inventory = self.complete(query.task_id, "capabilities")
        if inventory.value is not True:
            earliest.append(lower)
        result = _or(no_credential, self._inventory_or(candidates, query.task_id, "capabilities"))
        return result, min(earliest) if earliest else None

    def capability_in_window(self, query, lower: datetime, upper: datetime | None,
                             upper_exclusive: bool = False):
        return self.capability_window(query, lower, upper, upper_exclusive)[0]

    def _approval(self, record, query, right, restriction=None):
        candidates = []
        for approval in self.authorities["approval_rights"]:
            listed = _fact(record["approval_refs"], lambda ids: approval["id"] in ids,
                           f"{record['id']} approval references")
            issuer = _fact(record["issuer"], lambda holder: holder == approval["holder"],
                           f"{record['id']} issuer for {approval['id']}")
            decisions = [listed, issuer, _decision(right in approval["rights"],
                         "" if right in approval["rights"] else f"{approval['id']}: lacks {right}"),
                         self._clauses(approval, query), self._temporal(approval, query)]
            if restriction is not None:
                decisions.extend([
                    _fact(approval["restriction_ids"], lambda ids: restriction["id"] in ids,
                          f"{approval['id']} restriction scope"),
                    _fact(restriction["approval_refs"], lambda ids: approval["id"] in ids,
                          f"{restriction['id']} release approval references"),
                ])
            candidates.append(_and(*decisions))
        # Explicitly empty references cannot create authority from an unlisted right.
        refs = record["approval_refs"]
        if refs["state"] == "known" and not refs["value"]:
            return _decision(False, f"{record['id']}: no approval references", _refs(refs))
        return self._inventory_or(candidates, query.task_id, "approval_rights")

    def task_grant(self, query):
        candidates = [
            _and(self._clauses(record, query), self._temporal(record, query),
                 self._approval(record, query, "issue_task_grant"))
            for record in self.authorities["task_grants"]
        ]
        return self._inventory_or(candidates, query.task_id, "task_grants")

    def source_details(self, object_version_id, task_id):
        """Collect certain ancestry without converting missing lineage into emptiness."""
        key = (object_version_id, task_id)
        if key in self._source_cache:
            return self._source_cache[key]
        ancestors, restriction_ids, visiting, finished = set(), set(), set(), set()
        decisions = []
        stack = [(object_version_id, False)]
        while stack:
            object_id, leaving = stack.pop()
            if leaving:
                visiting.remove(object_id)
                finished.add(object_id)
                continue
            if object_id in visiting:
                decisions.append(_decision(None, f"{object_id}: cyclic source ancestry"))
                continue
            if object_id in finished:
                continue
            visiting.add(object_id)
            ancestors.add(object_id)
            if object_id in self._sources:
                actual = self._sources[object_id]
                ancestors.update(actual.ancestor_ids)
                restriction_ids.update(actual.restriction_ids)
                decisions.append(actual.completeness)
            item = self.objects[object_id]
            decisions.extend([
                _complete(item["parents_complete"], f"{object_id} parents"),
                _complete(item["restrictions_complete"], f"{object_id} restrictions"),
                _known(item["parents"], f"{object_id} parent identities"),
                _known(item["restriction_ids"], f"{object_id} restriction identities"),
                _decision(True, evidence=item["evidence_refs"]),
            ])
            if item["origin_kind"] == "unknown":
                decisions.append(_decision(None, f"{object_id}: source origin unknown"))
            if item["restriction_ids"]["state"] == "known":
                restriction_ids.update(item["restriction_ids"]["value"])
            stack.append((object_id, True))
            if item["parents"]["state"] == "known":
                stack.extend((parent, False) for parent in reversed(sorted(item["parents"]["value"])))
        # The restriction's own source binding is an independent known premise.
        restriction_ids.update(item["id"] for item in self.restrictions.values()
                               if item["source_object_id"] in ancestors)
        for collection in ("sources", "restrictions"):
            complete = self.complete(task_id, collection)
            decisions.append(complete if complete.value is True else _decision(
                None, f"{collection}: inventory completeness unresolved", complete.evidence_refs))
        details = SourceDetails(tuple(sorted(ancestors)), tuple(sorted(restriction_ids)), _and(*decisions))
        self._source_cache[key] = details
        return details

    def _exception(self, restriction, query):
        candidates = []
        for record in self.authorities["release_exceptions"]:
            candidates.append(_and(
                _fact(record["restriction_ids"], lambda ids: restriction["id"] in ids,
                      f"{record['id']} released restrictions"),
                self._clauses(record, query), self._temporal(record, query),
                self._approval(record, query, "release_restriction", restriction),
            ))
        return self._inventory_or(candidates, query.task_id, "release_exceptions")

    def restriction_ok(self, restriction, query):
        applicable = _fact(restriction["applies_to_operations"],
                           lambda ids: query.operation_id in ids,
                           f"{restriction['id']} operation applicability")
        if applicable.value is False:
            return _decision(True, evidence=applicable.evidence_refs)
        original = _or(*(self.match_scope(clause, query) for clause in restriction["allowed_clauses"]))
        allowed = _or(original, self._exception(restriction, query))
        if allowed.value is True:
            return allowed
        if applicable.value is None:
            return _and(applicable,
                        _decision(None, f"{restriction['id']}: applicability unresolved",
                                  allowed.evidence_refs))
        if allowed.value is False:
            return _and(allowed, _decision(False,
                        f"{restriction['id']}: no allowed clause or valid exception"))
        return allowed

    def authorization(self, query):
        if query.object_version_id is None:
            # Selecting a declared policy version changes no data/source grants.
            return self.task_grant(query)
        details = self.source_details(query.object_version_id, query.task_id)
        restrictions = [self.restriction_ok(self.restrictions[restriction_id], query)
                        for restriction_id in details.restriction_ids]
        return _and(self.task_grant(query), details.completeness, *restrictions)
