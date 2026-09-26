"""Small shared types for deterministic, bounded model analysis."""

from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Any, Iterable

from .model import Limits


@dataclass(frozen=True, slots=True)
class Decision:
    value: bool | None
    reasons: tuple[str, ...] = ()
    evidence_refs: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.value is not None and type(self.value) is not bool:
            raise TypeError("Decision value must be bool or None")
        object.__setattr__(self, "reasons", tuple(sorted(set(self.reasons))))
        object.__setattr__(self, "evidence_refs", tuple(sorted(set(self.evidence_refs))))


def _decisions(values: tuple) -> tuple[Decision, ...]:
    if len(values) == 1 and not isinstance(values[0], Decision):
        return tuple(values[0])
    return values


def decision_and(*values: Decision | Iterable[Decision]) -> Decision:
    parts = _decisions(values)
    relevant = tuple(x for x in parts if x.value is False)
    if relevant:
        value = False
    else:
        relevant = tuple(x for x in parts if x.value is None)
        value = None if relevant else True
        if not relevant:
            relevant = parts
    return Decision(value, tuple(r for x in relevant for r in x.reasons),
                    tuple(r for x in relevant for r in x.evidence_refs))


def decision_or(*values: Decision | Iterable[Decision]) -> Decision:
    parts = _decisions(values)
    relevant = tuple(x for x in parts if x.value is True)
    if relevant:
        value = True
    else:
        relevant = tuple(x for x in parts if x.value is None)
        value = None if relevant else False
        if not relevant:
            relevant = parts
    return Decision(value, tuple(r for x in relevant for r in x.reasons),
                    tuple(r for x in relevant for r in x.evidence_refs))


def fact_decision(fact: Any, reason: str = "fact_unknown") -> Decision:
    refs = tuple(fact.get("evidence_refs", ()))
    if fact["state"] == "known":
        if type(fact["value"]) is not bool:
            raise TypeError("fact_decision expects a Boolean Fact")
        return Decision(fact["value"], (), refs)
    if fact["state"] == "conflict":
        refs += tuple(r for c in fact["candidates"] for r in c["evidence_refs"])
    return Decision(None, (reason,), refs)


def scalar_key(value: str | int | float | bool) -> str:
    """Canonical equality for finite scalar conditions, keeping bool distinct."""
    if type(value) is float and value.is_integer():
        value = int(value)
    return json.dumps(value, sort_keys=True, ensure_ascii=True,
                      separators=(",", ":"), allow_nan=False)


@dataclass(frozen=True, slots=True)
class Query:
    task_id: str
    actor_id: str
    object_version_id: str | None
    operation_id: str
    interface_id: str
    recipient_id: str
    purpose_id: str
    effect_time: str | None
    workflow_id: str
    conditions: tuple[tuple[str, tuple[str, ...]], ...] = ()
    policy_target: tuple[str, str, tuple[str, ...]] | None = None


def policy_query(action: Any, effect: Any, document: Any, conditions: Any = ()) -> Query:
    control = next(c for c in document["controls"] if c["id"] == effect["control_id"])
    return Query(action["task_id"], action["actor_id"], None, action["operation_id"],
                 action["interface_id"], control["node_id"], action["purpose_id"],
                 action["effect_time"].get("value") if action["effect_time"]["state"] == "known" else None,
                 action["workflow_id"], conditions,
                 (effect["control_id"], effect["policy_version_id"], tuple(sorted(effect["fields"]))))


class BudgetExceeded(Exception):
    def __init__(self, resource: str):
        self.resource = resource
        self.reason = "max_" + resource
        super().__init__(self.reason)


class Budget:
    """One analysis-wide counter; a cap is checked before the next work item."""

    NAMES = ("states", "transition_checks", "scope_combinations", "clause_checks", "findings")

    def __init__(self, limits: Limits):
        self.limits = limits
        self.usage = dict.fromkeys(self.NAMES, 0)

    def consume(self, resource: str, amount: int = 1) -> None:
        if resource not in self.usage:
            raise ValueError("Unknown analysis budget")
        if type(amount) is not int or amount < 1:
            raise ValueError("Budget work must be a positive integer")
        if self.usage[resource] + amount > getattr(self.limits, "max_" + resource):
            raise BudgetExceeded(resource)
        self.usage[resource] += amount
