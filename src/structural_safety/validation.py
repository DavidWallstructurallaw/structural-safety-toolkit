"""Strict raw JSON entry validation with bounded, side-effect-free loading."""

from __future__ import annotations

import json
import math
from typing import Any

from .model import Deployment, Diagnostic, Limits, ValidationResult


SUPPORTED_SCHEMA = "sst.model/0.1"


class _InputProblem(Exception):
    def __init__(self, code: str, path: str, message: str, *, resource: bool = False):
        self.diagnostic = Diagnostic(code, path, message)
        self.resource = resource


class _ObjectPairs(list):
    """Preserve duplicate keys until a location-aware materialization walk."""


def _pointer(parent: str, key: str | int) -> str:
    escaped = str(key).replace("~", "~0").replace("/", "~1")
    return f"{parent}/{escaped}"


def _materialize(value: Any, path: str = "") -> Any:
    if isinstance(value, _ObjectPairs):
        result = {}
        for key, child in value:
            _materialize(key, path)
            location = _pointer(path, key)
            if key in result:
                raise _InputProblem("duplicate_key", location, "Duplicate JSON object key.")
            result[key] = _materialize(child, location)
        return result
    if isinstance(value, list):
        return [_materialize(child, _pointer(path, index)) for index, child in enumerate(value)]
    if isinstance(value, str):
        try:
            value.encode("utf-8")
        except UnicodeEncodeError as error:
            raise _InputProblem("invalid_unicode", path, "JSON string contains an unpaired Unicode surrogate.") from error
    return value


def _finite_float(token: str) -> float:
    value = float(token)
    if not math.isfinite(value):
        raise _InputProblem("non_finite_number", "", "JSON numbers must be finite.")
    return value


def _strict_integer(token: str) -> int:
    try:
        return int(token)
    except ValueError as error:
        # CPython limits conversion of unusually large decimal integer tokens.
        # Raising its process-wide policy would weaken other callers' limits.
        raise _InputProblem("integer_capacity", "", "Integer token exceeds parser capacity.", resource=True) from error


def _reject_constant(token: str) -> None:
    raise _InputProblem("non_standard_number", "", f"{token} is not a standard JSON number.")


def _scan_depth(text: str, limit: int) -> int:
    depth = maximum = 0
    in_string = escaped = False
    for character in text:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
        elif character == '"':
            in_string = True
        elif character in "[{":
            depth += 1
            maximum = max(maximum, depth)
            if maximum > limit:
                raise _InputProblem("max_depth", "", f"JSON nesting exceeds max_depth={limit}.", resource=True)
        elif character in "]}":
            depth -= 1
    return maximum


def _limits_from_input(document: dict[str, Any], caller: Limits) -> Limits:
    requested = document.get("limits")
    if not isinstance(requested, dict):
        raise _InputProblem("limits_object", "/limits", "A limits object is required.")
    defaults = Limits().to_dict()
    for key, value in requested.items():
        if key not in defaults:
            raise _InputProblem("unknown_limit", _pointer("/limits", key), "Unknown limit name.")
        if type(value) is not int or value <= 0:
            raise _InputProblem("invalid_limit", _pointer("/limits", key), "Limits must be strictly positive integers; booleans are not integers.")
    return Limits(**{
        name: min(requested.get(name, default), getattr(caller, name))
        for name, default in defaults.items()
    })


def _count_records(document: Any) -> int:
    """Count dictionary records occurring directly in arrays, before deduplication.

    Includes nested clauses, conditions, ports, versions, and Fact conflict
    candidates. Object-shaped containers and scalar reference lists do not
    themselves add records. This rule also bounds explicit extension records.
    """
    count = 0
    stack = [document]
    while stack:
        current = stack.pop()
        if isinstance(current, dict):
            stack.extend(current.values())
        elif isinstance(current, list):
            count += sum(isinstance(item, dict) for item in current)
            stack.extend(current)
    return count


def _atomic_action_count(document: dict[str, Any]) -> int:
    # Each finite effect has its own stable ID and receiving output port (for
    # data effects). Even an action with no effect consumes an execution item.
    return sum(max(1, len(action["effects"])) for action in document["actions"])


def _unsupported_items(document: dict[str, Any]) -> tuple[dict[str, Any], ...]:
    context = document["context"]
    items = list(context.get("unsupported_items", []))
    for operation in context["operation_definitions"]:
        if operation["semantic_kind"] == "unsupported":
            items.append({
                "id": operation["id"],
                "reason": operation["unsupported_reason"],
                "affected_refs": {
                    "state": "known",
                    "value": [{"collection": "operations", "id": operation["id"]}],
                    "evidence_refs": operation["evidence_refs"],
                },
            })
    for control_index, control in enumerate(document["controls"]):
        for policy_index, policy in enumerate(control["policy_versions"]):
            decision = policy["decision_mode"]
            if decision["state"] == "known":
                declared_modes = [decision["value"]]
            elif decision["state"] == "conflict":
                declared_modes = [candidate["value"] for candidate in decision["candidates"]]
            else:
                declared_modes = []
            unsupported_modes = sorted(set(declared_modes) & {"external", "unsupported"})
            if unsupported_modes:
                items.append({
                    "id": f"policy/{control['id']}/{policy['id']}",
                    "reason": policy.get("unsupported_reason", "Declared external or unsupported policy decision is not interpreted."),
                    "affected_refs": {"state": "known", "value": [
                        {"collection": "controls", "id": control["id"]}
                    ], "evidence_refs": decision["evidence_refs"]},
                    "policy_id": policy["id"],
                    "path": f"/controls/{control_index}/policy_versions/{policy_index}/decision_mode",
                    "decision_state": decision["state"],
                    "declared_modes": unsupported_modes,
                })
    return tuple(items)


def validate_json(document: str | bytes, *, limits: Limits | None = None) -> ValidationResult:
    """Validate raw JSON without analysis, I/O, or interpretation of references.

    Expected input failures return location diagnostics. Programmer misuse
    (such as passing an already decoded dict) raises ``TypeError``; unexpected
    implementation errors propagate and are never converted to unknown facts.
    """
    if not isinstance(document, (str, bytes)):
        raise TypeError("document must be raw JSON str or bytes")
    if limits is not None and not isinstance(limits, Limits):
        raise TypeError("limits must be Limits or None")
    effective = caller = limits if limits is not None else Limits()
    schema_version = None

    def result(status: str, diagnostics: tuple[Diagnostic, ...], *, data: dict | None = None) -> ValidationResult:
        return ValidationResult(
            validation_status=status,
            schema_version=schema_version,
            diagnostics=diagnostics,
            unsupported_items=_unsupported_items(data) if data is not None else (),
            effective_limits=effective,
            model=Deployment(data) if data is not None else None,
        )

    try:
        try:
            raw = document.encode("utf-8") if isinstance(document, str) else document
        except UnicodeEncodeError as error:
            raise _InputProblem("invalid_utf8", "", "Input text contains an invalid Unicode surrogate.") from error
        if len(raw) > caller.max_input_bytes:
            raise _InputProblem("max_input_bytes", "", f"Input exceeds max_input_bytes={caller.max_input_bytes}.", resource=True)
        try:
            text = raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError as error:
            raise _InputProblem("invalid_utf8", "", f"Input is not UTF-8 at byte {error.start}.") from error
        depth = _scan_depth(text, caller.max_depth)
        try:
            parsed = json.loads(text, object_pairs_hook=_ObjectPairs, parse_float=_finite_float,
                                parse_int=_strict_integer, parse_constant=_reject_constant)
            data = _materialize(parsed)
        except json.JSONDecodeError as error:
            raise _InputProblem("invalid_json", "", f"Invalid JSON at line {error.lineno}, column {error.colno}: {error.msg}.") from error
        except RecursionError as error:
            raise _InputProblem("parser_capacity", "", "JSON nesting exceeds parser capacity.", resource=True) from error
        if not isinstance(data, dict):
            raise _InputProblem("root_object", "", "The JSON root must be an object.")
        context = data.get("context")
        if not isinstance(context, dict):
            raise _InputProblem("context_object", "/context", "A context object is required.")
        version = context.get("schema_version")
        if not isinstance(version, str) or not version:
            raise _InputProblem("schema_version", "/context/schema_version", "A nonempty schema_version string is required.")
        schema_version = version
        # An unknown version is not interpreted using this version's fields.
        if schema_version != SUPPORTED_SCHEMA:
            return result("unsupported_schema", (Diagnostic("unsupported_schema", "/context/schema_version", f"Supported schema: {SUPPORTED_SCHEMA}."),))
        effective = _limits_from_input(data, caller)
        if len(raw) > effective.max_input_bytes:
            raise _InputProblem("max_input_bytes", "/limits/max_input_bytes", f"Input exceeds effective max_input_bytes={effective.max_input_bytes}.", resource=True)
        if depth > effective.max_depth:
            raise _InputProblem("max_depth", "/limits/max_depth", f"JSON nesting exceeds effective max_depth={effective.max_depth}.", resource=True)
        if _count_records(data) > effective.max_records:
            raise _InputProblem("max_records", "", f"Input records exceed max_records={effective.max_records}.", resource=True)
        if isinstance(data.get("actions"), list) and len(data["actions"]) > effective.max_actions:
            raise _InputProblem("max_actions", "/actions", f"Input actions exceed max_actions={effective.max_actions}.", resource=True)

        from .schema import validate_structure
        from .references import validate_references

        diagnostics = tuple(validate_structure(data))
        if diagnostics:
            return result("input_invalid", diagnostics)
        if _atomic_action_count(data) > effective.max_actions:
            raise _InputProblem("max_actions", "/actions", f"Normalized atomic effects exceed max_actions={effective.max_actions}.", resource=True)
        diagnostics = tuple(validate_references(data))
        if diagnostics:
            return result("input_invalid", diagnostics)
        return result("valid", (), data=data)
    except _InputProblem as error:
        status = "resource_rejected" if error.resource else "input_invalid"
        return result(status, (error.diagnostic,))
