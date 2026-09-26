"""Immutable input and validation models.

``Deployment`` is a validated, deeply immutable wrapper around the complete
input contract. References remain exact, case-sensitive identifiers; a
``Reference`` supplies an explicit namespace when a consumer builds indexes.
No model constructor performs safety analysis or establishes evidence truth.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from dataclasses import dataclass, fields
from types import MappingProxyType
from typing import Any, Literal


@dataclass(frozen=True, slots=True)
class Diagnostic:
    code: str
    path: str
    message: str
    severity: str = "error"

    def to_dict(self) -> dict[str, str]:
        return {field.name: getattr(self, field.name) for field in fields(self)}


@dataclass(frozen=True, slots=True)
class Limits:
    """Caller policy caps. Only strictly positive integers are accepted."""

    max_input_bytes: int = 2_097_152
    max_depth: int = 32
    max_records: int = 10_000
    max_actions: int = 128
    max_states: int = 10_000
    max_transition_checks: int = 100_000
    max_scope_combinations: int = 20_000
    max_clause_checks: int = 1_000_000
    max_findings: int = 1_000

    def __post_init__(self) -> None:
        for field in fields(self):
            value = getattr(self, field.name)
            if type(value) is not int:
                raise TypeError(f"{field.name} must be an integer, not {type(value).__name__}")
            if value <= 0:
                raise ValueError(f"{field.name} must be positive")

    def to_dict(self) -> dict[str, int]:
        return {field.name: getattr(self, field.name) for field in fields(self)}


@dataclass(frozen=True, slots=True)
class Reference:
    """A namespace-qualified reference, never interchangeable by ID alone."""

    collection: str
    id: str

    def __post_init__(self) -> None:
        if not isinstance(self.collection, str) or not self.collection:
            raise ValueError("reference collection must be a nonempty string")
        if not isinstance(self.id, str) or not self.id:
            raise ValueError("reference id must be a nonempty string")


@dataclass(frozen=True, slots=True)
class Fact(Mapping[str, Any]):
    """Immutable validated Fact, preserving unknown and conflict states.

    Empty evidence references on a known Fact give it supplied-assertion
    provenance. Nonempty references need later scoped interpretation and do
    not automatically gain a stronger evidence class. This attribute is
    normalization metadata, not an additional input-format field.
    """

    _fields: Mapping[str, Any]

    def __post_init__(self) -> None:
        object.__setattr__(self, "_fields", MappingProxyType({
            key: freeze(value) for key, value in self._fields.items()
        }))

    def __getitem__(self, key: str) -> Any:
        return self._fields[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self._fields)

    def __len__(self) -> int:
        return len(self._fields)

    @property
    def state(self) -> str:
        return self._fields["state"]

    @property
    def evidence_basis(self) -> tuple[str, ...]:
        if self.state == "known" and not self._fields.get("evidence_refs", ()):
            return ("supplied_assertion",)
        return ()

    def to_dict(self) -> dict[str, Any]:
        return thaw(self)


def freeze(value: Any) -> Any:
    """Copy JSON data into mappings/tuples, wrapping validated Fact shapes."""
    if isinstance(value, Fact):
        return value
    if isinstance(value, Mapping):
        if value.get("state") in ("known", "unknown", "conflict") and "evidence_refs" in value:
            return Fact(value)
        return MappingProxyType({key: freeze(item) for key, item in value.items()})
    if isinstance(value, (tuple, list)):
        return tuple(freeze(item) for item in value)
    return value


def thaw(value: Any) -> Any:
    """Produce a fresh JSON-shaped copy, with no mutable model aliases."""
    if isinstance(value, Mapping):
        return {key: thaw(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [thaw(item) for item in value]
    return value


@dataclass(frozen=True, slots=True)
class Deployment:
    """Validated input data. Submitted evidence is never direct observation."""

    data: Mapping[str, Any]

    def __post_init__(self) -> None:
        object.__setattr__(self, "data", freeze(self.data))

    @property
    def reported_evidence(self) -> tuple[Mapping[str, Any], ...]:
        """Submitted records, retaining their claims without authenticating them."""
        return self.data["evidence"]

    @property
    def reported_events(self) -> tuple[Mapping[str, Any], ...]:
        return self.data.get("events", ())

    def to_dict(self) -> dict[str, Any]:
        return thaw(self.data)


ValidationStatus = Literal["valid", "input_invalid", "unsupported_schema", "resource_rejected"]


@dataclass(frozen=True, slots=True)
class ValidationResult:
    validation_status: ValidationStatus
    schema_version: str | None
    diagnostics: tuple[Diagnostic, ...]
    unsupported_items: tuple[Mapping[str, Any], ...]
    effective_limits: Limits
    model: Deployment | None = None
    analysis_performed: Literal[False] = False
    supported_capabilities: tuple[str, ...] = ("input_validation",)

    def __post_init__(self) -> None:
        object.__setattr__(self, "diagnostics", tuple(self.diagnostics))
        object.__setattr__(self, "unsupported_items", tuple(freeze(item) for item in self.unsupported_items))
        object.__setattr__(self, "supported_capabilities", tuple(self.supported_capabilities))
        if self.analysis_performed is not False:
            raise ValueError("validation never performs analysis")

    @property
    def result_schema_version(self) -> str:
        return "sst.validation/0.1"

    def to_dict(self) -> dict[str, Any]:
        from .report import validation_to_dict
        return validation_to_dict(self)

    def to_markdown(self) -> str:
        from .report import validation_to_markdown
        return validation_to_markdown(self)
