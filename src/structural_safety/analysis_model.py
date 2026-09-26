"""Immutable public analysis result, separate from the internal search state."""

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from .model import Diagnostic, Limits, freeze


@dataclass(frozen=True, slots=True)
class AnalysisResult:
    """A bounded analysis report; completion never asserts overall safety.

    All report records are copied into immutable mappings and tuples. Methods
    return fresh serializable values without exposing the deployment model,
    runtime payloads, or mutable search state.
    """

    analysis_status: str
    schema_version: str | None = None
    analysis_performed: bool = True
    diagnostics: tuple[Diagnostic, ...] = ()
    findings: tuple[Mapping[str, Any], ...] = ()
    unresolved_items: tuple[Mapping[str, Any], ...] = ()
    obligations: tuple[Mapping[str, Any], ...] = ()
    input_completeness: tuple[Mapping[str, Any], ...] = ()
    supported_capabilities: tuple[str, ...] = ()
    unsupported_items: tuple[Mapping[str, Any], ...] = ()
    effective_limits: Limits = field(default_factory=Limits)
    budget_usage: Mapping[str, int] = field(default_factory=dict)
    truncation: tuple[Mapping[str, Any], ...] = ()
    action_results: tuple[Mapping[str, Any], ...] = ()
    coverage: tuple[Mapping[str, Any], ...] = ()
    scope: Mapping[str, Any] = field(default_factory=dict)
    event_reports: tuple[Mapping[str, Any], ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "diagnostics", tuple(self.diagnostics))
        object.__setattr__(self, "supported_capabilities", tuple(self.supported_capabilities))
        object.__setattr__(self, "budget_usage", freeze(self.budget_usage))
        object.__setattr__(self, "scope", freeze(self.scope))
        for name in (
            "findings", "unresolved_items", "obligations", "input_completeness",
            "unsupported_items", "truncation", "action_results", "coverage", "event_reports",
        ):
            object.__setattr__(self, name, tuple(freeze(item) for item in getattr(self, name)))

    @property
    def result_schema_version(self) -> str:
        return "sst.report/0.1"

    @property
    def rule_version(self) -> str:
        return "sst.rules/0.1"

    def to_dict(self) -> dict[str, Any]:
        from .report import analysis_to_dict
        return analysis_to_dict(self)

    def to_markdown(self) -> str:
        from .report import analysis_to_markdown
        return analysis_to_markdown(self)
