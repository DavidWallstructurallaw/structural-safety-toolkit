"""Immutable results for fixed, local synthetic experiments."""

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from .model import Diagnostic, Limits, freeze


@dataclass(frozen=True, slots=True)
class DemoResult:
    demo_status: str
    scenario: str
    protocol_verdict: str = "not_tested"
    cases: tuple[Mapping[str, Any], ...] = ()
    diagnostics: tuple[Diagnostic, ...] = ()
    effective_limits: Limits = field(default_factory=Limits)
    environment_errors: tuple[Mapping[str, Any], ...] = ()
    scope: Mapping[str, Any] = field(default_factory=dict)
    run_directory: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "diagnostics", tuple(self.diagnostics))
        object.__setattr__(self, "scope", freeze(self.scope))
        for name in ("cases", "environment_errors"):
            object.__setattr__(self, name, tuple(freeze(item) for item in getattr(self, name)))

    @property
    def result_schema_version(self) -> str:
        return "sst.demo/0.1"

    def to_dict(self) -> dict[str, Any]:
        from .report import demo_to_dict
        return demo_to_dict(self)

    def to_markdown(self) -> str:
        from .report import demo_to_markdown
        return demo_to_markdown(self)
