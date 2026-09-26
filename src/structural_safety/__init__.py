"""Structural Safety Toolkit: explicit deployment models and bounded analysis."""

from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
import tomllib


def _version_info() -> tuple[str, str]:
    try:
        return version("structural-safety-toolkit"), "installed metadata"
    except PackageNotFoundError:
        # A source checkout has no installed distribution metadata. Read the
        # single authoritative version instead of maintaining a second constant.
        project_file = Path(__file__).resolve().parents[2] / "pyproject.toml"
        try:
            with project_file.open("rb") as stream:
                project = tomllib.load(stream).get("project", {})
            if project.get("name") == "structural-safety-toolkit":
                project_version = project.get("version")
                if isinstance(project_version, str):
                    return project_version, "source checkout"
        except (OSError, ValueError):
            pass
        return "unknown", "distribution metadata unavailable"


__version__, _version_source = _version_info()

from .api import (  # noqa: E402
    AnalysisResult, DemoResult, Limits, ValidationResult, analyze_json, run_demo,
    validate_json,
)

__all__ = [
    "AnalysisResult", "DemoResult", "Limits", "ValidationResult", "analyze_json",
    "run_demo", "validate_json", "__version__",
]
