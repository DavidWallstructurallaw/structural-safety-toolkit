"""Public API for input validation and bounded structural analysis."""

from .analysis import analyze_json
from .analysis_model import AnalysisResult
from .model import Limits, ValidationResult
from .validation import validate_json

__all__ = ["AnalysisResult", "Limits", "ValidationResult", "analyze_json", "validate_json"]
