"""Editable finite business models, distinct from executable demo protocols."""

from importlib.resources import files
import json


TEMPLATE_NAMES = ("memory-handoff", "policy-self-modification", "human-oversight")
TEMPLATE_VARIANTS = ("exposed", "controlled")


def get_template(name: str, *, variant: str = "exposed") -> dict:
    """Return a fresh model; controlled means modeled conditions, not verification.

    Each call loads its own copy. Only the named, packaged resources are accepted;
    names cannot select arbitrary files. No deployment action is executed.
    """
    if not isinstance(name, str) or name not in TEMPLATE_NAMES:
        raise ValueError("Unknown business template.")
    if not isinstance(variant, str) or variant not in TEMPLATE_VARIANTS:
        raise ValueError("Unknown business template variant.")
    resource = files("structural_safety").joinpath("templates", f"{name}-{variant}.json")
    return json.loads(resource.read_text(encoding="utf-8"))
