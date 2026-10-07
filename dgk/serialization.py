from __future__ import annotations

import json
from typing import Any, Dict


# COMPONENT SERIALIZATION & DETERMINISTIC UTILITIES
# ============================================================
def canonicalize_dictionary(obj: Dict[str, Any]) -> str:
    """Converts input mapping structures into deterministic sorted strings."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def normalize_numeric_precision(obj: Any, precision: int = 10) -> Any:
    """Recursively processes values to lock floating-point accuracy scales."""
    if isinstance(obj, float):
        return round(obj, precision)
    if isinstance(obj, dict):
        return {k: normalize_numeric_precision(v, precision) for k, v in obj.items()}
    if isinstance(obj, list):
        return [normalize_numeric_precision(v, precision) for v in obj]
    return obj


def filter_private_keys(obj: Dict[str, Any]) -> Dict[str, Any]:
    """Strips runtime internal attributes starting with underscores."""
    return {k: v for k, v in obj.items() if not k.startswith("_")}


# ============================================================
