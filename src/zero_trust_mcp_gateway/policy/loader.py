from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .schema import Policy, normalize_policy_dict


def _load_yaml(text: str) -> dict[str, Any]:
    try:
        import yaml  # type: ignore
    except Exception as e:
        raise RuntimeError("PyYAML is required to load .yaml policies. Install pyyaml.") from e
    data = yaml.safe_load(text) or {}
    if not isinstance(data, dict):
        raise ValueError("Policy YAML must parse to a dict/object.")
    return data


def _load_json(text: str) -> dict[str, Any]:
    data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError("Policy JSON must parse to a dict/object.")
    return data


def load_policy_from_file(path: str) -> Policy:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(path)

    raw = p.read_text(encoding="utf-8")
    if p.suffix.lower() in [".yaml", ".yml"]:
        d = _load_yaml(raw)
    elif p.suffix.lower() == ".json":
        d = _load_json(raw)
    else:
        try:
            d = _load_yaml(raw)
        except Exception:
            d = _load_json(raw)

    d = normalize_policy_dict(d)
    return Policy.model_validate(d)


def load_policy_from_dict(d: dict[str, Any]) -> Policy:
    d = normalize_policy_dict(d)
    return Policy.model_validate(d)


class PolicyLoader:
    """
    Backward-compatible facade.

    Your repo's policy/__init__.py imports PolicyLoader, so we provide it.
    """

    @staticmethod
    def load_from_file(path: str) -> Policy:
        return load_policy_from_file(path)

    @staticmethod
    def load_from_dict(d: dict[str, Any]) -> Policy:
        return load_policy_from_dict(d)
