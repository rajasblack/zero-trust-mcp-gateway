from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


ConstraintType = Literal["string", "integer", "number", "boolean"]


class Constraint(BaseModel):
    type: ConstraintType = Field(..., description="Constraint type")
    description: str | None = None

    # string
    pattern: str | None = None
    enum: list[Any] | None = None

    # number/integer
    min: float | None = None
    max: float | None = None

    required: bool | None = None


class AllowRule(BaseModel):
    tool: str
    constraints: dict[str, Constraint] = Field(default_factory=dict)

    # optional RBAC
    roles: list[str] | None = None


class DenyRule(BaseModel):
    tool: str
    condition: dict[str, Any] | None = None
    reason: str = "Denied by policy"


class ValidateConfig(BaseModel):
    reject_unknown_args: bool = False
    max_arg_bytes: int = 0  # 0 => no limit


class RateLimitConfig(BaseModel):
    enabled: bool = False
    limit_per_minute: int = 0
    burst: int = 0
    scope: Literal["actor", "session", "tool", "actor+tool"] = "actor"


class DetectAttacksConfig(BaseModel):
    enabled: bool = False
    on_detect: Literal["deny", "allow"] = "deny"
    fields: list[str] = Field(default_factory=lambda: ["query", "sql", "where", "url", "path"])


class RedactConfig(BaseModel):
    enabled: bool = False
    deny_keys: list[str] = Field(
        default_factory=lambda: ["password", "token", "secret", "api_key", "authorization"]
    )
    pii_emails: bool = True
    pii_phones: bool = False
    max_string_len: int = 2048


class AuditConfig(BaseModel):
    enabled: bool = True
    include_result: bool = False
    include_argument_values: bool = False


class Policy(BaseModel):
    """
    NOTE: we intentionally do NOT name a field `validate`, because Pydantic BaseModel
    already has a `validate` attribute. We accept YAML key `validate` via alias.
    """

    policy_id: str
    version: str
    default: Literal["allow", "deny"] = "deny"

    allow_rules: list[AllowRule] = Field(default_factory=list)
    deny_rules: list[DenyRule] = Field(default_factory=list)

    # internal names, external YAML keys preserved via alias
    validate_cfg: ValidateConfig | None = Field(default=None, alias="validate")
    rate_limit: RateLimitConfig | None = None
    detect_attacks: DetectAttacksConfig | None = None
    redact: RedactConfig | None = None
    audit: AuditConfig | None = None

    # Pydantic v2: allow population by either field name or alias
    model_config = {
        "populate_by_name": True,
        "extra": "ignore",
    }


def normalize_policy_dict(d: dict[str, Any]) -> dict[str, Any]:
    return d
