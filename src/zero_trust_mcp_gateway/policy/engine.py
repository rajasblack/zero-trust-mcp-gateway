from __future__ import annotations

import re
from typing import Any

from ..decisions import Decision
from ..models import ToolCall
from .loader import load_policy_from_dict, load_policy_from_file
from .schema import AllowRule, Constraint, Policy


class PolicyEngine:
    """
    Core policy evaluation:
      - deny rules override allow rules
      - allow rules can include constraints and optional roles
      - default is allow/deny if no rules match
      - optional strict validation can deny unknown args / huge payloads
    """

    def __init__(self, policy: Policy):
        self.policy = policy

    @classmethod
    def from_file(cls, path: str) -> "PolicyEngine":
        return cls(load_policy_from_file(path))

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "PolicyEngine":
        return cls(load_policy_from_dict(d))

    def evaluate(self, tool_call: ToolCall) -> Decision:
        vcfg = self.policy.validate_cfg
        if vcfg and vcfg.max_arg_bytes:
            if tool_call.arguments_size_bytes() > vcfg.max_arg_bytes:
                return Decision(
                    allowed=False,
                    reason=f"Arguments too large (>{vcfg.max_arg_bytes} bytes)",
                    policy_id=self.policy.policy_id,
                    remediation="Reduce arguments payload size.",
                    layer="validate",
                )

        denied = self._match_deny(tool_call)
        if denied is not None:
            return Decision(
                allowed=False,
                reason=denied,
                policy_id=self.policy.policy_id,
                remediation=None,
                layer="authorize",
            )

        allow = self._match_allow(tool_call)
        if allow is not None:
            rule, validation_error = allow
            if validation_error is not None:
                return Decision(
                    allowed=False,
                    reason=validation_error,
                    policy_id=self.policy.policy_id,
                    remediation="Fix tool arguments to satisfy policy constraints.",
                    layer="validate",
                )

            if vcfg and vcfg.reject_unknown_args:
                unknown = set(tool_call.arguments.keys()) - set(rule.constraints.keys())
                if unknown:
                    return Decision(
                        allowed=False,
                        reason=f"Unknown arguments not allowed: {sorted(unknown)}",
                        policy_id=self.policy.policy_id,
                        remediation="Remove unknown arguments.",
                        layer="validate",
                    )

            return Decision(
                allowed=True,
                reason="Matched allow rule",
                policy_id=self.policy.policy_id,
                remediation=None,
                layer="authorize",
            )

        if self.policy.default == "allow":
            return Decision(
                allowed=True,
                reason="No matching rule; default allow",
                policy_id=self.policy.policy_id,
                remediation=None,
                layer="authorize",
            )

        return Decision(
            allowed=False,
            reason="No matching rule; default deny",
            policy_id=self.policy.policy_id,
            remediation="Request access via policy update.",
            layer="authorize",
        )

    def _match_deny(self, tool_call: ToolCall) -> str | None:
        for rule in self.policy.deny_rules:
            if rule.tool != tool_call.tool_name:
                continue

            if rule.condition is None:
                return rule.reason

            ok = True
            for k, v in rule.condition.items():
                if tool_call.arguments.get(k) != v:
                    ok = False
                    break

            if ok:
                return rule.reason

        return None

    def _match_allow(self, tool_call: ToolCall) -> tuple[AllowRule, str | None] | None:
        for rule in self.policy.allow_rules:
            if rule.tool != tool_call.tool_name:
                continue

            if rule.roles is not None:
                if not set(rule.roles).intersection(set(tool_call.roles)):
                    return (rule, "Actor role not permitted for this tool")

            err = self._validate_constraints(rule.constraints, tool_call.arguments)
            if err is not None:
                return (rule, err)

            return (rule, None)

        return None

    def _validate_constraints(self, constraints: dict[str, Constraint], args: dict[str, Any]) -> str | None:
        # required checks first
        for name, c in constraints.items():
            if c.required and name not in args:
                return f"Missing required argument: {name}"

        for name, c in constraints.items():
            if name not in args:
                continue

            value = args.get(name)

            # If present but explicitly null, treat as invalid for typed constraints
            if value is None:
                return f"Argument '{name}' must not be null"

            if c.type == "string":
                if not isinstance(value, str):
                    return f"Argument '{name}' must be a string"
                if c.pattern:
                    try:
                        if not re.match(c.pattern, value):
                            return f"Argument '{name}' does not match pattern"
                    except re.error:
                        return f"Invalid regex pattern in policy for '{name}'"
                if c.enum is not None and value not in c.enum:
                    return f"Argument '{name}' must be one of {c.enum}"

            elif c.type == "boolean":
                if not isinstance(value, bool):
                    return f"Argument '{name}' must be a boolean"

            elif c.type in ("integer", "number"):
                if c.type == "integer":
                    # bool is a subclass of int; reject it
                    if not isinstance(value, int) or isinstance(value, bool):
                        return f"Argument '{name}' must be an integer"
                else:
                    if not isinstance(value, (int, float)) or isinstance(value, bool):
                        return f"Argument '{name}' must be a number"

                # safe conversion for min/max comparisons
                try:
                    num = float(value)
                except (TypeError, ValueError):
                    return f"Argument '{name}' must be numeric"

                if c.min is not None and num < c.min:
                    return f"Argument '{name}' must be >= {c.min}"
                if c.max is not None and num > c.max:
                    return f"Argument '{name}' must be <= {c.max}"

            else:
                return f"Unsupported constraint type for '{name}': {c.type}"

        return None
