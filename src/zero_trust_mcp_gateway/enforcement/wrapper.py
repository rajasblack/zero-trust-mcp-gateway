from __future__ import annotations

from collections.abc import Callable
from typing import Any

from ..audit.logger import AuditLogger
from ..layers.audit import audit_layer
from ..layers.authorize import authorize_layer
from ..layers.detect_attacks import detect_attacks_layer
from ..layers.rate_limit import rate_limit_layer
from ..layers.redact import redact_layer
from ..layers.validate import validate_layer
from ..models import ToolCall
from ..pipeline.pipeline import Pipeline
from ..policy.engine import PolicyEngine
from ..rate_limit import InMemoryRateLimiter


class Enforcer:
    """
    Backward-compatible: enforcer.enforce(call, tool_fn) -> result
    Denials raise PolicyDeniedError.
    """

    def __init__(self, engine: PolicyEngine, audit_logger: AuditLogger | None = None):
        self.engine = engine
        self.audit_logger = audit_logger
        self._limiter = InMemoryRateLimiter()

    def enforce(self, tool_call: ToolCall, tool_fn: Callable[..., Any]) -> Any:
        policy = self.engine.policy

        layers = [
            validate_layer(policy.policy_id, policy.validate_cfg),
            rate_limit_layer(policy.policy_id, policy.rate_limit, self._limiter),
            authorize_layer(self.engine),
            detect_attacks_layer(policy.policy_id, policy.detect_attacks),
            redact_layer(policy.redact),
            audit_layer(self.audit_logger, policy.audit),
        ]

        pipeline = Pipeline(engine=self.engine, layers=layers)
        return pipeline.execute(tool_call, tool_fn)


def _callable_name(fn: Callable[..., Any]) -> str:
    """
    Robustly derive a name for any callable (functions, callables, partials, etc.).
    Avoids type-checker complaints and weird callables with no __name__.
    """
    name = getattr(fn, "__name__", None)
    if isinstance(name, str) and name:
        return name
    return fn.__class__.__name__


def enforce_tool_call(engine: PolicyEngine, audit_logger: AuditLogger | None = None):
    """
    Decorator style.
    """
    enforcer = Enforcer(engine, audit_logger)

    def decorator(fn: Callable[..., Any]):
        tool_name = _callable_name(fn)

        def wrapped(**kwargs: Any) -> Any:
            call = ToolCall(tool_name=tool_name, arguments=dict(kwargs))
            return enforcer.enforce(call, fn)

        return wrapped

    return decorator
