from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Decision:
    allowed: bool
    reason: str
    policy_id: str
    remediation: str | None = None
    layer: str | None = None  # authorize/rate_limit/validate/detect_attacks/etc


class PolicyDeniedError(RuntimeError):
    """
    Raised when a tool call is denied by policy or another security layer.
    Carries the Decision for structured handling.
    """

    def __init__(self, decision: Decision):
        super().__init__(f"Denied: {decision.reason}")
        self.decision = decision
