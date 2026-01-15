from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from ..redaction import DEFAULT_DENY_KEYS, redact_value


@dataclass(slots=True)
class AuditLogger:
    logger: logging.Logger
    deny_keys: list[str]

    def log(
        self,
        *,
        action: str,
        tool_name: str,
        decision: str,
        reason: str,
        policy_id: str,
        actor: str | None = None,
        request_id: str | None = None,
        arguments: dict[str, Any] | None = None,
        layer: str | None = None,
        latency_ms: int | None = None,
        client: dict[str, Any] | None = None,
        result: Any | None = None,
        include_result: bool = False,
        include_argument_values: bool = False,
    ) -> None:
        ts = datetime.now(timezone.utc).isoformat()

        args = arguments or {}
        args_summary = {"keys": sorted(list(args.keys())), "key_count": len(args.keys())}

        event: dict[str, Any] = {
            "timestamp": ts,
            "action": action,
            "tool_name": tool_name,
            "decision": decision,
            "reason": reason,
            "policy_id": policy_id,
            "actor": actor,
            "request_id": request_id,
            "layer": layer,
            "latency_ms": latency_ms,
            "arguments_summary": args_summary,
        }

        if client is not None:
            event["client"] = redact_value(client, deny_keys=self.deny_keys)

        if include_argument_values:
            event["arguments"] = redact_value(args, deny_keys=self.deny_keys)

        if include_result and result is not None:
            event["result"] = redact_value(result, deny_keys=self.deny_keys)

        event = {k: v for k, v in event.items() if v is not None}
        self.logger.info(json.dumps(event, ensure_ascii=False))


def get_audit_logger(name: str = "zero_trust_mcp.audit") -> AuditLogger:
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter("%(message)s")
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    return AuditLogger(logger=logger, deny_keys=DEFAULT_DENY_KEYS)
