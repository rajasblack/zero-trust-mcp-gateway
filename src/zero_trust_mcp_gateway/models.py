from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field


class ToolCall(BaseModel):
    """

    Fields:
      - tool_name
      - arguments
      - actor (optional)
      - request_id (optional)
      - roles: role names for RBAC-ish authz
      - client/context/auth/source: platform-agnostic metadata for tracing, auth, rate limiting
    """

    tool_name: str = Field(..., description="Tool/function name")
    arguments: dict[str, Any] = Field(default_factory=dict, description="Tool arguments")

    actor: str | None = Field(default=None, description="Actor/initiator identifier (e.g., email)")
    roles: list[str] = Field(default_factory=list, description="Roles associated with actor")

    request_id: str | None = Field(default=None, description="Request correlation ID")

    client: dict[str, Any] | None = Field(default=None, description="Client metadata (app, session_id, etc.)")
    context: dict[str, Any] | None = Field(default=None, description="Execution context (mcp server, transport, etc.)")
    auth: dict[str, Any] | None = Field(default=None, description="Authentication metadata (scheme, claims, etc.)")
    source: dict[str, Any] | None = Field(default=None, description="Source metadata (ip, user-agent, etc.)")

    timestamp: str | None = Field(
        default=None,
        description="ISO-8601 timestamp for the call; if omitted, caller can set it",
    )

    def iso_timestamp(self) -> str:
        if self.timestamp:
            return self.timestamp
        return datetime.now(timezone.utc).isoformat()

    def arguments_size_bytes(self) -> int:
        # simple size estimation without external deps
        import json

        try:
            return len(json.dumps(self.arguments, ensure_ascii=False).encode("utf-8"))
        except Exception:
            # if args aren't JSON-serializable, treat as huge and force deny if max_arg_bytes is used
            return 1_000_000_000


class PolicyDecisionContext(BaseModel):
    """
    Optional container for passing execution metadata into the engine.
    """
    now_iso: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
