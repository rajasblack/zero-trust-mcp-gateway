from zero_trust_mcp import Enforcer, PolicyEngine, ToolCall
from zero_trust_mcp.audit.logger import get_audit_logger

engine = PolicyEngine.from_file("policy.yaml")
enforcer = Enforcer(engine, get_audit_logger())

def hello(name: str):
    return {"msg": f"hi {name}"}

print(enforcer.enforce(ToolCall(tool_name="hello", arguments={"name": "Ada"}, roles=["support"]), hello))
