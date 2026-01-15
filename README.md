# Zero Trust MCP Gateway

**Zero-Trust Security Gateway for MCP & Agent Tool Calls**

> A policy-driven, defense-in-depth gateway that enforces zero-trust security controls on tool calls in Model Context Protocol (MCP) and agent workflows.

---

## 🚨 Why This Exists

As agents and LLM systems gain the ability to call tools (APIs, databases, services, CLIs), they introduce **new attack surfaces**:

- Privilege escalation via unintended arguments
- Prompt & injection attacks against downstream tools
- Data exfiltration via search/export tools
- Runaway agents making unbounded tool calls
- Weak auditability of agent behavior

**Zero Trust MCP Gateway** treats *every tool call as untrusted* and enforces a strict, layered security pipeline before execution.

---

## 🧠 Design Philosophy

This project follows **Zero Trust principles**:

- **Never trust** agent input by default
- **Always verify** identity, intent, and arguments
- **Least privilege** per tool and role
- **Explicit allow policies**
- **Full auditability**

This repository is the **advanced, gateway-grade implementation**.

> 🔹 For a lightweight, policy-only engine, see  
> **https://github.com/rajasblack/zero-trust-mcp**

---

## 🧱 Architecture: 8-Layer Zero-Trust Pipeline

Every tool call flows through the same deterministic pipeline:
┌────────────────────────────────────────────────┐
│ 1. Authenticate │ Who is calling?              |
├────────────────────────────────────────────────┤
│ 2. Rate Limit │ Too many calls?                |
├────────────────────────────────────────────────┤
│ 3. Validate │ Correct shape & size?            |
├────────────────────────────────────────────────┤
│ 4. Authorize │ Allowed by policy & role?       |
├────────────────────────────────────────────────┤
│ 5. Detect Attacks │ Injection / abuse patterns?|
├────────────────────────────────────────────────┤
│ 6. Forward │ Call the actual tool              |
├────────────────────────────────────────────────┤
│ 7. Redact │ Remove secrets & PII               |
├────────────────────────────────────────────────┤
│ 8. Audit Log │ Record decision & metadata      |
└────────────────────────────────────────────────┘


Each layer can **allow, deny, or enrich context**.

---

## ✨ Key Features

### 🔐 Zero-Trust Policy Enforcement
- Default-deny model
- Explicit allow & deny rules
- Role-aware authorization
- Argument constraints (type, regex, enum, ranges)

### 🛡 Defense-in-Depth
- Strict argument validation
- Injection detection (SQLi, traversal, SSRF heuristics)
- Rate limiting (runaway agent protection)

### 🧹 Safe Outputs
- Redacts secrets and PII from tool results
- Prevents sensitive data leakage back to agents

### 🧾 Full Audit Trail
- Structured JSON logs
- Safe-by-default (no argument values unless enabled)
- Includes decision layer, reason, and policy ID

### 🌍 Platform-Agnostic
- Policy format is portable YAML / JSON
- Gateway concept works for:
  - MCP servers
  - Agent frameworks
  - Tool routers
  - API wrappers

---

## 📦 Installation

```bash
pip install -e .

Python 3.10+ required.

## 🚀 Quickstart
### 1️⃣ Define a Policy `policy.yaml`

```yaml
policy_id: customer_support_policy
version: "1.0"
default: deny

validate:
  reject_unknown_args: true
  max_arg_bytes: 10000

allow_rules:
  - tool: hello
    roles: ["support"]
    constraints:
      name:
        type: string
        required: true

deny_rules:
  - tool: delete_user
    reason: "User deletion not permitted"
```

### 2️⃣ Enforce Tool Calls

```python
from zero_trust_mcp_gateway import PolicyEngine, Enforcer, ToolCall
from zero_trust_mcp_gateway.audit.logger import get_audit_logger

engine = PolicyEngine.from_file("policy.yaml")
enforcer = Enforcer(engine, get_audit_logger())

def hello(name: str):
    return {"msg": f"hi {name}", "email": "alice@example.com"}

result = enforcer.enforce(
    ToolCall(
        tool_name="hello",
        arguments={"name": "Ada"},
        roles=["support"]
    ),
    hello
)

print(result)
# => {"msg": "hi Ada", "email": "[REDACTED_EMAIL]"}
```

### 📜 Policy Model (Extended)
### Allow Rules

```yaml
allow_rules:
  - tool: get_user
    roles: ["support", "admin"]
    constraints:
      user_id:
        type: string
        pattern: "^EMP[0-9]{6}$"
```

### Validation Controls

```yaml
validate:
  reject_unknown_args: true
  max_arg_bytes: 16384
```

### Rate Limiting

```yaml
rate_limit:
  enabled: true
  limit_per_minute: 60
  burst: 10
  scope: actor
```

### Attack Detection

```yaml
detect_attacks:
  enabled: true
  on_detect: deny
  fields: ["query", "sql", "url"]
```

### Output Redaction

```yaml
redact:
  enabled: true
  deny_keys: ["password", "token"]
  pii_emails: true
```

## Project Structure

```
zero_trust_mcp_gateway/
├── models.py
├── decisions.py
├── policy/
│   ├── schema.py
│   ├── loader.py
│   └── engine.py
├── pipeline/
│   ├── context.py
│   └── pipeline.py
├── layers/
│   ├── authenticate.py   # (pluggable)
│   ├── rate_limit.py
│   ├── validate.py
│   ├── authorize.py
│   ├── detect_attacks.py
│   ├── redact.py
│   └── audit.py
├── audit/
│   └── logger.py
└── enforcement/
    └── wrapper.py
```

## Development

```bash
pip install -e ".[dev]"
pytest
ruff check src/ examples/
ruff format src/ examples/
```

## 🔒 Security Model
- Default deny
- Explicit allow
- Deterministic evaluation
- No side effects before authorization
- No sensitive data in logs by default
- This design maps cleanly to Zero Trust Architecture (ZTA) and Policy Enforcement Point (PEP) patterns.

## License
MIT License

## Contributing
Contributions welcome:
  1. New detection layers
  2. Alternative rate limit backends (Redis)
  3. MCP server adapters
  4. Agent framework integrations
Open an issue or PR.

#### Zero trust isn’t a feature. It’s an architecture.