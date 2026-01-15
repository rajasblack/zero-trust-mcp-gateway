# Changelog

All notable changes to **zero-trust-mcp-gateway** will be documented in this file.

This project follows:
- [Semantic Versioning](https://semver.org/)
- A security-first, zero-trust design philosophy

---

## [0.1.0] – 2026-01-XX

### 🎉 Initial Release (Gateway Edition)

First public release of **zero-trust-mcp-gateway**, the advanced, gateway-grade evolution of `zero-trust-mcp`.

This release introduces a **full defense-in-depth enforcement pipeline** for MCP and agent tool calls.

---

### ✨ Added

#### Zero-Trust Enforcement Pipeline (8 Layers)
- Authenticate (pluggable; scaffolded)
- Rate limit (in-memory token bucket)
- Strict argument validation
- Policy-based authorization (RBAC support)
- Injection & abuse detection (SQLi, traversal, SSRF heuristics)
- Tool forwarding
- Output redaction (PII & secrets)
- Structured audit logging

#### Policy Enhancements
- Role-aware allow rules
- Strict argument handling (`reject_unknown_args`)
- Maximum argument payload size
- Rate-limiting policy configuration
- Attack detection configuration
- Output redaction configuration
- Audit verbosity controls

#### Security Features
- Default-deny behavior
- Deny rules override allow rules
- Injection pattern detection
- Runaway-agent protection via rate limiting
- Safe-by-default logging (no sensitive values)

#### Developer Experience
- `src/`-based package layout
- Typed Pydantic v2 models
- Clear separation of layers
- Backward-compatible policy YAML keys
- Path-safe example scripts

---

### 🧱 Architecture
- Middleware-style pipeline execution
- Deterministic evaluation order
- Policy Enforcement Point (PEP) design
- Platform- and transport-agnostic policy model

---

### 🧪 Tooling
- Python ≥ 3.10
- Pydantic ≥ 2.0
- PyYAML ≥ 6.0
- Ruff for linting/formatting
- Pytest for testing
- `py.typed` for typing consumers

---

### 📌 Notes
- This repository is intentionally **separate** from `zero-trust-mcp`
- `zero-trust-mcp` remains a lightweight policy engine
- This project is suitable for:
  - MCP servers
  - Agent frameworks
  - Tool routers
  - Secure AI middleware

---

## [Unreleased]

### Planned
- Authentication providers (JWT, API key, SPIFFE)
- Redis-backed rate limiting
- MCP server adapters
- OpenTelemetry tracing hooks
- Policy decision caching
- Additional attack detectors
