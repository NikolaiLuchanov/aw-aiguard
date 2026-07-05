# aw-aiguard

> **Central Guardrail & Audit Service** — A layered, local-first LLM security gateway that intercepts, validates, and audits AI tool calls to prevent prompt injection, data exfiltration, and excessive-agency failures.

---

## 🎯 Overview

`aw-aiguard` is an architectural blueprint and implementation roadmap for a **guardrail proxy service** that sits in front of LLM-powered development tools (Claude Code, OpenAI Codex, Claude Cowork, Hermes Agent). It provides real-time safety classification, comprehensive audit logging, human-in-the-loop approval for irreversible actions, and provenance-tracked data flows.

The project addresses **[OWASP Top 10 for LLM Applications — LLM01: Prompt Injection](https://genai.owasp.org/llmrisk/llm01-prompt-injection)**, currently the #1 ranked risk in AI application security, and implements a defense-in-depth strategy to break the **"lethal trifecta"** (private data access + untrusted content reading + outbound data channel in a single agent).

### Architecture Choice: Shared LLM Reverse Proxy

The project adopts **Option B** — a shared LLM gateway / reverse proxy on `localhost:9020` — over alternative approaches (local CLI wrappers or event-bus pub-sub). This provides the lowest latency, zero external core dependencies for real-time blocking, and a unified audit log pipeline.

Every tool routes through the proxy as an **Anthropic API-compatible endpoint** (`/v1/messages`), understanding `messages`, `model`, and `system_prompts` natively without protocol rewriting.

---

## 🏗 Architecture

```
Developer Workstation
┌─────────────────────────────────────────────┐
│  CLI Tools     │ Cowork Desktop │ Agent Runtimes   │
│  Claude Code   │ OpenAI Codex   │ Hermes Agent    │
│        ▲       │        ▲        │              │
│        │env vars│        │config│        │         │
│        ▼       │        ▼       │              │
│  ┌─────────────────────────────────────┐      │
│  │  Guardrail Proxy Gateway             │      │
│  │  localhost:9020                      │      │
│  │                                      │      │
│  │  Pre-flight Gate  │ HITL Middleware  │      │
│  │  LLM05 Output Ctrl│ PII/Secrets Scan │      │
│  └────────┬──────────────────┬─────────┘      │
│           │                  │                │
│           ▼                  ▼                │
│  Anthropic API            OpenAI API          │
│  Cloud Endpoint    ───>    Cloud Endpoint     │
│                                      ▲         │
│           Async Audit Log (▼)        │         │
│  PostgreSQL (Hot Tier — 30d)         │         │
│  S3/MinIO (Cold Tier — Indefinite)   │         │
└─────────────────────────────────────────────┘
```

**Three security layers:**

| Layer | Purpose | Timing |
|---|---|---|
| **Layer 1: Pre-Flight Gate** | Block harmful intent before any tool executes | Real-time, <1s |
| **Layer 2: Post-Hoc Audit** | Log every interaction (allow + block) for traceability | Async |
| **Layer 3B: Output Control** | Prevent OWASP LLM05 — treat all LLM output as untrusted data | On delivery |

---

## 🛡 Security Layers

### Layer A: Granite4.1 Guardian Safety Gate
- Dedicated [IBM Granite4.1 Guardian 8B](https://ollama.com) model running locally via Ollama
- **Fast mode** (`--think=false`): ~0.5s, binary yes/no classification for pre-flight checks
- **Thinking mode** (`--think=true`): Deeper reasoning trace for post-response verification on high-sensitivity outputs
- Detects function-calling hallucinations (0.79 BAcc) and unsafe tool-call parameters

### Layer B: Human-in-the-Loop (HITL) Middleware
- Irreversible actions (send email, commit code, delete data/files, payments, destructive APIs, write-side-shell commands) **require explicit human approval**
- `pending_approval` status with configurable timeout window (default: 5 min, then auto-deny)
- Provenance tags on every HITL request so approvers see trust levels and data lineage

### Layer C: Data/Command Separation (CaMeL Pattern)
- All tool parameters validated against JSON schemas — **no string concatenation** of untrusted content into executable paths
- Type-enforced routing from a proxy configuration table, never from LLM output parsing
- Input sanitization at dedicated middleware stage (SQL injection, command injection, path traversal)

### Layer D: PII & Secrets Scanning
- Parallel async background threads with regex + entropy scoring (zero GPU required)
- Detects: AWS keys, OAuth tokens, Slack tokens, SSH private keys, emails, phone numbers, passwords, connection strings, internal subdomains
- Auto-redaction in-place (`***REDACTED_API_KEY***`) with asynchronous audit log warnings

### Layer E: Provenance Tagging & Trust-Gating
Every data event carries a `provenance` object from ingestion time:

| Field | Type | Description | Example |
|---|---|---|---|
| `source_id` | string | Unique source identifier | `git-repo-1`, `slack-channel-7` |
| `source_type` | enum | Class of data origin | `repository`, `chat`, `llm_output` |
| `trust_level` | float | Precomputed trust score (0.0–1.0) | `0.95` internal, `0.2` public web |
| `ingested_at` | timestamp | First-seen time | `2026-07-01T14:30:00Z` |

**Trust-gated operations:** Low-trust content (`trust_level < 0.5`) triggers enhanced Guardian checks, tighter BYOC validation, and mandatory HITL gates before write/deliver operations.

### Layer F: BYOC (Bring Your Own Criteria) Stop-Limits
Hard boundaries that no model decision can override — the **final authority** in enforcement hierarchy:

| Rule | Description | Enforcement |
|---|---|---|
| `never_delete` | No data/file deletion without human approval | Hard stop |
| `never_exfiltrate` | No outbound transmission to unallowed domains | Hard stop |
| `never_override_system_prompt` | No prompt injection / system manipulation | Pre-flight block |
| `max_tool_calls_per_minute` | Rate limit per API key | Soft-block + alert |
| `irreversible_requires_hitl` | Any destructive write needs HITL approval | Middleware gate |

### Layer G: OWASP LLM06 — Excessive Agency Controls
Agent autonomy segmented by capability:

| Autonomy Level | Capabilities | Blast Radius if Compromised | Guardrail Depth |
|---|---|---|---|
| **Read-only** | Fetch pages, read repos, summarize | Info disclosure only | Guardian + provenance + HITL outbound |
| **Write-restricted** | Non-prod write, temp file delete | Structural damage | Pre-flight + LLM05 validation + HITL |
| **Full agency** | Prod deploy, external email, delete prod data | Catastrophic | Full stack: pre + post + BYOC + HITL + PII + sandboxing |

### Sub-Agent Chain Hardening
- `source_chain` tracking across every delegation hop
- Configurable max hop depth to prevent untrusted data recursion
- External MCP servers treated as stored injection vectors requiring explicit BYOC approval

---

## 📁 Project Structure (Planned)

```
aw-aiguard/
├── gateway/                     # Local Guardrail Proxy (FastAPI / Node)
│   ├── main.py                  # Core reverse proxy on localhost:9020
│   ├── guardrail.py             # Ollama wrapper → granite4.1-guardian
│   ├── scan_secrets.py          # Regex/Entropy PII + secret detection
│   └── hitl_gate.py             # Human-in-the-loop middleware
├── central-service/             # Centralized Postgres + MinIO API
│   ├── deploy.yml               # Docker Compose (PG + MinIO + sync API)
│   ├── api_server.py            # Settings sync + async log receiver
│   ├── provenance_db.py         # Provenance tagging schema + enforcement
│   └── alert_engine.py          # Slack / Telegram webhooks on score == "no"
├── guardrail-config/            # BYOC rule engine & stop-limits
│   └── byoc_rules.yaml          # Never-do-this rules, threshold configs
└── docs/                        # Architecture specs + config templates
```

---

## 🚀 Implementation Roadmap

| Priority | Task | Target Sprint | Notes |
|---|---|---|---|
| **P0** | HITL middleware for irreversible actions | 1–2 | Pre-MVP requirement; blocks before prod deployment |
| **P0** | Core proxy at `localhost:9020` with Guardian pre-flight gate | 1 | Foundation for all features |
| **P1** | Provenance tagging schema + enforcement pipeline | 2 | Required for trust-gated operations |
| **P1** | Post-processing thinking-mode verification layer | 2 | Apply selectively to high-risk outputs |
| **P2** | Sub-agent chain depth limit logic | 2–3 | Prevent infinite delegation traversal |
| **P2** | BYOC stop-limits engine | 3 | "Never do this" rules as hard boundary |
| **P2** | Data/command separation validation schemas | 3 | Typed JSON schema enforcement at tool-call level |

---

## 📡 Alerting & Monitoring

Guardian review outcomes trigger programmable alerts via multiple channels:

| Channel | Use Case |
|---|---|
| **Telegram** | Instant mobile notification (fastest reach) |
| **Slack** | Team visibility + thread-based triage |
| **Email** | Persistent audit trail |

**Alert triggers:**

| Scenario | Alert Level | Action |
|---|---|---|
| Pre-exec Guardian = `no` on tool call | **CRITICAL — BLOCK** | Block + alert + pause |
| Post-response thinking-mode = `no` | **WARNING — REVIEW** | Deliver + audit |
| Function-calling hallucination detected | **HIGH — VERIFY** | Verify schema + alert |
| HITL approval timeout expired | **NOTICE — LOG** | Log denial event |
| Repeated `no` from same provenance | **ESCALATE** | Rate-limit source |

---

## ⚙ Configuration

### Local Settings (`~/.config/aw-aiguard/settings.yaml`)

| Setting | Default | Description |
|---|---|---|
| `guardian_threshold: 0.85` | `0.85` | Score boundary for block vs. warn/proceed |
| `llm_safety_mode: hard_block` | `hard_block` | One of `[hard_block, warn_only, hybrid]` |
| `secrets_block_mode: hard_block` | `hard_block` | Per-secret-type overrides |
| `alert_channels: [telegram]` | `[telegram]` | Received alert channels per developer |
| `audit_ttl_days: 30` | `30` | Hot storage retention TTL |

Backend syncs and version-controls settings daily, with immediate hot-reload on emergency changes.

---

## 📚 Documentation

| Document | Description |
|---|---|
| [summary.md](summary.md) | Prompt injection fundamentals, attack anatomy, lethal trifecta, security checklist |
| [architecture-design1.md](architecture-design1.md) | Full architecture design: proxy gateways, layered security, provenance, implementation plan |
| [recommendation1.md](recommendation1.md) | Implementation recommendations aligned to Granite4.1 Guardian & OWASP controls |

---

## 🔗 References & Sources

- [OWASP Top 10 for LLM — LLM01: Prompt Injection](https://genai.owasp.org/llmrisk/llm01-prompt-injection)
- [The Lethal Trifecta — Simon Willison](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta)
- [Hidden Risk in Notion 3.0 — CodeIntegrity](https://codeintegrity.ai/blog/notion)
- [CaMeL Framework — Google DeepMind & ETH Zürich](https://arxiv.org/abs/2503.18813)
- [Designing AI Agents to Resist Prompt Injection — OpenAI](https://openai.com/index/designing-agents-to-resist-prompt-injection)
- [NIST AI 100-2e2025, Adversarial ML](https://csrc.nist.gov)

---

*Built following the "security from architecture" principle: structural constraints (permissions, isolation, confirmations) over system-prompt text. Built to make unsafe behavior structurally impossible without human approval.*
