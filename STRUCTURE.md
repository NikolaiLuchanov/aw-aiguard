# Project Structure

```
aw-aiguard/                          # Project root
├── gateway/                         # Lightweight interception proxy (Port 9020)
│   ├── core/                        # Core safety modules
│   │   ├── __init__.py              # Module exports
│   │   ├── proxy.py                 # Reverse proxy with streaming support
│   │   ├── guardrail.py             # Guardian pre-flight safety adapter (4 fail-safe strategies)
│   │   ├── scanner.py               # PII/Secrets regex + entropy scanner (Sequence A/B/C)
│   │   ├── hitl.py                  # HITL pause middleware with full request resume flow
│   │   ├── byoc.py                  # BYOC stop-limits enforcement engine (hard_stop, soft_block)
│   │   ├── block.py                 # Standardized 403 block response generator
│   │   ├── function_call_detector.py # Function-call hallucination detection (Phase 4.1)
│   │   ├── sanitizer.py              # Ingestion sanitization for stored injection (Phase 4.2)
│   │   ├── provenance.py            # Provenance dataclass: extraction, serialization, trust-level checks, sanitization tracking
│   │   └── audit.py                 # Async audit logger (queue → backend, JSONL fallback)
│   ├── main.py                      # FastAPI server entry point
│   ├── middleware/                   # Additional HTTP middleware
│   └── README.md                    # Gateway documentation
├── central-service/                  # Resource-heavy management and audit backend (Port 8000)
│   ├── api_server.py                 # FastAPI: audit, settings, HITL, config sync, health
│   ├── audit_db.py                   # asyncpg pool, Pydantic models, typed INSERT helpers
│   ├── alert_engine.py               # Multi-channel notification dispatcher (Telegram, Slack, Email)
│   ├── partition_manager.py          # Partition lifecycle: archive → MinIO → drop → create
│   ├── migrations/                   # SQL migrations
│   │   ├── 001_initial.sql           # Schema: 4 tables + 3 monthly partitions + 5 indexes
│   │   └── 002_partition_lifecycle.sql # Partition lifecycle functions
│   ├── Dockerfile                    # Python 3.9 slim, uvicorn
│   ├── docker-compose.yml            # Local stack: PostgreSQL 16, MinIO, API server
│   └── README.md                     # Central service documentation
├── guardrail-config/                 # YAML-based safety rules and system thresholds
│   ├── README.md
│   ├── scan_rules.yaml               # PII/Secrets detection rules (block, redact, warn, ignore)
│   ├── settings.yaml                 # Guardian thresholds, safety mode, alert channels
│   ├── hitl_rules.yaml               # Irreversible action patterns with per-rule timeouts
│   ├── byoc_rules.yaml               # Structured BYOC stop-limits (patterns, enforcement, severity)
│   └── function_call_rules.yaml      # Function-call hallucination detection rules (Phase 4.1)
├── shared/                           # Shared schemas and utilities
│   ├── schemas.py                    # AuditEvent, ProvenanceEvent, SettingsChange Pydantic models
│   └── test_schemas.py               # Schema validation tests
├── tests/                            # 472 pytest unit tests
│   ├── conftest.py                   # Shared fixtures (temp YAML files, sample events, mock responses, env isolation)
│   ├── gateway/                      # Gateway layer tests
│   │   ├── test_guardrail.py         # GuardianGuard: allow/block/warn/fail-strategies
│   │   ├── test_scanner.py           # PIIScanner: AWS keys, private keys, email redaction
│   │   ├── test_hitl.py              # HITLGate: pause/approve/deny/expiry, status
│   │   ├── test_hitl_cloud.py        # HITL cloud sync, recovery, cleanup loop
│   │   ├── test_byoc.py              # BYOCEngine: pattern rules, rate limits, hard_stop/soft_block
│   │   ├── test_block.py             # BlockReason codes, generate_block_response
│   │   ├── test_audit.py             # AuditLogger: queue, buffer write, replay, flush
│   │   ├── test_proxy.py             # LLMProxy: safe pass-through, guardian block, byoc block, HITL pause
│   │   ├── test_provenance.py        # Provenance: from_headers, from_dict, is_low_trust
│   │   ├── test_proxy_provenance.py  # Proxy pipeline provenance integration
│   │   ├── test_proxy_hitl_cloud.py  # Proxy HITL cloud provenance passing
│   │   └── test_function_call_detector.py # Function-call hallucination detection (Phase 4.1)
│   ├── central_service/              # Central service tests
│   │   ├── test_alert_engine.py      # Telegram/Slack/Email dispatch, severity mapping
│   │   ├── test_api_server.py        # Severity mapping, settings YAML loading, HITL endpoints
│   │   ├── test_audit_db.py          # Pool init, DEFAULT_SETTINGS, schema field alignment
│   │   ├── test_hitl_cloud.py        # Cloud HITL bridge: create, recover, decision
│   │   ├── test_dashboard_hitl.py    # Dashboard HITL endpoints
│   │   ├── test_hitl_endpoints.py    # Cloud-persisted HITL bridge endpoints
│   │   └── test_partition_manager.py # Partition lifecycle: archive→MinIO, drop, create
│   ├── shared/                       # Shared schema tests
│   └── tools/                        # Test utilities
├── tools/                            # Development utilities (mocks, helpers)
├── docs/                             # Architecture specs and workflow diagrams (empty — reserved)
├── recommendation.md                 # Security recommendations and threat analysis
├── summary.md                        # Prompt injection summary and glossary
├── architecture-design.md            # Full architectural design document
├── architecture_workflow.html        # Interactive architecture workflow diagram (Mermaid)
├── IMPLEMENTATION_PLAN.md            # Phase-by-phase implementation roadmap
├── IMPLEMENTATION_PLAN_PHASE_4.md    # Phase 4 detailed plan
├── IMPLEMENTATION_PLAN_PHASE_4_1.md  # Phase 4.1 detailed plan
├── README.md                         # Project overview, quick start, safety pipeline
├── pyproject.toml                    # pytest config, coverage settings, test markers
├── requirements.txt                  # Python dependencies
├── .env.example                      # Environment variable template
└── venv/                             # Python virtual environment
```

## Security Pipeline Order (L0 → L6B)

| Layer | Module | Purpose |
|---|---|---|
| **L0** | `provenance.py` | Data tagging: source_id, trust_level at ingestion |
| **L1** | `scanner.py` | PII/Secrets redaction and leakage prevention |
| **L2** | `guardrail.py` | Guardian pre-flight safety gate (real-time scoring) |
| **L3** | `function_call_detector.py` | Function-call hallucination detection (Phase 4.1) |
| **L4** | `byoc.py` | BYOC stop-limits: hard boundaries, organizational policy |
| **L5** | `hitl.py` | Human-in-the-loop: pause for irreversible actions |
| **L6** | *(post-response)* | Thinking-mode Guardian verification for high-risk outputs |
| **L6B** | *(post-response)* | OWASP LLM05 output control: schema validation, escaping |

## Test Count by Module

| Module | Test File | Count |
|---|---|---|
| Provenance | `test_provenance.py` + `test_proxy_provenance.py` + `test_api_server_provenance.py` | 23 |
| PII Scanner | `test_scanner.py` | 14 |
| Guardian | `test_guardrail.py` | 12 |
| Ingestion Sanitizer | `test_sanitizer.py` | 24 |
| Function-Call Detector | `test_function_call_detector.py` | 17 |
| BYOC | `test_byoc.py` | 19 |
| HITL | `test_hitl.py` + `test_hitl_cloud.py` + `test_proxy_hitl_cloud.py` | 38 |
| Block Response | `test_block.py` | 5 |
| Audit Logger | `test_audit.py` | 14 |
| Proxy (end-to-end) | `test_proxy.py` + `test_proxy_provenance.py` | 18 |
| Alert Engine | `test_alert_engine.py` | 17 |
| API Server | `test_api_server.py` | 11 |
| Audit DB | `test_audit_db.py` + `test_hitl_cloud.py` + `test_dashboard_hitl.py` + `test_hitl_endpoints.py` | 39 |
| Partition Manager | `test_partition_manager.py` | 10 |
| Shared Schemas | `test_schemas.py` | 10 |
|| **Total** | | **472** |
