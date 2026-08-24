# Project Structure

```
aw-aiguard/                          # Project root
├── gateway/                         # Lightweight interception proxy (Port 9020)
│   ├── core/                        # Core safety modules
│   │   ├── __init__.py              # Module exports
│   │   ├── proxy.py                 # Reverse proxy with streaming support
│   │   ├── guardrail.py             # Guardian pre-flight safety adapter (4 fail-safe strategies)
│   │   ├── guardian_client.py       # Granite wire protocol: build_request, parse_score, load_prompts
│   │   ├── scanner.py               # PII/Secrets regex + entropy scanner (Sequence A/B/C)
│   │   ├── hitl.py                  # HITL pause middleware with full request resume flow
│   │   ├── byoc.py                  # BYOC stop-limits enforcement engine (hard_stop, soft_block)
│   │   ├── block.py                 # Standardized 403 block response generator
│   │   ├── function_call_detector.py # Function-call hallucination detection (Phase 4.1)
│   │   ├── sanitizer.py              # Ingestion sanitization for stored injection (Phase 4.2)
│   │   ├── thinking_mode.py          # Thinking-mode verification for post-response Guardian check (Phase 4.4)
│   │   ├── output_control.py         # LLM05 output control: schema validation, HTML escaping (Phase 4.3)
│   │   ├── schema_validator.py        # CaMeL JSON schema validation for tool parameters (Phase 4.5.1)
│   │   ├── agency_controller.py       # Delegation depth & chain integrity (Phase 4.5.2)
│   │   ├── provenance.py              # Provenance dataclass: extraction, serialization, trust-level checks, sanitization tracking, agency depth/hop tracking
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
│   ├── thinking_mode_rules.yaml       # Thinking-mode verification config (thresholds, actions, fail strategy)
│   ├── byoc_rules.yaml               # BYOC stop-limits (patterns, enforcement, severity)
│   ├── function_call_rules.yaml      # Function-call hallucination detection rules (Phase 4.1)
│   ├── tool_schemas.yaml               # CaMeL JSON schemas for tool parameters (Phase 4.5.1)
│   ├── camel_rules.yaml                # CaMeL enforcement rules (hard_stop) (Phase 4.5.1)
│   ├── agency_rules.yaml               # Delegation depth & agency constraints (Phase 4.5.2)
│   └── guardian_prompts.yaml         # Granite guardian classification prompts (fast, thinking, function_hallucination)
├── shared/                           # Shared schemas and utilities
│   ├── schemas.py                    # AuditEvent, ProvenanceEvent, SettingsChange Pydantic models
│   └── test_schemas.py               # Schema validation tests
├── tests/                            # 730 pytest unit tests
│   ├── conftest.py                   # Shared fixtures (temp YAML files, sample events, mock responses, env isolation)
│   ├── red_team/                     # 85 adversarial test cases (Phase 5.1)
│   │   ├── test_direct_injection.py  # 14 tests: jailbreak, exfiltration, action hijack, PII
│   │   ├── test_indirect_injection.py # 14 tests: web, RAG, GitHub, email, PDF, stored injection
│   │   ├── test_masking_techniques.py # 11 tests: CSS, Unicode, encoding, attribute masking
│   │   ├── test_exfiltration.py      # 8 tests: simple, covert, staged, multi-hop exfil
│   │   ├── test_action_hijack.py     # 7 tests: commit, delete, deploy, email, shell, branch
│   │   ├── test_quiet_commands.py    # 6 tests: "don't tell user", skip confirmation, act silently
│   │   ├── test_answer_manipulation.py # 5 tests: fact substitution, source manipulation
│   │   ├── test_lethal_trifecta.py   # 5 tests: full trifecta, broken trifecta variants
│   │   ├── test_delegation_chains.py # 5 tests: depth limit, chain broken, approval, MCP vetting
│   │   └── test_integration_pipeline.py # 6 tests: full pipeline, performance baseline
│   ├── performance/                  # Performance benchmarks (Phase 5.2)
│   ├── gateway/                      # Gateway layer tests
│   │   ├── test_guardrail.py         # GuardianGuard: allow/block/warn/fail-strategies
│   │   ├── test_guardian_client.py   # Protocol: build_request, parse_score, load_prompts
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
│   │   ├── test_function_call_detector.py # Function-call hallucination detection (Phase 4.1)
│   │   ├── test_sanitizer.py          # IngestionSanitizer: 12 patterns, action modes (Phase 4.2)
│   │   ├── test_output_control.py     # Output schema validation, HTML escaping, shell/DB quoting (Phase 4.3)
│   │   ├── test_thinking_mode.py      # Thinking-mode verification: decision matrix, Guardian integration (Phase 4.4)
│   │   ├── test_schema_validator.py   # CaMeL JSON schema validation for tool parameters (Phase 4.5.1)
│   │   ├── test_agency_controller.py  # Delegation depth & chain integrity (Phase 4.5.2)
│   │   └── test_phase4_integration.py # End-to-end: schema + agency integration tests
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
| **L4** | `hitl.py` | Human-in-the-loop: pause for irreversible actions |
| **L5** | `thinking_mode.py` | Thinking-mode Guardian verification for low-trust/high-risk outputs (Phase 4.4) |
| **L6** | *(post-response)* | Thinking-mode Guardian verification for high-risk outputs |
| **L6B** | *(post-response)* | OWASP LLM05 output control: schema validation, escaping |
| **L5.1** | *(pre-forward)* | CaMeL JSON schema validation for tool parameters (Phase 4.5.1) |
| **L5.2** | *(pre-forward)* | Agency constraints: delegation depth, chain integrity (Phase 4.5.2) |

## Test Count by Module

| Module | Test File | Count |
|---|---|---|
| Provenance | `test_provenance.py` + `test_proxy_provenance.py` + `test_api_server_provenance.py` | 23 |
| PII Scanner | `test_scanner.py` | 14 |
| Guardian | `test_guardrail.py` | 12 |
| Guardian Client | `test_guardian_client.py` | 26 | Protocol: build_request, parse_score, load_prompts |
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
| CaMeL Validator | `test_schema_validator.py` | 20 |
| Agency Controller | `test_agency_controller.py` | 12 |
| Phase 4.6 Integration | `test_phase4_integration.py` | 10 |
| Red-Team (Phase 5.1) | 10 test files | 85 |
| **Total** | | **730** |
