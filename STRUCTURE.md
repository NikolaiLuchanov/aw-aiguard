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
│   │   ├── agency_controller.py       # Delegation depth & chain integrity (Phase 4.6)
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
│   ├── scan_rules.yaml               # PII/Secrets detection rules (PCI DSS credit card, GDPR IP/passport/phone, AWS keys, private keys)
│   ├── settings.yaml                 # Guardian thresholds, safety mode, alert channels
│   ├── hitl_rules.yaml               # Irreversible action patterns with per-rule timeouts
│   ├── thinking_mode_rules.yaml       # Thinking-mode verification config (thresholds, actions, fail strategy)
│   ├── byoc_rules.yaml               # BYOC stop-limits (patterns, enforcement, severity)
│   ├── function_call_rules.yaml      # Function-call hallucination detection rules (Phase 4.1)
│   ├── tool_schemas.yaml               # CaMeL JSON schemas for tool parameters (Phase 4.5.1)
│   ├── camel_rules.yaml                # CaMeL enforcement rules (hard_stop) (Phase 4.5.1)
│   ├── agency_rules.yaml               # Delegation depth & agency constraints (Phase 4.6)
│   └── guardian_prompts.yaml         # Granite guardian classification prompts (fast, thinking, function_hallucination)
├── shared/                           # Shared schemas and utilities
│   ├── schemas.py                    # AuditEvent, ProvenanceEvent, SettingsChange Pydantic models
│   └── test_schemas.py               # Schema validation tests
├── tests/                            # 712 pytest unit tests
│   ├── conftest.py                   # Shared fixtures (temp YAML files, sample events, mock responses, env isolation)
│   ├── red_team/                     # 85 adversarial test cases (Phase 5.1)
│   │   ├── test_direct_injection.py  # 16 tests: jailbreak, exfiltration, action hijack, PII
│   │   ├── test_indirect_injection.py # 16 tests: web, RAG, GitHub, email, PDF, stored injection
│   │   ├── test_masking_techniques.py # 11 tests: CSS, Unicode, encoding, attribute masking
│   │   ├── test_exfiltration.py      # 8 tests: simple, covert, staged, multi-hop exfil
│   │   ├── test_action_hijack.py     # 7 tests: commit, delete, deploy, email, shell, branch
│   │   ├── test_quiet_commands.py    # 6 tests: "don't tell user", skip confirmation, act silently
│   │   ├── test_answer_manipulation.py # 5 tests: fact substitution, source manipulation
│   │   ├── test_lethal_trifecta.py   # 5 tests: full trifecta, broken trifecta variants
│   │   ├── test_delegation_chains.py # 5 tests: depth limit, chain broken, approval, MCP vetting
│   │   └── test_integration_pipeline.py # 6 tests: full pipeline, performance baseline
│   ├── gateway/                      # Gateway layer tests
│   │   ├── test_guardrail.py         # GuardianGuard: allow/block/warn/fail-strategies
│   │   ├── test_guardian_client.py   # Protocol: build_request, parse_score, load_prompts
│   │   ├── test_scanner.py           # PIIScanner: AWS keys, private keys, email redaction
│   │   ├── test_hitl.py              # HITLGate: pause/approve/deny/expiry, status
│   │   ├── test_hitl_cloud.py        # HITL cloud sync, recovery, cleanup loop
│   │   ├── test_byoc.py              # BYOCEngine: pattern rules, rate limits, hard_stop/soft_block
│   │   ├── test_byoc_cloud.py        # BYOC cloud sync
│   │   ├── test_byoc_sync.py          # BYOC sync from central service
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
│   │   ├── test_agency_controller.py  # Delegation depth & chain integrity (Phase 4.6)
│   │   ├── test_phase4_integration.py # End-to-end: schema + agency integration tests
│   │   ├── test_central_service_url_wiring.py # Central service URL wiring
│   │   ├── test_gateway_heartbeat.py  # Gateway heartbeat
│   │   ├── test_settings_poll.py      # Settings polling
│   │   ├── test_wiring.py             # Wiring integration tests
│   │   └── test_env_validation.py     # Environment variable validation
│   ├── central_service/              # Central service tests
│   │   ├── test_alert_engine.py      # Telegram/Slack/Email dispatch, severity mapping
│   │   ├── test_api_server.py        # Severity mapping, settings YAML loading, HITL endpoints
│   │   ├── test_api_server_provenance.py # API server provenance handling
│   │   ├── test_audit_db.py          # Pool init, DEFAULT_SETTINGS, schema field alignment
│   │   ├── test_hitl_cloud.py        # Cloud HITL bridge: create, recover, decision
│   │   ├── test_hitl_endpoints.py    # Cloud-persisted HITL bridge endpoints
│   │   ├── test_dashboard_hitl.py    # Dashboard HITL endpoints
│   │   ├── test_dashboard_byoc.py    # Dashboard BYOC endpoints
│   │   ├── test_dashboard_audit.py   # Dashboard audit endpoints
│   │   ├── test_dashboard_gateways.py # Dashboard gateways endpoints
│   │   ├── test_dashboard_heartbeat.py # Dashboard heartbeat endpoints
│   │   ├── test_dashboard_settings.py # Dashboard settings endpoints
│   │   ├── test_partition_manager.py # Partition lifecycle: archive→MinIO, drop, create
│   │   ├── test_settings_audit_extended.py # Settings audit extended
│   │   ├── test_settings_history.py  # Settings history
│   │   ├── test_templates.py         # Notification templates
│   │   └── test_port_config.py       # Port configuration
│   ├── shared/                       # Shared schema tests
│   │   └── test_schemas.py           # AuditEvent, ProvenanceEvent, SettingsChange validation
│   ├── tools/                        # Test utilities
│   │   └── test_threat_probe.py      # Threat probe utility tests
│   └── test_smoke_env.py             # Smoke test: env setup, import chain
├── tools/                            # Development utilities (mocks, helpers)
├── docs/                             # Architecture specs and developer guides
│   ├── architecture.md               # Full architecture documentation
│   ├── audit_guide.md                # Security audit trail guide
│   ├── developer_guide.md            # Developer onboarding guide
│   ├── red_team_report.md            # Phase 5.1 red team findings
│   ├── security_checklist.md         # Implementation checklist
│   └── setup_guide.md                # Complete setup guide
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

## Security Pipeline Order (Inbound → Post-response)

| Layer | Direction | Module | Phase | Purpose |
|---|---|---|---|---|
| **L0** | Inbound | `provenance.py` | 2.5 | Data tagging: source_id, trust_level at ingestion |
| **L1** | Inbound | `scanner.py` | — | PII/Secrets regex + entropy scan (Sequence A/B/C) |
| **L2** | Inbound | `guardrail.py` | — | Guardian pre-flight safety gate (real-time scoring) |
| **L3.5** | Inbound | `function_call_detector.py` | 4.1 | Function-call hallucination detection |
| **L3** | Inbound | `byoc.py` | 3.2 | BYOC stop-limits: hard boundaries, organizational policy |
| **L5.1** | Inbound | `schema_validator.py` | 4.5.1 | CaMeL JSON schema validation for tool parameters |
| **L5.2** | Inbound | `agency_controller.py` | 4.6 | Delegation depth limits & chain integrity |
| **L4** | Inbound | `hitl.py` | 1.5 | Human-in-the-loop: pause for irreversible actions |
| — | Forward | `proxy.py` | — | Forward to cloud API |
| **L2+** | Post-response | `sanitizer.py` | 4.2 | Ingestion sanitization of LLM responses |
| **L6** | Post-response | `thinking_mode.py` | 4.4 | Thinking-mode Guardian verification for high-risk outputs |
| **L6B** | Post-response | `output_control.py` | 4.3 | OWASP LLM05 output control: schema validation, escaping |

## Test Count by Module

### Gateway Layer (tests/gateway/) — 377 tests

| Module | Test File | Count |
|---|---|---|
| Provenance | `test_provenance.py` | 26 |
| | `test_proxy_provenance.py` | 6 |
| Inbound PII Scanner | `test_scanner.py` | 15 |
| Inbound Guardian | `test_guardrail.py` | 14 |
| Inbound Guardian Client | `test_guardian_client.py` | 8 |
| Inbound Sanitizer | `test_sanitizer.py` | 24 |
| Inbound Function-Call Detector | `test_function_call_detector.py` | 17 |
| Inbound BYOC | `test_byoc.py` | 17 |
| | `test_byoc_cloud.py` | 16 |
| | `test_byoc_sync.py` | 14 |
| Inbound Schema Validator | `test_schema_validator.py` | 22 |
| Inbound Agency Controller | `test_agency_controller.py` | 17 |
| Inbound HITL | `test_hitl.py` | 28 |
| | `test_hitl_cloud.py` | 12 |
| | `test_proxy_hitl_cloud.py` | 5 |
| Block Response | `test_block.py` | 5 |
| Audit Logger | `test_audit.py` | 15 |
| Proxy (end-to-end) | `test_proxy.py` | 18 |
| Post-Response Output Control | `test_output_control.py` | 25 |
| Post-Response Thinking Mode | `test_thinking_mode.py` | 23 |
| Phase 4 Integration | `test_phase4_integration.py` | 13 |
| Central Service URL Wiring | `test_central_service_url_wiring.py` | 4 |
| Gateway Heartbeat | `test_gateway_heartbeat.py` | 9 |
| Settings Poll | `test_settings_poll.py` | 9 |
| Proxy Wiring | `test_wiring.py` | 5 |
| Env Validation | `test_env_validation.py` | 10 |

### Central Service (tests/central_service/) — 165 tests

| Module | Test File | Count |
|---|---|---|
| Alert Engine | `test_alert_engine.py` | 17 |
| API Server | `test_api_server.py` | 13 |
| | `test_api_server_provenance.py` | 6 |
| Audit DB | `test_audit_db.py` | 12 |
| Cloud HITL Bridge | `test_hitl_cloud.py` | 10 |
| HITL Endpoints | `test_hitl_endpoints.py` | 8 |
| Dashboard HITL | `test_dashboard_hitl.py` | 15 |
| Dashboard BYOC | `test_dashboard_byoc.py` | 12 |
| Dashboard Audit | `test_dashboard_audit.py` | 8 |
| Dashboard Gateways | `test_dashboard_gateways.py` | 5 |
| Dashboard Heartbeat | `test_dashboard_heartbeat.py` | 8 |
| Dashboard Settings | `test_dashboard_settings.py` | 10 |
| Partition Manager | `test_partition_manager.py` | 18 |
| Settings Audit Extended | `test_settings_audit_extended.py` | 7 |
| Settings History | `test_settings_history.py` | 4 |
| Templates | `test_templates.py` | 10 |
| Port Config | `test_port_config.py` | 2 |

### Red Team (tests/red_team/) — 85 tests

| Module | Test File | Count |
|---|---|---|
| Direct Injection | `test_direct_injection.py` | 16 |
| Indirect Injection | `test_indirect_injection.py` | 16 |
| Masking Techniques | `test_masking_techniques.py` | 11 |
| Exfiltration | `test_exfiltration.py` | 8 |
| Action Hijack | `test_action_hijack.py` | 7 |
| Quiet Commands | `test_quiet_commands.py` | 6 |
| Answer Manipulation | `test_answer_manipulation.py` | 5 |
| Lethal Trifecta | `test_lethal_trifecta.py` | 5 |
| Delegation Chains | `test_delegation_chains.py` | 5 |
| Integration Pipeline | `test_integration_pipeline.py` | 6 |

### Other

| Module | Test File | Count |
|---|---|---|
| Shared Schemas | `test_schemas.py` | 9 |
| Tools Threat Probe | `test_threat_probe.py` | 55 |
| Smoke/Env | `test_smoke_env.py` | 21 |
| | **Total** | **712** |
