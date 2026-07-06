# aw-aiguard: Implementation Roadmap

**Status:** Finalized Plan (Revised for P0 Safety Alignment)
**Tech Stack:** Python (FastAPI), Cloud-Deployed Containers (for Model Server, Backend/Audit, and Dashboard), PostgreSQL, MinIO, Containerized Granite 4.1 Guardian (Cloud Instance).
**Core Objective:** Build a security gateway that intercepts LLM traffic to prevent prompt injection, mandate human approval for dangerous actions, and provide a centralized audit and configuration hub.

---

## 🏁 Current State $\\rightarrow$ Complete State
**Current:** Design and safety recommendations documented.  
**Complete:** A fully operational `aw-aiguard` ecosystem where every LLM request is vetted by a local safety model, sensitive data is redacted, irreversible actions are paused for human approval via a web dashboard, and all events are audited in a local database.

---

## 🗺️ la Phase-by-Phase Execution Plan

### Phase 1: The Critical Edge (P0 Safety)
*Goal: Establish the interception point and implement immediate, stateless safety. No irreversible action can be taken without the HITL gate.*

- [ ] **1.1 Project Scaffolding**
    - Initialize directory structure: `gateway/`, `central-service/`, `guardrail-config/`.
    - Set up Python virtual environment and dependency management (`pyproject.toml` or `requirements.txt`).
- [ ] **1.2 Basic Pass-Through Proxy**
    - Implement FastAPI server on `localhost:9020`.
    - Build an Anthropic/OpenAI compatible reverse proxy that forwards requests to cloud APIs.
- [ ] **1.3 Guardian Pre-flight Gate**
    - Implement `guardrail.py` to interface with the containerized model server.
    - Logic: `User Input` $\\rightarrow$ `Model Server` $\\rightarrow$ `Score (yes/no)` $\\rightarrow$ `Forward or Block`.
- [ ] **1.4 PII & Secrets Scanner**
    - Implement the regex/entropy-based scanning layer.
    - Logic: Redact sensitive patterns in-place before they leave the local machine.
- [ ] **1.5 HITL "Pause" Middleware (P0 Requirement)**
    - Implement the interception logic for irreversible tool calls (e.g., delete, send email, commit code).
    - Logic: Match irreversible pattern $\\rightarrow$ Mark status as `pending_approval` $\\rightarrow$ Return `pending` response to agent.
- [ ] **1.6 Basic Block Responses**
    - Create standardized \"Safe Block\" responses for guardrail triggers and HITL denials.

### Phase 2: Infrastructure & Audit (The \"Cloud Brain\")
*Goal: Deploy the management and safety layer to the cloud to offload local resources and establish a permanent audit trail.*

- [ ] **2.1 Cloud Backend Deployment**
    - Deploy the container stack (Docker Compose/K8s) to a cloud provider.
    - Stack: **Model Server** (Granite 4.1), **PostgreSQL** (Hot Tier), **MinIO** (Cold Tier).
- [ ] **2.2 Remote Async Audit Pipeline**
    - Update the Python gateway to push logs to the remote cloud endpoint using a secure API key.
    - Logic: Proxy $\\rightarrow$ Cloud Audit API $\\rightarrow$ PostgreSQL.
- [ ] **2.3 Cloud Alert Engine**
    - Configure cloud-side webhooks for Telegram, Slack, and Email.
    - Logic: Cloud Model Server `no` score $\\rightarrow$ Cloud Alert Engine $\\rightarrow$ User.
- [ ] **2.4 Cloud DB Schema**
    - Initialize the cloud PostgreSQL tables for `audit_logs`, `api_keys`, and `settings_history`.

### Phase 3: The Policy Hub (Management & Control)
*Goal: Implement the human approval interface and the final "Hard Boundary" enforcement layer.*

- [ ] **3.1 Centralized Admin Dashboard (Web UI)**
    - Build a lightweight web interface integrated with the central service.
    - **Approval Queue:** View pending HITL requests with provenance $\\rightarrow$ Click \"Approve\" or \"Deny\".
- [ ] **3.2 BYOC Stop-Limits Engine**
    - Codify \"Never Do This\" rules in `byoc_rules.yaml` (e.g., `never_delete`, `never_exfiltrate`).
    - Logic: Apply as a final authority after Guardian checks; block execution immediately if violated.
- [ ] **3.3 Approval Execution Flow**
    - Logic: `Approval Clicked` $\\rightarrow$ `Update DB Status` $\\rightarrow$ `Signal Proxy to Resume/Forward Request`.
- [ ] **3.4 Centralized Config Sync**
    - Implement backend-to-local sync for Guardian thresholds, alert channels, and BYOC updates.

### Phase 4: Defense-in-Depth (Advanced Hardening)
*Goal: Implement complex safety patterns and structural constraints to address indirect injection and data poisoning.*

- [ ] **4.1 Provenance Tagging Pipeline (Layer 0)**
    - Implement the `provenance` object (source\\_id, trust\\_level, etc.) and ensure it carries through the request lifecycle.
- [ ] **4.2 Stored Injection Countermeasures**
    - Implement ingestion-time sanitization (e.g., stripping `<script>` tags, zero-width chars) for RAG data and fetched content.
- [ ] **4.3 LLM05 Output Control**
    - Implement output schema validation and HTML/text escaping for all model-generated content before it reaches the user/shell.
- [ ] **4.4 Thinking-Mode Verification**
    - Implement the \"Deep Reasoning\" pass (`--think=true`) selectively for high-risk outputs or low-trust provenance.
- [ ] **4.5 CaMeL Structural Enforcement**
    - Implement JSON schema validation for all tool-call parameters to prevent \"data-as-code\" injections.
- [ ] **4.6 Agency Constraints**
    - Implement max-hop depth limits for sub-agent delegation chains to prevent recursive injection attacks.

### Phase 5: Validation & Finalization
*Goal: Stress test the architecture against adversarial attacks and prepare for production.*

- [ ] **5.1 Red-Teaming & Penetration Testing**
    - Attempt prompt injections, secret exfiltration, and fact substitution.
    - Verify that all \"Block\", \"Pause\", and \"BYOC\" events are correctly logged and alerted.
- [ ] **5.2 Performance Optimization**
    - Tune Ollama inference and FastAPI middleware to minimize latency between local and cloud hops.
- [ ] **5.3 Documentation & Handover**
    - Finalize the setup guide, developer documentation, and security audit logs.

---

## 🛠️ Technical Summary & Internal Communication
**Internal Flow:** `Client` $\rightarrow$ `Gateway Proxy (9020)` $\rightarrow$ `Central Service (8000/Cloud)` $\rightarrow$ `LLM Cloud API`.

**Dev $\rightarrow$ Prod Transition:**
The Gateway Proxy is designed to be stateless. The switch from local development to cloud production is handled exclusively via the `GUARD_BACKEND_URL` environment variable. In Phase 2, the transition occurs when this URL is updated from `localhost:8000` to the deployed cloud endpoint, shifting the audit and configuration load from the local machine to the cloud infrastructure.

| Component | Technology | Role |
| :--- | :--- | :--- |
| **Gateway Proxy** | Python / FastAPI | Interception, Guardian Scoring, PII Scanning, HITL Pause, LLM05 Control |
| **Safety Model** | Ollama / Granite 4.1 | Pre-flight safety classification & Thinking-mode verification |
| **Admin Dashboard** | Python (Web Framework) | HITL Approvals, BYOC Management & System Configuration |
| **Audit Storage** | PostgreSQL / MinIO | Event logging, Settings, and Long-term archiving |
| **Deployment** | Docker Compose | Local orchestration of backend services |
| **Notifications** | Telegram/Slack/Email | Real-time safety alerts and HITL notifications |
