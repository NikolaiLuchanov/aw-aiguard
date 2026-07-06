# aw-aiguard: Implementation Roadmap

**Status:** Finalized Plan  
**Tech Stack:** Python (FastAPI), Cloud-Deployed Containers (for Model Server, Backend/Audit, and Dashboard), PostgreSQL, MinIO, Containerized Granite 4.1 Guardian (Cloud Instance).  
**Core Objective:** Build a security gateway that intercepts LLM traffic to prevent prompt injection, mandate human approval for dangerous actions, and provide a centralized audit and configuration hub.

---

## 🏁 Current State $\rightarrow$ Complete State
**Current:** Design and safety recommendations documented.  
**Complete:** A fully operational `aw-aiguard` ecosystem where every LLM request is vetted by a local safety model, sensitive data is redacted, irreversible actions are paused for human approval via a web dashboard, and all events are audited in a local database.

---

## 🗺️ Phase-by-Phase Execution Plan

### Phase 1: The Core Guardrail (The "Edge")
*Goal: Establish the interception point and implement immediate, stateless safety.*

- [ ] **1.1 Project Scaffolding**
    - Initialize directory structure: `gateway/`, `central-service/`, `guardrail-config/`.
    - Set up Python virtual environment and dependency management (`pyproject.toml` or `requirements.txt`).
- [ ] **1.2 Basic Pass-Through Proxy**
    - Implement FastAPI server on `localhost:9020`.
    - Build an Anthropic/OpenAI compatible reverse proxy that forwards requests to cloud APIs.
- [ ] **1.3 Guardian Pre-flight Gate**
    - Implement `guardrail.py` to interface with the **containerized** model server.
    - Logic: `User Input` $\rightarrow$ `Containerized Model Server` $\rightarrow$ `Score (yes/no)` $\rightarrow$ `Forward or Block`.
- [ ] **1.4 PII & Secrets Scanner**
    - Implement the regex/entropy-based scanning layer.
    - Logic: Redact sensitive patterns in-place before they leave the local machine.
- [ ] **1.5 Basic Block Responses**
    - Create standardized "Safe Block" responses to be returned to the agent when a guardrail is triggered.

### Phase 2: Infrastructure & Audit (The "Cloud Brain")
*Goal: Deploy the management and safety layer to the cloud to offload local resources.*

- [ ] **2.1 Cloud Backend Deployment**
    - Deploy the container stack to a cloud provider (e.g., AWS, Render, Railway).
    - Stack contains:
        - **Model Server:** Containerized inference for Granite 4.1.
        - **PostgreSQL:** For the "Hot Tier" audit logs and settings.
        - **MinIO:** For the "Cold Tier" S3-compatible archive.
- [ ] **2.2 Remote Async Audit Pipeline**
    - Update the Python gateway to push logs to the **remote cloud endpoint** using a secure API key.
    - Logic: Proxy $\rightarrow$ Cloud Audit API $\rightarrow$ PostgreSQL.
- [ ] **2.3 Cloud Alert Engine**
    - Configure cloud-side webhooks for Telegram, Slack, and Email.
    - Logic: Cloud Model Server `no` score $\rightarrow$ Cloud Alert Engine $\rightarrow$ User.
- [ ] **2.4 Cloud DB Schema**
    - Initialize the cloud PostgreSQL tables for `audit_logs`, `api_keys`, and `settings_history`.

### Phase 3: HITL & Admin Dashboard (The "Control")
*Goal: Implement human-in-the-loop approval and centralized management.*

- [ ] **3.1 HITL Middleware Logic**
    - Implement the "Pause" mechanism: Identify irreversible tool calls $\rightarrow$ Mark status as `pending_approval` $\rightarrow$ Trigger Alert.
- [ ] **3.2 Centralized Admin Dashboard (Web UI)**
    - Build a lightweight web interface (integrated with the central service).
    - **Approval Queue:** View pending HITL requests with provenance $\rightarrow$ Click "Approve" or "Deny".
    - **Configuration Hub:** Edit Guardian thresholds, BYOC rules, and alert settings.
- [ ] **3.3 Approval Execution Flow**
    - Logic: `Approval Clicked` $\rightarrow$ `Update DB Status` $\rightarrow$ `Signal Proxy to Resume/Forward Request`.

### Phase 4: Advanced Hardening (The "Defense-in-Depth")
*Goal: Implement complex safety patterns and structural constraints.*

- [ ] **4.1 Provenance Tagging Pipeline**
    - Implement the `provenance` object (source\_id, trust\_level, etc.) and ensure it carries through the entire request lifecycle.
- [ ] **4.2 Thinking-Mode Verification**
    - Implement the "Deep Reasoning" pass (`--think=true`) for high-risk outputs or low-trust provenance.
- [ ] **4.3 BYOC Stop-Limits Engine**
    - Codify the "Never Do This" rules in `byoc_rules.yaml` as a final, immutable enforcement layer.
- [ ] **4.4 CaMeL Structural Enforcement**
    - Implement JSON schema validation for all tool-call parameters to prevent "data-as-code" injections.
- [ ] **4.5 Agency Constraints**
    - Implement max-hop depth limits for sub-agent chains.

### Phase 5: Validation & Finalization
*Goal: Stress test and prepare for production use.*

- [ ] **5.1 Red-Teaming & Penetration Testing**
    - Attempt prompt injections, secret exfiltration, and fact substitution.
    - Verify that all "Block" and "Pause" events are correctly logged and alerted.
- [ ] **5.2 Performance Optimization**
    - Tune Ollama inference and FastAPI middleware to minimize latency.
- [ ] **5.3 Documentation & Handover**
    - Finalize the setup guide and developer documentation.

---

## 🛠️ Technical Summary
| Component | Technology | Role |
| :--- | :--- | :--- |
| **Gateway Proxy** | Python / FastAPI | Interception, Guardian Scoring, PII Scanning, HITL Pause |
| **Safety Model** | Ollama / Granite 4.1 | Pre-flight safety classification |
| **Admin Dashboard** | Python (Web Framework) | HITL Approvals & System Configuration |
| **Audit Storage** | PostgreSQL / MinIO | Event logging, Settings, and Long-term archiving |
| **Deployment** | Docker Compose | Local orchestration of backend services |
| **Notifications** | Telegram/Slack/Email | Real-time safety alerts and HITL notifications |
