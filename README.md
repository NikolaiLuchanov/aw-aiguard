# aw-aiguard: LLM Security Gateway

`aw-aiguard` is a security middleware layer designed to protect LLM agents from prompt injection, data exfiltration, and catastrophic automated actions. It implements a "Security from Architecture" approach by enforcing hard boundaries, human-in-the-loop (HITL) gates, and provenance tracking.

## 🚀 Quick Start

### 1. Environment Setup
This project uses a single virtual environment at the root for local development of both the Gateway and the Central Service.

```bash
# Initialize and activate the environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Configuration
Copy the example environment file and fill in your API keys:
```bash
cp .env.example .env
# Edit .env with your ANTHROPIC_API_KEY and OPENAI_API_KEY
```

### 3. Port Map & Communication Flow
The system operates using two distinct ports to separate the lightweight proxy from the heavy backend.

| Port | Role | Direction | Description |
| :--- | :--- | :--- | :--- |
| **`9020`** | **Gateway Proxy** | `Client` $\rightarrow$ `Gateway` | The "Front Door." Point Claude Code, Codex, or Hermes here. |
| **`8000`** | **Central Service** | `Gateway` $\rightarrow$ `Backend` | The "Brain." Handles DB, Audit logs, and HITL state. |

## ☁️ Dev vs. Production Transition

The system is designed to be "Cloud-Ready." The transition from local development to production is controlled by the `GUARD_BACKEND_URL` in your `.env` file.

- **Development Mode:** `GUARD_BACKEND_URL=http://localhost:8000`
  - The Gateway communicates with a local instance of the Central Service and a local PostgreSQL DB.
- **Production Mode:** `GUARD_BACKEND_URL=https://api.aw-aiguard.cloud`
  - The Gateway communicates with the cloud-deployed container stack (PostgreSQL, Model Server, and Management Dashboard).

## 🏗️ Project Structure
- `gateway/`: The lightweight interception proxy (Port 9020).
- `central-service/`: The resource-heavy management and audit backend (Port 8000).
- `guardrail-config/`: YAML-based safety rules (BYOC) and system thresholds.
- `docs/`: Architecture specs and workflow diagrams.
