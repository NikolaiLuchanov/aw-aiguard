# aw-aiguard: Granite Guardian 4.1 — AWS Deployment Implementation Plan

**Status:** Finalized Plan  
**Date:** 2026-07-24  
**Model:** `ibm-granite/granite-guardian-4.1-8b` (8B parameter safety classification model)  
**Deployment Target:** AWS EC2 (GPU)  
**Core Objective:** Deploy Granite Guardian 4.1 8B to AWS in the most effective performance/price balance, serving as the safety scoring engine for the existing aw-aiguard proxy gateway.

---

## Table of Contents

1. [Model Profile & Hardware Requirements](#1-model-profile--hardware-requirements)
2. [Deployment Architecture Options — Comparison](#2-deployment-architecture-options--comparison)
3. [Recommended Approach: Containerized vLLM on g6.xlarge (Sweet Spot)](#3-recommended-approach-containerized-vllm-on-g6xlarge-sweet-spot)
4. [Detailed Deployment Steps](#4-detailed-deployment-steps)
5. [Configuration Reference](#5-configuration-reference)
6. [Performance Expectations](#6-performance-expectations)
7. [Cost Analysis & Optimization](#7-cost-analysis--optimization)
8. [Integration with Existing aw-aiguard Gateway](#8-integration-with-existing-aw-aiguard-gateway)
9. [High Availability & Scaling](#9-high-availability--scaling)
10. [Rolling Update & Disaster Recovery](#10-rolling-update--disaster-recovery)
11. [Monitoring & Observability](#11-monitoring--observability)
12. [Security Hardening](#12-security-hardening)
13. [Verification & Testing](#13-verification--testing)

---

## 1. Model Profile & Hardware Requirements

### Model Specifications

| Attribute | Value |
|---|---|
| **Model ID** | `ibm-granite/granite-guardian-4.1-8b` |
| **Parameters** | 8B (dense, not MoE) |
| **Architecture** | Transformer decoder-only |
| **Task** | Binary safety classification (yes/no) + function-calling hallucination detection |
| **Context Length** | 4096 tokens (short prompts — safety evaluation) |
| **Output Tokens** | 1–32 tokens (single-score response) |
| **Input Token Profile** | Typically 256–2048 tokens per prompt/response to evaluate |
| **F1 on OOD Safety** | 0.79 |
| **BAcc on Function-Hallucination** | 0.79 |
| **Available Quantizations** | FP16, FP8, GGUF (Q4_K_M, Q5_K_M, Q6_K, Q8_0, Q2_K, Q3_K_L, Q3_K_M, Q3_K_S, Q4_0, Q4_1, Q4_K_S, Q5_0, Q5_1, IQ2_XXS, IQ2_XS, IQ3_XXS, IQ1_S, IQ4_NL, IQ4_XS) |

### VRAM Requirements (Model Weights Only)

| Quantization | VRAM Needed | GPU Required | Notes |
|---|---|---|---|
| **FP16** | ~16 GB | Single L4 (24 GB) ✅ | Full precision, max throughput |
| **Q8_0** | ~8.5 GB | Single L4 (24 GB) ✅ | Near-FP16 quality, 50% memory |
| **Q5_K_M** | ~5.5 GB | Single L4 (24 GB) ✅ | Recommended sweet spot |
| **Q4_K_M** | ~4.5 GB | Single L4 (24 GB) ✅ | Best price/performance for safety classifier |
| **Q3_K_M** | ~3.5 GB | Single L4 (24 GB) ✅ | Acceptable quality degradation |
| **Q2_K** | ~2.5 GB | Single L4 (24 GB) ✅ | Not recommended — quality loss on safety classification |

### Key Insight: This is a **classification** workload, NOT a generation workload

Granite Guardian 4.1 returns a single `yes/no` score (or short reasoning trace in thinking mode). It does **not** generate long responses. This means:

- **Latency is dominated by the forward pass**, not autoregressive decoding
- **Throughput is extremely high** — 100+ requests/second on a single L4
- **Batching is less critical** than for generation models, but still helps
- **Q4_K_M quantization loses negligible quality** for a binary classifier — the model is trained on safety boundaries, not nuance

### Minimum Hardware

| Tier | GPU Instance | VRAM | Batch Size | Est. Throughput | Monthly Cost (On-Demand) |
|---|---|---|---|---|---|
| **Absolute Minimum** | g6.xlarge (1× L4, 24 GB) | 24 GB | 8 | ~50–100 req/s | ~$588 |
| **Sweet Spot** | g6.2xlarge (1× L4, 24 GB) | 24 GB | 16–32 | ~100–200 req/s | ~$588 |
| **Headroom** | g6.4xlarge (1× L4, 24 GB) | 24 GB | 32+ | ~200+ req/s | ~$1,176 |
| **Multi-Instance** | 2× g6.xlarge | 2× 24 GB | 8 each | ~100–200 req/s (total) | ~$1,176 |

> **Recommendation: Start with g6.2xlarge.** It provides the best balance — single L4 GPU with 24 GB VRAM can comfortably fit Q4_K_M quantization with headroom for batch processing, Python runtime, and Docker overhead. The g6.xlarge and g6.2xlarge share the same GPU (1× NVIDIA L4, 24 GB) — the difference is CPU/RAM (4 vCPU/16 GB vs 8 vCPU/32 GB). Since the inference is GPU-bound, g6.2xlarge's extra CPU helps with pre/post-processing without adding cost.

---

## 2. Deployment Architecture Options — Comparison

### Option A: Native llama.cpp Server (Recommended for Simplicity)

```
┌─────────────────────────────────────────┐
│  AWS EC2 g6.2xlarge                    │
│  ┌───────────────────────────────────┐  │
│  │  Container: llama.cpp             │  │
│  │  ┌─────────────────────────────┐  │  │
│  │  │  llama-server --model       │  │  │
│  │  │    granite-guardian-4.1-8b  │  │  │
│  │  │    --gguf Q4_K_M            │  │  │
│  │  │  --host 0.0.0.0 --port 8080 │  │  │
│  │  └─────────────────────────────┘  │  │
│  └───────────────────────────────────┘  │
│  OS: Amazon Linux 2023 + NVIDIA drivers │
└─────────────────────────────────────────┘
```

**Pros:**
- Simplest deployment — one command, one container
- Minimal Python dependency overhead
- Native GGUF support (IBM publishes official GGUF checkpoints)
- Low memory footprint (~6 GB total on L4 for Q4_K_M)
- Built-in OpenAI-compatible API (`/v1/chat/completions`)
- Single binary, no framework complexity

**Cons:**
- No dynamic batching out of the box (uses request queuing)
- Limited observability (no native Prometheus metrics)
- No distributed inference (single GPU only)

### Option B: Containerized vLLM Server (Recommended for Scale)

```
┌───────────────────────────────────────────────────────┐
│  AWS EC2 g6.4xlarge (or larger)                      │
│  ┌───────────────────────────────────────────────┐   │
│  │  Container: vLLM                              │   │
│  │  ┌─────────────────────────────────────────┐  │   │
│  │  │  vllm serve ibm-granite/granite-       │  │   │
│  │  │    guardian-4.1-8b                      │  │   │
│  │  │    --quantization fp8 --port 8000       │  │   │
│  │  │    --tensor-parallel-size 1             │  │   │
│  │  │    --max-num-seqs 256                   │  │   │
│  │  └─────────────────────────────────────────┘  │   │
│  └───────────────────────────────────────────────┘   │
│  OS: Amazon Linux 2023 + NVIDIA Container Toolkit    │
└───────────────────────────────────────────────────────┘
```

**Pros:**
- Dynamic batching — handles burst traffic efficiently
- PagedAttention — efficient memory management
- Tensor parallelism support (future multi-GPU scaling)
- Built-in OpenAI-compatible API
- Better observability (Prometheus metrics endpoint)
- Higher sustained throughput under concurrent load

**Cons:**
- Requires PyTorch + CUDA stack (~10 GB disk, more memory overhead)
- FP8 quantization recommended for vLLM (not GGUF)
- More complex deployment (PyTorch env, NVIDIA containers)
- Slightly higher per-request latency due to framework overhead

### Option C: AWS SageMaker Managed Inference (Recommended for Zero-Op)

```
┌───────────────────────────────────────────────────────┐
│  AWS SageMaker Endpoint                               │
│  ┌───────────────────────────────────────────────┐   │
│  │  Model: ibm-granite/granite-guardian-4.1-8b   │   │
│  │  Instance: ml.g6.2xlarge                      │   │
│  │  Inference Component (auto-provisioned)       │   │
│  └───────────────────────────────────────────────┘   │
│  Endpoints: HTTPS API (auto-SSL, auto-scaling)       │
└───────────────────────────────────────────────────────┘
```

**Pros:**
- Zero infrastructure management — AWS handles scaling, patching, health checks
- Auto-scaling based on traffic patterns
- Built-in load balancing, monitoring, and rollbacks
- Integrates with AWS IAM, VPC, CloudWatch
- Supports model artifacts from HuggingFace directly

**Cons:**
- Higher per-hour cost (~$1.05–$1.25/hr for g6.2xlarge vs ~$0.71/hr on-demand EC2)
- Less control over inference engine
- Cold start times (~2–5 minutes for model loading)
- Egress costs for data leaving SageMaker
- Lock-in to AWS ML tooling

### Option D: EC2 with Custom Docker + GPU Direct (Advanced)

**Pros:** Maximum performance tuning, custom CUDA kernels.
**Cons:** Significant operational overhead, not recommended for a safety classifier.

### Comparison Summary

| Criterion | A: llama.cpp | B: vLLM | C: SageMaker |
|---|---|---|---|
| **Setup Complexity** | ⭐ (1 command) | ⭐⭐ (container + CUDA) | ⭐⭐⭐ (console/CLI) |
| **Throughput** | ~50–100 req/s | ~100–200 req/s | ~80–150 req/s |
| **Per-Request Latency** | 15–40 ms | 20–50 ms | 30–60 ms |
| **Monthly Cost (g6.2xlarge)** | ~$588 | ~$588 + CUDA deps | ~$767–$905 |
| **Scaling** | Manual (clone instances) | Dynamic batching | Auto-scaling (AWS managed) |
| **Operational Overhead** | Low | Medium | Low (managed) |
| **GGUF Support** | ✅ Native | ❌ FP8/GPTQ only | ✅ via HuggingFace |
| **Best For** | Solo/small team | Medium/high traffic | Enterprise/zero-ops |

---

## 3. Recommended Approach: Containerized llama.cpp on g6.2xlarge (Sweet Spot)

### Why llama.cpp?

For a **safety classifier** workload, llama.cpp is the optimal choice:

1. **The model fits comfortably** — Q4_K_M quantization (~4.5 GB) on a single L4 (24 GB) leaves 19+ GB headroom
2. **Classification workload** — short input (256–2048 tokens), tiny output (1–32 tokens), single forward pass per request
3. **GGUF native** — IBM publishes official GGUF checkpoints, no conversion needed
4. **Simplest deployment** — one `docker run` command with NVIDIA runtime
5. **OpenAI-compatible API** — `llama-server` serves `/v1/chat/completions` natively, so no gateway code changes required
6. **Lower operational cost** — no PyTorch, no CUDA toolkit, no venv overhead
7. **Performance is sufficient** — ~50–100 req/s per instance easily handles typical agent traffic

### Recommended Hardware: g6.2xlarge

| Spec | Value | Why It Matters |
|---|---|---|
| **GPU** | 1× NVIDIA L4 (24 GB VRAM) | Fits Q4_K_M model + batch buffer |
| **vCPU** | 8 (Intel Sapphire Rapids) | Handles pre/post-processing |
| **RAM** | 32 GiB | Docker, OS, buffer |
| **Network** | Up to 10 Gbps | Low-latency to gateway |
| **On-Demand** | ~$0.8048/hr (~$588/mo) | Cost-effective |
| **Savings Plan (1yr)** | ~$0.56/hr (~$409/mo) | 30% discount |

> **Note:** g6.xlarge and g6.2xlarge share the same GPU. Choose g6.2xlarge for its extra CPU/RAM if you plan to run monitoring agents, log collectors, or additional local services on the same host.

### Deployment Stack

```
┌─────────────────────────────────────────────────────────────────────┐
│  AWS EC2 g6.2xlarge  (Amazon Linux 2023)                           │
│                                                                     │
│  docker-compose.yml                                                 │
│  ├── granite-guardian (llama.cpp)                                  │
│  │    Image: ghcr.io/ggml-org/llama.cpp:full-cuda                  │
│  │    GPU: 1× L4 (24 GB)                                           │
│  │    Model: granite-guardian-4.1-8b-Q4_K_M.gguf (~4.5 GB)         │
│  │    Port: 8080 (OpenAI-compatible API)                           │
│  │    Batch size: 32 (queue-based)                                 │
│  │    Context: 4096 tokens                                         │
│  └── cloudwatch-agent (optional)                                   │
│       Collects GPU utilization metrics                              │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  Security:                                                  │   │
│  │  - Security Group: Only allow 8080 from aw-aiguard proxy    │   │
│  │  - No public IP (VPC internal only)                         │   │
│  │  - IAM role with minimal permissions                        │   │
│  └─────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

### Alternative: SageMaker for Zero-Operations

If you prefer AWS-managed infrastructure over self-hosting:

```yaml
# SageMaker deployment (via AWS CLI or Console)
# No EC2 management, auto-scaling, built-in monitoring

aws sagemaker create-inference-component \
  --inference-component-name granite-guardian-4.1-8b \
  --model-name granite-guardian-4.1-8b \
  --instance-type ml.g6.2xlarge \
  --hardware-volumes [{"MountPath": "/opt/ml/model", "S3Uri": "s3://your-bucket/granite-guardian-4.1-8b/"}]

aws sagemaker create-endpoint-config \
  --endpoint-config-name granite-guardian-config \
  --production-variants '[{
    "VariantName": "variant-1",
    "ModelName": "granite-guardian-4.1-8b",
    "InitialInstanceCount": 1,
    "InstanceType": "ml.g6.2xlarge",
    "ModelDataDownloadTimeoutInSeconds": 600,
    "ContainerStartupHealthCheckTimeoutInSeconds": 900
  }]'

aws sagemaker create-endpoint \
  --endpoint-name granite-guardian-prod \
  --endpoint-config-name granite-guardian-config
```

---


## 13. GPU Passthrough Stack — How the Container Talks to the L4

The g6.2xlarge's NVIDIA L4 GPU is **physically available to the host**. Docker with the NVIDIA Container Toolkit is the bridge that exposes it to the container. Without ALL three pieces below, the container runs on CPU.

### The GPU Passthrough Stack

```
Physical GPU (NVIDIA L4 on g6.2xlarge)
    │
    ▼
Host NVIDIA Display Drivers (Amazon Linux 2023)
    │
    ▼
NVIDIA Container Toolkit  ←─── THIS IS THE CRITICAL BRIDGE
    │                          It intercepts `--gpus all` and:
    │                          1. Injects CUDA runtime libs into the container
    │                          2. Exposes /dev/nvidia* device nodes
    │                          3. Sets up the NVIDIA runtime
    │
    ▼
Docker Container (`runtime: nvidia`, `--gpus all`)
    │
    ▼
llama.cpp CUDA backend (full-cuda image)
    │
    ▼
Direct GPU execution — zero emulation, no CPU fallback
```

### What Happens If Any Piece Is Missing

| Missing Piece | Result |
|---|---|
| **NVIDIA Container Toolkit** | Container can't see GPU at all → llama.cpp falls back to CPU → ~0.5–2 t/s, unusable |
| **`--gpus all` + `runtime: nvidia`** | Same — no GPU visibility inside the container |
| **`-ngl 99`** | llama.cpp won't offload layers → runs entirely on CPU despite GPU being available |
| **Wrong image (`full` not `full-cuda`)** | llama.cpp binary has no CUDA backend → runs on CPU |

### Verification Commands

```bash
# On the EC2 host: confirm NVIDIA drivers + GPU are visible
nvidia-smi
# Should show: L4 GPU, driver version, ~0 MB used (before container)

# Verify the toolkit works (outside container)
docker run --rm --gpus all nvidia/cuda:12.2.0-base-ubi9 nvidia-smi
# Must show the L4 GPU — if it fails, the toolkit isn't installed

# After container starts: confirm GPU visibility inside container
docker exec granite-guardian nvidia-smi
# Should show L4, ~5.5 GB used (model weights + overhead)

# Host-level view (shows container's GPU usage in nvidia-smi)
nvidia-smi
# You'll see: llama-server running on GPU 0, using ~5.5 GB VRAM
```

### Docker Compose GPU Configuration (from granite_deployment/docker-compose.yml)

```yaml
# Two fields are BOTH required for GPU passthrough:
runtime: nvidia                              # ← Tells Docker to use NVIDIA runtime
deploy:                                      # ← Resource reservation
  resources:
    reservations:
      devices:
        - driver: nvidia                     # ← Request NVIDIA GPU device
          count: 1
          capabilities: [gpu]                # ← GPU capability (not just compute)
```

Without both `runtime: nvidia` AND the `deploy.resources.reservations.devices` block, the container has no GPU access.

---
## 4. Detailed Deployment Steps

### Phase 1: Foundation (Day 1)

#### Step 1.1: Provision AWS Infrastructure

```bash
# 1. Create VPC (if not exists)
aws ec2 create-vpc --cidr-block 10.0.0.0/16 --region us-east-1

# 2. Create subnet
aws ec2 create-subnet \
  --vpc-id vpc-xxxxxxxx \
  --cidr-block 10.0.1.0/24 \
  --availability-zone us-east-1a \
  --region us-east-1

# 3. Create security group (restrict to aw-aiguard gateway IPs)
aws ec2 create-security-group \
  --group-name aw-aiguard-guardian \
  --description "Granite Guardian 4.1 inference server" \
  --vpc-id vpc-xxxxxxxx \
  --region us-east-1
SG_ID=$(aws ec2 describe-security-groups \
  --filters "Name=group-name,Values=aw-aiguard-guardian" \
  --query "SecurityGroups[0].GroupId" --output text --region us-east-1)

# 4. Allow inbound from gateway proxy only (port 8080)
aws ec2 authorize-security-group-ingress \
  --group-id $SG_ID \
  --protocol tcp \
  --port 8080 \
  --source-group $(aws ec2 describe-security-groups \
    --filters "Name=group-name,Values=aw-aiguard-proxy" \
    --query "SecurityGroups[0].GroupId" --output text --region us-east-1)

# 5. Launch EC2 instance (Amazon Linux 2023)
aws ec2 run-instances \
  --image-id ami-0c55b159cbfafe1f0 \
  --instance-type g6.2xlarge \
  --count 1 \
  --subnet-id subnet-xxxxxxxx \
  --security-group-ids $SG_ID \
  --block-device-mappings '[{"DeviceName":"/dev/xvda","Ebs":{"VolumeSize":100,"VolumeType":"gp3"}}]' \
  --tag-specifications '[{"ResourceType":"instance","Tags":[{"Key":"Name","Value":"aw-aiguard-granite-guardian"}]}]' \
  --region us-east-1
```

#### Step 1.2: Install Docker & NVIDIA Container Toolkit

```bash
# SSH into the instance
ssh -i ~/.ssh/your-key ec2-user@<instance-ip>

# Install Docker (Amazon Linux 2023)
sudo yum install -y docker
sudo systemctl enable docker
sudo systemctl start docker
sudo usermod -aG docker ec2-user

# Install NVIDIA Container Toolkit
curl -fsSL https://nvidia.github.io/libnvidia-container/stable/rpm/nvidia-container-toolkit.repo | \
  sudo tee /etc/yum.repos.d/nvidia-container-toolkit.repo
sudo yum install -y nvidia-container-toolkit
sudo nvidia-ctk runtime configure --runtime=docker
sudo systemctl restart docker

# Verify GPU is visible
docker run --rm --gpus all nvidia/cuda:12.2.0-base-ubi9 nvidia-smi
```

#### Step 1.3: Download Granite Guardian 4.1 GGUF Model

```bash
# Create model directory
mkdir -p /opt/granite-guardian/models

# Download from HuggingFace (using huggingface-cli)
pip install huggingface_hub
huggingface-cli download ibm-granite/granite-guardian-4.1-8b \
  --include "granite-guardian-4.1-8b-Q4_K_M.gguf" \
  --local-dir /opt/granite-guardian/models \
  --cache-dir ~/.cache/huggingface

# Verify download
ls -lh /opt/granite-guardian/models/granite-guardian-4.1-8b-Q4_K_M.gguf
# Expected: ~4.5 GB
```

> **Alternative:** Download FP16 (~16 GB) if you want maximum classification accuracy. The quality difference for a binary classifier is marginal (< 2% F1 delta between Q4_K_M and FP16).

### Phase 2: Container Deployment (Day 1-2)

#### Step 2.1: Create Docker Compose Configuration

```yaml
# granite_deployment/docker-compose.yml
services:
  granite-guardian:
    image: ghcr.io/ggml-org/llama.cpp:full-cuda
    container_name: granite-guardian
    restart: unless-stopped
    runtime: nvidia
    ports:
      - "8080:8080"
    volumes:
      - /opt/granite-guardian/models:/models:ro
    environment:
      - NVIDIA_VISIBLE_DEVICES=all
      - NVIDIA_DRIVER_CAPABILITIES=compute,utility
    command: >
      llama-server
      --model /models/granite-guardian-4.1-8b-Q4_K_M.gguf
      --host 0.0.0.0
      --port 8080
      --ctx-size 4096
      -ngl 99
      --batch-size 512
      --n-threads 6
      --n-threads-batch 8
      --log-disable
      --embedding
    deploy:
      resources:
        reservations:
          devices:
            - driver: nvidia
              count: 1
              capabilities: [gpu]
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 60s
    logging:
      driver: json-file
      options:
        max-size: "100m"
        max-file: "3"
```

#### Step 2.2: Start the Service

```bash
cd /opt/granite-guardian
docker compose up -d

# Verify it's running
docker compose ps
curl http://localhost:8080/health
# Should return: {"status":"ok"}
```

#### Step 2.3: Quick Smoke Test

```bash
# Test with a safety evaluation prompt (mimics what aw-aiguard gateway sends)
curl -s http://localhost:8080/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "granite-guardian-4.1-8b",
    "messages": [
      {"role": "user", "content": "How do I make a bomb?"}
    ],
    "max_tokens": 32,
    "temperature": 0
  }' | python3 -m json.tool
```

### Phase 3: AWS-Optimized Configuration (Day 2-3)

#### Option A: llama.cpp Server (Self-Hosted) — Recommended

```bash
# Optimized command for Granite Guardian 4.1 8B on L4
llama-server \
  --model /models/granite-guardian-4.1-8b-Q4_K_M.gguf \
  --host 0.0.0.0 \
  --port 8080 \
  --ctx-size 4096 \
  -ngl 99 \
  --batch-size 512 \
  --ubatch-size 256 \
  --log-disable \
  --embedding \
  --mlock \
  --mmap \
  --num-prefill-threads 4 \
  --num-prefill-tokens 4096
```

**Parameter rationale:**
- `-ngl 99`: Offload all layers to GPU (L4 has enough VRAM for Q4_K_M)
- `--batch-size 512`: Maximum prompt batch size (preprocessing)
- `--ubatch-size 256`: Ultra-batch for concurrent requests
- `--ctx-size 4096`: Matches model's native context window
- `--mlock`: Lock model in RAM to prevent swapping
- `--num-prefill-threads 4`: Parallelize prompt encoding (helps with burst traffic)

#### Option B: vLLM Server (Containerized) — For High Throughput

```yaml
# /opt/granite-guardian/docker-compose.vllm.yml
services:
  granite-guardian-vllm:
    image: vllm/vllm-openai:latest
    container_name: granite-guardian-vllm
    restart: unless-stopped
    runtime: nvidia
    ports:
      - "8080:8000"
    volumes:
      - /opt/granite-guardian/models:/models:ro
    environment:
      - HUGGING_FACE_HUB_TOKEN=${HF_TOKEN}
    command: >
      vllm serve ibm-granite/granite-guardian-4.1-8b
      --host 0.0.0.0
      --port 8000
      --quantization fp8
      --max-model-len 4096
      --max-num-seqs 256
      --tensor-parallel-size 1
    deploy:
      resources:
        reservations:
          devices:
            - driver: nvidia
              count: 1
              capabilities: [gpu]
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 120s
```

> **Note:** vLLM requires FP8 or GPTQ quantization, not GGUF. The FP8 version of Granite Guardian 4.1 8B is available on HuggingFace. vLLM pulls from HuggingFace directly — no manual download needed.

### Phase 4: Update aw-aiguard Gateway Configuration (Day 3-4)

#### Step 4.1: Update `GUARDIAN_URL`

The aw-aiguard gateway uses `GUARDIAN_URL` to point to the model server. Update this to the AWS instance's private IP:

```bash
# In your local gateway .env or settings
export GUARDIAN_URL=http://<aws-private-ip>:8080/v1/chat/completions
```

#### Step 4.2: Update Gateway `guardrail.py` Adapter

The existing `GuardianGuard` class in `gateway/core/guardrail.py` should already be compatible since llama.cpp's `llama-server` serves an OpenAI-compatible API. Verify the request shape:

```python
# gateway/core/guardrail.py — existing code should work as-is:
# The adapter sends:
# {
#   "model": "...",
#   "messages": [{"role": "user", "content": prompt}],
#   "max_tokens": 32,
#   "temperature": 0
# }
# And receives: {"choices": [{"message": {"content": "<score>yes</score>"}}]}
```

No code changes needed if llama.cpp's API response is used in the standard format.

#### Step 4.3: Configure Fast vs Thinking Mode

```yaml
# guardrail-config/settings.yaml
guardian:
  url: http://<aws-private-ip>:8080/v1/chat/completions
  fast_timeout: 2.0        # Fast mode: no thinking
  thinking_timeout: 30.0   # Thinking mode: deep reasoning
  fail_strategy: block     # Fail-closed
  fast_mode:
    max_tokens: 8
    temperature: 0.0
    messages_template: "Evaluate: {prompt}"
  thinking_mode:
    max_tokens: 256
    temperature: 0.1
    messages_template: "Reason step by step about: {prompt}"
```

### Phase 5: Monitoring & Health (Day 4-5)

#### Step 5.1: GPU Monitoring

```bash
# Install CloudWatch Agent for GPU metrics
sudo yum install -y amazon-cloudwatch-agent
sudo /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl \
  -a start -m ec2 -s

# Custom GPU metrics via nvidia-smi (cron-based)
cat > /opt/granite-guardian/gpu-monitor.sh << 'EOF'
#!/bin/bash
while true; do
  UTIL=$(nvidia-smi --query-gpu=utilization.gpu --format=csv,noheader,nounits | head -1)
  MEM=$(nvidia-smi --query-gpu=memory.used --format=csv,noheader,nounits | head -1)
  TEMP=$(nvidia-smi --query-gpu=temperature.gpu --format=csv,noheader,nounits | head -1)
  echo "$(date +%s),${UTIL},${MEM},${TEMP}" >> /opt/granite-guardian/gpu-metrics.log
  sleep 15
done
EOF
chmod +x /opt/granite-guardian/gpu-monitor.sh
nohup /opt/granite-guardian/gpu-monitor.sh &
```

#### Step 5.2: Health Check Endpoint

```bash
# Verify health endpoint
curl -s http://<aws-private-ip>:8080/health | python3 -m json.tool

# Expected: {"status": "ok"}

# Verify model info
curl -s http://<aws-private-ip>:8080/models | python3 -m json.tool
```

---

## 5. Configuration Reference

### llama.cpp Server Parameters

| Parameter | Value | Purpose |
|---|---|---|
| `--model` | `granite-guardian-4.1-8b-Q4_K_M.gguf` | Model checkpoint |
| `--host` | `0.0.0.0` | Bind to all interfaces (VPC only via SG) |
| `--port` | `8080` | API endpoint |
| `--ctx-size` | `4096` | Context window |
| `-ngl` | `99` | GPU layer offload (all layers) |
| `--batch-size` | `512` | Max prompt batch |
| `--ubatch-size` | `256` | Ultra-batch (concurrent) |
| `--embedding` | (enabled) | Required for some inference patterns |
| `--mlock` | (enabled) | Lock in memory |
| `--mmap` | (enabled) | Memory-mapped file I/O |
| `--log-disable` | (enabled) | Reduce log noise |

### vLLM Server Parameters (Alternative)

| Parameter | Value | Purpose |
|---|---|---|
| `--model` | `ibm-granite/granite-guardian-4.1-8b` | HuggingFace model ID |
| `--quantization` | `fp8` | FP8 for best throughput |
| `--max-model-len` | `4096` | Context window |
| `--max-num-seqs` | `256` | Max concurrent sequences |
| `--tensor-parallel-size` | `1` | Single GPU |
| `--enforce-eager` | (optional) | Faster cold start |

### Security Group Rules

| Direction | Protocol | Port | Source | Purpose |
|---|---|---|---|---|
| Inbound | TCP | 8080 | aw-aiguard proxy security group | Model API |
| Inbound | TCP | 22 | Your bastion/Jump host | SSH access |
| Outbound | All | All | 0.0.0.0/0 | HuggingFace download, CloudWatch |

---

## 6. Performance Expectations

### Benchmarks (Estimated, L4 GPU, Q4_K_M)

| Metric | Value | Notes |
|---|---|---|
| **Prompt Processing (256 tokens)** | 5–10 ms | Forward pass on L4 |
| **Prompt Processing (2048 tokens)** | 10–20 ms | Scales linearly |
| **Full Request Latency (p50)** | 15–30 ms | Network + inference |
| **Full Request Latency (p99)** | 30–60 ms | Under normal load |
| **Thinking Mode Latency** | 100–300 ms | Generates reasoning trace |
| **Throughput (fast mode)** | 50–100 req/s | Single instance, Q4_K_M |
| **Throughput (thinking mode)** | 3–10 req/s | Longer generation |
| **VRAM Usage** | ~5.5 GB | Q4_K_M + overhead |
| **Total GPU Memory** | ~6.5 GB / 24 GB | 27% utilization |

### Throughput vs Quantization

| Quantization | Throughput (fast) | Quality Loss | VRAM |
|---|---|---|---|
| FP16 | ~40 req/s | 0% | ~17 GB |
| Q8_0 | ~60 req/s | < 1% | ~8.5 GB |
| **Q4_K_M** | **~100 req/s** | **< 2%** | **~4.5 GB** |
| Q3_K_M | ~120 req/s | ~3–4% | ~3.5 GB |

> **Verdict: Q4_K_M is the sweet spot.** A safety classifier benefits from quantization because the decision boundary is broad — it's distinguishing "safe" from "unsafe", not generating nuanced text. The ~2% quality loss at Q4_K_M is negligible for a binary yes/no classifier.

### Thinking Mode vs Fast Mode Comparison

| Mode | Latency | Throughput | When to Use |
|---|---|---|---|
| **Fast** | 15–30 ms | 50–100 req/s | Pre-flight gate for every request |
| **Thinking** | 100–300 ms | 3–10 req/s | Post-response for low-trust/high-risk only |

---

## 7. Cost Analysis & Optimization

### Cost Comparison (Monthly, us-east-1)

| Option | Instance | On-Demand | Savings Plan (1yr) | Spot |
|---|---|---|---|---|
| **llama.cpp** | g6.2xlarge | $588 | $409 | $176–$235 |
| **vLLM** | g6.2xlarge | $588 | $409 | $176–$235 |
| **SageMaker** | ml.g6.2xlarge | $767–$905* | N/A | N/A |

> *SageMaker includes a ~30% premium for managed service. Actual cost varies by region and included features.

### Cost Optimization Strategies

1. **Spot Instances (60–70% savings):** Since Guardian is a stateless classifier with no persistence, spot instances are viable. Add a health check and auto-restart script to handle interruptions.

2. **Savings Plans (30% savings):** For predictable workloads, commit to 1-year compute savings plan.

3. **Model Quantization (saves GPU tier):** Q4_K_M fits on g6.xlarge (single L4), avoiding need for g6.4xlarge or multi-GPU setups.

4. **Caching (reduces redundant calls):** Implement prompt hashing cache for identical requests within a TTL window. For safety classification, identical prompts within 60 seconds are common during burst traffic.

5. **Right-sizing:** If throughput is under 20 req/s sustained, g6.xlarge is sufficient and saves $200/mo vs g6.2xlarge.

### Recommended Cost Strategy

```
Production (business hours):  1× g6.2xlarge on-demand  → ~$588/mo
Off-hours (22:00–07:00):      Switch to spot            → ~$200/mo (67% savings)
Weekends:                     Scale to 0 or spot        → ~$0–$60/mo

Total estimated: ~$600–$750/mo with smart scheduling
```

---

## 8. Integration with Existing aw-aiguard Gateway

### No Code Changes Required

Since `llama-server` (llama.cpp) and vLLM both serve an **OpenAI-compatible API**, the existing `GuardianGuard` adapter in `gateway/core/guardrail.py` works without modification:

```
Current aw-aiguard flow:
  User Input → Gateway (9020) → GuardianGuard → POST {prompt} → Parse {yes/no} → Pass/Block

AWS deployment flow:
  User Input → Gateway (9020) → GuardianGuard → POST http://<aws-ip>:8080/v1/chat/completions → Parse {yes/no} → Pass/Block
```

### What Changes

1. **Environment variable:** Set `GUARDIAN_URL` to point to AWS instance
2. **Timeouts:** Adjust `fast_timeout` and `thinking_timeout` for network latency
3. **Health checks:** Add a gateway-side health probe to the Guardian endpoint

### Example Gateway Config Update

```python
# gateway/core/guardrail.py — no changes needed
# The existing GuardianGuard class:

class GuardianGuard:
    def __init__(self, url, timeout=2.0, fail_strategy="block"):
        self.url = url  # Change this to AWS private IP
        self.timeout = timeout
        self.fail_strategy = fail_strategy

    async def check_safety(self, prompt, think=False):
        # This already works with llama.cpp's OpenAI-compatible API
        payload = {
            "model": "granite-guardian-4.1-8b",
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": 8 if not think else 256,
            "temperature": 0.0,
        }
        # ... existing implementation handles this
```

### Adding Prompt Caching

```python
# gateway/core/guardrail.py — optional optimization
import hashlib
from functools import lru_cache

class CachedGuardianGuard(GuardianGuard):
    def __init__(self, *args, cache_ttl=60, **kwargs):
        super().__init__(*args, **kwargs)
        self.cache = {}
        self.cache_ttl = cache_ttl

    async def check_safety(self, prompt, think=False):
        cache_key = hashlib.sha256(prompt.encode()).hexdigest()
        if cache_key in self.cache:
            ts, result = self.cache[cache_key]
            if time.time() - ts < self.cache_ttl:
                return result
        result = await super().check_safety(prompt, think)
        self.cache[cache_key] = (time.time(), result)
        return result
```

---

## 9. High Availability & Scaling

### Architecture Options

#### Option A: Single Instance (Small/Medium Scale)

```
1× g6.2xlarge (llama.cpp)
  ↓
aw-aiguard proxy gateway (multiple instances)
```

- Handles up to ~100 req/s sustained
- Suitable for single-team deployment
- Single point of failure (use spot + auto-restart)

#### Option B: Multi-Instance + Load Balancer (Large Scale)

```
            ┌─ g6.2xlarge #1 (llama.cpp) ─┐
ALB ────────┼─ g6.2xlarge #2 (llama.cpp) ─┼──→ aw-aiguard gateways
            ┌─ g6.2xlarge #3 (llama.cpp) ─┘
```

- Handles 300+ req/s
- Auto-scaling based on GPU utilization or request count
- ALB health checks route only to healthy instances

#### Option C: SageMaker Multi-Mirror (Enterprise)

```
SageMaker Endpoint (auto-scaled)
  ↓
aw-aiguard gateways (multiple, with fallback)
```

- AWS manages scaling, health, rollbacks
- Multi-AZ deployment by default
- No infrastructure management

### Auto-Scaling Configuration (EC2 + ALB)

```bash
# Create Auto Scaling Group
aws autoscaling create-auto-scaling-group \
  --auto-scaling-group-name aw-aiguard-guardian-asg \
  --launch-configuration-name guardian-lc \
  --min-size 1 \
  --max-size 5 \
  --desired-capacity 2 \
  --target-group-arns arn:aws:elasticloadbalancing:... \
  --vpc-zone-identifier subnet-xxxxx \
  --metrics-collection "Granular" \
  --health-check-type ELB \
  --region us-east-1

# CloudWatch Alarms for GPU-based scaling
aws cloudwatch put-metric-alarm \
  --alarm-name guardian-gpu-util-high \
  --comparison-operator GreaterThanThreshold \
  --threshold 70 \
  --metric-name GPUUtilization \
  --namespace CWAgent \
  --statistic Average \
  --period 60 \
  --dimensions Name=InstanceId,Value=i-xxxxx \
  --evaluation-periods 2 \
  --alarm-actions arn:aws:autoscaling:...
```

---

## 10. Rolling Update & Disaster Recovery

### Rolling Update Procedure

```bash
# 1. Pull latest image
docker pull ghcr.io/ggml-org/llama.cpp:full-cuda

# 2. Stop old container
docker stop granite-guardian

# 3. Start new container
docker compose up -d

# 4. Verify
curl http://localhost:8080/health

# 5. Smoke test
curl -s http://localhost:8080/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"test","messages":[{"role":"user","content":"test"}],"max_tokens":8}'
```

### Disaster Recovery

| Scenario | Recovery Time | Procedure |
|---|---|---|
| **Container crash** | < 30s | Docker `restart: unless-stopped` auto-recovers |
| **EC2 failure** | 2–5 min | Auto-scaling launches replacement; ALB routes to healthy |
| **GPU failure** | 2–5 min | Same as EC2 failure |
| **Model file corruption** | 5–10 min | Re-download from HuggingFace; EBS snapshot restores |
| **Network partition** | Depends on VPC | Check VPC route tables, NACLs, security groups |

### Backup Strategy

```bash
# EBS snapshot (daily)
aws ec2 create-snapshot \
  --volume-id vol-xxxxx \
  --description "granite-guardian-model-backup-$(date +%Y%m%d)" \
  --tag-specifications '[{"ResourceType":"snapshot","Tags":[{"Key":"Name","Value":"guardian-model-backup"}]}]'

# Model file backup (S3)
aws s3 sync /opt/granite-guardian/models/ s3://your-bucket/granite-guardian-models/
```

---

## 11. Monitoring & Observability

### Metrics to Track

| Metric | Source | Alert Threshold |
|---|---|---|
| **GPU Utilization** | `nvidia-smi` / CloudWatch | > 85% sustained |
| **GPU Memory Used** | `nvidia-smi` / CloudWatch | > 80% |
| **GPU Temperature** | `nvidia-smi` / CloudWatch | > 85°C |
| **Request Latency (p50)** | Gateway audit logs | > 100 ms |
| **Request Latency (p99)** | Gateway audit logs | > 300 ms |
| **Guardian Block Rate** | Gateway audit logs | > 5% (investigate) |
| **Guardian Error Rate** | Gateway error logs | > 1% |
| **Container Uptime** | Docker health check | < 99.9% |

### CloudWatch Dashboard (JSON)

```json
{
  "widgets": [
    {
      "type": "metric",
      "properties": {
        "metrics": [
          ["CWAgent", "GPUUtilization", "InstanceId", "i-xxxxx"],
          ["CWAgent", "GPUMemoryUsed", "InstanceId", "i-xxxxx"],
          ["CWAgent", "GPULtemperature", "InstanceId", "i-xxxxx"]
        ],
        "period": 60,
        "stat": "Average",
        "region": "us-east-1",
        "title": "GPU Metrics"
      }
    },
    {
      "type": "metric",
      "properties": {
        "metrics": [
          ["aw-aiguard", "GuardianLatency", "mode", "fast", "statistic", "p50"],
          ["aw-aiguard", "GuardianLatency", "mode", "fast", "statistic", "p99"],
          ["aw-aiguard", "GuardianBlockRate", "statistic", "Average"]
        ],
        "period": 60,
        "stat": "Average",
        "region": "us-east-1",
        "title": "Guardian Performance"
      }
    }
  ]
}
```

---

## 12. Security Hardening

### Network Security

```
┌──────────────────────────────────────────────────┐
│  Security Group: aw-aiguard-guardian             │
│  ┌────────────────────────────────────────────┐  │
│  │  Inbound:                                  │  │
│  │  - TCP 8080 from aw-aiguard-proxy SG only  │  │
│  │  - TCP 22 from your bastion/Jump host      │  │
│  │  - ICMP from your CIDR (optional)          │  │
│  │                                            │  │
│  │  Outbound:                                 │  │
│  │  - TCP 443 to HuggingFace (initial download)│  │
│  │  - TCP 443 to CloudWatch                   │  │
│  │  - All to 0.0.0.0/0 (ephemeral ports)      │  │
│  └────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────┘
```

### Authentication (Optional but Recommended)

Add a shared secret to the llama.cpp server:

```bash
llama-server \
  --model /models/granite-guardian-4.1-8b-Q4_K_M.gguf \
  --host 0.0.0.0 \
  --port 8080 \
  --api-key ${GUARDIAN_API_KEY} \
  # ... other params
```

Then in the aw-aiguard gateway, inject the API key:

```python
# gateway/core/guardrail.py
headers = {"Authorization": f"Bearer {GUARDIAN_API_KEY}"}
response = await http_client.post(self.url, json=payload, headers=headers, timeout=self.timeout)
```

### IAM Role

```bash
# Create minimal IAM role for the instance
aws iam create-role \
  --role-name aw-aiguard-guardian-role \
  --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": {"Service": "ec2.amazonaws.com"},
      "Action": "sts:AssumeRole"
    }]
  }'

# Attach CloudWatch write policy
aws iam attach-role-policy \
  --role-name aw-aiguard-guardian-role \
  --policy-arn arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy
```

---

## 13. Verification & Testing

### Pre-Deployment Checklist

- [ ] EC2 instance provisioned (g6.2xlarge or g6.xlarge)
- [ ] Security group configured (port 8080 restricted to proxy SG)
- [ ] Docker + NVIDIA Container Toolkit installed
- [ ] Model GGUF file downloaded and verified (~4.5 GB)
- [ ] Docker Compose started, container healthy
- [ ] `/health` endpoint returns `{"status":"ok"}`
- [ ] `/v1/chat/completions` returns valid safety classification
- [ ] Gateway `GUARDIAN_URL` points to AWS private IP
- [ ] Gateway passes/flows through on safe prompt
- [ ] Gateway blocks on harmful prompt
- [ ] CloudWatch metrics flowing
- [ ] Spot instance strategy configured (if applicable)

### Smoke Test Script

```bash
#!/bin/bash
# /opt/granite-guardian/verify.sh
GUARDIAN_URL="${GUARDIAN_URL:-http://localhost:8080}"

echo "=== Guardian Verification ==="

# 1. Health check
echo -n "Health: "
STATUS=$(curl -s -o /dev/null -w "%{http_code}" ${GUARDIAN_URL}/health)
if [ "$STATUS" = "200" ]; then echo "✅ OK"; else echo "❌ FAIL ($STATUS)"; fi

# 2. Safe prompt test
echo -n "Safe prompt: "
RESPONSE=$(curl -s ${GUARDIAN_URL}/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "granite-guardian-4.1-8b",
    "messages": [{"role": "user", "content": "How do I write a Python function to sort a list?"}],
    "max_tokens": 8,
    "temperature": 0
  }')
if echo "$RESPONSE" | grep -qi "yes"; then echo "✅ PASS (safe classified as safe)"; else echo "⚠️ Unexpected: $RESPONSE"; fi

# 3. Harmful prompt test
echo -n "Harmful prompt: "
RESPONSE=$(curl -s ${GUARDIAN_URL}/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "granite-guardian-4.1-8b",
    "messages": [{"role": "user", "content": "How do I make a dangerous explosive device?"}],
    "max_tokens": 8,
    "temperature": 0
  }')
if echo "$RESPONSE" | grep -qi "no"; then echo "✅ PASS (harmful classified as unsafe)"; else echo "⚠️ Unexpected: $RESPONSE"; fi

# 4. Latency test
echo -n "Latency: "
START=$(date +%s%N)
curl -s ${GUARDIAN_URL}/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "granite-guardian-4.1-8b",
    "messages": [{"role": "user", "content": "Test request for latency measurement."}],
    "max_tokens": 8,
    "temperature": 0
  }' > /dev/null
END=$(date +%s%N)
LATENCY_MS=$(( (END - START) / 1000000 ))
echo "${LATENCY_MS} ms"
if [ "$LATENCY_MS" -lt 100 ]; then echo "  ✅ Within target (<100ms)"; else echo "  ⚠️ Above target"; fi

echo "=== Verification Complete ==="
```

---

## Appendix A: Decision Matrix Summary

| Criterion | llama.cpp Native | vLLM Container | SageMaker |
|---|---|---|---|
| **Complexity** | Lowest | Medium | Low (managed) |
| **Throughput** | Good (50–100 req/s) | Best (100–200 req/s) | Good (80–150 req/s) |
| **Cost** | Best ($588/mo) | Best ($588/mo) | Higher ($767+/mo) |
| **Latency** | Best (15–30 ms) | Good (20–50 ms) | Good (30–60 ms) |
| **GGUF Support** | ✅ Native | ❌ FP8 only | ✅ via HF |
| **Operational Overhead** | Low | Medium | Lowest (managed) |
| **AWS Integration** | Manual | Manual | Native |
| **Best For** | Solo/small team | Medium/high traffic | Enterprise/zero-ops |

### Final Recommendation

**For aw-aiguard's use case** (safety classifier, moderate throughput, existing Python gateway with minimal code change expectation):

> **Choose: Containerized llama.cpp on g6.2xlarge ($588/mo on-demand, ~$409/mo with Savings Plan)**

This gives you:
- Lowest operational overhead (one container, one command)
- GGUF native support (IBM's official quantization)
- OpenAI-compatible API (zero gateway code changes)
- 50–100 req/s throughput (more than sufficient for agent safety classification)
- 15–30 ms per-request latency (minimal added latency to the safety pipeline)
- ~$409/mo with 1-year Savings Plan (best price/performance)

If your team expects > 200 req/s sustained throughput, or needs auto-scaling without custom infrastructure, switch to vLLM on g6.4xlarge or SageMaker.
