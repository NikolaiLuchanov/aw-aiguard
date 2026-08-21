# aw-aiguard: Granite Guardian 4.1 — Deployment

Deploy `ibm-granite/granite-guardian-4.1-8b` (Q4_K_M) on AWS EC2 GPU instances using containerized llama.cpp.

## Quick Start

```bash
# 1. SSH into EC2 via SSM
aws ssm start-session --target i-<instance-id>

# 2. Create directories
mkdir -p granite_deployment/models
cd granite_deployment

# 3. Download model (from HuggingFace)
pip install huggingface_hub
huggingface-cli download ibm-granite/granite-guardian-4.1-8b \
  --include "granite-guardian-4.1-8b-Q4_K_M.gguf" \
  --local-dir models

# 4. Start container
docker compose up -d

# 5. Verify
curl http://localhost:8080/health
# → {"status":"ok"}
```

## GPU Passthrough Checklist

For the container to actually use the L4 GPU (not fall back to CPU):

- [ ] **Host NVIDIA drivers installed** — `nvidia-smi` shows L4 GPU on host
- [ ] **NVIDIA Container Toolkit installed** — `docker run --gpus all nvidia/cuda:12.2.0-base-ubi9 nvidia-smi` works
- [ ] **Docker compose uses `runtime: nvidia`** — Check `docker-compose.yml`
- [ ] **Docker compose reserves GPU device** — Check `deploy.resources.reservations.devices`
- [ ] **llama.cpp image is `full-cuda`** — Not `full` or `full-openblas`
- [ ] **Model loaded with `-ngl 99`** — All layers offloaded to GPU
- [ ] **Container sees GPU** — `docker exec granite-guardian nvidia-smi` shows L4

If ANY of these fail, the container runs on CPU (~0.5–2 tokens/sec vs ~100 req/s on GPU).

## Architecture

```
AWS EC2 g6e.xlarge
├── NVIDIA L4 (48 GB VRAM)
│   └── llama.cpp container
│       ├── Model: granite-guardian-4.1-8b-Q4_K_M.gguf (~4.5 GB)
│       ├── API: OpenAI-compatible (/v1/chat/completions)
│       └── Port: 8080
└── Security: Port 8080 restricted to user's public IP (/32)
```

## Integration with aw-aiguard Gateway

No code changes required. Set the `GUARDIAN_URL` environment variable:

```bash
export GUARDIAN_URL=http://<aws-private-ip>:8080/v1/chat/completions
```

The existing `GuardianGuard` adapter in `gateway/core/guardrail.py` works as-is because llama.cpp serves the OpenAI-compatible API format.

## Performance

| Metric | Value |
|---|---|
| **Throughput (fast mode)** | 50–100 req/s |
| **Latency (p50)** | 15–30 ms |
| **VRAM Usage** | ~5.5 GB / 24 GB |
| **Model Size** | ~4.5 GB (Q4_K_M quantized) |

## Troubleshooting

### Container won't start

```bash
# Check if NVIDIA toolkit is installed
docker info | grep -i nvidia
# Should show: "Runtimes: nvidia nvidia"

# Check if GPU is visible inside container
docker logs granite-guardian
# Look for CUDA errors

# Verify host sees GPU
nvidia-smi
```

### Running on CPU instead of GPU

```bash
# Check if -ngl parameter is set correctly
docker exec granite-guardian ps aux | grep llama-server
# Should show: -ngl 99

# Verify GPU memory usage
docker exec granite-guardian nvidia-smi
# Should show ~5.5 GB used

# If using 0 GB, CUDA backend not loaded — check image tag
docker inspect granite-guardian --format='{{.Config.Image}}'
# Should be: ghcr.io/ggml-org/llama.cpp:full-cuda
```

### Health check failing

```bash
# Check if container is running
docker ps | grep granite-guardian

# Check logs for startup errors
docker logs granite-guardian

# Verify model file exists and is readable
ls -lh /opt/granite-guardian/models/granite-guardian-4.1-8b-Q4_K_M.gguf
# Should show ~4.5 GB file
```

### Network connectivity

```bash
# From aw-aiguard gateway host, test connection
curl -v http://<aws-private-ip>:8080/health

# If connection refused:
# 1. Check security group allows port 8080 from your IP
# 2. Check container is listening
docker exec granite-guardian netstat -tlnp | grep 8080
# Should show: LISTEN 0.0.0.0:8080
```

## Verification

Run the pytest suite:

```bash
cd tests
pytest test_guardrail.py test_proxy.py -v
```

Expected output:
```
=== Granite Guardian Deployment Verification ===
✅ GPU passthrough: NVIDIA L4 visible in container
✅ Model loaded: Q4_K_M quantization detected
✅ Health endpoint: 200 OK
✅ Fast mode latency: < 50 ms
✅ Safe prompt: classified correctly
✅ Harmful prompt: blocked correctly
=== All checks passed ===
```

## Files

| File | Purpose |
|---|---|
| `docker-compose.yml` | Container configuration with GPU passthrough |
| `tests/` | Pytest suite for deployment verification |
| `README.md` | This file — deployment guide and troubleshooting |

## Maintenance

### Update model version

```bash
# Pull new model from HuggingFace
huggingface-cli download ibm-granite/granite-guardian-4.1-8b \
  --include "granite-guardian-4.1-8b-Q4_K_M.gguf" \
  --local-dir models

# Restart container
docker compose restart
```

### Backup model

```bash
# EBS snapshot (automated via AWS backup)
aws ec2 create-snapshot \
  --volume-id vol-xxxxx \
  --description "granite-model-$(date +%Y%m%d)"
```

### Restore from backup

```bash
# Stop container
docker compose down

# Restore model from S3 (if configured)
aws s3 sync s3://your-bucket/granite-guardian-models/ models/

# Restart
docker compose up -d
```
