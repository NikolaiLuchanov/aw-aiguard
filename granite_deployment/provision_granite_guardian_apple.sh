#!/usr/bin/env bash
# ============================================================================
# aw-aiguard: Granite Guardian 4.1 — AWS Provisioning Script
# ============================================================================
#
# Hybrid provisioning: local AWS CLI launches infrastructure, SSH bootstrap
# installs Docker, NVIDIA toolkit, downloads model, and starts container.
#
# Usage:
#   export AWS_PROFILE=my-profile
#   chmod +x provision_granite_guardian.sh
#   ./provision_granite_guardian.sh
#
# Prerequisites:
#   - aws CLI v2 installed and configured (aws configure)
#   - ssh key pair available on local machine
#   - jq installed (for parsing AWS output)
#   - macOS or Linux with bash 4+
#
# What it provisions:
#   1. VPC + subnet (us-east-1 default, configurable)
#   2. Security groups: proxy (9020) + guardian (8080)
#   3. EC2 g6.2xlarge on-demand with NVIDIA L4 GPU
#   4. Bootstrap: Docker, NVIDIA Container Toolkit, model download, container
#
# Output: Guardian IP for GUARDIAN_URL in aw-aiguard gateway config
# ============================================================================

set -euo pipefail

# ─── Configuration ───────────────────────────────────────────────────────────
# Override these before running:

REGION="${REGION:-us-east-1}"
INSTANCE_TYPE="${INSTANCE_TYPE:-g6.2xlarge}"
KEY_NAME="${KEY_NAME:-granite-guardian-key}"  # Replace with your actual key name
AVAILABILITY_ZONE="${AVAILABILITY_ZONE:-${REGION}a}"
PROJECT_NAME="${PROJECT_NAME:-aw-aiguard}"
AMAZON_LINUX_2023_AMI="${AMAZON_LINUX_2023_AMI:-}"  # Auto-detected if empty

# Model configuration
MODEL_REPO="${MODEL_REPO:-ibm-granite/granite-guardian-4.1-8b}"
MODEL_QUANT="${MODEL_QUANT:-Q4_K_M}"
MODEL_FILE="${MODEL_FILE:-granite-guardian-4.1-8b-${MODEL_QUANT}.gguf}"
MODEL_DIR="/opt/granite-guardian/models"

# Docker / llama.cpp
LLAMA_IMAGE="${LLAMA_IMAGE:-ghcr.io/ggml-org/llama.cpp:full-cuda}"
LLAMA_PORT="${LLAMA_PORT:-8080}"
GUARDIAN_URL_PATH="/v1/chat/completions"

# Timing
SSH_WAIT_SECONDS="${SSH_WAIT_SECONDS:-90}"
BOOTSTRAP_TIMEOUT="${BOOTSTRAP_TIMEOUT:-600}"

# Tags
COMMON_TAGS="Project=${PROJECT_NAME},ManagedBy=provision_granite_guardian.sh,Environment=production"

# ─── Color codes ─────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

info()  { echo -e "${BLUE}[INFO]${NC} $1"; }
ok()    { echo -e "${GREEN}[OK]${NC} $1"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
fail()  { echo -e "${RED}[FAIL]${NC} $1"; exit 1; }

# ─── Pre-flight checks ───────────────────────────────────────────────────────
preflight() {
    info "Checking prerequisites..."

    command -v aws >/dev/null 2>&1 || fail "aws CLI not found — install with: brew install awscli"
    command -v ssh >/dev/null 2>&1  || fail "ssh not found"
    command -v jq >/dev/null 2>&1  || fail "jq not found — install with: brew install jq"
    command -v docker >/dev/null 2>&1  || warn "docker not found locally (not required, but useful)"

    # Verify AWS credentials
    if ! aws sts get-caller-identity >/dev/null 2>&1; then
        fail "AWS credentials not configured — run: aws configure"
    fi

    info "AWS region: ${REGION}"
    info "Instance type: ${INSTANCE_TYPE}"
    info "VPC/SG: Will be created"
    echo ""
}

# ─── Step 1: Create VPC ─────────────────────────────────────────────────────
create_vpc() {
    info "Step 1/6: Creating VPC and subnet..."

    # VPC
    local vpc_output
    vpc_output=$(aws ec2 create-vpc \
        --cidr-block 10.0.0.0/16 \
        --tag-specifications "ResourceType=vpc,Tags=[${COMMON_TAGS},Name=${PROJECT_NAME}-vpc]" \
        --query "Vpc.{VpcId:VpcId,State:State}" \
        --output json \
        --region "$REGION" 2>&1) || fail "Failed to create VPC: $(echo "$vpc_output")"

    VPC_ID=$(echo "$vpc_output" | jq -r '.VpcId')
    info "VPC created: ${VPC_ID}"

    # Wait for VPC ready
    aws ec2 wait vpc-available --vpc-ids "$VPC_ID" --region "$REGION" || fail "VPC did not become available"

    # Enable DNS support
    aws ec2 modify-vpc-attribute --vpc-id "$VPC_ID" --enable-dns-support '{"Value":true}' --region "$REGION" >/dev/null
    aws ec2 modify-vpc-attribute --vpc-id "$VPC_ID" --enable-dns-hostnames '{"Value":true}' --region "$REGION" >/dev/null

    # Subnet
    local subnet_output
    subnet_output=$(aws ec2 create-subnet \
        --vpc-id "$VPC_ID" \
        --cidr-block 10.0.1.0/24 \
        --availability-zone "$AVAILABILITY_ZONE" \
        --tag-specifications "ResourceType=subnet,Tags=[${COMMON_TAGS},Name=${PROJECT_NAME}-subnet]" \
        --query "Subnet.{SubnetId:SubnetId}" \
        --output json \
        --region "$REGION" 2>&1) || fail "Failed to create subnet: $(echo "$subnet_output")"

    SUBNET_ID=$(echo "$subnet_output" | jq -r '.SubnetId')
    info "Subnet created: ${SUBNET_ID} (${AVAILABILITY_ZONE})"

    # Internet Gateway (for model downloads via HuggingFace)
    local igw_output
    igw_output=$(aws ec2 create-internet-gateway \
        --tag-specifications "ResourceType=internet-gateway,Tags=[${COMMON_TAGS},Name=${PROJECT_NAME}-igw]" \
        --query "InternetGateway.{InternetGatewayId:InternetGatewayId}" \
        --output json \
        --region "$REGION" 2>&1) || fail "Failed to create IGW: $(echo "$igw_output")"

    IGW_ID=$(echo "$igw_output" | jq -r '.InternetGatewayId')
    aws ec2 attach-internet-gateway --internet-gateway-id "$IGW_ID" --vpc-id "$VPC_ID" --region "$REGION" >/dev/null

    # Route table with internet access
    local rt_output
    rt_output=$(aws ec2 create-route-table \
        --vpc-id "$VPC_ID" \
        --tag-specifications "ResourceType=route-table,Tags=[${COMMON_TAGS},Name=${PROJECT_NAME}-rt]" \
        --query "RouteTable.{RouteTableId:RouteTableId}" \
        --output json \
        --region "$REGION" 2>&1) || fail "Failed to create route table: $(echo "$rt_output")"

    ROUTE_TABLE_ID=$(echo "$rt_output" | jq -r '.RouteTableId')

    # Route to internet
    aws ec2 create-route \
        --route-table-id "$ROUTE_TABLE_ID" \
        --destination-cidr-block 0.0.0.0/0 \
        --gateway-id "$IGW_ID" \
        --region "$REGION" >/dev/null

    # Associate subnet with route table
    aws ec2 associate-route-table \
        --route-table-id "$ROUTE_TABLE_ID" \
        --subnet-id "$SUBNET_ID" \
        --region "$REGION" >/dev/null

    ok "VPC: ${VPC_ID} | Subnet: ${SUBNET_ID} | IGW: ${IGW_ID} | RT: ${ROUTE_TABLE_ID}"
}

# ─── Step 2: Create Security Groups ─────────────────────────────────────────
create_security_groups() {
    info "Step 2/6: Creating security groups..."

    # ─── Proxy Security Group (for future gateway instances) ───
    local proxy_sg_output
    proxy_sg_output=$(aws ec2 create-security-group \
        --group-name "${PROJECT_NAME}-proxy" \
        --description "aw-aiguard proxy gateway security group" \
        --vpc-id "$VPC_ID" \
        --tag-specifications "ResourceType=security-group,Tags=[${COMMON_TAGS},Name=${PROJECT_NAME}-proxy]" \
        --query "GroupId" \
        --output text \
        --region "$REGION" 2>&1) || fail "Failed to create proxy SG: $(echo "$proxy_sg_output")"

    PROXY_SG_ID="$proxy_sg_output"
    info "Proxy security group created: ${PROXY_SG_ID}"

    # Allow inbound HTTP to proxy
    aws ec2 authorize-security-group-ingress \
        --group-id "$PROXY_SG_ID" \
        --protocol tcp \
        --port 9020 \
        --cidr 0.0.0.0/0 \
        --region "$REGION" >/dev/null 2>&1 || warn "Port 9020 rule may already exist"

    # ─── Guardian Security Group ───
    local guardian_sg_output
    guardian_sg_output=$(aws ec2 create-security-group \
        --group-name "${PROJECT_NAME}-guardian" \
        --description "Granite Guardian 4.1 inference server security group" \
        --vpc-id "$VPC_ID" \
        --tag-specifications "ResourceType=security-group,Tags=[${COMMON_TAGS},Name=${PROJECT_NAME}-guardian]" \
        --query "GroupId" \
        --output text \
        --region "$REGION" 2>&1) || fail "Failed to create guardian SG: $(echo "$guardian_sg_output")"

    GUARDIAN_SG_ID="$guardian_sg_output"
    info "Guardian security group created: ${GUARDIAN_SG_ID}"

    # Allow port 8080 from proxy SG only (not the internet!)
    aws ec2 authorize-security-group-ingress \
        --group-id "$GUARDIAN_SG_ID" \
        --protocol tcp \
        --port "$LLAMA_PORT" \
        --source-group "$PROXY_SG_ID" \
        --region "$REGION" 2>&1 || warn "Port 8080 from proxy rule may already exist"

    # Allow SSH (replace with your bastion IP or CIDR)
    aws ec2 authorize-security-group-ingress \
        --group-id "$GUARDIAN_SG_ID" \
        --protocol tcp \
        --port 22 \
        --cidr 0.0.0.0/0 \
        --region "$REGION" 2>&1 || warn "SSH rule may already exist"

    # Allow outbound (HuggingFace download, CloudWatch)
    aws ec2 authorize-security-group-egress \
        --group-id "$GUARDIAN_SG_ID" \
        --protocol -1 \
        --cidr 0.0.0.0/0 \
        --region "$REGION" >/dev/null 2>&1 || warn "Egress rule may already exist"

    ok "Proxy SG: ${PROXY_SG_ID} (inbound: 9020 from anywhere)"
    ok "Guardian SG: ${GUARDIAN_SG_ID} (inbound: ${LLAMA_PORT} from proxy only)"
}

# ─── Step 3: Find Amazon Linux 2023 AMI ──────────────────────────────────────
find_ami() {
    info "Step 3/6: Finding Amazon Linux 2023 AMI..."

    if [ -n "$AMAZON_LINUX_2023_AMI" ]; then
        AMI_ID="$AMAZON_LINUX_2023_AMI"
        ok "Using provided AMI: ${AMI_ID}"
        return
    fi

    local ami_output
    ami_output=$(aws ec2 describe-images \
        --owners amazon \
        --filters \
            "Name=name,Values=al2023-ami-*-x86_64" \
            "Name=state,Values=available" \
            "Name=root-device-type,Values=ebs" \
        --query "Images | sort_by(@, &CreationDate) | [-1].{ImageId:ImageId,Name:Name,CreationDate:CreationDate}" \
        --output json \
        --region "$REGION" 2>&1) || fail "Failed to query AMIs: $(echo "$ami_output")"

    local ami_name ami_date
    ami_name=$(echo "$ami_output" | jq -r '.[0].Name')
    ami_date=$(echo "$ami_output" | jq -r '.[0].CreationDate')
    AMI_ID=$(echo "$ami_output" | jq -r '.[0].ImageId')

    if [ -z "$AMI_ID" ] || [ "$AMI_ID" = "null" ]; then
        fail "No Amazon Linux 2023 AMI found in ${REGION}"
    fi

    info "Found AMI: ${ami_name} (created: ${ami_date})"
    ok "AMI ID: ${AMI_ID}"
}

# ─── Step 4: Launch EC2 Instance ─────────────────────────────────────────────
launch_instance() {
    info "Step 4/6: Launching EC2 instance (${INSTANCE_TYPE})..."

    local launch_output
    launch_output=$(aws ec2 run-instances \
        --image-id "$AMI_ID" \
        --instance-type "$INSTANCE_TYPE" \
        --count 1 \
        --subnet-id "$SUBNET_ID" \
        --security-group-ids "$GUARDIAN_SG_ID" \
        --block-device-mappings '[{"DeviceName":"/dev/xvda","Ebs":{"VolumeSize":100,"VolumeType":"gp3"}}]' \
        --tag-specifications "ResourceType=instance,Tags=[${COMMON_TAGS},Name=${PROJECT_NAME}-granite-guardian]" \
        --metadata-options "HttpTokens=required,HttpEndpoint=enabled" \
        --query "Instances[0].{InstanceId:InstanceId,PrivateIp:PrivateIpAddress,PublicIp:PublicIpAddress,State:State.Name}" \
        --output json \
        --region "$REGION" 2>&1) || fail "Failed to launch instance: $(echo "$launch_output")"

    INSTANCE_ID=$(echo "$launch_output" | jq -r '.InstanceId')
    INSTANCE_IP=$(echo "$launch_output" | jq -r '.PrivateIp')
    PUBLIC_IP=$(echo "$launch_output" | jq -r '.PublicIp')

    if [ -z "$INSTANCE_ID" ] || [ "$INSTANCE_ID" = "null" ]; then
        fail "Instance launch failed: $(echo "$launch_output")"
    fi

    info "Instance ID: ${INSTANCE_ID}"
    info "Private IP: ${INSTANCE_IP}"
    if [ "$PUBLIC_IP" != "null" ]; then
        info "Public IP: ${PUBLIC_IP}"
    fi
    ok "State: ${INSTANCE_ID} launched in ${AVAILABILITY_ZONE}"

    # Wait for instance to be running
    info "Waiting for instance to be in 'running' state (this may take 1-3 minutes)..."
    aws ec2 wait instance-running --instance-ids "$INSTANCE_ID" --region "$REGION" || warn "Instance did not reach 'running' state in expected time"

    # Wait for status check
    info "Waiting for status check to pass..."
    aws ec2 wait instance-status-ok --instance-ids "$INSTANCE_ID" --region "$REGION" || warn "Status check did not pass in expected time"

    ok "Instance ${INSTANCE_ID} is running"
}

# ─── Step 5: Bootstrap Script (written to file, then SSH-injected) ───────────
generate_bootstrap_script() {
    info "Step 5/6: Generating bootstrap script..."

    BOOTSTRAP_SCRIPT=$(cat << 'BOOTSTRAP_EOF'
#!/usr/bin/env bash
# ============================================================================
# Bootstrap script for Granite Guardian 4.1 EC2 instance
# Runs on the EC2 instance itself after first boot
# ============================================================================
set -euo pipefail

echo "===== Bootstrap starting ====="
echo "Date: $(date -u)"
echo "Hostname: $(hostname)"

# ─── Step 1: Update system ───
echo "[1/7] Updating system packages..."
sudo yum update -y --setopt=install_weak_deps=False >/dev/null 2>&1
echo "  System updated."

# ─── Step 2: Install Docker ───
echo "[2/7] Installing Docker..."
sudo yum install -y docker
sudo systemctl enable docker
sudo systemctl start docker
sudo usermod -aG docker ec2-user
echo "  Docker installed and started."

# ─── Step 3: Install NVIDIA Container Toolkit ───
echo "[3/7] Installing NVIDIA Container Toolkit..."

# Check if NVIDIA driver is already installed (should be on Amazon Linux 2023 GPU AMI)
if ! nvidia-smi >/dev/null 2>&1; then
    echo "  WARNING: nvidia-smi not found — NVIDIA drivers may need manual install"
    echo "  Run: sudo yum install -y cuda-drivers"
    exit 1
fi
echo "  NVIDIA drivers OK: $(nvidia-smi --query-gpu=name --format=csv,noheader --id=0 2>/dev/null | head -1)"

# Install NVIDIA Container Toolkit
curl -fsSL https://nvidia.github.io/libnvidia-container/stable/rpm/nvidia-container-toolkit.repo \
    | sudo tee /etc/yum.repos.d/nvidia-container-toolkit.repo
sudo yum install -y nvidia-container-toolkit
sudo nvidia-ctk runtime configure --runtime=docker
sudo systemctl restart docker
echo "  NVIDIA Container Toolkit installed."

# Verify GPU visibility in Docker
echo "  Verifying GPU visibility in Docker..."
if ! docker run --rm --gpus all nvidia/cuda:12.2.0-base-ubi9 nvidia-smi >/dev/null 2>&1; then
    echo "  ERROR: GPU not visible to Docker containers"
    echo "  Troubleshooting:"
    echo "    1. Check: sudo nvidia-smi"
    echo "    2. Check: docker info | grep -i nvidia"
    echo "    3. Restart: sudo systemctl restart docker"
    exit 1
fi
echo "  GPU visible in Docker — OK"

# ─── Step 4: Create model directory and download ───
echo "[4/7] Setting up model directory..."
sudo mkdir -p /opt/granite-guardian/models
sudo chown ec2-user:ec2-user /opt/granite-guardian

echo "[5/7] Downloading Granite Guardian 4.1 model..."
# Install huggingface-cli
pip3 install --user huggingface_hub >/dev/null 2>&1 || {
    sudo yum install -y python3-pip
    pip3 install --user huggingface_hub >/dev/null 2>&1 || pip3 install huggingface_hub >/dev/null 2>&1
}

export HF_HOME="/home/ec2-user/.cache/huggingface"

huggingface-cli download ibm-granite/granite-guardian-4.1-8b \
    --include "granite-guardian-4.1-8b-Q4_K_M.gguf" \
    --local-dir /opt/granite-guardian/models \
    --cache-dir "$HF_HOME" 2>&1 || {
        echo "  ERROR: Model download failed"
        echo "  Check: huggingface-cli download ibm-granite/granite-guardian-4.1-8b --include '*.gguf'"
        exit 1
    }

# Verify model file
if [ ! -f /opt/granite-guardian/models/granite-guardian-4.1-8b-Q4_K_M.gguf ]; then
    echo "  ERROR: Model file not found at /opt/granite-guardian/models/"
    ls -la /opt/granite-guardian/models/
    exit 1
fi

MODEL_SIZE=$(du -sh /opt/granite-guardian/models/granite-guardian-4.1-8b-Q4_K_M.gguf | cut -f1)
echo "  Model downloaded: ${MODEL_SIZE}"

# ─── Step 6: Create docker-compose.yml ───
echo "[6/7] Creating docker-compose.yml..."
cat > /home/ec2-user/granite_guardian/docker-compose.yml << 'COMPOSE_EOF'
services:
  granite-guardian:
    image: ghcr.io/ggml-org/llama.cpp:full-cuda
    container_name: granite-guardian
    restart: unless-stopped
    runtime: nvidia
    deploy:
      resources:
        reservations:
          devices:
            - driver: nvidia
              count: 1
              capabilities: [gpu]
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
      --ubatch-size 256
      --log-disable
      --embedding
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
COMPOSE_EOF
echo "  docker-compose.yml created."

# ─── Step 7: Start container ───
echo "[7/7] Starting Granite Guardian container..."
cd /home/ec2-user/granite_guardian

# Install docker compose plugin (may not be present on Amazon Linux)
if ! docker compose version >/dev/null 2>&1; then
    echo "  Installing Docker Compose plugin..."
    sudo mkdir -p /usr/libexec/docker/cli-plugins
    curl -SL "https://github.com/docker/compose/releases/download/v2.24.0/docker-compose-linux-x86_64" \
        -o /usr/libexec/docker/cli-plugins/docker-compose
    sudo chmod +x /usr/libexec/docker/cli-plugins/docker-compose
    echo "  Docker Compose installed."
fi

# Pull and start
docker compose pull 2>&1 || {
    echo "  ERROR: Failed to pull llama.cpp image"
    echo "  Check: docker pull ghcr.io/ggml-org/llama.cpp:full-cuda"
    exit 1
}

docker compose up -d 2>&1

# Wait for health check
echo "  Waiting for container health check..."
for i in {1..30}; do
    HEALTH=$(curl -sf http://localhost:8080/health 2>/dev/null || echo '""')
    STATUS=$(echo "$HEALTH" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status','error'))" 2>/dev/null || echo "error")
    if [ "$STATUS" = "ok" ]; then
        echo "  Container health: OK"
        break
    fi
    if [ $i -eq 30 ]; then
        echo "  WARNING: Health check not passing yet — checking container status..."
        docker ps --filter "name=granite-guardian" --format "{{.Status}}"
    fi
    sleep 5
done

echo ""
echo "===== Bootstrap complete ====="
echo "Guardian API: http://localhost:8080"
echo "Health check: curl http://localhost:8080/health"
echo "Logs: docker logs -f granite-guardian"
echo ""
echo "Next steps:"
echo "  1. Set GUARDIAN_URL=http://<this-private-ip>:8080/v1/chat/completions"
echo "     in your aw-aiguard gateway .env or settings"
echo "  2. Verify: curl http://localhost:8080/v1/chat/completions"
echo "     -H 'Content-Type: application/json'"
echo "     -d '{\"model\":\"test\",\"messages\":[{\"role\":\"user\",\"content\":\"test\"}],\"max_tokens\":8}'"
BOOTSTRAP_EOF
    echo "  Bootstrap script generated (length: ${#BOOTSTRAP_SCRIPT} bytes)"
}

inject_bootstrap() {
    info "Injecting bootstrap script to instance..."

    # Create temp file for bootstrap script
    TEMP_BOOTSTRAP=$(mktemp /tmp/bootstrap_granite_XXXXXX.sh)
    cat > "$TEMP_BOOTSTRAP" << 'INJECT_EOF'
#!/usr/bin/env bash
BOOTSTRAP=$(cat << 'INNER_EOF'
#!/usr/bin/env bash
set -euo pipefail
echo "===== Bootstrap starting ====="
echo "Date: $(date -u)"

echo "[1/7] Updating system packages..."
sudo yum update -y --setopt=install_weak_deps=False >/dev/null 2>&1
echo "  System updated."

echo "[2/7] Installing Docker..."
sudo yum install -y docker
sudo systemctl enable docker
sudo systemctl start docker
sudo usermod -aG docker ec2-user
echo "  Docker installed and started."

echo "[3/7] Installing NVIDIA Container Toolkit..."
if ! nvidia-smi >/dev/null 2>&1; then
    echo "  ERROR: nvidia-smi not found — NVIDIA drivers may need manual install"
    exit 1
fi
echo "  NVIDIA drivers OK: $(nvidia-smi --query-gpu=name --format=csv,noheader --id=0 2>/dev/null | head -1)"

curl -fsSL https://nvidia.github.io/libnvidia-container/stable/rpm/nvidia-container-toolkit.repo \
    | sudo tee /etc/yum.repos.d/nvidia-container-toolkit.repo
sudo yum install -y nvidia-container-toolkit
sudo nvidia-ctk runtime configure --runtime=docker
sudo systemctl restart docker
echo "  NVIDIA Container Toolkit installed."

echo "  Verifying GPU visibility in Docker..."
if ! docker run --rm --gpus all nvidia/cuda:12.2.0-base-ubi9 nvidia-smi >/dev/null 2>&1; then
    echo "  ERROR: GPU not visible to Docker containers"
    exit 1
fi
echo "  GPU visible in Docker — OK"

echo "[4/7] Setting up model directory..."
sudo mkdir -p /opt/granite-guardian/models
sudo chown ec2-user:ec2-user /opt/granite-guardian

echo "[5/7] Downloading Granite Guardian 4.1 model..."
pip3 install --user huggingface_hub >/dev/null 2>&1 || {
    sudo yum install -y python3-pip 2>/dev/null || true
    pip3 install --user huggingface_hub >/dev/null 2>&1 || pip3 install huggingface_hub >/dev/null 2>&1
}

export HF_HOME="/home/ec2-user/.cache/huggingface"

huggingface-cli download ibm-granite/granite-guardian-4.1-8b \
    --include "granite-guardian-4.1-8b-Q4_K_M.gguf" \
    --local-dir /opt/granite-guardian/models \
    --cache-dir "$HF_HOME" 2>&1 || {
        echo "  ERROR: Model download failed"
        exit 1
    }

if [ ! -f /opt/granite-guardian/models/granite-guardian-4.1-8b-Q4_K_M.gguf ]; then
    echo "  ERROR: Model file not found"
    ls -la /opt/granite-guardian/models/
    exit 1
fi

MODEL_SIZE=$(du -sh /opt/granite-guardian/models/granite-guardian-4.1-8b-Q4_K_M.gguf | cut -f1)
echo "  Model downloaded: ${MODEL_SIZE}"

echo "[6/7] Creating docker-compose.yml..."
mkdir -p /home/ec2-user/granite_guardian
cat > /home/ec2-user/granite_guardian/docker-compose.yml << 'COMPOSE_EOF'
services:
  granite-guardian:
    image: ghcr.io/ggml-org/llama.cpp:full-cuda
    container_name: granite-guardian
    restart: unless-stopped
    runtime: nvidia
    deploy:
      resources:
        reservations:
          devices:
            - driver: nvidia
              count: 1
              capabilities: [gpu]
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
      --ubatch-size 256
      --log-disable
      --embedding
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
COMPOSE_EOF
echo "  docker-compose.yml created."

echo "[7/7] Starting Granite Guardian container..."
cd /home/ec2-user/granite_guardian

if ! docker compose version >/dev/null 2>&1; then
    echo "  Installing Docker Compose plugin..."
    sudo mkdir -p /usr/libexec/docker/cli-plugins
    curl -SL "https://github.com/docker/compose/releases/download/v2.24.0/docker-compose-linux-x86_64" \
        -o /usr/libexec/docker/cli-plugins/docker-compose
    sudo chmod +x /usr/libexec/docker/cli-plugins/docker-compose
fi

docker compose pull 2>&1 || {
    echo "  ERROR: Failed to pull image"
    exit 1
}

docker compose up -d 2>&1

echo "  Waiting for container health check..."
for i in {1..30}; do
    HEALTH=$(curl -sf http://localhost:8080/health 2>/dev/null || echo '""')
    STATUS=$(echo "$HEALTH" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status','error'))" 2>/dev/null || echo "error")
    if [ "$STATUS" = "ok" ]; then
        echo "  Container health: OK"
        break
    fi
    if [ $i -eq 30 ]; then
        echo "  WARNING: Health check not passing yet — checking container status..."
        docker ps --filter "name=granite-guardian" --format "{{.Status}}"
    fi
    sleep 5
done

echo ""
echo "===== Bootstrap complete ====="
echo "Guardian API: http://localhost:8080"
echo "Next: Set GUARDIAN_URL=http://$(hostname -i):8080/v1/chat/completions"
INNER_EOF

# Write the bootstrap script and make it executable, then run it
cat > /tmp/granite_bootstrap.sh <<< "$BOOTSTRAP"
chmod +x /tmp/granite_bootstrap.sh
sudo bash /tmp/granite_bootstrap.sh
INJECT_EOF
    chmod +x "$TEMP_BOOTSTRAP"

    # Upload and execute on the instance
    info "Copying bootstrap script to instance (${INSTANCE_IP})..."
    scp -i ~/.ssh/"$KEY_NAME" -o StrictHostKeyChecking=no \
        "$TEMP_BOOTSTRAP" ec2-user@"${INSTANCE_IP}":/tmp/granite_bootstrap.sh 2>&1 || \
        scp -o StrictHostKeyChecking=no \
            "$TEMP_BOOTSTRAP" ec2-user@"${INSTANCE_IP}":/tmp/granite_bootstrap.sh 2>&1 || \
        fail "Failed to copy bootstrap script via SCP"

    info "Executing bootstrap script on instance..."
    ssh -i ~/.ssh/"$KEY_NAME" -o StrictHostKeyChecking=no \
        ec2-user@"${INSTANCE_IP}" \
        "chmod +x /tmp/granite_bootstrap.sh && sudo bash /tmp/granite_bootstrap.sh" 2>&1 || \
    ssh -o StrictHostKeyChecking=no \
        ec2-user@"${INSTANCE_IP}" \
        "chmod +x /tmp/granite_bootstrap.sh && sudo bash /tmp/granite_bootstrap.sh" 2>&1 || \
        warn "Bootstrap execution may have had issues — check container status manually"

    rm -f "$TEMP_BOOTSTRAP"
    ok "Bootstrap script deployed and executed"
}

# ─── Step 6: Verification ───────────────────────────────────────────────────
verify_deployment() {
    info "Step 6/6: Verifying deployment..."

    local retries=0
    local max_retries=10

    while [ $retries -lt $max_retries ]; do
        local health
        health=$(curl -sf --max-time 5 "http://${INSTANCE_IP}:${LLAMA_PORT}/health" 2>/dev/null || echo "")
        if [ -n "$health" ]; then
            local status
            status=$(echo "$health" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status','error'))" 2>/dev/null || echo "error")
            if [ "$status" = "ok" ]; then
                ok "Guardian API is healthy!"
                return 0
            fi
        fi
        retries=$((retries + 1))
        info "Health check ${retries}/${max_retries}: waiting..."
        sleep 15
    done

    warn "Guardian API not responding yet — this may be expected if model is still loading"
    warn "Run manually: curl http://${INSTANCE_IP}:${LLAMA_PORT}/health"
    warn "Check logs: ssh ec2-user@${INSTANCE_IP} 'docker logs granite-guardian'"
    return 0
}

# ─── Summary ─────────────────────────────────────────────────────────────────
print_summary() {
    echo ""
    echo "============================================================"
    echo "  Deployment Summary"
    echo "============================================================"
    echo ""
    echo "  Infrastructure:"
    echo "    VPC:        ${VPC_ID}"
    echo "    Subnet:     ${SUBNET_ID}"
    echo "    IGW:        ${IGW_ID}"
    echo "    Route Table: ${ROUTE_TABLE_ID}"
    echo "    Proxy SG:   ${PROXY_SG_ID}"
    echo "    Guardian SG: ${GUARDIAN_SG_ID}"
    echo ""
    echo "  EC2 Instance:"
    echo "    Instance ID: ${INSTANCE_ID}"
    echo "    Private IP:  ${INSTANCE_IP}"
    echo "    Public IP:   ${PUBLIC_IP:-N/A}"
    echo "    Type:        ${INSTANCE_TYPE}"
    echo "    Region:      ${REGION}"
    echo "    AZ:          ${AVAILABILITY_ZONE}"
    echo ""
    echo "  Guardian API:"
    echo "    URL:         http://${INSTANCE_IP}:${LLAMA_PORT}${GUARDIAN_URL_PATH}"
    echo "    Health:      http://${INSTANCE_IP}:${LLAMA_PORT}/health"
    echo "    Image:       ${LLAMA_IMAGE}"
    echo ""
    echo "  Next Steps:"
    echo "    1. Set this GUARDIAN_URL in your aw-aiguard gateway:"
    echo "       export GUARDIAN_URL=http://${INSTANCE_IP}:${LLAMA_PORT}${GUARDIAN_URL_PATH}"
    echo ""
    echo "    2. Verify:"
    echo "       curl http://${INSTANCE_IP}:${LLAMA_PORT}/health"
    echo ""
    echo "    3. Check logs:"
    echo "       ssh ec2-user@${INSTANCE_IP} 'docker logs granite-guardian'"
    echo ""
    echo "    4. Smoke test:"
    echo "       curl -X POST http://${INSTANCE_IP}:${LLAMA_PORT}/v1/chat/completions \\"
    echo "         -H 'Content-Type: application/json' \\"
    echo "         -d '{\"model\":\"granite-guardian-4.1-8b\",\"messages\":[{\"role\":\"user\",\"content\":\"test\"}],\"max_tokens\":8}'"
    echo ""
    echo "    5. Clean up (destroy everything):"
    echo "       ./teardown_granite_guardian.sh"
    echo ""
    echo "============================================================"
}

# ─── Main ────────────────────────────────────────────────────────────────────
main() {
    echo ""
    echo "============================================================"
    echo "  aw-aiguard: Granite Guardian 4.1 — AWS Provisioning"
    echo "============================================================"
    echo "  Region:        ${REGION}"
    echo "  Instance:      ${INSTANCE_TYPE}"
    echo "  Model:         ${MODEL_REPO} (${MODEL_QUANT})"
    echo "  Container:     ${LLAMA_IMAGE}"
    echo "============================================================"
    echo ""

    preflight
    create_vpc
    create_security_groups
    find_ami
    launch_instance
    generate_bootstrap_script
    inject_bootstrap
    verify_deployment
    print_summary

    ok "Provisioning complete!"
}

main "$@"
