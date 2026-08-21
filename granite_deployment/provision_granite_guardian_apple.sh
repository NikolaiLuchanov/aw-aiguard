#!/usr/bin/env bash
# ============================================================================
# aw-aiguard: Granite Guardian 4.1 — AWS Provisioning Script
# ============================================================================
#
# Hybrid provisioning: local AWS CLI launches infrastructure, SSM bootstrap
# installs Docker, NVIDIA toolkit, downloads model, and starts container.
#
# Usage:
#   export AWS_PROFILE=my-profile
#   chmod +x provision_granite_guardian.sh
#   ./provision_granite_guardian.sh
#
# Prerequisites:
#   - aws CLI v2 installed and configured (aws configure)
#   - jq installed (for parsing AWS output)
#   - curl installed (for public IP detection)
#   - macOS or Linux with bash 4+
#
# What it provisions:
#   1. VPC + subnet (us-east-2 default, configurable)
#   2. Security group: guardian (8080, scoped to your public IP)
#   3. EC2 g6e.xlarge on-demand with NVIDIA L4 GPU
#   4. Bootstrap via SSM: Docker, NVIDIA toolkit, model download, container
#
# Output: Guardian private IP for GUARDIAN_URL in aw-aiguard gateway config
# ============================================================================

set -euo pipefail

# ─── Configuration ───────────────────────────────────────────────────────────
# Override these before running:

REGION="${REGION:-us-east-2}"
INSTANCE_TYPE="${INSTANCE_TYPE:-g6e.xlarge}"
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
    command -v jq >/dev/null 2>&1  || fail "jq not found — install with: brew install jq"
    command -v curl >/dev/null 2>&1 || fail "curl not found"

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
    info "Step 1/8: Creating VPC and subnet..."

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

# ─── Step 2: Detect local public IP ─────────────────────────────────────────
detect_public_ip() {
    info "Step 2/8: Detecting local public IP for access rules..."

    MY_PUBLIC_IP=$(curl -s --max-time 10 ifconfig.me 2>/dev/null || \
                   curl -s --max-time 10 icanhazip.com 2>/dev/null || \
                   curl -s --max-time 10 checkip.amazonaws.com 2>/dev/null)

    if [ -z "$MY_PUBLIC_IP" ]; then
        fail "Cannot detect public IP. Check internet connection."
    fi

    info "Detected public IP: ${MY_PUBLIC_IP}/32"
}

# ─── Step 3: Create Security Groups ─────────────────────────────────────────
create_security_groups() {
    info "Step 3/8: Creating security groups..."

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

    # Allow port 8080 (Guardian API) from local IP only
    aws ec2 authorize-security-group-ingress \
        --group-id "$GUARDIAN_SG_ID" \
        --protocol tcp \
        --port "$LLAMA_PORT" \
        --cidr "${MY_PUBLIC_IP}/32" \
        --region "$REGION" 2>&1 || warn "Port 8080 rule may already exist"

    # No SSH (port 22) — use AWS SSM Session Manager instead (safer, no key needed)

    # Allow outbound (HuggingFace download, CloudWatch)
    aws ec2 authorize-security-group-egress \
        --group-id "$GUARDIAN_SG_ID" \
        --protocol -1 \
        --cidr 0.0.0.0/0 \
        --region "$REGION" >/dev/null 2>&1 || warn "Egress rule may already exist"

    ok "Guardian SG: ${GUARDIAN_SG_ID} (inbound: ${LLAMA_PORT} from ${MY_PUBLIC_IP}/32)"
}

# ─── Step 4: Find Amazon Linux 2023 AMI ──────────────────────────────────────
find_ami() {
    info "Step 4/8: Finding Amazon Linux 2023 AMI..."

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

# ─── Step 5: Create SSM IAM Role ─────────────────────────────────────────────
create_ssm_role() {
    info "Step 5/8: Creating SSM IAM instance role..."

    # Check if role already exists
    local role_output
    role_output=$(aws iam get-role \
        --role-name "${PROJECT_NAME}-ssm-role" \
        --region "$REGION" \
        --query "Role.Arn" \
        --output text 2>/dev/null || echo "")

    if [ -n "$role_output" ] && [ "$role_output" != "None" ]; then
        IAM_ROLE_ARN="$role_output"
        info "SSM role already exists: ${IAM_ROLE_ARN}"
        return 0
    fi

    # Create trust policy for SSM
    cat > /tmp/${PROJECT_NAME}-ssm-trust.json << 'TRUST_EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
TRUST_EOF

    local role_create_output
    role_create_output=$(aws iam create-role \
        --role-name "${PROJECT_NAME}-ssm-role" \
        --assume-role-policy-document file:///tmp/${PROJECT_NAME}-ssm-trust.json \
        --description "SSM Session Manager role for ${PROJECT_NAME} instances" \
        --region "$REGION" \
        --query "Role.Arn" \
        --output text 2>&1) || fail "Failed to create SSM role: $(echo "$role_create_output")"

    IAM_ROLE_ARN="$role_create_output"

    # Attach SSM managed policy
    aws iam attach-role-policy \
        --role-name "${PROJECT_NAME}-ssm-role" \
        --policy-arn arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore \
        --region "$REGION" >/dev/null 2>&1 || warn "SSM policy attach failed (may already be attached)"

    # Attach CloudWatch agent policy for GPU metrics
    aws iam attach-role-policy \
        --role-name "${PROJECT_NAME}-ssm-role" \
        --policy-arn arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy \
        --region "$REGION" >/dev/null 2>&1 || true

    info "SSM IAM role created: ${IAM_ROLE_ARN}"
}

# ─── Step 6: Launch EC2 Instance ─────────────────────────────────────────────
launch_instance() {
    info "Step 6/8: Launching EC2 instance (${INSTANCE_TYPE})..."

    local launch_output
    launch_output=$(aws ec2 run-instances \
        --image-id "$AMI_ID" \
        --instance-type "$INSTANCE_TYPE" \
        --count 1 \
        --subnet-id "$SUBNET_ID" \
        --security-group-ids "$GUARDIAN_SG_ID" \
        --block-device-mappings '[{"DeviceName":"/dev/xvda","Ebs":{"VolumeSize":100,"VolumeType":"gp3"}}]' \
        --iam-instance-profile "Arn=${IAM_ROLE_ARN}" \
        --no-tag-specifications \
        --query "Instances[0].{InstanceId:InstanceId,PrivateIp:PrivateIpAddress}" \
        --output json \
        --region "$REGION" 2>&1) || fail "Failed to launch instance: $(echo "$launch_output")"

    INSTANCE_ID=$(echo "$launch_output" | jq -r '.InstanceId')
    INSTANCE_IP=$(echo "$launch_output" | jq -r '.PrivateIp')

    if [ -z "$INSTANCE_ID" ] || [ "$INSTANCE_ID" = "null" ]; then
        fail "Instance launch failed: $(echo "$launch_output")"
    fi

    # Tag the instance
    aws ec2 create-tags \
        --resources "$INSTANCE_ID" \
        --tags "Key=Name,Value=${PROJECT_NAME}-granite-guardian" "${COMMON_TAGS}" \
        --region "$REGION" >/dev/null

    info "Instance ID: ${INSTANCE_ID}"
    info "Private IP: ${INSTANCE_IP}"
    ok "State: ${INSTANCE_ID} launched in ${AVAILABILITY_ZONE} (no public IP)"

    # Wait for instance to be running
    info "Waiting for instance to be in 'running' state (this may take 1-3 minutes)..."
    aws ec2 wait instance-running --instance-ids "$INSTANCE_ID" --region "$REGION" || warn "Instance did not reach 'running' state in expected time"

    # Wait for status check
    info "Waiting for status check to pass..."
    aws ec2 wait instance-status-ok --instance-ids "$INSTANCE_ID" --region "$REGION" || warn "Status check did not pass in expected time"

    ok "Instance ${INSTANCE_ID} is running"
}

# ─── Step 7: Bootstrap via SSM ──────────────────────────────────────────────
inject_bootstrap() {
    info "Step 7/8: Bootstrapping instance via SSM..."

    # Wait for SSM agent to be ready (Amazon Linux 2023 includes it, but it takes a moment)
    info "Waiting for SSM agent to be available..."
    local ssm_retries=0
    while [ $ssm_retries -lt 15 ]; do
        if aws ssm describe-instance-information \
            --filters "Key=InstanceIds,Values=${INSTANCE_ID}" \
            --query "InstanceInformationList[?InstanceId==\`${INSTANCE_ID}\`].AgentStatus" \
            --output text --region "$REGION" 2>/dev/null | grep -q "Online"; then
            info "SSM agent is Online"
            break
        fi
        ssm_retries=$((ssm_retries + 1))
        info "  SSM agent not ready yet (${ssm_retries}/15)..."
        sleep 10
    done

    if [ $ssm_retries -eq 15 ]; then
        warn "SSM agent did not report Online — attempting bootstrap anyway"
    fi

    # Write bootstrap script to a local temp file
    local TEMP_BOOTSTRAP
    TEMP_BOOTSTRAP=$(mktemp /tmp/granite_bootstrap_XXXXXX.sh)
    cat > "$TEMP_BOOTSTRAP" << 'BOOTSCRIPT'
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
BOOTSCRIPT

    # Base64 encode the bootstrap script and send via SSM
    local ENCODED_SCRIPT
    ENCODED_SCRIPT=$(base64 -w 0 < "$TEMP_BOOTSTRAP")

    info "Sending bootstrap script to instance via SSM..."
    aws ssm send-command \
        --instance-ids "$INSTANCE_ID" \
        --document-name "AWS-RunShellScript" \
        --parameters 'commands=["echo ' "$ENCODED_SCRIPT" ' | base64 -d | bash"]' \
        --timeout-seconds 600 \
        --region "$REGION" \
        --query "Command.CommandId" \
        --output text 2>&1) || fail "Failed to send bootstrap command via SSM"

    COMMAND_ID="$ssm_command"
    info "SSM Command ID: ${COMMAND_ID}"
    info "Waiting for bootstrap execution to complete (this may take 5-10 minutes for model download)..."

    # Wait for command execution to complete
    local cmd_retries=0
    local max_cmd_retries=120
    while [ $cmd_retries -lt $max_cmd_retries ]; do
        local cmd_status
        cmd_status=$(aws ssm get-command-invocation \
            --command-id "$COMMAND_ID" \
            --instance-id "$INSTANCE_ID" \
            --query "Status" \
            --output text \
            --region "$REGION" 2>/dev/null || echo "Unknown")

        if [ "$cmd_status" = "Success" ]; then
            ok "Bootstrap executed successfully"
            rm -f "$TEMP_BOOTSTRAP"
            return 0
        elif [ "$cmd_status" = "Failed" ] || [ "$cmd_status" = "Cancelled" ] || [ "$cmd_status" = "TimedOut" ]; then
            warn "Bootstrap command failed with status: $cmd_status"
            warn "Check output: aws ssm get-command-invocation --command-id $COMMAND_ID --instance-id $INSTANCE_ID --query 'StandardOutputContent' --output text"
            # Show last 50 lines of output
            aws ssm get-command-invocation \
                --command-id "$COMMAND_ID" \
                --instance-id "$INSTANCE_ID" \
                --query 'StandardOutputContent' \
                --output text \
                --region "$REGION" 2>/dev/null | tail -50
            rm -f "$TEMP_BOOTSTRAP"
            return 1
        fi

        cmd_retries=$((cmd_retries + 1))
        if [ $((cmd_retries % 10)) -eq 0 ]; then
            info "  Still executing (${cmd_retries}/${max_cmd_retries}) — Status: $cmd_status"
        fi
        sleep 5
    done

    warn "Bootstrap command did not complete in expected time"
    warn "Check status: aws ssm get-command-invocation --command-id $COMMAND_ID --instance-id $INSTANCE_ID"
    rm -f "$TEMP_BOOTSTRAP"
    return 0
}

# ─── Step 8: Verification ───────────────────────────────────────────────────
verify_deployment() {
    info "Step 8/8: Verifying deployment..."

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
    warn "Check logs: aws ssm start-session --target ${INSTANCE_ID} 'docker logs granite-guardian'"
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
    echo "    Guardian SG: ${GUARDIAN_SG_ID}"
    echo ""
    echo "  EC2 Instance:"
    echo "    Instance ID: ${INSTANCE_ID}"
    echo "    Private IP:  ${INSTANCE_IP}"
    echo "    Public IP:   none (SSM only)"
    echo "    Type:        ${INSTANCE_TYPE}"
    echo "    Region:      ${REGION}"
    echo "    AZ:          ${AVAILABILITY_ZONE}"
    echo ""
    echo "  Guardian API:"
    echo "    URL:         http://${INSTANCE_IP}:${LLAMA_PORT}${GUARDIAN_URL_PATH}"
    echo "    Health:      http://${INSTANCE_IP}:${LLAMA_PORT}/health"
    echo "    Image:       ${LLAMA_IMAGE}"
    echo ""
    echo "  Remote Access:"
    echo "    SSM:         aws ssm start-session --target ${INSTANCE_ID}"
    echo "    Logs:        aws ssm start-session --target ${INSTANCE_ID} 'docker logs granite-guardian'"
    echo ""
    echo "  Next Steps:"
    echo "    1. Set this GUARDIAN_URL in your aw-aiguard gateway:"
    echo "       export GUARDIAN_URL=http://${INSTANCE_IP}:${LLAMA_PORT}${GUARDIAN_URL_PATH}"
    echo ""
    echo "    2. Verify:"
    echo "       curl http://${INSTANCE_IP}:${LLAMA_PORT}/health"
    echo ""
    echo "    3. Check logs:"
    echo "       aws ssm start-session --target ${INSTANCE_ID} 'docker logs granite-guardian'"
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
    detect_public_ip
    create_security_groups
    find_ami
    create_ssm_role
    launch_instance
    inject_bootstrap
    verify_deployment
    print_summary

    ok "Provisioning complete!"
}

main "$@"
