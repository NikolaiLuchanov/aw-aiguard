#!/usr/bin/env bash
# deploy-central-service-ec2.sh
# Deploy the Central Service to an EC2 instance via AWS SSM (no SSH required).
#
# Prerequisites:
#   - AWS CLI configured with credentials having SSM RunCommand and EC2 permissions
#   - EC2 instance has SSM Agent installed and running
#   - EC2 instance has an IAM role with SSM permissions (AmazonSSMManagedInstanceCore)
#   - Docker installed on the EC2 instance (or uncomment the docker install block)
#
# Usage:
#   export CENTRAL_EC2_INSTANCE_ID=i-xxxxxxxxxxxxxxxxx
#   export PG_PASSWORD=your_secure_password
#   export MINIO_ROOT_PASSWORD=your_secure_password
#   ./scripts/deploy-central-service-ec2.sh

set -euo pipefail

# ─── Configuration ───────────────────────────────────────────────────────
CENTRAL_SERVICE_DIR="$HOME/aw-aiguard/central-service"
GUARDRAIL_CONFIG_DIR="$HOME/aw-aiguard/guardrail-config"

# ─── EC2 Instance ID ────────────────────────────────────────────────────
if [[ -z "${CENTRAL_EC2_INSTANCE_ID:-}" ]]; then
    echo "ERROR: CENTRAL_EC2_INSTANCE_ID is not set."
    echo "Usage: export CENTRAL_EC2_INSTANCE_ID=i-xxxxxxxxxxxxxxxxx"
    echo "       ./scripts/deploy-central-service-ec2.sh"
    exit 1
fi

echo "==> Deploying Central Service to EC2 instance: $CENTRAL_EC2_INSTANCE_ID"

# ─── Helper: run a command on the EC2 instance via SSM ───────────────────
run_on_ec2() {
    local command="$1"
    echo "  → EC2> $command"
    aws ssm send-command \
        --instance-id "$CENTRAL_EC2_INSTANCE_ID" \
        --document-name "AWS-RunShellScript" \
        --parameters "commands=[$command]" \
        --query 'Command.CommandId' \
        --output text
}

# ─── Step 1: Bootstrap EC2 (Docker + git) ───────────────────────────────
# Uncomment the docker install block if Docker is not pre-installed.
echo "==> Step 1: Bootstrapping EC2 instance..."

# Optional: Install Docker
# aws ssm send-command \
#     --instance-id "$CENTRAL_EC2_INSTANCE_ID" \
#     --document-name "AWS-RunShellScript" \
#     --parameters "commands=[curl -fsSL https://get.docker.com | sh]"
echo "  → Docker bootstrap (skip if Docker is pre-installed)"

# ─── Step 2: Clone the repository ───────────────────────────────────────
echo "==> Step 2: Cloning aw-aiguard repository..."

CLONE_CMD='git clone https://github.com/your-org/aw-aiguard.git ~/aw-aiguard && cd ~/aw-aiguard && git checkout master'
CLONE_ID=$(aws ssm send-command \
    --instance-id "$CENTRAL_EC2_INSTANCE_ID" \
    --document-name "AWS-RunShellScript" \
    --parameters "commands=[$CLONE_CMD]" \
    --query 'Command.CommandId' \
    --output text)

echo "  → Clone command ID: $CLONE_ID"
aws ssm wait command-invoked --command-id "$CLONE_ID" --instance-id "$CENTRAL_EC2_INSTANCE_ID"
echo "  → Repository cloned."

# ─── Step 3: Create .env file ───────────────────────────────────────────
echo "==> Step 3: Creating .env file on EC2..."

# Generate the .env content
PG_PASS="${PG_PASSWORD:-$(openssl rand -hex 24)}"
MINIO_PASS="${MINIO_ROOT_PASSWORD:-$(openssl rand -hex 24)}"

ENV_FILE_CONTENT="PG_PASSWORD=${PG_PASS}
MINIO_ROOT_USER=aiguard
MINIO_ROOT_PASSWORD=${MINIO_PASS}
TELEGRAM_BOT_TOKEN=${TELEGRAM_BOT_TOKEN:-}
TELEGRAM_CHAT_ID=${TELEGRAM_CHAT_ID:-}
SLACK_WEBHOOK_URL=${SLACK_WEBHOOK_URL:-}
SMTP_HOST=${SMTP_HOST:-}
SMTP_PORT=587
SMTP_USER=${SMTP_USER:-}
SMTP_PASSWORD=${SMTP_PASSWORD:-}
SMTP_FROM=${SMTP_FROM:-}
SMTP_TO=${SMTP_TO:-}
AUDIT_TTL_DAYS=30"

# Write the .env file on EC2
echo "$ENV_FILE_CONTENT" | aws ssm send-command \
    --instance-id "$CENTRAL_EC2_INSTANCE_ID" \
    --document-name "AWS-RunShellScript" \
    --parameters "commands=[cat > $CENTRAL_SERVICE_DIR/.env]" \
    --query 'Command.CommandId' \
    --output text
echo "  → .env file created."

# ─── Step 4: Copy guardrail-config ──────────────────────────────────────
echo "==> Step 4: Copying guardrail-config directory..."

# rsync the guardrail-config directory to EC2
rsync -avz --delete \
    --exclude '.git' \
    -e "ssh" \  # Alternative: use aws s3 cp if SSH is not available
    "$PWD/guardrail-config/" \
    "ec2-user@${CENTRAL_EC2_PRIVATE_IP:-$CENTRAL_EC2_INSTANCE_ID}:$GUARDRAIL_CONFIG_DIR/"

# If using SSM instead of SSH, use s3 as a middleman:
# aws s3 cp guardrail-config/ s3://your-bucket/aw-aiguard-guardrail-config/ --recursive
# aws ssm send-command \
#     --instance-id "$CENTRAL_EC2_INSTANCE_ID" \
#     --document-name "AWS-RunShellScript" \
#     --parameters "commands=[aws s3 cp s3://your-bucket/aw-aiguard-guardrail-config/ $GUARDRAIL_CONFIG_DIR/ --recursive]"

echo "  → guardrail-config copied."

# ─── Step 5: Deploy Central Service ─────────────────────────────────────
echo "==> Step 5: Starting Central Service (docker compose prod)..."

DEPLOY_CMD="cd $CENTRAL_SERVICE_DIR && docker compose -f docker-compose.prod.yml up -d --build"
DEPLOY_ID=$(aws ssm send-command \
    --instance-id "$CENTRAL_EC2_INSTANCE_ID" \
    --document-name "AWS-RunShellScript" \
    --parameters "commands=[$DEPLOY_CMD]" \
    --query 'Command.CommandId' \
    --output text)

echo "  → Deploy command ID: $DEPLOY_ID"
aws ssm wait command-invoked --command-id "$DEPLOY_ID" --instance-id "$CENTRAL_EC2_INSTANCE_ID"

# ─── Step 6: Verify ─────────────────────────────────────────────────────
echo "==> Step 6: Verifying deployment..."

VERIFY_CMD="cd $CENTRAL_SERVICE_DIR && docker compose -f docker-compose.prod.yml ps"
VERIFY_ID=$(aws ssm send-command \
    --instance-id "$CENTRAL_EC2_INSTANCE_ID" \
    --document-name "AWS-RunShellScript" \
    --parameters "commands=[$VERIFY_CMD]" \
    --query 'Command.CommandId' \
    --output text)

aws ssm wait command-invoked --command-id "$VERIFY_ID" --instance-id "$CENTRAL_EC2_INSTANCE_ID"
aws ssm get-command-invocation \
    --command-id "$VERIFY_ID" \
    --instance-id "$CENTRAL_EC2_INSTANCE_ID" \
    --query 'StandardOutputContent' \
    --output text

echo ""
echo "============================================================"
echo "  Deployment complete!"
echo "  EC2 Instance: $CENTRAL_EC2_INSTANCE_ID"
echo "  Central Service: http://<ec2-public-ip>:8000"
echo "  Admin Dashboard: http://<ec2-public-ip>:8000/ui/"
echo "  Audit API:       http://<ec2-public-ip>:8000/health"
echo "============================================================"
echo ""
echo "Next steps:"
echo "  1. Configure security group to allow inbound TCP 8000 from Gateway IP"
echo "  2. Set CENTRAL_SERVICE_URL=http://<ec2-central-ip>:8000 in gateway/.env"
echo "  3. Verify with: curl http://<ec2-public-ip>:8000/health"
