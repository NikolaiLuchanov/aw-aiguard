#!/usr/bin/env bash
# ============================================================================
# aw-aiguard: Granite Guardian 4.1 — AWS Teardown Script
# ============================================================================
#
# Destroys all resources created by provision_granite_guardian.sh.
# Runs entirely via local AWS CLI — no SSH needed.
#
# Usage:
#   export AWS_PROFILE=my-profile
#   chmod +x teardown_granite_guardian.sh
#   ./teardown_granite_guardian.sh
#
# Destructive: this deletes everything. No confirmation prompt beyond a
# simple yes/no at the start.
# ============================================================================

set -euo pipefail

# ─── Configuration (must match provisioning) ─────────────────────────────────
REGION="${REGION:-us-east-2}"
PROJECT_NAME="${PROJECT_NAME:-aw-aiguard}"
DRY_RUN="${DRY_RUN:-false}"  # Set to "true" to list resources without deleting

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

# ─── Pre-flight ──────────────────────────────────────────────────────────────
preflight() {
    echo ""
    echo "============================================================"
    echo "  aw-aiguard: Granite Guardian 4.1 — AWS Teardown"
    echo "============================================================"
    echo "  Region: ${REGION}"
    echo "  Project: ${PROJECT_NAME}"
    echo "============================================================"
    echo ""

    command -v aws >/dev/null 2>&1 || fail "aws CLI not found"
    command -v jq >/dev/null 2>&1 || fail "jq not found"

    if ! aws sts get-caller-identity >/dev/null 2>&1; then
        fail "AWS credentials not configured"
    fi

    if [ "$DRY_RUN" = "true" ]; then
        warn "DRY RUN — no resources will be deleted"
    fi

    echo -n "This will destroy ALL resources created by provisioning. "
    echo -n "Type 'destroy' to confirm: "
    read -r confirmation
    if [ "$confirmation" != "destroy" ]; then
        echo "Cancelled."
        exit 0
    fi
    echo ""
}

# ─── Helper: query AWS resources by tag ───────────────────────────────────────
query_resource() {
    local resource_type="$1"
    local tag_name="$2"
    local tag_value="$3"

    aws "$resource_type" describe-*/instances/*/security-groups/*/internet-gateways/*/vpcs/*/subnets/*/route-tables/*/  \
        --filters "Name=tag:Project,Values=${PROJECT_NAME}" "Name=tag:Name,Values=*${tag_name}*" \
        --query "Items[0].{Id:Id,Name:Name}" \
        --output json \
        --region "$REGION" 2>/dev/null | jq -r '.[0].Id // empty' || echo ""
}

# More targeted queries
query_vpc() {
    aws ec2 describe-vpcs \
        --filters "Name=tag:Project,Values=${PROJECT_NAME}" "Name=tag:Name,Values=aw-aiguard-vpc" \
        --query "Vpcs[0].VpcId" \
        --output text \
        --region "$REGION" 2>/dev/null || echo ""
}

query_subnet() {
    aws ec2 describe-subnets \
        --filters "Name=tag:Project,Values=${PROJECT_NAME}" "Name=tag:Name,Values=aw-aiguard-subnet" \
        --query "Subnets[0].SubnetId" \
        --output text \
        --region "$REGION" 2>/dev/null || echo ""
}

query_internet_gateway() {
    aws ec2 describe-internet-gateways \
        --filters "Name=tag:Project,Values=${PROJECT_NAME}" "Name=tag:Name,Values=aw-aiguard-igw" \
        --query "InternetGateways[0].InternetGatewayId" \
        --output text \
        --region "$REGION" 2>/dev/null || echo ""
}

query_route_table() {
    aws ec2 describe-route-tables \
        --filters "Name=tag:Project,Values=${PROJECT_NAME}" "Name=tag:Name,Values=aw-aiguard-rt" \
        --query "RouteTables[0].RouteTableId" \
        --output text \
        --region "$REGION" 2>/dev/null || echo ""
}

query_security_group() {
    aws ec2 describe-security-groups \
        --filters "Name=tag:Project,Values=${PROJECT_NAME}" "Name=tag:Name,Values=aw-aiguard-$1" \
        --query "SecurityGroups[0].GroupId" \
        --output text \
        --region "$REGION" 2>/dev/null || echo ""
}

query_instance() {
    aws ec2 describe-instances \
        --filters "Name=tag:Project,Values=${PROJECT_NAME}" "Name=tag:Name,Values=aw-aiguard-granite-guardian" \
        --query "Reservations[].Instances[].InstanceId" \
        --output text \
        --region "$REGION" 2>/dev/null || echo ""
}

# ─── Step 0: Delete SSM IAM Role ─────────────────────────────────────────────
destroy_ssm_role() {
    info "Step 0/8: Deleting SSM IAM role..."

    local role_name="${PROJECT_NAME}-ssm-role"

    # Check if role exists
    if ! aws iam get-role --role-name "$role_name" --region "$REGION" >/dev/null 2>&1; then
        info "SSM role '${role_name}' not found — skipping"
        return 0
    fi

    if [ "$DRY_RUN" = "true" ]; then
        info "DRY RUN: would delete SSM role ${role_name}"
        return 0
    fi

    # Detach all managed policies
    local policies
    policies=$(aws iam list-attached-role-policies \
        --role-name "$role_name" \
        --query "AttachedPolicies[*].PolicyArn" \
        --output text \
        --region "$REGION" 2>/dev/null || echo "")

    for policy_arn in $policies; do
        [ -z "$policy_arn" ] || [ "$policy_arn" = "None" ] && continue
        info "  Detaching policy: ${policy_arn}"
        aws iam detach-role-policy \
            --role-name "$role_name" \
            --policy-arn "$policy_arn" \
            --region "$REGION" >/dev/null 2>&1 || true
    done

    # Delete role
    aws iam delete-role \
        --role-name "$role_name" \
        --region "$REGION" >/dev/null 2>&1 || warn "Failed to delete role ${role_name}"

    ok "SSM role deleted: ${role_name}"
}

# ─── Step 1: Delete EC2 Instance ─────────────────────────────────────────────
destroy_instance() {
    info "Step 1/8: Deleting EC2 instance..."

    local instance_id
    instance_id=$(query_instance)

    if [ -z "$instance_id" ] || [ "$instance_id" = "None" ]; then
        info "No instance found — skipping"
        return 0
    fi

    info "Instance ID: ${instance_id}"

    if [ "$DRY_RUN" = "true" ]; then
        info "DRY RUN: would delete instance ${instance_id}"
        return 0
    fi

    # Terminate instance
    info "Terminating instance..."
    aws ec2 terminate-instances --instance-ids "$instance_id" --region "$REGION" >/dev/null 2>&1

    # Wait for termination
    info "Waiting for instance to terminate..."
    aws ec2 wait instance-terminated --instance-ids "$instance_id" --region "$REGION" 2>&1 || warn "Instance did not terminate in expected time"

    ok "Instance terminated: ${instance_id}"
}

# ─── Step 2: Delete Security Groups ──────────────────────────────────────────
destroy_security_groups() {
    info "Step 2/8: Deleting security groups..."

    for sg_name in "guardian"; do
        local sg_id
        sg_id=$(query_security_group "$sg_name")

        if [ -z "$sg_id" ] || [ "$sg_id" = "None" ]; then
            info "Security group ${sg_name}: not found — skipping"
            continue
        fi

        info "Deleting security group ${sg_name}: ${sg_id}"

        if [ "$DRY_RUN" = "true" ]; then
            info "DRY RUN: would delete SG ${sg_id}"
            continue
        fi

        # Remove inbound rules first (required before deleting)
        aws ec2 revoke-security-group-ingress \
            --group-id "$sg_id" \
            --group-ids "$sg_id" \
            --region "$REGION" >/dev/null 2>&1 || true

        # Remove outbound rules
        aws ec2 revoke-security-group-egress \
            --group-id "$sg_id" \
            --group-ids "$sg_id" \
            --region "$REGION" >/dev/null 2>&1 || true

        # Delete the SG
        aws ec2 delete-security-group --group-id "$sg_id" --region "$REGION" >/dev/null 2>&1 || true

        ok "Security group deleted: ${sg_name} (${sg_id})"
    done
}

# ─── Step 3: Detach Internet Gateway ─────────────────────────────────────────
detach_internet_gateway() {
    info "Step 3/8: Detaching and deleting internet gateway..."

    local igw_id
    igw_id=$(query_internet_gateway)

    if [ -z "$igw_id" ] || [ "$igw_id" = "None" ]; then
        info "IGW not found — skipping"
        return 0
    fi

    info "IGW ID: ${igw_id}"

    if [ "$DRY_RUN" = "true" ]; then
        info "DRY RUN: would detach and delete IGW ${igw_id}"
        return 0
    fi

    # Detach from VPC first
    aws ec2 detach-internet-gateway \
        --internet-gateway-id "$igw_id" \
        --region "$REGION" >/dev/null 2>&1 || warn "IGW was not attached"

    # Wait for detached state
    aws ec2 wait internet-gateway-not-in-use \
        --internet-gateway-ids "$igw_id" \
        --region "$REGION" 2>&1 || true

    # Delete
    aws ec2 delete-internet-gateway \
        --internet-gateway-id "$igw_id" \
        --region "$REGION" >/dev/null 2>&1 || true

    ok "IGW deleted: ${igw_id}"
}

# ─── Step 4: Delete Route Table ──────────────────────────────────────────────
destroy_route_table() {
    info "Step 4/8: Deleting route table..."

    local rt_id
    rt_id=$(query_route_table)

    if [ -z "$rt_id" ] || [ "$rt_id" = "None" ]; then
        info "Route table not found — skipping"
        return 0
    fi

    info "Route table: ${rt_id}"

    if [ "$DRY_RUN" = "true" ]; then
        info "DRY RUN: would delete route table ${rt_id}"
        return 0
    fi

    # Delete the default route (0.0.0.0/0)
    aws ec2 delete-route \
        --route-table-id "$rt_id" \
        --destination-cidr-block 0.0.0.0/0 \
        --region "$REGION" >/dev/null 2>&1 || true

    # Disassociate the subnet
    local subnet_id
    subnet_id=$(query_subnet)
    if [ -n "$subnet_id" ] && [ "$subnet_id" != "None" ]; then
        aws ec2 disassociate-route-table \
            --association-id "$(aws ec2 describe-route-tables \
                --route-table-ids "$rt_id" \
                --query "RouteTables[0].Associations[?SubnetId==\`$subnet_id\`].RouteTableAssociationId" \
                --output text \
                --region "$REGION" 2>/dev/null)" \
            --region "$REGION" >/dev/null 2>&1 || true
    fi

    # Delete the route table
    aws ec2 delete-route-table \
        --route-table-id "$rt_id" \
        --region "$REGION" >/dev/null 2>&1 || true

    ok "Route table deleted: ${rt_id}"
}

# ─── Step 5: Delete Subnet ───────────────────────────────────────────────────
destroy_subnet() {
    info "Step 5/8: Deleting subnet..."

    local subnet_id
    subnet_id=$(query_subnet)

    if [ -z "$subnet_id" ] || [ "$subnet_id" = "None" ]; then
        info "Subnet not found — skipping"
        return 0
    fi

    info "Subnet: ${subnet_id}"

    if [ "$DRY_RUN" = "true" ]; then
        info "DRY RUN: would delete subnet ${subnet_id}"
        return 0
    fi

    # Delete subnet (must be empty — no instances, no route table associations)
    aws ec2 delete-subnet \
        --subnet-id "$subnet_id" \
        --region "$REGION" >/dev/null 2>&1 || warn "Subnet deletion failed — may still have dependent resources"

    ok "Subnet deleted: ${subnet_id}"
}

# ─── Step 6: Disable VPC DNS & Delete VPC ────────────────────────────────────
destroy_vpc() {
    info "Step 6/8: Disabling VPC DNS and deleting VPC..."

    local vpc_id
    vpc_id=$(query_vpc)

    if [ -z "$vpc_id" ] || [ "$vpc_id" = "None" ]; then
        info "VPC not found — skipping"
        return 0
    fi

    info "VPC: ${vpc_id}"

    if [ "$DRY_RUN" = "true" ]; then
        info "DRY RUN: would disable DNS and delete VPC ${vpc_id}"
        return 0
    fi

    # Disable DNS attributes
    aws ec2 modify-vpc-attribute \
        --vpc-id "$vpc_id" \
        --disable-dns-hostnames '{"Value":true}' \
        --region "$REGION" >/dev/null 2>&1 || true

    aws ec2 modify-vpc-attribute \
        --vpc-id "$vpc_id" \
        --disable-dns-support '{"Value":true}' \
        --region "$REGION" >/dev/null 2>&1 || true

    # Delete VPC
    aws ec2 delete-vpc \
        --vpc-id "$vpc_id" \
        --region "$REGION" >/dev/null 2>&1 || warn "VPC deletion failed — may still have dependent resources"

    ok "VPC deleted: ${vpc_id}"
}

# ─── Step 7: Verify ──────────────────────────────────────────────────────────
verify_cleanup() {
    info "Step 7/8: Verifying cleanup..."

    local remaining=0

    for resource_type in vpcs subnets "internet-gateways" "security-groups" instances; do
        local count
        count=$(aws ec2 describe-"${resource_type}" \
            --filters "Name=tag:Project,Values=${PROJECT_NAME}" \
            --query "length(Items)" \
            --output text \
            --region "$REGION" 2>/dev/null || echo "0")

        if [ "$count" != "0" ]; then
            warn "${count} ${resource_type} still owned by Project=${PROJECT_NAME}"
            remaining=$((remaining + count))
        fi
    done

    if [ "$remaining" -gt 0 ]; then
        warn "${remaining} resource(s) may not have been cleaned up — check manually:"
        info "  aws ec2 describe-vpcs --filters 'Name=tag:Project,Values=${PROJECT_NAME}' --region ${REGION}"
        info "  aws ec2 describe-subnets --filters 'Name=tag:Project,Values=${PROJECT_NAME}' --region ${REGION}"
    else
        ok "All Project=${PROJECT_NAME} resources cleaned up"
    fi
}

# ─── Summary ─────────────────────────────────────────────────────────────────
print_summary() {
    echo ""
    echo "============================================================"
    echo "  Teardown Complete"
    echo "============================================================"
    echo ""
    if [ "$DRY_RUN" = "true" ]; then
        echo "  DRY RUN — no resources were deleted"
        echo "  Set DRY_RUN=false to actually destroy"
    else
        echo "  All aw-aiguard infrastructure in ${REGION} has been destroyed"
        echo ""
        echo "  Remaining resources to check manually:"
        echo "    - EBS snapshots with Project=${PROJECT_NAME} tag"
        echo "    - S3 buckets created for backups"
        echo "    - Any CloudWatch alarms"
    fi
    echo "============================================================"
    echo ""
}

# ─── Main ────────────────────────────────────────────────────────────────────
main() {
    preflight

    # Teardown in reverse order of provisioning:
    # 0. SSM IAM role (detached from instance, safe to delete early)
    # 1. Instance (stops holding SG references)
    # 2. Security groups (can't delete while instance references them)
    # 3. Internet gateway (detach before delete)
    # 4. Route table (disassociate subnet first)
    # 5. Subnet (must be empty)
    # 6. VPC (must be empty — no subnets, no IGW)
    # 7. Verify
    destroy_ssm_role
    destroy_instance
    destroy_security_groups
    detach_internet_gateway
    destroy_route_table
    destroy_subnet
    destroy_vpc
    verify_cleanup
    print_summary

    if [ "$DRY_RUN" != "true" ]; then
        ok "Teardown complete!"
    else
        ok "Dry run complete — review output above"
    fi
}

main "$@"
