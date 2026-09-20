#!/usr/bin/env bash
# Destroy the lab AND verify the cleanup.
#
# Running delete-stack and assuming success is not verification. This queries
# the resulting state of every billable resource class the lab could have
# created and reports what is actually left.
set -euo pipefail
REGION="${SDNGUARD_REGION:-ap-south-1}"
STACK="${SDNGUARD_STACK:-sdnguard-p6-lab}"

echo "[destroy] deleting stack $STACK in $REGION"
aws cloudformation delete-stack --region "$REGION" --stack-name "$STACK"
aws cloudformation wait stack-delete-complete --region "$REGION" --stack-name "$STACK" 2>/dev/null || true

echo "[destroy] verifying cleanup"
fail=0
check() {
  local label="$1" count="$2"
  printf '  %-28s %s\n' "$label" "$count"
  [ "$count" = "0" ] || fail=1
}

check "stacks named $STACK" "$(aws cloudformation list-stacks --region "$REGION" \
  --stack-status-filter CREATE_COMPLETE UPDATE_COMPLETE DELETE_FAILED ROLLBACK_COMPLETE \
  --query "length(StackSummaries[?StackName=='$STACK'])" --output text)"
check "instances (not terminated)" "$(aws ec2 describe-instances --region "$REGION" \
  --filters Name=tag:Project,Values=sdnguard \
            Name=instance-state-name,Values=pending,running,stopping,stopped,shutting-down \
  --query 'length(Reservations[].Instances[])' --output text)"
check "EBS volumes" "$(aws ec2 describe-volumes --region "$REGION" \
  --filters Name=tag:Project,Values=sdnguard --query 'length(Volumes)' --output text)"
check "snapshots" "$(aws ec2 describe-snapshots --region "$REGION" --owner-ids self \
  --filters Name=tag:Project,Values=sdnguard --query 'length(Snapshots)' --output text)"
check "elastic IPs" "$(aws ec2 describe-addresses --region "$REGION" \
  --query 'length(Addresses)' --output text)"
check "network interfaces" "$(aws ec2 describe-network-interfaces --region "$REGION" \
  --filters Name=tag:Project,Values=sdnguard --query 'length(NetworkInterfaces)' --output text)"
check "security groups (lab)" "$(aws ec2 describe-security-groups --region "$REGION" \
  --filters Name=tag:Project,Values=sdnguard --query 'length(SecurityGroups)' --output text)"
check "key pairs" "$(aws ec2 describe-key-pairs --region "$REGION" \
  --query 'length(KeyPairs)' --output text)"
check "load balancers" "$(aws elbv2 describe-load-balancers --region "$REGION" \
  --query 'length(LoadBalancers)' --output text 2>/dev/null || echo 0)"
check "NAT gateways" "$(aws ec2 describe-nat-gateways --region "$REGION" \
  --filter Name=state,Values=pending,available --query 'length(NatGateways)' --output text)"
check "IAM roles (lab)" "$(aws iam list-roles \
  --query "length(Roles[?starts_with(RoleName, '$STACK')])" --output text)"

if [ "$fail" = "0" ]; then echo "[destroy] CLEANUP VERIFIED: no billable resources remain"
else echo "[destroy] CLEANUP INCOMPLETE - see nonzero counts above" >&2; exit 1; fi
