#!/usr/bin/env bash
# Create the sdnguard P6 lab. One command, idempotent, pinned AMI.
set -euo pipefail
REGION="${SDNGUARD_REGION:-ap-south-1}"
# Least-privilege by default: temporary STS credentials from the lab role.
# Override only with a deliberate SDNGUARD_PROFILE.
export AWS_PROFILE="${SDNGUARD_PROFILE:-sdnguard}"
STACK="${SDNGUARD_STACK:-sdnguard-p6-lab}"
AMI="${SDNGUARD_AMI:-ami-0c0fd09cfe77b59dc}"      # Ubuntu 24.04 LTS x86_64, pinned
TYPE="${SDNGUARD_INSTANCE_TYPE:-t3a.large}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

VPC="$(aws ec2 describe-vpcs --region "$REGION" --filters Name=isDefault,Values=true \
        --query 'Vpcs[0].VpcId' --output text)"
SUBNET="$(aws ec2 describe-subnets --region "$REGION" \
        --filters Name=vpc-id,Values="$VPC" Name=default-for-az,Values=true \
        --query 'Subnets[0].SubnetId' --output text)"

echo "[create] region=$REGION stack=$STACK ami=$AMI type=$TYPE"
aws cloudformation deploy --region "$REGION" --stack-name "$STACK" \
  --template-file "$HERE/../aws/lab-stack.yaml" \
  --capabilities CAPABILITY_IAM \
  --parameter-overrides AmiId="$AMI" VpcId="$VPC" SubnetId="$SUBNET" InstanceType="$TYPE" \
  --tags Project=sdnguard Lab=p6

IID="$(aws cloudformation describe-stacks --region "$REGION" --stack-name "$STACK" \
      --query 'Stacks[0].Outputs[?OutputKey==`InstanceId`].OutputValue' --output text)"
echo "[create] instance: $IID"

echo "[create] waiting for SSM registration and bootstrap"
for _ in $(seq 1 60); do
  N="$(aws ssm describe-instance-information --region "$REGION" \
       --filters "Key=InstanceIds,Values=$IID" \
       --query 'length(InstanceInformationList)' --output text 2>/dev/null || echo 0)"
  [ "$N" = "1" ] && break
  sleep 10
done
for _ in $(seq 1 60); do
  R="$(SDNGUARD_INSTANCE="$IID" "$HERE/remote.sh" \
       'test -f /var/lib/sdnguard-bootstrap-complete && echo COMPLETE || echo RUNNING' \
       2>/dev/null | head -1 || echo RUNNING)"
  [ "$R" = "COMPLETE" ] && { echo "[create] bootstrap complete"; exit 0; }
  sleep 15
done
echo "[create] bootstrap did not complete in time" >&2
exit 1
