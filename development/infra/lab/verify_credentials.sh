#!/usr/bin/env bash
# Prove the scoped credential works for the lab AND cannot do anything else.
#
# A least-privilege claim that only exercises the allowed operations is
# worthless; the value is in the denials. Identity values are never printed.
#
# KF-20: a denial probe is only meaningful if the request actually reaches IAM
# authorization. Several EC2 actions validate resource identifiers first, so a
# probe using a fake id fails with InvalidXxx and never tests the policy at
# all. Such a probe is reported INCONCLUSIVE, never as a pass. Region-scoped
# probes therefore use `--dry-run` with a positive control in the lab region.
set -uo pipefail
PROFILE="${SDNGUARD_PROFILE:-sdnguard}"
REGION="${SDNGUARD_REGION:-ap-south-1}"

pass=0; fail=0; inconclusive=0

allow() {
  local label="$1"; shift
  if "$@" >/dev/null 2>&1; then printf '  ALLOW  %-48s ok\n' "$label"; pass=$((pass+1))
  else printf '  ALLOW  %-48s UNEXPECTEDLY DENIED\n' "$label"; fail=$((fail+1)); fi
}

deny() {
  local label="$1"; shift
  local out; out="$("$@" 2>&1)"
  if [[ "$out" == *AccessDenied* || "$out" == *UnauthorizedOperation* || "$out" == *"not authorized"* ]]; then
    printf '  DENY   %-48s correctly denied\n' "$label"; pass=$((pass+1))
  elif [[ "$out" == *Invalid*ID* || "$out" == *Malformed* || "$out" == *NotFound* ]]; then
    printf '  DENY   %-48s INCONCLUSIVE (rejected before authz)\n' "$label"
    inconclusive=$((inconclusive+1))
  else
    printf '  DENY   %-48s NOT DENIED - PRIVILEGE TOO BROAD\n' "$label"; fail=$((fail+1))
  fi
}

reaches_authz() {   # positive control: proves the probe is evaluated by IAM
  local label="$1"; shift
  local out; out="$("$@" 2>&1)"
  if [[ "$out" == *DryRunOperation* ]]; then
    printf '  CONTROL %-47s reaches authz and is permitted here\n' "$label"; pass=$((pass+1))
  else
    printf '  CONTROL %-47s probe does not reach authz - denial test is void\n' "$label"
    fail=$((fail+1))
  fi
}

echo "credential session type:"
aws --profile "$PROFILE" sts get-caller-identity --query Arn --output text 2>/dev/null \
  | sed -E 's#arn:aws:sts::[0-9]+:assumed-role/([^/]+)/.*#  assumed-role/\1 (temporary session)#'
echo
echo "operations the lab actually needs:"
allow "sts:GetCallerIdentity"            aws --profile "$PROFILE" sts get-caller-identity
allow "ec2:DescribeInstances"            aws --profile "$PROFILE" ec2 describe-instances --region "$REGION"
allow "ec2:DescribeVpcs"                 aws --profile "$PROFILE" ec2 describe-vpcs --region "$REGION"
allow "cloudformation:ListStacks"        aws --profile "$PROFILE" cloudformation list-stacks --region "$REGION"
allow "ssm:DescribeInstanceInformation"  aws --profile "$PROFILE" ssm describe-instance-information --region "$REGION"
allow "ssm:GetParameter (AMI lookup)"    aws --profile "$PROFILE" ssm get-parameter --region "$REGION" \
        --name /aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id
allow "pricing:GetProducts"              aws --profile "$PROFILE" pricing get-products --region "$REGION" \
        --service-code AmazonEC2 --max-items 1
echo
echo "positive controls -- these probes demonstrably reach IAM authorization:"
reaches_authz "ec2:CreateSecurityGroup in $REGION" aws --profile "$PROFILE" ec2 create-security-group \
        --region "$REGION" --group-name sdnguard-authz-probe --description probe \
        --vpc-id vpc-00000000000000000 --dry-run
reaches_authz "ec2:DescribeKeyPairs in $REGION"    aws --profile "$PROFILE" ec2 describe-key-pairs \
        --region "$REGION" --dry-run
echo
echo "operations it must NOT be able to perform:"
deny "iam:CreateUser (self-escalation)"        aws --profile "$PROFILE" iam create-user --user-name sdnguard-probe-should-fail
deny "iam:AttachUserPolicy (admin grab)"       aws --profile "$PROFILE" iam attach-user-policy \
        --user-name sdnguard-operator --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
deny "iam:CreateAccessKey (key minting)"       aws --profile "$PROFILE" iam create-access-key --user-name sdnguard-operator
deny "iam:PutRolePolicy (widen own role)"      aws --profile "$PROFILE" iam put-role-policy \
        --role-name sdnguard-lab-role --policy-name evil --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}'
deny "s3:ListBuckets (out of scope service)"   aws --profile "$PROFILE" s3api list-buckets
deny "organizations:DescribeOrganization"      aws --profile "$PROFILE" organizations describe-organization
deny "ec2:DescribeInstances outside region"    aws --profile "$PROFILE" ec2 describe-instances --region us-east-1
deny "ec2:DescribeKeyPairs outside region"     aws --profile "$PROFILE" ec2 describe-key-pairs --region us-east-1 --dry-run
deny "ec2:CreateSecurityGroup outside region"  aws --profile "$PROFILE" ec2 create-security-group \
        --region us-east-1 --group-name sdnguard-authz-probe --description probe \
        --vpc-id vpc-00000000000000000 --dry-run
deny "cloudformation:DeleteStack, other stack" aws --profile "$PROFILE" cloudformation delete-stack \
        --region "$REGION" --stack-name some-unrelated-stack
echo
echo "result: $pass expected, $fail unexpected, $inconclusive inconclusive"
[ "$fail" = "0" ] || exit 1
