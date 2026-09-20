#!/usr/bin/env bash
# Run a command on the lab host via SSM Run Command and print its output.
#
# There is no SSH key and no inbound port anywhere in this lab; SSM is the
# only access path, and every invocation is recorded in CloudTrail.
#
#   development/infra/lab/remote.sh 'ovs-vsctl show'
#   development/infra/lab/remote.sh -f script.sh      # send a whole script
set -euo pipefail

REGION="${SDNGUARD_REGION:-ap-south-1}"
STACK="${SDNGUARD_STACK:-sdnguard-p6-lab}"
TIMEOUT="${SDNGUARD_TIMEOUT:-300}"

instance_id() {
  if [[ -n "${SDNGUARD_INSTANCE:-}" ]]; then echo "$SDNGUARD_INSTANCE"; return; fi
  aws cloudformation describe-stacks --region "$REGION" --stack-name "$STACK" \
    --query 'Stacks[0].Outputs[?OutputKey==`InstanceId`].OutputValue' --output text
}

if [[ "${1:-}" == "-f" ]]; then
  SCRIPT="$(cat "$2")"
else
  SCRIPT="$*"
fi

IID="$(instance_id)"
CMD_ID="$(aws ssm send-command --region "$REGION" --instance-ids "$IID" \
  --document-name AWS-RunShellScript \
  --comment "sdnguard p6 lab" \
  --timeout-seconds "$TIMEOUT" \
  --parameters "$(python3 -c 'import json,sys; print(json.dumps({"commands":[sys.stdin.read()]}))' <<<"$SCRIPT")" \
  --query 'Command.CommandId' --output text)"

for _ in $(seq 1 "$((TIMEOUT / 3))"); do
  STATUS="$(aws ssm get-command-invocation --region "$REGION" \
    --command-id "$CMD_ID" --instance-id "$IID" \
    --query 'Status' --output text 2>/dev/null || echo Pending)"
  case "$STATUS" in Success|Failed|Cancelled|TimedOut) break;; esac
  sleep 3
done

aws ssm get-command-invocation --region "$REGION" --command-id "$CMD_ID" \
  --instance-id "$IID" --query 'StandardOutputContent' --output text
ERR="$(aws ssm get-command-invocation --region "$REGION" --command-id "$CMD_ID" \
  --instance-id "$IID" --query 'StandardErrorContent' --output text)"
[[ -n "$ERR" && "$ERR" != "None" ]] && { echo "--- stderr ---"; echo "$ERR"; } || true
echo "--- ssm status: $STATUS ---"
[[ "$STATUS" == "Success" ]] || exit 1
