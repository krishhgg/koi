#!/usr/bin/env bash
# Re-runs host/cloud-init.sh on the running box, to apply host changes without
# replacing the instance (which would wipe its build caches). The box must be
# running; start it first with `aws ec2 start-instances` if it is not.
#
#   AWS_PROFILE=<admin> scripts/provision-host.sh
#
# The script travels inside the SSM command as base64, which is shell-safe, so
# the box needs no AWS CLI and nothing is interpolated into a shell. The one
# value it carries, the preview domain, is a tofu output and is checked to be
# a bare hostname before it goes in.
set -euo pipefail

repo=$(cd "$(dirname "$0")/.." && pwd)
region=${AWS_REGION:-us-east-1}
out() { tofu -chdir="$repo/infra" output -raw "$1"; }
instance=$(out box_instance_id)
domain=$(out domain)
if ! [[ $domain =~ ^[a-z0-9.-]+$ ]]; then
	echo "the domain output '$domain' is not a bare hostname; check var.domain in infra/koi.auto.tfvars" >&2
	exit 1
fi
# The pool verification run networks come from (var.verify_pool), checked
# here as cloud-init.sh checks it, before it goes into a shell line.
verify_pool=$(out verify_pool)
if ! [[ $verify_pool =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}/(1[6-9]|2[0-8])$ ]]; then
	echo "the verify_pool output '$verify_pool' is not an IPv4 network between /16 and /28; check var.verify_pool" >&2
	exit 1
fi

# cloud-init.sh reads the domain from KOI_DOMAIN and the pool from
# KOI_VERIFY_POOL. Lines in front of the script set them, the same way
# infra/box.tf passes them to the box at first boot.
payload=$({
	printf '#!/bin/bash\nKOI_DOMAIN=%s\nKOI_VERIFY_POOL=%s\n' "$domain" "$verify_pool"
	cat "$repo/host/cloud-init.sh"
} | base64 -w0)
# SSM may run its commands with /bin/sh (dash on Ubuntu), so the script is
# written to a file and run with bash explicitly. The idle timer is paused for
# the run, so the box cannot power off half way through an update, and is
# started again however the run ends.
params=$(python3 -c 'import json,sys; print(json.dumps({"commands": [
    "systemctl stop koi-idle.timer 2>/dev/null || true",
    "touch /var/lib/koi/last-activity 2>/dev/null || true",
    "trap \"touch /var/lib/koi/last-activity 2>/dev/null; systemctl start koi-idle.timer 2>/dev/null || true\" EXIT",
    "echo " + sys.argv[1] + " | base64 -d > /root/koi-provision.sh",
    "bash /root/koi-provision.sh",
], "executionTimeout": ["1800"]}))' "$payload")

command_id=$(aws ssm send-command --region "$region" \
	--instance-ids "$instance" \
	--document-name AWS-RunShellScript \
	--comment "koi: re-run host provisioning" \
	--parameters "$params" \
	--query 'Command.CommandId' --output text)
echo "sent $command_id; waiting"

# `aws ssm wait` gives up after about 100 seconds; provisioning can take far
# longer. Poll until the command finishes, up to its own 30-minute limit.
deadline=$(( $(date +%s) + 1900 ))
status=Pending
while :; do
	status=$(aws ssm get-command-invocation --region "$region" --command-id "$command_id" --instance-id "$instance" \
		--query Status --output text 2>/dev/null || echo Pending)
	case "$status" in Pending | InProgress | Delayed) ;; *) break ;; esac
	if [ "$(date +%s)" -ge "$deadline" ]; then echo "gave up waiting for $command_id" >&2; exit 1; fi
	sleep 10
done
aws ssm get-command-invocation --region "$region" --command-id "$command_id" --instance-id "$instance" \
	--query '{status:Status,stdout:StandardOutputContent,stderr:StandardErrorContent}' --output json
[ "$status" = "Success" ]
