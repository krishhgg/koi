#!/usr/bin/env bash
# Re-runs host/cloud-init.sh on the running box, to apply host changes without
# replacing the instance (which would wipe its build caches). The box must be
# running; start it first with `aws ec2 start-instances` if it is not.
#
#   AWS_PROFILE=<admin> scripts/provision-host.sh
#
# The deployment comes from KOI_INSTANCE_ID, KOI_DOMAIN and KOI_VERIFY_POOL
# where they are set, and from `tofu output` of infra/ (the personal root)
# where they are not; with KOI_INSTANCE_ID set, all three must be set.
# AWS_PROFILE picks the credentials. AWS_REGION picks the
# region, else the region output of infra/ when the deployment comes from
# there, else the profile's region (scripts/host-settings.sh, koi_region).
#
# The script travels inside the SSM command as base64, which is shell-safe, so
# the box needs no AWS CLI and nothing is interpolated into a shell. The values
# it carries, the preview domain, the verification pool and the region, are
# checked before they go in.
set -euo pipefail

repo=$(cd "$(dirname "$0")/.." && pwd)
. "$repo/scripts/host-settings.sh"
region=$(koi_region)
instance=$(koi_setting KOI_INSTANCE_ID box_instance_id)
domain=$(koi_setting KOI_DOMAIN domain)
# The pool verification run networks come from (var.verify_pool).
verify_pool=$(koi_setting KOI_VERIFY_POOL verify_pool)
# Checked here as cloud-init.sh checks them, before they go into shell lines.
koi_check "$region" '^[a-z]{2}(-[a-z]+)+-[0-9]+$' 'The region from AWS_REGION, the region output or the profile' 'an AWS region name'
koi_check "$instance" '^i-[0-9a-f]{8,17}$' 'KOI_INSTANCE_ID or the box_instance_id output' 'an EC2 instance id'
koi_check "$domain" '^[a-z0-9.-]+$' 'KOI_DOMAIN or the domain output' 'a bare hostname'
koi_check_pool "$verify_pool" 'KOI_VERIFY_POOL or the verify_pool output'

# cloud-init.sh reads the domain from KOI_DOMAIN, the pool from
# KOI_VERIFY_POOL and the region from KOI_REGION. Lines in front of the script
# set them, the same way infra/modules/koi/box.tf passes them to the box at
# first boot.
payload=$({
	printf '#!/bin/bash\nKOI_DOMAIN=%s\nKOI_VERIFY_POOL=%s\nKOI_REGION=%s\n' "$domain" "$verify_pool" "$region"
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
