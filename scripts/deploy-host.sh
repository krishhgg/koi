#!/usr/bin/env bash
# Installs the current koid and built-in recipes on the box and restarts koid.
#
#   AWS_PROFILE=<admin> scripts/deploy-host.sh
#
# The deployment comes from KOI_INSTANCE_ID, KOI_BUCKET, KOI_PREVIEWS_PARAM and
# KOI_DOMAIN where they are set, and from `tofu output` of infra/ (the personal
# root) where they are not; a deployment made by another root sets all four
# from that root's module outputs. AWS_PROFILE picks the credentials.
# AWS_REGION picks the region, else the region output of infra/ when the
# deployment comes from there, else the profile's region
# (scripts/host-settings.sh, koi_region).
#
# Builds koid and the SSH gateway, uploads them with a recipes tarball, the
# egress proxy bundle, the verification helper bundle and the SSH bundle to the
# uploads bucket under host/, and runs an SSM command that downloads them through
# presigned URLs, checks their SHA-256, installs them (host/ssh/install.sh sets up
# the koi-connect account and sshd for it), writes /etc/koi/env and restarts koid.
# Starts the box first if it is stopped. Run scripts/provision-host.sh first
# when host/cloud-init.sh has changed.
set -euo pipefail

repo=$(cd "$(dirname "$0")/.." && pwd)
. "$repo/scripts/host-settings.sh"
region=$(koi_region)
instance=$(koi_setting KOI_INSTANCE_ID box_instance_id)
bucket=$(koi_setting KOI_BUCKET uploads_bucket)
param=$(koi_setting KOI_PREVIEWS_PARAM previews_parameter)
domain=$(koi_setting KOI_DOMAIN domain)
# Each value goes into a shell heredoc on the box, so check its shape here,
# not only where the module validated it: a value from the environment never
# went through the module.
koi_check "$region" '^[a-z]{2}(-[a-z]+)+-[0-9]+$' 'The region from AWS_REGION, the region output or the profile' 'an AWS region name'
koi_check "$instance" '^i-[0-9a-f]{8,17}$' 'KOI_INSTANCE_ID or the box_instance_id output' 'an EC2 instance id'
koi_check "$bucket" '^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$' 'KOI_BUCKET or the uploads_bucket output' 'an S3 bucket name'
koi_check "$param" '^/[A-Za-z0-9_./-]+$' 'KOI_PREVIEWS_PARAM or the previews_parameter output' 'an SSM parameter name starting with /'
koi_check "$domain" '^[a-z0-9.-]+$' 'KOI_DOMAIN or the domain output' 'a bare hostname'
version=$(date -u +%Y%m%dT%H%M%SZ)-$(git -C "$repo" rev-parse --short HEAD)

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

echo "building koid and the SSH gateway"
(cd "$repo/packages/daemon" && bun build --compile --target=bun-linux-x64 --outfile "$work/koid" ./src/main.ts >/dev/null)
(cd "$repo" && bun build --compile --target=bun-linux-x64 --outfile "$work/koi-ssh-gateway" ./host/ssh/koi-ssh-gateway.ts >/dev/null)
tar -czf "$work/recipes.tar.gz" -C "$repo/recipes" .
tar -czf "$work/egress.tar.gz" -C "$repo/host/egress" --exclude=test --exclude=__pycache__ .
tar -czf "$work/ssh.tar.gz" -C "$repo/host/ssh" --exclude=test .
tar -czf "$work/verify.tar.gz" -C "$repo/host/verify" --exclude=test --exclude=__pycache__ .
koid_sha=$(sha256sum "$work/koid" | cut -d' ' -f1)
gateway_sha=$(sha256sum "$work/koi-ssh-gateway" | cut -d' ' -f1)
recipes_sha=$(sha256sum "$work/recipes.tar.gz" | cut -d' ' -f1)
egress_sha=$(sha256sum "$work/egress.tar.gz" | cut -d' ' -f1)
ssh_sha=$(sha256sum "$work/ssh.tar.gz" | cut -d' ' -f1)
verify_sha=$(sha256sum "$work/verify.tar.gz" | cut -d' ' -f1)

echo "uploading host/$version"
aws s3 cp --region "$region" --only-show-errors "$work/koid" "s3://$bucket/host/$version/koid"
aws s3 cp --region "$region" --only-show-errors "$work/koi-ssh-gateway" "s3://$bucket/host/$version/koi-ssh-gateway"
aws s3 cp --region "$region" --only-show-errors "$work/recipes.tar.gz" "s3://$bucket/host/$version/recipes.tar.gz"
aws s3 cp --region "$region" --only-show-errors "$work/egress.tar.gz" "s3://$bucket/host/$version/egress.tar.gz"
aws s3 cp --region "$region" --only-show-errors "$work/ssh.tar.gz" "s3://$bucket/host/$version/ssh.tar.gz"
aws s3 cp --region "$region" --only-show-errors "$work/verify.tar.gz" "s3://$bucket/host/$version/verify.tar.gz"
koid_url=$(aws s3 presign --region "$region" --expires-in 900 "s3://$bucket/host/$version/koid")
gateway_url=$(aws s3 presign --region "$region" --expires-in 900 "s3://$bucket/host/$version/koi-ssh-gateway")
recipes_url=$(aws s3 presign --region "$region" --expires-in 900 "s3://$bucket/host/$version/recipes.tar.gz")
egress_url=$(aws s3 presign --region "$region" --expires-in 900 "s3://$bucket/host/$version/egress.tar.gz")
ssh_url=$(aws s3 presign --region "$region" --expires-in 900 "s3://$bucket/host/$version/ssh.tar.gz")
verify_url=$(aws s3 presign --region "$region" --expires-in 900 "s3://$bucket/host/$version/verify.tar.gz")

state=$(aws ec2 describe-instances --region "$region" --instance-ids "$instance" \
	--query 'Reservations[0].Instances[0].State.Name' --output text)
if [ "$state" = "stopped" ]; then
	echo "starting the box"
	aws ec2 start-instances --region "$region" --instance-ids "$instance" >/dev/null
fi
echo "waiting for the box's SSM agent"
for _ in $(seq 1 60); do
	online=$(aws ssm describe-instance-information --region "$region" \
		--filters "Key=InstanceIds,Values=$instance" --query 'InstanceInformationList[0].PingStatus' --output text)
	[ "$online" = "Online" ] && break
	sleep 5
done
[ "$online" = "Online" ] || { echo "the box's SSM agent never came online" >&2; exit 1; }

# Everything interpolated below is either a hex digest, a presigned URL
# (URL-safe characters only, single-quoted) or a value checked above.
script=$(cat <<SCRIPT
set -euo pipefail
cd /tmp
curl -fsSL -o koid.new '$koid_url'
echo '$koid_sha  koid.new' | sha256sum -c -
curl -fsSL -o recipes.tar.gz '$recipes_url'
echo '$recipes_sha  recipes.tar.gz' | sha256sum -c -
install -m 0755 koid.new /usr/local/bin/koid
rm -rf /usr/local/share/koi/recipes.new
mkdir -p /usr/local/share/koi/recipes.new
tar -xzf recipes.tar.gz -C /usr/local/share/koi/recipes.new --no-same-owner
rm -rf /usr/local/share/koi/recipes
mv /usr/local/share/koi/recipes.new /usr/local/share/koi/recipes
rm -f koid.new recipes.tar.gz
# The egress proxy previews reach the internet through (host/egress).
curl -fsSL -o egress.tar.gz '$egress_url'
echo '$egress_sha  egress.tar.gz' | sha256sum -c -
rm -rf /usr/local/share/koi/egress
mkdir -p /usr/local/share/koi/egress
tar -xzf egress.tar.gz -C /usr/local/share/koi/egress --no-same-owner
rm -f egress.tar.gz
bash /usr/local/share/koi/egress/install.sh
# The verification network helper (host/verify), which koid runs through
# sudo to install a run's firewall permits. The sudoers rule comes from
# provisioning (scripts/provision-host.sh); the chains the helper installs
# itself, from its installer.
curl -fsSL -o verify.tar.gz '$verify_url'
echo '$verify_sha  verify.tar.gz' | sha256sum -c -
rm -rf /usr/local/share/koi/verify
mkdir -p /usr/local/share/koi/verify
tar -xzf verify.tar.gz -C /usr/local/share/koi/verify --no-same-owner
rm -f verify.tar.gz
bash /usr/local/share/koi/verify/install.sh
. /etc/koi/egress/env
# The SSH gateway and the account sshd runs it for (host/ssh). On the AWS box
# the security group admits no SSH, so this prepares the box without opening
# it; a plain Linux host is reached through it.
curl -fsSL -o koi-ssh-gateway.new '$gateway_url'
echo '$gateway_sha  koi-ssh-gateway.new' | sha256sum -c -
curl -fsSL -o ssh.tar.gz '$ssh_url'
echo '$ssh_sha  ssh.tar.gz' | sha256sum -c -
rm -rf /usr/local/share/koi/ssh
mkdir -p /usr/local/share/koi/ssh
tar -xzf ssh.tar.gz -C /usr/local/share/koi/ssh --no-same-owner
rm -f ssh.tar.gz
bash /usr/local/share/koi/ssh/install.sh /tmp/koi-ssh-gateway.new
rm -f koi-ssh-gateway.new
cat > /etc/koi/env <<ENV
KOI_DOMAIN=$domain
KOI_UPLOADS_BUCKET=$bucket
KOI_PREVIEWS_PARAM=$param
AWS_REGION=$region
KOI_EGRESS_PROXY=http://\$KOI_EGRESS_HOST:\$KOI_EGRESS_PORT
KOI_EGRESS_CA=/etc/koi/egress/ca.pem
ENV
systemctl daemon-reload
systemctl enable koid.service
systemctl restart koid.service
# koid listens only after it has checked the box, measured its previews' disk
# use and reconciled them, which takes a minute or more with large images.
for i in \$(seq 1 300); do
	curl -fsS http://127.0.0.1:7777/__koi/health && exit 0
	sleep 1
done
echo "koid did not answer; if it says the box is not provisioned, run scripts/provision-host.sh" >&2
journalctl -u koid --no-pager -n 50
exit 1
SCRIPT
)
# SSM may run its commands with /bin/sh (dash on Ubuntu); send the script as
# base64, which is shell-safe, and run it with bash. The idle timer is paused
# for the run and started again however it ends.
payload=$(printf '%s\n' "$script" | base64 -w0)
params=$(python3 -c 'import json,sys; print(json.dumps({"commands": [
    "systemctl stop koi-idle.timer 2>/dev/null || true",
    "touch /var/lib/koi/last-activity 2>/dev/null || true",
    "trap \"touch /var/lib/koi/last-activity 2>/dev/null; systemctl start koi-idle.timer 2>/dev/null || true\" EXIT",
    "echo " + sys.argv[1] + " | base64 -d > /root/koi-deploy.sh",
    "bash /root/koi-deploy.sh",
], "executionTimeout": ["900"]}))' "$payload")
command_id=$(aws ssm send-command --region "$region" --instance-ids "$instance" \
	--document-name AWS-RunShellScript --comment "koi: deploy koid $version" \
	--parameters "$params" --query 'Command.CommandId' --output text)
echo "sent $command_id; waiting"
# `aws ssm wait` gives up after about 100 seconds; poll to the command's own limit.
deadline=$(( $(date +%s) + 960 ))
status=Pending
while :; do
	status=$(aws ssm get-command-invocation --region "$region" --command-id "$command_id" --instance-id "$instance" \
		--query Status --output text 2>/dev/null || echo Pending)
	case "$status" in Pending | InProgress | Delayed) ;; *) break ;; esac
	if [ "$(date +%s)" -ge "$deadline" ]; then echo "gave up waiting for $command_id" >&2; exit 1; fi
	sleep 5
done
aws ssm get-command-invocation --region "$region" --command-id "$command_id" --instance-id "$instance" \
	--query '{status:Status,stdout:StandardOutputContent,stderr:StandardErrorContent}' --output json
[ "$status" = "Success" ]
echo "koid $version is running"
