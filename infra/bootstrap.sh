#!/usr/bin/env bash
# Creates or updates the koi stack. Run with an admin session, for example:
#   aws login --profile <admin>
#   AWS_PROFILE=<admin> infra/bootstrap.sh
#
# 1. Creates the state bucket (OpenTofu cannot manage its own backend).
# 2. Builds the wake function, writes a plan, shows it, and applies exactly
#    that plan.
# 3. Creates an access key for koi-cli and writes it to ~/.aws/credentials as
#    profile koi-cli. The key never enters state.
#
# Re-runnable: every step checks before it creates. Set KOI_PLAN_ONLY=1 to stop
# after printing the plan.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/.." && pwd)
region=us-east-1
account=$(aws sts get-caller-identity --query Account --output text)
bucket="koi-tfstate-${account}"

if ! aws s3api head-bucket --bucket "$bucket" 2>/dev/null; then
	echo "creating state bucket $bucket"
	aws s3api create-bucket --bucket "$bucket" --region "$region"
	aws s3api put-bucket-versioning --bucket "$bucket" --versioning-configuration Status=Enabled
	aws s3api put-bucket-encryption --bucket "$bucket" \
		--server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}'
	aws s3api put-public-access-block --bucket "$bucket" \
		--public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
fi

"$repo/scripts/build-lambda.sh"

# The state bucket's name carries the account id, so backend.hcl is written
# here and gitignored (backend.hcl.example shows its shape). Once it exists,
# `tofu -chdir=infra init -backend-config=backend.hcl` works by hand too.
cat >"$here/backend.hcl" <<HCL
bucket       = "$bucket"
key          = "koi.tfstate"
region       = "$region"
use_lockfile = true
HCL

plan="$here/koi.tfplan"
trap 'rm -f "$plan"' EXIT
tofu -chdir="$here" init -input=false -backend-config=backend.hcl
tofu -chdir="$here" plan -input=false -out="$plan"
if [ "${KOI_PLAN_ONLY:-0}" = "1" ]; then
	echo "KOI_PLAN_ONLY=1: stopping before apply"
	exit 0
fi
tofu -chdir="$here" apply -input=false "$plan"

user=koi-cli
if [ -z "$(aws iam list-access-keys --user-name "$user" --query 'AccessKeyMetadata[].AccessKeyId' --output text)" ]; then
	echo "creating access key for $user"
	key=$(aws iam create-access-key --user-name "$user" --query 'AccessKey.[AccessKeyId,SecretAccessKey]' --output text)
	aws configure set aws_access_key_id "$(cut -f1 <<<"$key")" --profile "$user"
	aws configure set aws_secret_access_key "$(cut -f2 <<<"$key")" --profile "$user"
	aws configure set region "$region" --profile "$user"
else
	echo "$user already has an access key; leaving it alone"
fi

echo "done"
