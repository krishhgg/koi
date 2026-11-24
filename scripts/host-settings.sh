# Where scripts/deploy-host.sh and scripts/provision-host.sh find the
# deployment they act on. Sourced, not run; expects $repo to be the checkout.
#
# A deployment made by infra/ (the personal root) needs nothing set: each value
# comes from `tofu output` there. One made by another root, in another
# account, sets KOI_INSTANCE_ID, KOI_BUCKET, KOI_PREVIEWS_PARAM, KOI_DOMAIN
# and KOI_VERIFY_POOL from that root's module outputs, and the scripts never
# run tofu.

# koi_setting VAR OUTPUT prints the environment variable VAR when it is set,
# else the tofu output OUTPUT of infra/. Set and empty is a mistake, not an
# absence, as for the CLI's own variables.
koi_setting() {
	if [ -n "${!1+set}" ]; then
		if [ -z "${!1}" ]; then
			echo "$1 is set but empty; unset it to read the $2 output of infra/" >&2
			return 1
		fi
		printf '%s\n' "${!1}"
		return 0
	fi
	if ! tofu -chdir="$repo/infra" output -raw "$2"; then
		echo "$1 is not set, and infra/ has no $2 output to read; set $1, or init infra/ with the personal backend" >&2
		return 1
	fi
}

# koi_region prints AWS_REGION, else AWS_DEFAULT_REGION, else the region of
# the AWS profile (AWS_PROFILE), else us-east-1.
koi_region() {
	local region=${AWS_REGION:-${AWS_DEFAULT_REGION:-}}
	if [ -z "$region" ]; then
		region=$(aws configure get region 2>/dev/null || true)
	fi
	printf '%s\n' "${region:-us-east-1}"
}

# koi_check VALUE REGEX SOURCE SHAPE stops the script unless VALUE matches
# REGEX. SOURCE and SHAPE name where the value came from and what it should
# be, for the message.
koi_check() {
	if ! [[ $1 =~ $2 ]]; then
		echo "$3 is '$1', which is not $4" >&2
		exit 1
	fi
}
