# Where scripts/deploy-host.sh and scripts/provision-host.sh find the
# deployment they act on. Sourced, not run; expects $repo to be the checkout.
#
# A deployment made by infra/ (the personal root) needs nothing set: each value
# comes from `tofu output` there. One made by another root, in another
# account, sets KOI_INSTANCE_ID, KOI_BUCKET, KOI_PREVIEWS_PARAM, KOI_DOMAIN
# and KOI_VERIFY_POOL from that root's module outputs, and the scripts never
# run tofu. KOI_INSTANCE_ID set is what marks another root's deployment, as
# in koi_region.

# koi_setting VAR OUTPUT prints the environment variable VAR when it is set,
# else the tofu output OUTPUT of infra/. Set and empty is a mistake, not an
# absence, as for the CLI's own variables. With KOI_INSTANCE_ID set, VAR must
# be set too: on a machine where infra/ is initialised with the personal
# backend, reading the output there would mix the personal deployment's
# bucket, parameter or domain into another root's box.
koi_setting() {
	if [ -n "${!1+set}" ]; then
		if [ -z "${!1}" ]; then
			if [ -n "${KOI_INSTANCE_ID+set}" ] && [ "$1" != KOI_INSTANCE_ID ]; then
				echo "$1 is set but empty; set it from the other root's $2 output" >&2
			else
				echo "$1 is set but empty; unset it to read the $2 output of infra/" >&2
			fi
			return 1
		fi
		printf '%s\n' "${!1}"
		return 0
	fi
	if [ -n "${KOI_INSTANCE_ID+set}" ]; then
		echo "KOI_INSTANCE_ID is set, so the deployment comes from another root, but $1 is not; set it from that root's $2 output" >&2
		return 1
	fi
	if ! tofu -chdir="$repo/infra" output -raw "$2"; then
		echo "$1 is not set, and infra/ has no $2 output to read; set $1, or init infra/ with the personal backend" >&2
		return 1
	fi
}

# koi_region prints AWS_REGION, else AWS_DEFAULT_REGION. Without either, a
# deployment read from infra/ (KOI_INSTANCE_ID unset) is in the region output
# there, or in us-east-1 for state applied before that output existed; one
# made by another root is in the AWS profile's region, else us-east-1.
koi_region() {
	local region=${AWS_REGION:-${AWS_DEFAULT_REGION:-}}
	if [ -z "$region" ]; then
		if [ -z "${KOI_INSTANCE_ID+set}" ]; then
			region=$(tofu -chdir="$repo/infra" output -raw region 2>/dev/null || true)
		else
			region=$(aws configure get region 2>/dev/null || true)
		fi
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

# koi_check_pool VALUE SOURCE stops the script unless VALUE is an IPv4 network
# between a /16 and a /28, written as its network address, as koid and the
# firewall helper take it: 10.213.0.1/20 names a host, and the box would turn
# verification off.
koi_check_pool() {
	koi_check "$1" '^(0|[1-9][0-9]{0,2})(\.(0|[1-9][0-9]{0,2})){3}/(1[6-9]|2[0-8])$' "$2" 'an IPv4 network between /16 and /28'
	local octets octet address=0 bits=${1#*/}
	IFS=. read -r -a octets <<<"${1%/*}"
	for octet in "${octets[@]}"; do
		if ((10#$octet > 255)); then
			echo "$2 is '$1', which is not an IPv4 network: $octet is over 255" >&2
			exit 1
		fi
		address=$((address * 256 + 10#$octet))
	done
	if ((address & ((1 << (32 - bits)) - 1))); then
		echo "$2 is '$1', which names a host; give the network's own address" >&2
		exit 1
	fi
}
