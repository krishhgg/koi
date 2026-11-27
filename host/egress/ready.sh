#!/bin/bash
# koi-egress.service runs this after starting mitmdump (ExecStartPost), so the
# unit counts as started only once the proxy listens. mitmdump starts with its
# server off, and only koi_egress.py turns it on, once its policy is set up;
# so listening means the policy is active. If that has not happened within
# KOI_EGRESS_READY_SECONDS (30), this fails, systemd stops mitmdump, and
# Restart= tries again. Meanwhile nothing listens: previews find the proxy
# down, never open.
set -euo pipefail
: "${KOI_EGRESS_HOST:?}" "${KOI_EGRESS_PORT:?}"
# The transparent and DNS listeners start with the proxy's (one server
# switch turns them all on), so the unit waits for all three.
listening() {
	ss -Htln "sport = :$KOI_EGRESS_PORT" | grep -qF "$KOI_EGRESS_HOST:$KOI_EGRESS_PORT" &&
		{ [ -z "${KOI_EGRESS_TRANSPARENT_PORT:-}" ] ||
			ss -Htln "sport = :$KOI_EGRESS_TRANSPARENT_PORT" | grep -qF "$KOI_EGRESS_HOST:$KOI_EGRESS_TRANSPARENT_PORT"; } &&
		{ [ -z "${KOI_EGRESS_TRANSPARENT_PORT:-}" ] || ss -Hlun "sport = :53" | grep -qF "$KOI_EGRESS_HOST:53"; }
}
for _ in $(seq 1 "${KOI_EGRESS_READY_SECONDS:-30}"); do
	if listening; then
		exit 0
	fi
	sleep 1
done
echo "koi-egress: koi_egress.py did not start the proxy on $KOI_EGRESS_HOST" >&2
exit 1
