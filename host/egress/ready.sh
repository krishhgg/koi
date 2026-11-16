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
for _ in $(seq 1 "${KOI_EGRESS_READY_SECONDS:-30}"); do
	if ss -Htln "sport = :$KOI_EGRESS_PORT" | grep -qF "$KOI_EGRESS_HOST:$KOI_EGRESS_PORT"; then
		exit 0
	fi
	sleep 1
done
echo "koi-egress: koi_egress.py did not start the proxy on $KOI_EGRESS_HOST:$KOI_EGRESS_PORT" >&2
exit 1
