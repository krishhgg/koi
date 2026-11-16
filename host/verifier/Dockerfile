# The default verifier image: where a project's runner commands execute
# during a verification run (docs/verify.md, "Writing a runner"). Python 3
# and the Playwright client for Python, and no browser: the browser is the
# recorder's, which a runner reaches over the run network with the ws URL
# koid gives it. The supervisor that runs a point's steps is not in the
# image; koid puts host/verifier/supervisor.py in every verifier's read-only
# /koi volume and makes it the entrypoint, so an image's own ENTRYPOINT never
# runs. What this image provides is python3 on PATH, the
# Playwright client, and the koi_runner module. The container runs as uid
# 10002 on a read-only root with /tmp and /work as its only writable space;
# the daemon fixes the rest of the flags (packages/daemon/src/docker.ts,
# verifierArgs).
#
# Build it on the box and tell koid which image it is, by id:
#   docker build -t koi-verifier:1 host/verifier
#   docker image inspect --format '{{.Id}}' koi-verifier:1
# and set KOI_VERIFIER_IMAGE to that sha256 in /etc/koi/verify/env. A
# manifest names it as `koi-verifier` (runner.image).
#
# Everything is pinned: the base image by digest, each wheel by version and
# sha256 (pip refuses anything else with --require-hashes). The Playwright
# client is the version the recorder's server runs, since a client and a
# server of different versions may not agree on the protocol.
ARG BASE=python:3.13.13-slim-bookworm@sha256:355bfa66770995d7e9a0da4b3473b44d0cb451f6b56f5615ad9c39e3c4eca03f

FROM ${BASE}
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir --no-deps --require-hashes --root-user-action=ignore \
	-r /tmp/requirements.txt \
	&& rm /tmp/requirements.txt \
	&& rm -rf /root/.cache
# The protocol clients: the Python one on the Python path, the JavaScript one
# beside it for images that have Node. Root-owned and read-only.
COPY --chown=0:0 clients/koi_runner.py /usr/local/lib/python3.13/site-packages/koi_runner.py
COPY --chown=0:0 clients/koi-runner.mjs /opt/koi/clients/koi-runner.mjs
RUN chmod 0444 /usr/local/lib/python3.13/site-packages/koi_runner.py /opt/koi/clients/koi-runner.mjs \
	&& python3 -c 'import koi_runner, playwright.sync_api' \
	&& groupadd --gid 10002 koi \
	&& useradd --uid 10002 --gid 10002 --no-create-home --home-dir /tmp/home --shell /usr/sbin/nologin koi
# The variables a step sees are set by koid on the container, not here; the
# supervisor passes its allowlist on and nothing else. These are the image's
# own runtime constants, which koid's image check accepts.
ENV PYTHONDONTWRITEBYTECODE=1 \
	PYTHONUNBUFFERED=1 \
	PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1
USER 10002:10002
WORKDIR /workspace
# Never reached under koid, which sets the entrypoint; here so a stray
# `docker run` of the image does nothing.
ENTRYPOINT ["python3", "-c", "print('koi-verifier: koid runs this image with its supervisor as the entrypoint')"]
