# The recorder image: the browser koi records a verification run with
# (docs/verify.md, "Recorder and evidence"). It starts from Microsoft's
# Playwright image, pinned by digest, which carries Chromium and Node, and
# adds the server in src/, compiled here. The server runs as uid 10001 on a
# read-only root with /tmp as its only writable space; the daemon fixes the
# rest of the container's flags (packages/daemon/src/docker.ts, recorderArgs)
# and starts it with seccomp.json, so Chromium's own sandbox can make the
# user namespace it needs. Never --no-sandbox. dist/probe.js starts Chromium
# the same way and exits; koid runs it before it calls verification available.
#
# Build it on the box and tell koid which image it is, by id:
#   docker build -t koi-recorder:1 host/recorder
#   docker image inspect --format '{{.Id}}' koi-recorder:1
# and set KOI_RECORDER_IMAGE to that sha256 in /etc/koi/verify/env.
#
# Two lockfiles pin the same versions: bun.lock at the repository root
# installs this package for type checking and tests, and package-lock.json
# here is what npm ci reads in this build, where there is no bun.
ARG BASE=mcr.microsoft.com/playwright:v1.64.1-noble@sha256:2f05f8a734509a7b3f26a912639488ee08f58a7b292d14d62271bcff9038768f

FROM ${BASE} AS build
WORKDIR /build
COPY package.json package-lock.json tsconfig.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY src ./src
RUN ./node_modules/.bin/tsc -p tsconfig.json \
	&& npm prune --omit=dev --ignore-scripts --no-audit --no-fund

FROM ${BASE}
# Root-owned and read-only to the server: it cannot change its own code.
COPY --from=build --chown=0:0 /build/dist /app/dist
COPY --from=build --chown=0:0 /build/node_modules /app/node_modules
COPY --chown=0:0 package.json /app/package.json
RUN chmod -R a-w,o+rX /app
ENV NODE_ENV=production \
	PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
	HOME=/tmp/koi-recorder/home \
	TMPDIR=/tmp
USER 10001:10001
WORKDIR /app
EXPOSE 4317 4318
ENTRYPOINT ["node", "/app/dist/server.js"]
