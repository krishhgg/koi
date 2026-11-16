# Review guidance for koi

koi takes a source tree from a pull request, builds it on one EC2 box, runs it in a
container, and publishes it at `https://<label>.<domain>`, under the operator's own
domain, for a reviewer to click through. The pull request may come from a stranger.
Review with that in mind.

## What matters most

1. The preview container runs untrusted code. It must never reach the internet except
   through koi's egress proxy, never see a real provider key, never reach the instance
   metadata endpoint, and never touch the Docker socket or host filesystem.
2. Caller-supplied strings (preview names, branches, hostnames, PR numbers) must be
   validated with the schemas in `packages/shared` and passed to processes as argv
   arrays. No shell strings built from them.
3. Reviewer keys live in the browser and in the key proxy's memory only. If a change
   makes a key touch a disk, a log line, a container, or a response body, that is the
   finding.
4. The box must not get stuck. Builds and container starts need timeouts, failures must
   leave the preview record in `failed` with a message, and `koi up` must be re-runnable.
5. Infrastructure changes in `infra/` are reviewed for scope: least-privilege IAM,
   inbound only on 443 from CloudFront, no new paid resources without a comment
   explaining why.
6. The daemon keeps three things in agreement: preview records, Docker containers and
   Caddy's routes. Look for crash windows and races that leave them disagreeing, and
   for any container removed while a route may still point at its address.
7. The egress proxy (`host/egress`, Python, mitmproxy) is the previews' only way out
   and the only place real provider keys live. It intercepts TLS in every tunnel, so it
   can hold the TLS server name and each request's Host or :authority to the host the
   CONNECT named, and it swaps koi tokens for keys only on the LLM provider hosts it
   lists. A tunnel it cannot check is refused, never passed through.

## Conventions

- TypeScript, strict, Bun runtime. Tabs, single quotes, semicolons (Biome enforces).
- Workspaces: `shared` (schemas and pure functions), `cli` (the `koi` binary), `daemon`
  (`koid` on the box), `lambda` (wake page). Shared types belong in `shared`, not
  duplicated.
- `host/egress` is Python for mitmproxy 12. It lands with the keys pull request; from
  then on its tests run with
  `uv run --with mitmproxy==12.2.3 --with pytest pytest host/egress/test`.
- `recipes/<name>/` holds a built-in recipe: `recipe.json`, and a `Dockerfile` when it
  brings its own. Recipe Dockerfiles run untrusted source only inside BuildKit.
- Tests use `bun test` next to the code in `test/`. A bug fix includes the test that
  fails without it.
- Conventional commits: `feat(daemon):`, `fix(cli):`, `chore(infra):`.

## Do not flag

- Formatting that Biome already enforces.
- Missing JSDoc on internal functions.
- The wake page's inline CSS and script; it is intentionally dependency-free.
