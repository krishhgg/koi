import {
	labelFromHost,
	MAX_BUILD_TIMEOUT_MINUTES,
	MAX_HEALTH_TIMEOUT_SECONDS,
	RESERVED_LABELS,
} from '@koi/shared';
import { TLS_ASK_PATH } from './caddy.ts';
import type { Deployer, PreviewView } from './deployer.ts';
import { page } from './pages.ts';

export const DAEMON_VERSION = '0.1.0';

// How long a waiting page keeps checking. A first deployment may take the
// longest build and health check any recipe allows; koid fails it after
// that, and the page then shows the failure. A build queued behind others
// can take longer, and the page then offers a refresh. Starting a stopped
// preview takes at most the longest health check.
export const BUILD_WAIT_MINUTES = MAX_BUILD_TIMEOUT_MINUTES + MAX_HEALTH_TIMEOUT_SECONDS / 60;
export const START_WAIT_MINUTES = MAX_HEALTH_TIMEOUT_SECONDS / 60;

export interface HttpOptions {
	port: number;
	domain: string;
	hostname?: string;
	deployer: Pick<Deployer, 'view' | 'ensureRunning'>;
	onVisit: (label: string) => void;
	log: (message: string) => void;
	// Whether Caddy gets certificates on demand and asks koid first (acme-http).
	tlsAsk?: boolean;
	// koi's own pages, by reserved label (keys.<domain> -> the keys page).
	pages?: Record<string, (request: Request) => Promise<Response>>;
}

// The localhost server Caddy sends everything it cannot route to a running
// preview: health checks, unknown hosts, and previews whose container is down.
// Never reachable from the internet except through Caddy.
export function createHttpServer(options: HttpOptions) {
	return Bun.serve({
		port: options.port,
		hostname: options.hostname ?? '127.0.0.1',
		fetch: (request) => handle(request, options),
	});
}

export async function handle(request: Request, options: HttpOptions): Promise<Response> {
	const url = new URL(request.url);
	if (url.pathname === TLS_ASK_PATH && options.tlsAsk === true) return tlsAsk(url, options);
	const host = labelFromHost(request.headers.get('host'), options.domain);
	// koi's own subdomains are never previews: health reports the box, and
	// everything else goes to their page.
	const reserved = host !== null && (RESERVED_LABELS as readonly string[]).includes(host);
	const label = reserved ? null : host;
	if (label !== null) options.onVisit(label);

	if (url.pathname === '/__koi/health') {
		if (label === null) return Response.json({ ok: true, version: DAEMON_VERSION });
		const view = await options.deployer.view(label);
		wakeIfStopped(label, view, options);
		const ok = view.kind === 'running';
		return Response.json(
			{ ok, preview: view.kind },
			{
				status: ok ? 200 : view.kind === 'unknown' ? 404 : 503,
				headers: { 'cache-control': 'no-store' },
			},
		);
	}

	if (reserved && host !== null) {
		const ownPage = options.pages?.[host];
		if (ownPage !== undefined) return ownPage(request);
	}

	if (label === null) {
		return page({
			status: 404,
			title: 'Not a preview address',
			message: `Preview addresses look like name.${options.domain}.`,
		});
	}
	const view = await options.deployer.view(label);
	wakeIfStopped(label, view, options);
	return pageFor(view);
}

// Caddy's question before it gets a certificate on demand (acme-http in
// caddy.ts): may it get one for the name in ?domain=. Yes for koi's own
// pages and for a preview koid has a record of, no for anything else, so
// that a visitor cannot make the host ask the ACME server for names of
// their choosing and run into its rate limits. Only Caddy asks: koid
// answers only in that mode, and Caddy's site sends nobody there.
async function tlsAsk(url: URL, options: HttpOptions): Promise<Response> {
	const label = labelFromHost(url.searchParams.get('domain'), options.domain);
	const own = label !== null && options.pages?.[label] !== undefined;
	const known = own || (label !== null && (await options.deployer.view(label)).kind !== 'unknown');
	return new Response(null, {
		status: known ? 200 : 404,
		headers: { 'cache-control': 'no-store' },
	});
}

// Starts a stopped preview in the background. ensureRunning expires an
// overdue one instead of starting it.
function wakeIfStopped(label: string, view: PreviewView, options: HttpOptions): void {
	if (view.kind !== 'stopped' && view.kind !== 'overdue') return;
	options.deployer
		.ensureRunning(label)
		.catch((err: unknown) =>
			options.log(`starting ${label}: ${err instanceof Error ? err.message : String(err)}`),
		);
}

function pageFor(view: PreviewView): Response {
	switch (view.kind) {
		case 'unknown':
			return page({
				status: 404,
				title: 'No preview here',
				message: 'Nothing is deployed at this address. Ask the author to run koi up.',
				refresh: true,
			});
		case 'expired':
		case 'overdue':
			return page({
				status: 410,
				title: 'This preview has expired',
				message:
					'Nobody had visited it for a while, so it was removed. Ask the author to run koi up again.',
				refresh: true,
			});
		case 'halted':
			return page({
				status: 507,
				title: 'This preview was stopped',
				message:
					'It was stopped for using too much disk, and stays stopped until the author runs koi up again.',
				refresh: true,
			});
		case 'failed':
			return page({
				status: 500,
				title: 'The build failed',
				message:
					'There is no working version of this preview yet. The author can see why with koi logs.',
				refresh: true,
			});
		case 'building':
			return page({
				status: 503,
				title: 'Building',
				message:
					'The first version of this preview is still building. This page reloads when it is ready.',
				poll: {
					minutes: BUILD_WAIT_MINUTES,
					timeout: `This page stopped checking after ${BUILD_WAIT_MINUTES} minutes, longer than any build may take. Refresh to check again.`,
				},
			});
		case 'stopped':
		case 'running':
			// Running but routed here: Caddy has not picked up the new route yet.
			return page({
				status: 503,
				title: 'Starting the preview',
				message: 'This usually takes a few seconds. The page reloads when it is ready.',
				poll: {
					minutes: START_WAIT_MINUTES,
					timeout: `The preview did not answer within ${START_WAIT_MINUTES} minutes, and this page stopped checking. Refresh to try again.`,
				},
			});
	}
}
