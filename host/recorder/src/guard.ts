import type { CdpClient, CdpEvent } from './cdp.ts';
import type { EventLog } from './events.ts';
import { type Origin, urlAllowed } from './origin.ts';

// The browser-level origin guard: every request the browser makes, from
// any page, frame or worker in any context, redirects included, is paused
// in the DevTools Fetch domain at the request stage and continued only when
// its URL is on the app origin (origin.ts). Everything else fails with
// BlockedByClient and is reported as `denied`. This is the readable layer;
// the network layer under it is Chromium's proxy setting (proxyArgs in
// origin.ts), which makes a request to any host but the app's fail even if
// this guard missed it.
//
// Why Fetch and not Playwright's route(): the pinned Playwright skips route
// handlers for redirected requests, and a route sees one context. The guard
// attaches to every target Chromium makes, with waitForDebuggerOnStart, so
// Fetch is enabled before a new target's first request.

const PATTERNS = [{ urlPattern: '*', requestStage: 'Request' }];

interface AttachedParams {
	sessionId: string;
	targetInfo: { targetId: string; type: string; url: string; browserContextId?: string };
	waitingForDebugger: boolean;
}

interface PausedParams {
	requestId: string;
	request: { url: string; method: string };
	resourceType: string;
	redirectedRequestId?: string;
	frameId?: string;
}

export class OriginGuard {
	private readonly stop: () => void;
	// Sessions the guard enabled Fetch on, by sessionId; a request is only
	// answered on the session it was paused in.
	private readonly sessions = new Set<string>();

	private constructor(
		private readonly client: CdpClient,
		private readonly origin: Origin,
		private readonly events: EventLog,
	) {
		this.stop = client.on((event) => this.onEvent(event));
	}

	// Starts the guard on an open DevTools connection: attaches to every
	// target, new ones paused until Fetch is on.
	static async start(client: CdpClient, origin: Origin, events: EventLog): Promise<OriginGuard> {
		const guard = new OriginGuard(client, origin, events);
		await client.send('Target.setAutoAttach', {
			autoAttach: true,
			waitForDebuggerOnStart: true,
			flatten: true,
		});
		return guard;
	}

	get sessionCount(): number {
		return this.sessions.size;
	}

	// Calls `listener` when the guard's DevTools connection ends. From then on
	// nothing pauses a request, so only the proxy layer holds the origin.
	onClosed(listener: () => void): void {
		this.client.onClosed(listener);
	}

	close(): void {
		this.stop();
		this.client.close();
	}

	private onEvent(event: CdpEvent): void {
		switch (event.method) {
			case 'Target.attachedToTarget':
				void this.attached(event.params as unknown as AttachedParams);
				return;
			case 'Target.detachedFromTarget':
				this.sessions.delete(String(event.params.sessionId ?? ''));
				return;
			case 'Fetch.requestPaused':
				if (event.sessionId !== undefined) {
					void this.paused(event.params as unknown as PausedParams, event.sessionId);
				}
				return;
			default:
				return;
		}
	}

	// A new session: Fetch first, then nested auto-attach (a page's frames
	// and workers are attached through the page, not the browser), and only
	// then is the target let run. A target Fetch cannot be enabled on is let
	// run too: the proxy layer still holds it, and the event says so.
	private async attached(params: AttachedParams): Promise<void> {
		const { sessionId, targetInfo } = params;
		try {
			await this.client.send('Fetch.enable', { patterns: PATTERNS }, sessionId);
			this.sessions.add(sessionId);
		} catch (err) {
			this.events.push('guard-unavailable', {
				targetType: targetInfo.type,
				url: targetInfo.url,
				error: messageOf(err),
			});
		}
		await this.client
			.send(
				'Target.setAutoAttach',
				{ autoAttach: true, waitForDebuggerOnStart: true, flatten: true },
				sessionId,
			)
			.catch(() => {});
		if (params.waitingForDebugger) {
			await this.client.send('Runtime.runIfWaitingForDebugger', {}, sessionId).catch(() => {});
		}
	}

	private async paused(params: PausedParams, sessionId: string): Promise<void> {
		const url = params.request.url;
		if (urlAllowed(url, this.origin)) {
			await this.client
				.send('Fetch.continueRequest', { requestId: params.requestId }, sessionId)
				.catch(() => {});
			return;
		}
		this.events.push('denied', {
			what: params.redirectedRequestId !== undefined ? 'redirect' : 'request',
			method: params.request.method,
			url,
			resourceType: params.resourceType,
			reason: 'outside the app origin',
		});
		await this.client
			.send(
				'Fetch.failRequest',
				{ requestId: params.requestId, errorReason: 'BlockedByClient' },
				sessionId,
			)
			.catch(() => {});
	}
}

function messageOf(err: unknown): string {
	return err instanceof Error ? err.message : String(err);
}
