// A small DevTools client of the recorder's own, on Chromium's loopback
// endpoint, for the origin guard (guard.ts). It is separate from the
// Playwright connection the broker drives the browser with, because a
// Playwright CDPSession drops messages for sessions it did not attach
// itself, and the guard attaches to every target Chromium makes. Flattened
// sessions only: a message for an attached target carries its sessionId.

export interface CdpEvent {
	method: string;
	params: Record<string, unknown>;
	sessionId?: string | undefined;
}

export class CdpError extends Error {
	constructor(
		readonly method: string,
		message: string,
	) {
		super(`${method}: ${message}`);
	}
}

// What the client needs of a WebSocket: enough that a test can pass a fake.
export interface CdpSocket {
	send(text: string): void;
	close(): void;
	onmessage: ((text: string) => void) | undefined;
	onclose: (() => void) | undefined;
}

const SEND_TIMEOUT_MS = 30_000;

export class CdpClient {
	private nextId = 1;
	private readonly pending = new Map<
		number,
		{ method: string; resolve: (v: Record<string, unknown>) => void; reject: (e: Error) => void }
	>();
	private readonly listeners = new Set<(event: CdpEvent) => void>();
	private readonly closeListeners = new Set<() => void>();
	private closed = false;

	constructor(private readonly socket: CdpSocket) {
		socket.onmessage = (text) => this.onMessage(text);
		socket.onclose = () => this.onClose();
	}

	// Connects to a ws:// DevTools URL with the platform's WebSocket (Node
	// 22 and later, and Bun, have one).
	static connect(url: string): Promise<CdpClient> {
		return new Promise((resolve, reject) => {
			const ws = new WebSocket(url);
			ws.binaryType = 'arraybuffer';
			const socket: CdpSocket = {
				send: (text) => ws.send(text),
				close: () => ws.close(),
				onmessage: undefined,
				onclose: undefined,
			};
			ws.onmessage = (event) => socket.onmessage?.(String(event.data));
			ws.onclose = () => socket.onclose?.();
			ws.onerror = () => {
				reject(new Error('the DevTools connection failed'));
				socket.onclose?.();
			};
			ws.onopen = () => resolve(new CdpClient(socket));
		});
	}

	get isClosed(): boolean {
		return this.closed;
	}

	send(
		method: string,
		params: Record<string, unknown> = {},
		sessionId?: string,
	): Promise<Record<string, unknown>> {
		if (this.closed) return Promise.reject(new CdpError(method, 'the connection is closed'));
		const id = this.nextId++;
		const message = JSON.stringify({ id, method, params, ...(sessionId ? { sessionId } : {}) });
		return new Promise((resolve, reject) => {
			const timer = setTimeout(() => {
				this.pending.delete(id);
				reject(new CdpError(method, 'no reply in time'));
			}, SEND_TIMEOUT_MS);
			timer.unref();
			this.pending.set(id, {
				method,
				resolve: (v) => {
					clearTimeout(timer);
					resolve(v);
				},
				reject: (e) => {
					clearTimeout(timer);
					reject(e);
				},
			});
			this.socket.send(message);
		});
	}

	on(listener: (event: CdpEvent) => void): () => void {
		this.listeners.add(listener);
		return () => this.listeners.delete(listener);
	}

	// Calls `listener` once when the connection ends, whichever side ended it.
	// A connection that has ended already calls it at once: one that dropped
	// before the caller got here would otherwise go unreported.
	onClosed(listener: () => void): void {
		if (this.closed) {
			listener();
			return;
		}
		this.closeListeners.add(listener);
	}

	close(): void {
		if (this.closed) return;
		this.socket.close();
		this.onClose();
	}

	private onMessage(text: string): void {
		let parsed: unknown;
		try {
			parsed = JSON.parse(text);
		} catch {
			return;
		}
		if (typeof parsed !== 'object' || parsed === null) return;
		const message = parsed as {
			id?: unknown;
			method?: unknown;
			params?: unknown;
			sessionId?: unknown;
			result?: unknown;
			error?: { message?: unknown };
		};
		if (typeof message.id === 'number') {
			const call = this.pending.get(message.id);
			if (call === undefined) return;
			this.pending.delete(message.id);
			if (message.error !== undefined) {
				call.reject(new CdpError(call.method, String(message.error.message ?? 'error')));
			} else {
				call.resolve(
					typeof message.result === 'object' && message.result !== null
						? (message.result as Record<string, unknown>)
						: {},
				);
			}
			return;
		}
		if (typeof message.method !== 'string') return;
		const event: CdpEvent = {
			method: message.method,
			params:
				typeof message.params === 'object' && message.params !== null
					? (message.params as Record<string, unknown>)
					: {},
			...(typeof message.sessionId === 'string' ? { sessionId: message.sessionId } : {}),
		};
		for (const listener of this.listeners) listener(event);
	}

	private onClose(): void {
		if (this.closed) return;
		this.closed = true;
		for (const call of this.pending.values()) {
			call.reject(new CdpError(call.method, 'the connection closed'));
		}
		this.pending.clear();
		for (const listener of this.closeListeners) listener();
		this.closeListeners.clear();
	}
}
