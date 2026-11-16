import { createConnection } from 'node:net';
import { type EgressReply, EgressReplySchema } from '@koi/shared';

// Client for the egress proxy's control socket (host/egress/koi_egress.py):
// one JSON request per connection, one JSON line back. Keys pass through this
// process's memory on their way to the proxy's; nothing here stores or logs
// them.
export interface EgressControl {
	// Registers keys for the preview `label`. The proxy derives a token for
	// each key (the same one each time that key is registered for that
	// preview), good only for its provider and in requests from that
	// preview's container, and returns them by provider. `source` is where
	// the registration came from (see viewerSource in keys.ts); the proxy caps
	// the tokens it holds from each.
	register(
		label: string,
		keys: Record<string, string>,
		source: string,
	): Promise<Record<string, string>>;
	forget(token: string): Promise<void>;
	// Every preview container's address on the preview network and its label,
	// replacing what the proxy had. A token works only from an address mapped
	// to its preview.
	previews(addresses: Record<string, string>): Promise<void>;
}

export interface EgressControlOptions {
	// How long a call may take, connecting included. Default 10 seconds.
	timeoutMs?: number;
}

type Accepted = Extract<EgressReply, { ok: true }>;

// node:net rather than Bun.connect: node's socket queues whatever one write
// cannot send at once, and Bun's sends what fits and leaves the rest to the
// caller.
export function egressControl(
	socketPath: string,
	options: EgressControlOptions = {},
): EgressControl {
	const timeoutMs = options.timeoutMs ?? 10_000;
	const call = (request: unknown) =>
		new Promise<Accepted>((resolve, reject) => {
			const socket = createConnection(socketPath);
			let reply = '';
			let settled = false;
			// Settles the call once, and hangs up.
			const finish = (result: Accepted | Error) => {
				if (settled) return;
				settled = true;
				clearTimeout(timer);
				socket.destroy();
				if (result instanceof Error) reject(result);
				else resolve(result);
			};
			const timer = setTimeout(
				() => finish(new Error('the egress proxy did not answer')),
				timeoutMs,
			);
			// Decodes across chunks, so a character cut between two stays whole.
			socket.setEncoding('utf8');
			socket.on('data', (chunk: string) => {
				reply += chunk;
				const end = reply.indexOf('\n');
				if (end !== -1) finish(readReply(reply.slice(0, end)));
			});
			// A proxy that hangs up before a whole line has said all it will.
			socket.on('end', () => finish(readReply(reply)));
			socket.on('close', () => finish(readReply(reply)));
			socket.on('error', (err) => finish(err));
			socket.write(`${JSON.stringify(request)}\n`);
		});
	return {
		async register(label, keys, source) {
			const { tokens } = await call({ op: 'register', label, keys, source });
			// A token for each key sent, and nothing else.
			const providers = Object.keys(keys).sort();
			if (tokens === undefined || Object.keys(tokens).sort().join() !== providers.join()) {
				throw new Error(UNREADABLE);
			}
			return tokens;
		},
		forget: async (token) => void (await call({ op: 'forget', token })),
		previews: async (addresses) => void (await call({ op: 'previews', previews: addresses })),
	};
}

const UNREADABLE = 'the egress proxy sent an unreadable reply';

// The accepted reply, or why the call failed.
function readReply(line: string): Accepted | Error {
	let parsed: EgressReply;
	try {
		parsed = EgressReplySchema.parse(JSON.parse(line));
	} catch {
		return new Error(UNREADABLE);
	}
	return parsed.ok ? parsed : new Error(parsed.error);
}

// The deployer's `previews` for a proxy reached through `control`. When
// nothing listens on the control socket (no socket file, or one nobody
// accepts on), no policy is loaded, and the address map went with the last
// one: the socket closes as the policy unloads (koi_egress.py, done), and a
// policy that loads again starts with no map. That is as safe as a map
// without the address, so it counts as taken; the next sync tells the new
// policy. Any other failure, such as a proxy that does not answer, leaves
// what the proxy holds unknown, and rejects.
export function proxyPreviews(control: EgressControl) {
	return async (addresses: Record<string, string>): Promise<void> => {
		try {
			await control.previews(addresses);
		} catch (err) {
			const code = (err as NodeJS.ErrnoException).code;
			if (code === 'ENOENT' || code === 'ECONNREFUSED') return;
			throw err;
		}
	};
}
