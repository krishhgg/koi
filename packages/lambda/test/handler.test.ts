import { describe, expect, test } from 'bun:test';
import { awsDeps, createHandler, type InstanceState, type WakeDeps } from '../src/handler.ts';
import { wakePage } from '../src/wake-page.ts';

function fakeDeps(state: InstanceState, live: string[]) {
	const calls = { started: 0 };
	const deps: WakeDeps = {
		instanceState: async () => state,
		startInstance: async () => {
			calls.started += 1;
		},
		livePreviews: async () => live,
	};
	return { deps, calls };
}

const get = (rawPath: string, query?: string) => ({
	rawPath,
	rawQueryString: query,
	requestContext: { http: { method: 'GET' } },
});

const DOMAIN = 'previews.example.net';

describe('wake handler', () => {
	test('serves the wake page uncached', async () => {
		const { deps } = fakeDeps('stopped', []);
		const res = await createHandler(deps, { domain: DOMAIN })(get('/__koi-wake/index.html'));
		expect(res.statusCode).toBe(200);
		expect(res.headers['cache-control']).toBe('no-store');
		expect(res.body).toBe(wakePage());
	});

	test('starts a stopped box for a known preview', async () => {
		const { deps, calls } = fakeDeps('stopped', ['storefront-pr-2518']);
		const res = await createHandler(deps, { domain: DOMAIN })(
			get('/__koi-wake/wake', 'host=storefront-pr-2518.previews.example.net'),
		);
		expect(res.statusCode).toBe(200);
		expect(JSON.parse(res.body)).toEqual({ known: true, instance: 'pending' });
		expect(calls.started).toBe(1);
	});

	test('does not start the box twice while it is already coming up', async () => {
		const { deps, calls } = fakeDeps('pending', ['hello']);
		const res = await createHandler(deps, { domain: DOMAIN })(
			get('/__koi-wake/wake', 'host=hello.previews.example.net'),
		);
		expect(JSON.parse(res.body)).toEqual({ known: true, instance: 'pending' });
		expect(calls.started).toBe(0);
	});

	test('a box caught while stopping is started on a later call', async () => {
		const states: InstanceState[] = ['stopping', 'stopped'];
		let started = 0;
		const deps: WakeDeps = {
			instanceState: async () => states.shift() ?? 'pending',
			startInstance: async () => {
				started += 1;
			},
			livePreviews: async () => ['hello'],
		};
		const h = createHandler(deps, { domain: DOMAIN });
		const first = await h(get('/__koi-wake/wake', 'host=hello.previews.example.net'));
		expect(JSON.parse(first.body)).toEqual({ known: true, instance: 'stopping' });
		expect(started).toBe(0);
		const second = await h(get('/__koi-wake/wake', 'host=hello.previews.example.net'));
		expect(JSON.parse(second.body)).toEqual({ known: true, instance: 'pending' });
		expect(started).toBe(1);
	});

	test('always wakes the box for the keys page', async () => {
		const { deps, calls } = fakeDeps('stopped', []);
		const res = await createHandler(deps, { domain: DOMAIN })(
			get('/__koi-wake/wake', 'host=keys.previews.example.net'),
		);
		expect(JSON.parse(res.body)).toEqual({ known: true, instance: 'pending' });
		expect(calls.started).toBe(1);
	});

	test('refuses to wake for an unknown preview', async () => {
		const { deps, calls } = fakeDeps('stopped', ['hello']);
		const res = await createHandler(deps, { domain: DOMAIN })(
			get('/__koi-wake/wake', 'host=other.previews.example.net'),
		);
		expect(res.statusCode).toBe(404);
		expect(JSON.parse(res.body)).toEqual({ known: false });
		expect(calls.started).toBe(0);
	});

	test('rejects hosts outside the domain or with bad labels', async () => {
		const { deps, calls } = fakeDeps('stopped', ['hello']);
		const h = createHandler(deps, { domain: DOMAIN });
		expect((await h(get('/__koi-wake/wake', 'host=hello.evil.example'))).statusCode).toBe(400);
		expect((await h(get('/__koi-wake/wake', 'host=Hello.previews.example.net'))).statusCode).toBe(
			400,
		);
		expect((await h(get('/__koi-wake/wake'))).statusCode).toBe(400);
		expect(calls.started).toBe(0);
	});

	test('answers HEAD like GET', async () => {
		const { deps } = fakeDeps('running', []);
		const res = await createHandler(deps, { domain: DOMAIN })({
			rawPath: '/__koi-wake/index.html',
			requestContext: { http: { method: 'HEAD' } },
		});
		expect(res.statusCode).toBe(200);
		expect(res.headers['content-type']).toContain('text/html');
	});

	test('reports instance state', async () => {
		const { deps } = fakeDeps('running', []);
		const res = await createHandler(deps, { domain: DOMAIN })(get('/__koi-wake/status'));
		expect(JSON.parse(res.body)).toEqual({ instance: 'running' });
	});

	test('rejects other methods and paths', async () => {
		const { deps } = fakeDeps('running', []);
		const h = createHandler(deps, { domain: DOMAIN });
		expect(
			(await h({ rawPath: '/__koi-wake/wake', requestContext: { http: { method: 'POST' } } }))
				.statusCode,
		).toBe(405);
		expect((await h(get('/anything'))).statusCode).toBe(404);
	});
});

describe('wake handler on AWS errors', () => {
	test('says try again rather than no preview when AWS fails', async () => {
		const deps: WakeDeps = {
			instanceState: async () => 'stopped',
			startInstance: async () => {},
			livePreviews: async () => {
				throw new Error('ThrottlingException');
			},
		};
		const res = await createHandler(deps, { domain: DOMAIN })(
			get('/__koi-wake/wake', 'host=hello.previews.example.net'),
		);
		expect(res.statusCode).toBe(503);
		expect(JSON.parse(res.body)).toEqual({ error: 'try again' });
	});
});

describe('awsDeps', () => {
	function clients(responses: { ec2?: unknown; ssm?: unknown }) {
		const sent: Array<{ name: string; input: unknown }> = [];
		const client = (reply: unknown) => ({
			send: async (cmd: { constructor: { name: string }; input: unknown }) => {
				sent.push({ name: cmd.constructor.name, input: cmd.input });
				return reply;
			},
		});
		return {
			sent,
			clients: { ec2: client(responses.ec2) as never, ssm: client(responses.ssm) as never },
		};
	}

	test('reads the instance state of the configured box', async () => {
		const c = clients({ ec2: { Reservations: [{ Instances: [{ State: { Name: 'stopped' } }] }] } });
		expect(await awsDeps('i-0abc', '/koi/previews', c.clients).instanceState()).toBe('stopped');
		expect(c.sent).toEqual([
			{ name: 'DescribeInstancesCommand', input: { InstanceIds: ['i-0abc'] } },
		]);
	});

	test('reports unknown for a missing instance or an unexpected state', async () => {
		expect(await awsDeps('i-0abc', '/p', clients({ ec2: {} }).clients).instanceState()).toBe(
			'unknown',
		);
		const odd = clients({
			ec2: { Reservations: [{ Instances: [{ State: { Name: 'rebooting' } }] }] },
		});
		expect(await awsDeps('i-0abc', '/p', odd.clients).instanceState()).toBe('unknown');
	});

	test('starts only the configured box', async () => {
		const c = clients({ ec2: {} });
		await awsDeps('i-0abc', '/p', c.clients).startInstance();
		expect(c.sent).toEqual([{ name: 'StartInstancesCommand', input: { InstanceIds: ['i-0abc'] } }]);
	});

	test('reads and validates the live preview list', async () => {
		const c = clients({ ssm: { Parameter: { Value: '["hello","storefront-pr-7"]' } } });
		expect(await awsDeps('i', '/koi/previews', c.clients).livePreviews()).toEqual([
			'hello',
			'storefront-pr-7',
		]);
		expect(c.sent).toEqual([{ name: 'GetParameterCommand', input: { Name: '/koi/previews' } }]);
	});

	test('rejects a malformed live preview list', async () => {
		for (const value of ['not json', '{"a":1}', '["Bad_Label"]', '[1]']) {
			const c = clients({ ssm: { Parameter: { Value: value } } });
			await expect(awsDeps('i', '/p', c.clients).livePreviews()).rejects.toThrow();
		}
	});
});
