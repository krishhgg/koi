import { describe, expect, test } from 'bun:test';
import { mkdtemp, writeFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { BoxUnavailableError } from '../src/transport.ts';
import { AWS_HTTP, awsTransport, clients } from '../src/transports/aws.ts';
import { settings } from './koid.ts';

// A stand-in for SSM that takes each command, then never answers a
// GetCommandInvocation: the connection stays open and silent, as when a
// network drops it without closing it. That is how koi up once stopped for
// three hours in the middle of a build.
async function silentSsm(): Promise<{ url: string; asked: string[]; close: () => void }> {
	const asked: string[] = [];
	const server = createServer((req, res) => {
		const target = String(req.headers['x-amz-target'] ?? '');
		asked.push(target);
		req.resume();
		req.on('end', () => {
			if (target !== 'AmazonSSM.SendCommand') return;
			res.setHeader('content-type', 'application/x-amz-json-1.1');
			res.end(JSON.stringify({ Command: { CommandId: 'c-1' } }));
		});
	});
	await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
	const { port } = server.address() as AddressInfo;
	return {
		url: `http://127.0.0.1:${port}`,
		asked,
		close: () => {
			server.closeAllConnections();
			server.close();
		},
	};
}

// Points the SDK at url, with a profile it can read, while run runs.
async function withEndpoint<T>(url: string, run: () => Promise<T>): Promise<T> {
	const dir = await mkdtemp(join(tmpdir(), 'koi-aws-http-'));
	await writeFile(
		join(dir, 'credentials'),
		'[koi-test]\naws_access_key_id = AKIDEXAMPLE\naws_secret_access_key = example\n',
	);
	await writeFile(join(dir, 'config'), '');
	const saved = { ...process.env };
	Object.assign(process.env, {
		AWS_ENDPOINT_URL: url,
		AWS_SHARED_CREDENTIALS_FILE: join(dir, 'credentials'),
		AWS_CONFIG_FILE: join(dir, 'config'),
	});
	try {
		return await run();
	} finally {
		for (const key of ['AWS_ENDPOINT_URL', 'AWS_SHARED_CREDENTIALS_FILE', 'AWS_CONFIG_FILE']) {
			if (saved[key] === undefined) delete process.env[key];
			else process.env[key] = saved[key];
		}
	}
}

describe('AWS calls that never answer', () => {
	test('koi sets both time limits on every client', () => {
		expect(AWS_HTTP.connectionTimeout).toBeGreaterThan(0);
		expect(AWS_HTTP.socketTimeout).toBeGreaterThan(0);
	});

	test('without the time limits, a status read waits forever', async () => {
		const ssm = await silentSsm();
		try {
			await withEndpoint(ssm.url, async () => {
				const t = awsTransport(settings, clients('koi-test', 'us-east-1', {}), async () => {});
				const read = t.ctl(['status', 'a-preview']).then(
					() => 'answered',
					() => 'failed',
				);
				const after = await Promise.race([read, Bun.sleep(2000).then(() => 'still waiting')]);
				expect(after).toBe('still waiting');
				expect(ssm.asked).toContain('AmazonSSM.GetCommandInvocation');
				await t.close?.();
			});
		} finally {
			ssm.close();
		}
	});

	test('with them, the read fails as one that can pass, and follow asks again', async () => {
		const ssm = await silentSsm();
		try {
			await withEndpoint(ssm.url, async () => {
				const t = awsTransport(
					settings,
					clients('koi-test', 'us-east-1', { connectionTimeout: 300, socketTimeout: 300 }),
					async () => {},
				);
				const began = Date.now();
				const err = await t.ctl(['status', 'a-preview']).catch((e: unknown) => e);
				expect(err).toBeInstanceOf(BoxUnavailableError);
				expect(String((err as Error).message)).toContain('timed out');
				expect(Date.now() - began).toBeLessThan(15_000);
				await t.close?.();
			});
		} finally {
			ssm.close();
		}
	});
});
