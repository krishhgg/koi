import { expect, test } from 'bun:test';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Readable } from 'node:stream';
import { s3Uploads } from '../src/uploads.ts';

const ID = 'abcdefghij0123456789';

function fakeClient(body: Readable | undefined, length: number) {
	const sent: string[] = [];
	return {
		sent,
		client: {
			send: async (cmd: { input: { Key: string } }) => {
				sent.push(cmd.input.Key);
				return { Body: body, ContentLength: length };
			},
		} as never,
	};
}

test('streams the source tarball to the file', async () => {
	const data = Buffer.alloc(300_000, 7);
	const { client, sent } = fakeClient(
		Readable.from([data.subarray(0, 100_000), data.subarray(100_000)]),
		data.length,
	);
	const file = join(await mkdtemp(join(tmpdir(), 'koid-up-')), 'source.tar.gz');
	await s3Uploads('bucket', client).downloadSource(ID, file);
	expect(sent).toEqual([`sources/${ID}.tar.gz`]);
	expect(Buffer.from(await Bun.file(file).arrayBuffer()).equals(data)).toBe(true);
});

test('refuses a source over 2 GB before downloading it', async () => {
	const { client } = fakeClient(Readable.from([Buffer.alloc(1)]), 3 * 1024 ** 3);
	const file = join(await mkdtemp(join(tmpdir(), 'koid-up-')), 'source.tar.gz');
	await expect(s3Uploads('bucket', client).downloadSource(ID, file)).rejects.toThrow(/over 2 GB/);
});

test('an empty body is an error', async () => {
	const { client } = fakeClient(undefined, 0);
	const file = join(await mkdtemp(join(tmpdir(), 'koid-up-')), 'source.tar.gz');
	await expect(s3Uploads('bucket', client).downloadSource(ID, file)).rejects.toThrow(/empty/);
});
