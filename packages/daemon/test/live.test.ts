import { describe, expect, test } from 'bun:test';
import { type PutParameterCommand, SSMClient } from '@aws-sdk/client-ssm';
import { ssmLiveList, ssmRoom } from '../src/live.ts';

// A real SSM client whose send records each command instead of calling AWS,
// and fails the next `failures` calls.
function client() {
	const sent: Array<PutParameterCommand['input']> = [];
	let failures = 0;
	const ssm = new SSMClient({ region: 'us-east-1' });
	ssm.send = (async (command: PutParameterCommand) => {
		if (failures > 0) {
			failures -= 1;
			throw new Error('ThrottlingException: Rate exceeded');
		}
		sent.push(command.input);
		return {};
	}) as typeof ssm.send;
	return {
		ssm,
		sent,
		fail(n: number) {
			failures = n;
		},
	};
}

// 62 characters each: with quotes and commas, 63 of them take exactly
// 1 + 63 * 65 = 4096 bytes.
const long = (i: number) => `x${String(i).padStart(3, '0')}${'a'.repeat(58)}`;
const labels = (n: number) => Array.from({ length: n }, (_, i) => long(i));

describe('ssmLiveList', () => {
	test('writes the labels, each once and sorted, as a String parameter', async () => {
		const c = client();
		await ssmLiveList('/koi/previews', c.ssm).publish(['b', 'a', 'b']);
		expect(c.sent).toEqual([
			{ Name: '/koi/previews', Value: '["a","b"]', Type: 'String', Overwrite: true },
		]);
	});

	test('skips the call when the list has not changed, in any order', async () => {
		const c = client();
		const live = ssmLiveList('/koi/previews', c.ssm);
		await live.publish(['a', 'b']);
		await live.publish(['b', 'a']);
		expect(c.sent).toHaveLength(1);
		await live.publish(['a']);
		expect(c.sent.map((s) => s.Value)).toEqual(['["a","b"]', '["a"]']);
	});

	test('sends the same list again after a call that failed', async () => {
		const c = client();
		const live = ssmLiveList('/koi/previews', c.ssm);
		c.fail(1);
		await expect(live.publish(['a'])).rejects.toThrow('ThrottlingException');
		await live.publish(['a']);
		expect(c.sent.map((s) => s.Value)).toEqual(['["a"]']);
	});

	test('writes a list of exactly 4096 bytes and refuses a longer one without calling SSM', async () => {
		const c = client();
		const live = ssmLiveList('/koi/previews', c.ssm);
		await live.publish(labels(63));
		expect(new TextEncoder().encode(c.sent[0]?.Value ?? '').length).toBe(4096);
		await expect(live.publish([...labels(63), 'a'])).rejects.toThrow(
			'64 live previews do not fit in the 4096 bytes of /koi/previews',
		);
		expect(c.sent).toHaveLength(1);
	});

	test('refuses a label that is not a preview label without calling SSM', async () => {
		const c = client();
		await expect(ssmLiveList('/koi/previews', c.ssm).publish(['Bad_Label'])).rejects.toThrow();
		expect(c.sent).toEqual([]);
	});

	test('has room for a list of exactly 4096 bytes and not for one label more, and says why', () => {
		const c = client();
		const live = ssmLiveList('/koi/previews', c.ssm);
		expect(live.room(labels(63))).toEqual({ ok: true });
		expect(live.room([...labels(63), 'a'])).toEqual({
			ok: false,
			reason: 'it would pass the 4096 bytes its SSM parameter holds',
		});
		expect(live.room).toBe(ssmRoom);
		expect(c.sent).toEqual([]);
	});
});
