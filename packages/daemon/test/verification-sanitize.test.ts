import { describe, expect, test } from 'bun:test';
import { mkdir, mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { EvidenceEventSchema, loadVerifyConfig, type ProofRecord } from '@koi/shared';
import { SecretRegistry } from '../src/redact.ts';
import { declaredCredential, sanitizeRunData, scrubFields } from '../src/verification-sanitize.ts';

const SECRET = 'private-value-1234';

function rules(...values: string[]) {
	const secrets = new SecretRegistry();
	for (const value of [SECRET, ...values]) secrets.add(value);
	return { redact: (text: string) => secrets.redact(text) };
}

describe('sanitizeRunData', () => {
	test('scrubs a record of its runtime text, leaves what the project declared, and never changes what it is given', () => {
		const record = {
			points: [
				{ id: 'app.search', state: 'done', reason: `names ${SECRET}`, evidence: [] },
				{ id: 'hello.home', state: 'done', evidence: ['recorder:aria:1'] },
			],
			uncovered: [`docs/${SECRET}.md`],
			profile: SECRET,
			policy: {
				path: `.koi/${SECRET}.yaml`,
				advisory: { error: SECRET, required: [{ id: 'app.search', revision: 1 }] },
			},
		};
		const before = structuredClone(record);
		const clean = sanitizeRunData(record, rules('app.search', 'hello.home'));
		expect(clean).toEqual({
			points: [
				{ id: 'app.search', state: 'done', reason: 'names [redacted]', evidence: [] },
				{ id: 'hello.home', state: 'done', evidence: ['recorder:aria:1'] },
			],
			uncovered: [`docs/${SECRET}.md`],
			profile: SECRET,
			policy: {
				path: `.koi/${SECRET}.yaml`,
				advisory: { error: '[redacted]', required: [{ id: 'app.search', revision: 1 }] },
			},
		});
		// The caller's record is left alone: the run goes on mutating its own.
		expect(record).toEqual(before);
	});

	test('takes text whole, and a list or a missing record as it comes', () => {
		const given = rules();
		expect(sanitizeRunData(`# text ${SECRET}\n`, given)).toBe('# text [redacted]\n');
		expect(sanitizeRunData([SECRET, 'plain'], given)).toEqual(['[redacted]', 'plain']);
		expect(sanitizeRunData(undefined, given)).toBeUndefined();
	});

	// One of each: what the schemas hold to a form or an enum, and what the project wrote.
	const FIXED = {
		artifact: 'recorder:screenshot:1',
		assertion: 'home-says-hello',
		assertions: ['home-says-hello'],
		at: '2026-10-06T12:00:00.000Z',
		availability: 'available',
		base: '2'.repeat(40),
		baseBranch: 'release-branch',
		capturedAt: '2026-10-06T12:00:01.000Z',
		checkedAt: '2026-10-06T12:00:02.000Z',
		cleanup: 'succeeded',
		code: 'capture_failed',
		commit: 'c'.repeat(40),
		completion: 'evaluated',
		deploymentId: 'd'.repeat(20),
		evidence: ['recorder:aria:1'],
		executionDigest: `sha256:${'e'.repeat(64)}`,
		expiresAt: '2026-10-06T12:00:03.000Z',
		finalizedAt: '2026-10-06T12:00:04.000Z',
		finishedAt: '2026-10-06T12:00:05.000Z',
		freshness: 'current',
		head: '1'.repeat(40),
		id: 'hello.home',
		idempotencyKey: 'retry-key-1',
		imageDigest: `sha256:${'1'.repeat(64)}`,
		kind: 'screenshot',
		label: 'hello-pr-7',
		leaseId: 'l'.repeat(20),
		mediaType: 'text/plain; charset=utf-8',
		origin: 'recorder',
		outcome: 'blocked',
		path: '.koi/required.yaml',
		planDigest: `sha256:${'a'.repeat(64)}`,
		planId: 'p'.repeat(20),
		pointId: 'app.search',
		policyDigest: `sha256:${'b'.repeat(64)}`,
		profile: 'pr-checks',
		retainedUntil: '2026-10-06T12:00:06.000Z',
		runId: 'r'.repeat(20),
		sha256: `sha256:${'c'.repeat(64)}`,
		source: 'base-branch',
		startedAt: '2026-10-06T12:00:07.000Z',
		state: 'completed',
		status: 'sanitized',
		stopped: 'protocol-limit',
		tombstoneUntil: '2026-10-06T12:00:08.000Z',
		uncovered: ['docs/redacted.md'],
		updatedAt: '2026-10-06T12:00:09.000Z',
	};

	test('leaves a field of project text or koid values alone, or a registered value could break the record', () => {
		const secrets = new SecretRegistry();
		for (const value of Object.values(FIXED).flat()) secrets.add(value);
		const given = { redact: (text: string) => secrets.redact(text) };
		expect(sanitizeRunData(FIXED, given)).toEqual(FIXED);
		// The same value in runtime text is still scrubbed.
		expect(sanitizeRunData({ reason: 'it was evaluated' }, given)).toEqual({
			reason: 'it was [redacted]',
		});
	});

	test('keeps every field name of a record, whatever is registered', () => {
		const secrets = new SecretRegistry();
		for (const word of ['evidence', 'assertion', 'observations']) secrets.add(word);
		const given = { redact: (text: string) => secrets.redact(text) };
		const verdict = {
			id: 'hello.home',
			outcome: 'fail',
			reasons: ['the assertion showed no evidence'],
			evidence: ['recorder:screenshot:1'],
		};
		expect(sanitizeRunData(verdict, given)).toEqual({
			...verdict,
			reasons: ['the [redacted] showed no [redacted]'],
		});
	});

	test('leaves what koid fills and a declared name, and scrubs what a runner chose', () => {
		const secrets = new SecretRegistry();
		for (const word of ['protocol-limit', 'recorder', 'screenshot', 'shows-hello', SECRET]) {
			secrets.add(word);
		}
		const given = { redact: (text: string) => secrets.redact(text) };
		expect(
			sanitizeRunData(
				{
					stopped: 'protocol-limit',
					assertions: ['shows-hello'],
					asserted: [
						{
							assertion: 'shows-hello',
							outcome: 'pass',
							cited: ['recorder:screenshot:1', `capture:${SECRET}`],
							detail: `saw ${SECRET}`,
						},
					],
					labels: [{ name: SECRET, artifact: 'recorder:screenshot:1' }],
					verdict: { evidence: ['recorder:screenshot:1'] },
				},
				given,
			),
		).toEqual({
			stopped: 'protocol-limit',
			assertions: ['shows-hello'],
			asserted: [
				{
					assertion: 'shows-hello',
					outcome: 'pass',
					cited: ['[redacted]:[redacted]:1', 'capture:[redacted]'],
					detail: 'saw [redacted]',
				},
			],
			labels: [{ name: '[redacted]', artifact: 'recorder:screenshot:1' }],
			verdict: { evidence: ['recorder:screenshot:1'] },
		});
	});

	test('a reference is held to its bound after the scrub', () => {
		const clean = sanitizeRunData(
			{ asserted: [{ cited: [`${'x'.repeat(250)}${SECRET}`] }] },
			rules(),
		);
		// The mask would pass the bound, and a cut never stops inside it.
		expect(clean.asserted[0]?.cited[0]).toBe('x'.repeat(250));
	});

	test('scrubs any field it has no name for, as a leak is worse than an ugly mask', () => {
		const given = rules();
		for (const key of ['note', 'detail', 'reasons', 'url', 'name', 'newField']) {
			expect(sanitizeRunData({ [key]: SECRET }, given)).toEqual({ [key]: '[redacted]' });
		}
		expect(sanitizeRunData({ deep: { deeper: [{ text: SECRET }] } }, given)).toEqual({
			deep: { deeper: [{ text: '[redacted]' }] },
		});
	});

	test('no field is fixed in a runner report, whatever the runner calls it', () => {
		// A runner's words as they came, under any name it picks, are no project text.
		const report = {
			name: SECRET,
			outcome: SECRET,
			evidence: [SECRET],
			label: SECRET,
			kind: SECRET,
			detail: SECRET,
			nested: { outcome: SECRET },
		};
		const clean = sanitizeRunData({ assertions: ['kept'], reports: [report] }, rules());
		expect(clean).toEqual({
			assertions: ['kept'],
			reports: [
				{
					name: '[redacted]',
					outcome: '[redacted]',
					evidence: ['[redacted]'],
					label: '[redacted]',
					kind: '[redacted]',
					detail: '[redacted]',
					nested: { outcome: '[redacted]' },
				},
			],
		} as never);
	});

	test('holds runtime text to what its schema allows, after the scrub', () => {
		const given = rules();
		// The cut comes after the scrub, so no half of the secret is left at the end, and it
		// never leaves a piece of the mask for a later scrub to read differently.
		const clean = sanitizeRunData(
			{
				reason: `${'x'.repeat(1990)}${SECRET}`,
				limitations: [`${'y'.repeat(495)}${SECRET}`],
				removedFields: [`${'z'.repeat(195)}${SECRET}`],
			},
			given,
		);
		expect(clean.reason).toBe(`${'x'.repeat(1990)}[redacted]`);
		expect(clean.limitations[0]).toBe('y'.repeat(495));
		expect(clean.removedFields[0]).toBe('z'.repeat(195));
		expect(JSON.stringify(clean)).not.toContain(SECRET.slice(0, 8));
		expect(sanitizeRunData(clean, given)).toEqual(clean);
	});

	test('an event keeps its envelope, in the order the schema gives it, and scrubs the rest', () => {
		const clean = sanitizeRunData(
			{
				type: 'point-opened',
				source: 'recorder',
				at: '2026-10-06T12:00:00.000Z',
				seq: 4,
				kind: SECRET,
				state: SECRET,
				[`k-${SECRET}`]: { deep: [SECRET] },
				attempt: 1,
				pointId: 'hello.home',
			},
			rules('hello.home', 'point-opened'),
		);
		const line = JSON.stringify(clean);
		expect(line).not.toContain(SECRET);
		// A field of an event is the page's to name, whatever a record means by it.
		expect(clean.kind).toBe('[redacted]');
		expect(clean.state).toBe('[redacted]');
		expect(clean['k-[redacted]' as 'seq']).toEqual({ deep: ['[redacted]'] } as never);
		expect(Object.keys(clean).slice(0, 6)).toEqual([
			'seq',
			'at',
			'source',
			'type',
			'pointId',
			'attempt',
		]);
		// The envelope's point id and type stay: a mask would fail the event's schema.
		expect(clean.pointId).toBe('hello.home');
		expect(clean.type).toBe('point-opened');
		// A reader's copy of the line, parsed and written again, is the same bytes.
		expect(JSON.stringify(EvidenceEventSchema.parse(JSON.parse(line)))).toBe(line);
	});

	describe('is idempotent', () => {
		const given = rules(
			'chromium',
			'hello.home',
			'.koi/runners',
			'redacted',
			'[redacted]',
			'acted]tail',
		);
		const twice = <T>(record: T) => {
			const once = sanitizeRunData(record, given);
			expect(sanitizeRunData(once, given)).toEqual(once);
			expect(JSON.stringify(sanitizeRunData(once, given))).toBe(JSON.stringify(once));
			return once;
		};

		test.each([
			[
				'a controller record',
				{ id: 'hello.home', reason: `chromium ${SECRET}`, profile: 'chromium' },
			],
			['a status', { problems: [{ code: 'x', detail: `token=${SECRET}`, at: 'now' }] }],
			['an observations file', { assertions: ['chromium'], reports: [{ name: SECRET }] }],
			['a mask in text', { reason: 'it said [redacted] and redacted' }],
			['a path in text', { reason: 'docs/redacted.md and .koi/runners/home.sh' }],
			['a mask run into a known value', { reason: `${SECRET}tail [redacted]tail` }],
		])('on %s', (_what, record) => {
			twice(record);
		});

		test('on an event, to the byte, including a name that scrubs', () => {
			const event = {
				seq: 1,
				at: '2026-10-06T12:00:00.000Z',
				source: 'recorder',
				type: 'console',
				pointId: 'hello.home',
				attempt: 1,
				text: `token=abc chromium ${SECRET} [redacted]`,
				[`k-${SECRET}`]: [`Authorization: Bearer ${SECRET}`],
			};
			const once = twice(event);
			expect(once.text).toBe('token=[redacted] [redacted] [redacted] [redacted]');
		});

		test('on a field cut at its bound, where the cut could fall inside a mask', () => {
			const fields = { text: `${'x'.repeat(92)}token=abcdef`, ok: true, n: 1 };
			const cut = scrubFields(given, fields, 100);
			expect(cut.text).toBe(`${'x'.repeat(92)}token=`);
			// The writer and a reply scrub again with no bound, and must say the same.
			expect(scrubFields(given, cut)).toEqual(cut);
		});
	});
});

describe('declaredCredential', () => {
	const KEY = `sk-proj-${'AbCdEf0123456789'.repeat(2)}`;
	const POINT = (id: string, more = '') => `id: ${id}
revision: 1
claim: It works.
select:
  paths: [src/**]
run:
  command: [sh, .koi/runners/home.sh]
${more}assertions:
  - name: works
    description: It answers.
    evidence: [screenshot]
`;
	const config = async (manifest: string, points: Record<string, string>) => {
		const root = await mkdtemp(join(tmpdir(), 'koid-declared-'));
		await mkdir(join(root, '.koi/points'), { recursive: true });
		await mkdir(join(root, '.koi/runners'), { recursive: true });
		await writeFile(join(root, '.koi/runners/home.sh'), 'exit 0\n');
		await writeFile(join(root, '.koi/verify.yaml'), manifest);
		for (const [name, text] of Object.entries(points)) {
			await writeFile(join(root, '.koi/points', name), text);
		}
		return loadVerifyConfig(root);
	};
	const MANIFEST = `version: 1
points: [points/*.yaml]
profiles:
  pr:
    always: [a.point]
runner:
  image: busybox:1.37
`;
	const declared = async (
		manifest: string,
		points: Record<string, string>,
		more: {
			policy?: { path: string; required: Array<{ id: string }>; error?: string };
			records?: ProofRecord[];
			errors?: string[];
		} = {},
	) =>
		declaredCredential({
			config: await config(manifest, points),
			policy: more.policy,
			proofs: { records: more.records ?? [], errors: more.errors ?? [] },
		});

	test('finds nothing in a clean project', async () => {
		expect(await declared(MANIFEST, { 'a.yaml': POINT('a.point') })).toBeUndefined();
	});

	test('names the field and the position, in the order a reader would look', async () => {
		expect(
			await declared(MANIFEST.replace('busybox:1.37', `acme/${KEY}:1`), {
				'a.yaml': POINT('a.point'),
			}),
		).toBe('.koi/verify.yaml, field runner.image');
		expect(
			await declared(MANIFEST, {
				'a.yaml': POINT('a.point'),
				'b.yaml': POINT('b.point', `setup:\n  command: [run, "${KEY}"]\n`),
			}),
		).toBe(
			'point 2 of 2, counting the point files in the sorted order of their paths, field setup.command[1]',
		);
	});

	test('reads an image reference by its grammar: only a key by its own shape counts', async () => {
		const points = { 'a.yaml': POINT('a.point') };
		const image = (reference: string) => MANIFEST.replace('busybox:1.37', reference);
		expect(
			await declared(image('ghcr.io/acme/token:DevelopmentBuild20261103'), points),
		).toBeUndefined();
		expect(
			await declared(image('ghcr.io/acme/password:DevelopmentBuild20261103'), points),
		).toBeUndefined();
		for (const reference of [
			'ghcr.io/acme/token:AKIAIOSFODNN7EXAMPLE',
			`ghcr.io/acme/${KEY}:1`,
			`koi-${'a1b2c3d4'.repeat(3)}/runner:1`,
		]) {
			expect(await declared(image(reference), points)).toBe('.koi/verify.yaml, field runner.image');
		}
		// The same text in any other field still reads as an assignment.
		expect(
			await declared(
				MANIFEST.replace(
					'runner:\n',
					'runner:\n  command: [run, "token:DevelopmentBuild20261103"]\n',
				),
				points,
			),
		).toBe('.koi/verify.yaml, field runner.command[1]');
	});

	test('quotes no file name, even one whose prefix hides a key from the patterns', async () => {
		const login = `koi-${'a1b2c3d4'.repeat(3)}`;
		const found = await declared(MANIFEST, {
			'a.yaml': POINT('a.point'),
			[`prefix${login}.yaml`]: POINT('b.point').replace('It works.', `Uses ${login}.`),
		});
		expect(found).toBe(
			'point 2 of 2, counting the point files in the sorted order of their paths, field claim',
		);
	});

	test('names no value by way of a key the project chose', async () => {
		const login = `koi-${'a1b2c3d4'.repeat(3)}`;
		const found = await declared(
			MANIFEST.replace('profiles:\n', `profiles:\n  ${login}:\n    always: []\n`),
			{ 'a.yaml': POINT('a.point') },
		);
		expect(found).toBe('.koi/verify.yaml, field profiles[0].name');
		const named = await declared(MANIFEST, { [`${KEY}.yaml`]: POINT('a.point') });
		expect(named).toBe(
			'point 1 of 1, counting the point files in the sorted order of their paths, field path',
		);
	});

	test('looks at the policy and the proof records too, whose errors can quote a file', async () => {
		const points = { 'a.yaml': POINT('a.point') };
		const path = '.koi/required.yaml';
		expect(
			await declared(MANIFEST, points, { policy: { path, required: [], error: `bad key ${KEY}` } }),
		).toBe('the required policy, field error');
		expect(
			await declared(MANIFEST, points, { errors: [`.koi/proofs/x.yaml: bad key ${KEY}`] }),
		).toBe('the proof records, field errors[0]');
	});
});
