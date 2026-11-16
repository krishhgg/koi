import { describe, expect, test } from 'bun:test';
import { existsSync } from 'node:fs';
import { mkdir, mkdtemp, readFile, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { GLOB_MAX_CHARS, GlobWork } from '../src/glob.ts';
import type { PreviewRecord } from '../src/preview.ts';
import {
	type DeploymentIdentity,
	DeploymentIdentitySchema,
	deploymentIdentity,
	digest,
	escapeControls,
	ImageRefSchema,
	KoiPathSchema,
	loadVerifyConfig,
	MANIFEST_GLOBS_MAX,
	MAX_VERIFY_FILE_BYTES,
	OutcomeSchema,
	type Plan,
	PlanSchema,
	PointIdSchema,
	PointSchema,
	type ProofRecord,
	ProofRecordSchema,
	RequiredPolicySchema,
	type Result,
	ResultSchema,
	type Run,
	type RunnerAck,
	RunnerAckSchema,
	type RunnerEvent,
	RunnerEventSchema,
	RunnerFileSchema,
	RunSchema,
	readVerifyFile,
	type SupervisorLine,
	SupervisorLineSchema,
	VerifyConfigError,
	VerifyManifestSchema,
} from '../src/verify.ts';

const HELLO = join(import.meta.dir, '../../../examples/hello');

const MANIFEST = {
	version: 1,
	skills: [{ id: 'storefront', path: 'skills/verify-storefront/SKILL.md' }],
	points: ['points/*.yaml'],
	profiles: {
		pr: { always: ['app.canvas.save', 'app.canvas.duplicate'], select: 'changed' },
		provider: { include: ['app.anthropic.thinking'] },
	},
	runner: { image: 'ghcr.io/acme/verify-runner:1.2', command: ['node', 'run.mjs'] },
	budgets: { timeoutSeconds: 600, maxRequests: 10 },
	fallback: { mode: 'suggest', onUnmapped: 'needs-review' },
};

const POINT = {
	id: 'app.canvas.save',
	revision: 1,
	claim: 'A cart item saved in the editor survives a fresh read.',
	feature: 'skills/verify-storefront/features/cart.md',
	select: { always: true, paths: ['**/CartPanel.tsx', '**/cart_api.py'] },
	requires: {
		services: ['web', 'payment_api', 'search_index'],
		fixtures: ['fixtures/cart-items.json'],
		browser: true,
		provider: 'anthropic',
		network: 'provider-https',
	},
	setup: { command: ['node', '.koi/runners/storefront.mjs', 'seed'] },
	run: { command: ['node', '.koi/runners/storefront.mjs', 'save'] },
	cleanup: { command: ['node', '.koi/runners/storefront.mjs', 'cleanup'] },
	assertions: [
		{
			name: 'save-accepted',
			description: 'The panel closes without a validation error.',
			evidence: ['browser-trace', 'screenshot'],
		},
		{
			name: 'persisted-name',
			description: 'A fresh editor load shows the marker.',
			evidence: ['saved-document', 'screenshot'],
		},
	],
	budgets: { timeoutSeconds: 120 },
};

const SHA = 'a'.repeat(40);
const DIGEST = `sha256:${'b'.repeat(64)}`;
const ID = 'c'.repeat(20);
const DEPLOYMENT: DeploymentIdentity = {
	label: 'hello-pr-7',
	deploymentId: ID,
	imageDigest: DIGEST,
	commit: SHA,
	merge: { head: 'd'.repeat(40), base: 'e'.repeat(40), baseBranch: 'main' },
};

describe('VerifyManifestSchema', () => {
	test('parses a full manifest and fills profile defaults', () => {
		const m = VerifyManifestSchema.parse(MANIFEST);
		expect(m.profiles.pr).toEqual({
			always: ['app.canvas.save', 'app.canvas.duplicate'],
			select: 'changed',
			include: [],
		});
		expect(m.profiles.provider).toEqual({
			always: [],
			select: 'none',
			include: ['app.anthropic.thinking'],
		});
		expect(m.runner.command).toEqual(['node', 'run.mjs']);
	});

	test('a manifest needs only version, points, profiles and a runner image', () => {
		const m = VerifyManifestSchema.parse({
			version: 1,
			points: ['points/*.yaml'],
			profiles: {},
			runner: { image: 'busybox:1.37' },
		});
		expect(m.skills).toEqual([]);
		expect(m.budgets).toBeUndefined();
		expect(m.fallback).toBeUndefined();
	});

	test.each([
		['an unknown key', { ...MANIFEST, extra: 1 }],
		[
			'an unknown key in a profile',
			{ ...MANIFEST, profiles: { pr: { select: 'changed', required: true } } },
		],
		['another version', { ...MANIFEST, version: 2 }],
		['no points', { ...MANIFEST, points: [] }],
		['an absolute skill path', { ...MANIFEST, skills: [{ id: 'x', path: '/etc/passwd' }] }],
		['a skill path with ..', { ...MANIFEST, skills: [{ id: 'x', path: '../koi.yaml' }] }],
		['a glob with ..', { ...MANIFEST, points: ['../**/*.yaml'] }],
		['an absolute glob', { ...MANIFEST, points: ['/points/*.yaml'] }],
		['a glob that is only .', { ...MANIFEST, points: ['./'] }],
		[
			'two skills with one id',
			{
				...MANIFEST,
				skills: [
					{ id: 'x', path: 'a.md' },
					{ id: 'x', path: 'b.md' },
				],
			},
		],
		[
			'a runner command as a shell string',
			{ ...MANIFEST, runner: { image: 'busybox', command: 'sh run.sh' } },
		],
		['a runner image with a space', { ...MANIFEST, runner: { image: 'busybox; rm -rf /' } }],
		['a profile name with capitals', { ...MANIFEST, profiles: { PR: { select: 'changed' } } }],
		['an unknown select', { ...MANIFEST, profiles: { pr: { select: 'all' } } }],
		[
			'an unknown fallback mode',
			{ ...MANIFEST, fallback: { mode: 'invent', onUnmapped: 'blocked' } },
		],
	])('rejects %s', (_what, data) => {
		expect(VerifyManifestSchema.safeParse(data).success).toBe(false);
	});
});

describe('what a plan names', () => {
	const plan = {
		version: 1,
		planId: ID,
		deployment: {
			label: 'hello-pr-7',
			deploymentId: ID,
			imageDigest: DIGEST,
			commit: 'c'.repeat(40),
		},
		profile: 'pr',
		points: [{ id: 'a.point', revision: 1, digest: DIGEST, runners: [], why: 'always' }],
		blocked: [],
		uncovered: [],
		planDigest: DIGEST,
	};

	test('a point id and a profile are what a project declares, and nothing a mask could make', () => {
		expect(PlanSchema.safeParse(plan).success).toBe(true);
		for (const id of ['refused:1', '[redacted]']) {
			const issues = PlanSchema.safeParse({
				...plan,
				points: [{ ...plan.points[0], id }],
			}).error?.issues;
			expect(issues?.map((i) => i.path.join('.'))).toEqual(['points.0.id']);
			const blocked = { ...plan, points: [], blocked: [{ id, reason: 'blocked' }] };
			expect(PlanSchema.safeParse(blocked).success).toBe(false);
		}
		for (const profile of ['refused:profile', '[redacted]']) {
			expect(PlanSchema.safeParse({ ...plan, profile }).success).toBe(false);
		}
	});

	test('a runner path and an image hold what a project can declare, so no scrub may touch them', () => {
		const runner = (path: string) => ({ path, digest: DIGEST });
		expect(RunnerFileSchema.safeParse(runner('.koi/runners/home.sh')).success).toBe(true);
		expect(RunnerFileSchema.safeParse(runner('[redacted]/home.sh')).success).toBe(false);
		expect(ImageRefSchema.safeParse('ghcr.io/acme/runner:1').success).toBe(true);
		expect(ImageRefSchema.safeParse('ghcr.io/[redacted]:1').success).toBe(false);
	});
});

describe('escapeControls', () => {
	test.each([
		['ESC', '\x1b', '\\x1b'],
		['BEL', '\x07', '\\x07'],
		['NUL', '\x00', '\\x00'],
		['a newline', '\n', '\\x0a'],
		['a carriage return', '\r', '\\x0d'],
		['a tab', '\t', '\\x09'],
		['DEL', '\x7f', '\\x7f'],
		['C1 CSI', '\x9b', '\\x9b'],
		['the last of C1', '\x9f', '\\x9f'],
		['a line separator', '\u2028', '\\u2028'],
		['a paragraph separator', '\u2029', '\\u2029'],
		['a right-to-left override', '\u202e', '\\u202e'],
		['a bidi isolate', '\u2066', '\\u2066'],
	])('shows %s as an escape', (_what, char, shown) => {
		expect(escapeControls(`a${char}b`)).toBe(`a${shown}b`);
	});

	test('leaves everything else as it is, and a second pass changes nothing', () => {
		const text = 'src/日本語/café 🐟 \\x1b `tick` | [x](y).ts';
		expect(escapeControls(text)).toBe(text);
		const once = escapeControls('a\x1b]0;title\x07b');
		expect(once).toBe('a\\x1b]0;title\\x07b');
		expect(escapeControls(once)).toBe(once);
	});
});

describe('what a glob may be', () => {
	const withGlob = (glob: string) => ({ ...POINT, select: { paths: [glob] } });
	const allowed = (glob: string) => PointSchema.safeParse(withGlob(glob)).success;
	const says = (glob: string) => {
		const parsed = PointSchema.safeParse(withGlob(glob));
		return parsed.success ? undefined : parsed.error.issues.map((i) => i.message).join('; ');
	};

	test('a real glob passes', () => {
		for (const glob of [
			'src/**',
			'**/CartPanel.tsx',
			'{apps,packages}/{web,api}/**/*.{ts,tsx,js,jsx,css,scss}',
			'*.{ts,tsx,js,jsx,mjs,cjs,json,yaml,yml,css,scss,html,md,mdx,toml}',
			'{apps,packages}/{web,api,cli,shared}/**/*.{ts,tsx,js,jsx,mjs,cjs,json,yaml,yml,css,scss,html,md,mdx,toml}',
		]) {
			expect(allowed(glob)).toBe(true);
		}
	});

	test('an exact path as long as a changed name may be is a glob', () => {
		expect(allowed('a'.repeat(GLOB_MAX_CHARS))).toBe(true);
		expect(allowed('a'.repeat(GLOB_MAX_CHARS + 1))).toBe(false);
	});

	test('a first input a reviewer built, whose braces Bun.Glob miscounted, is refused', () => {
		// Bun counted the `}` inside `[a}]` as closing the group, and answered false for a path
		// an expansion matches, so a file that should select the point landed in `uncovered`.
		const group = `{[a},${Array(9).fill('a'.repeat(20)).join(',')}}`;
		expect(says(`${group.repeat(5)}b`)).toContain('[ is not supported');
	});

	test.each([
		['[a-z].ts', '[ is not supported'],
		['!src/**', 'a leading ! is not supported'],
		['./!src/**', 'a leading ! is not supported'],
		['a\\b', '\\ is not supported'],
		['{a,{b,c}}', 'a group inside a group is not supported'],
		['{a', 'has a { with no } after it'],
		['a}', 'has a } with no { before it'],
	])('%s is refused, and the message says what a glob holds', (glob, part) => {
		expect(says(glob)).toContain(part);
		expect(says(glob)).toContain('{a,b} groups');
	});

	test('the path rules still apply', () => {
		expect(allowed('/src/**')).toBe(false);
		expect(allowed('src/../**')).toBe(false);
		expect(allowed('-src/**')).toBe(false);
		expect(PointSchema.parse(withGlob('./src//**')).select.paths).toEqual(['src/**']);
	});

	test('a manifest is held to its count of point globs and to the same rules', () => {
		const points = (list: string[]) =>
			VerifyManifestSchema.safeParse({ ...MANIFEST, points: list }).success;
		const many = Array.from({ length: MANIFEST_GLOBS_MAX }, (_, i) => `points/${i}/*.yaml`);
		expect(points(many)).toBe(true);
		expect(points([...many, 'one/more.yaml'])).toBe(false);
		expect(points(['points/[a-z].yaml'])).toBe(false);
		expect(points(['{a,b}'.repeat(11)])).toBe(false);
	});

	describe('point globs in the loader', () => {
		const SMALL_POINT = {
			id: 'tasks.save',
			revision: 1,
			claim: 'A task saved stays saved.',
			select: { paths: ['src/**'] },
			run: { command: ['true'] },
			assertions: [{ name: 'saved', description: 'It is there.', evidence: ['read'] }],
		};
		const project = async (globs: string[], names: string[]) => {
			const root = await mkdtemp(join(tmpdir(), 'koi-verify-globs-'));
			await mkdir(join(root, '.koi/points'), { recursive: true });
			for (const [i, name] of names.entries()) {
				const point = { ...SMALL_POINT, id: `tasks.save${i}` };
				await writeFile(join(root, '.koi/points', name), `${JSON.stringify(point)}\n`);
			}
			await writeFile(
				join(root, '.koi/verify.yaml'),
				`version: 1\npoints: ${JSON.stringify(globs)}\nprofiles: {}\nrunner:\n  image: busybox:1.37\n`,
			);
			return root;
		};

		test('match with the same matcher, braces and dot files too', async () => {
			const root = await project(
				['points/{save,.hidden}.yaml', 'points/?th*.y?ml'],
				['save.yaml', '.hidden.yaml', 'other.yaml', 'skipped.yaml'],
			);
			const config = await loadVerifyConfig(root);
			expect(config.points.map((p) => p.path)).toEqual([
				'.koi/points/.hidden.yaml',
				'.koi/points/other.yaml',
				'.koi/points/save.yaml',
			]);
		});

		test('a glob that matches nothing is still refused', async () => {
			const root = await project(['points/{a,b}.yaml'], ['save.yaml']);
			const err = await loadVerifyConfig(root).catch((e: unknown) => e);
			expect(err).toBeInstanceOf(VerifyConfigError);
			expect((err as Error).message).toContain('matches no file under .koi/');
		});

		test('over the budget, the project does not load, and the error says where', async () => {
			const root = await project(['points/*.yaml'], ['save.yaml']);
			const err = await loadVerifyConfig(root, { budget: 1 }).catch((e: unknown) => e);
			expect(err).toBeInstanceOf(VerifyConfigError);
			expect((err as VerifyConfigError).field).toBe('points');
			expect((err as Error).message).toContain('went past the 1 steps allowed');
		});

		test("steps go on the plan's work when it passes its own", async () => {
			const root = await project(['points/*.yaml'], ['save.yaml']);
			const work = new GlobWork({ over: () => new Error('over'), budget: 10_000 });
			expect((await loadVerifyConfig(root, { work })).points).toHaveLength(1);
			expect(work.steps).toBeGreaterThan(0);

			const over = new Error('over');
			const tight = new GlobWork({ over: () => over, budget: 1 });
			expect(await loadVerifyConfig(root, { work: tight }).catch((e: unknown) => e)).toBe(over);
		});
	});
});

describe('PointSchema', () => {
	test('parses a full point', () => {
		const p = PointSchema.parse(POINT);
		expect(p.requires?.fixtures).toEqual(['fixtures/cart-items.json']);
		expect(p.select.paths).toEqual(['**/CartPanel.tsx', '**/cart_api.py']);
	});

	test('needs only id, revision, claim, select, run and one assertion', () => {
		const p = PointSchema.parse({
			id: 'tasks.create-persists',
			revision: 3,
			claim: 'A task created through the form remains after reload.',
			select: { paths: ['src/**'] },
			run: { command: ['node', 'check.mjs'] },
			assertions: [
				{ name: 'persisted', description: 'The task is there.', evidence: ['task-read'] },
			],
		});
		expect(p.requires).toBeUndefined();
		expect(p.setup).toBeUndefined();
	});

	test.each([
		'app.canvas.save',
		'home',
		'tasks.create-persists',
		'app.http-tool.whitelist',
		'a1.b2',
	])('accepts the id %s', (id) => {
		expect(PointIdSchema.safeParse(id).success).toBe(true);
	});

	test.each([
		'APP.Canvas.Save',
		'app..save',
		'.app',
		'app.',
		'app_canvas',
		'app canvas',
		'',
		'app.-x',
		'-app',
	])('rejects the id %p', (id) => {
		expect(PointIdSchema.safeParse(id).success).toBe(false);
	});

	test.each([
		['an unknown key', { ...POINT, steps: ['Open the canvas.'] }],
		['revision 0', { ...POINT, revision: 0 }],
		['a fractional revision', { ...POINT, revision: 1.5 }],
		['a run command as a shell string', { ...POINT, run: { command: 'node save.mjs' } }],
		['an empty run command', { ...POINT, run: { command: [] } }],
		['a newline in a command argument', { ...POINT, run: { command: ['sh', '-c', 'a\nb'] } }],
		['no assertions', { ...POINT, assertions: [] }],
		[
			'an assertion without evidence',
			{ ...POINT, assertions: [{ name: 'x', description: 'y', evidence: [] }] },
		],
		[
			'two assertions with one name',
			{
				...POINT,
				assertions: [
					{ name: 'x', description: 'y', evidence: ['e'] },
					{ name: 'x', description: 'z', evidence: ['e'] },
				],
			},
		],
		['a select with no paths and no always', { ...POINT, select: { paths: [] } }],
		['an absolute select path', { ...POINT, select: { paths: ['/src/**'] } }],
		['a fixture with ..', { ...POINT, requires: { fixtures: ['../koi.yaml'] } }],
		['an absolute fixture', { ...POINT, requires: { fixtures: ['/etc/passwd'] } }],
		['an unknown provider', { ...POINT, requires: { provider: 'acme' } }],
		['an unknown requirement', { ...POINT, requires: { credential: 'koi-token:anthropic' } }],
		['a budget over an hour', { ...POINT, budgets: { timeoutSeconds: 3601 } }],
	])('rejects %s', (_what, data) => {
		expect(PointSchema.safeParse(data).success).toBe(false);
	});

	test('a select with always and no paths is fine', () => {
		expect(PointSchema.safeParse({ ...POINT, select: { always: true, paths: [] } }).success).toBe(
			true,
		);
	});

	test('a step may list the files under .koi/ its command depends on', () => {
		const run = { command: ['node', 'run.mjs'], files: ['runners/run.mjs', 'runners/lib.mjs'] };
		expect(PointSchema.parse({ ...POINT, run }).run).toEqual(run);
		expect(PointSchema.parse({ ...POINT, cleanup: run }).cleanup).toEqual(run);
		for (const files of [['../run.mjs'], ['/srv/run.mjs'], 'runners/run.mjs', ['']]) {
			expect(PointSchema.safeParse({ ...POINT, run: { ...run, files } }).success).toBe(false);
		}
	});
});

describe('OutcomeSchema', () => {
	test('is exactly the six outcomes', () => {
		expect(OutcomeSchema.options).toEqual([
			'pass',
			'fail',
			'blocked',
			'not-run',
			'needs-review',
			'pass-with-recovery',
		]);
		expect(OutcomeSchema.safeParse('passed').success).toBe(false);
		expect(OutcomeSchema.safeParse('not-applicable').success).toBe(false);
	});
});

describe('RunnerEventSchema', () => {
	test('reads the four kinds of event', () => {
		const events: RunnerEvent[] = [
			{
				type: 'assertion',
				point: 'app.canvas.save',
				name: 'persisted-name',
				outcome: 'pass',
				evidence: ['recorder:screenshot:7'],
			},
			{
				type: 'assertion',
				point: 'app.canvas.save',
				name: 'save-accepted',
				outcome: 'needs-review',
				evidence: [],
				detail: 'the panel closed, but a toast showed for a moment',
			},
			{ type: 'capture', kind: 'screenshot', label: 'after-reload' },
			{ type: 'read', label: 'state-after-save', path: '/api/pipelines/7' },
			{ type: 'read', label: 'head', path: '/', method: 'HEAD' },
			{ type: 'note', text: 'first chat load needed one reconnect' },
			{ type: 'phase', name: 'journey', state: 'start' },
		];
		for (const event of events) expect(RunnerEventSchema.parse(event)).toEqual(event);
	});

	test('acknowledgments and supervisor lines have their own shapes', () => {
		const acks: RunnerAck[] = [
			{ version: 1, type: 'start', key: 'a'.repeat(64), timeoutSeconds: 12.5 },
			{
				version: 1,
				type: 'capture-result',
				label: 'after-reload',
				status: 'ready',
				artifact: 'recorder:screenshot:7',
			},
			{ version: 1, type: 'capture-result', label: 'x', status: 'failed', error: 'withheld' },
		];
		for (const ack of acks) expect(RunnerAckSchema.parse(ack)).toEqual(ack);
		// A start says how long the point has left, which is some time.
		for (const seconds of [undefined, 0, -1, '60']) {
			expect(
				RunnerAckSchema.safeParse({
					version: 1,
					type: 'start',
					key: 'a'.repeat(64),
					timeoutSeconds: seconds,
				}).success,
			).toBe(false);
		}
		// A ready acknowledgment needs an artifact, a failed one a code.
		expect(
			RunnerAckSchema.safeParse({ version: 1, type: 'capture-result', label: 'x', status: 'ready' })
				.success,
		).toBe(false);
		expect(
			RunnerAckSchema.safeParse({
				version: 1,
				type: 'capture-result',
				label: 'x',
				status: 'failed',
				error: 'withheld',
				artifact: 'recorder:screenshot:1',
			}).success,
		).toBe(false);
		expect(
			RunnerAckSchema.safeParse({ version: 2, type: 'start', key: 'a'.repeat(64) }).success,
		).toBe(false);
		// Start hands over what signs the supervisor's lines; none, or a short
		// one, is not start.
		expect(RunnerAckSchema.safeParse({ version: 1, type: 'start' }).success).toBe(false);
		expect(RunnerAckSchema.safeParse({ version: 1, type: 'start', key: 'short' }).success).toBe(
			false,
		);
		const lines: SupervisorLine[] = [
			{ version: 1, type: 'supervisor', event: 'started' },
			{ version: 1, type: 'supervisor', event: 'step', step: 'run', status: 'exited', code: 0 },
			{
				version: 1,
				type: 'supervisor',
				event: 'exit',
				step: 'cleanup',
				status: 'timeout',
				steps: [{ step: 'run', status: 'exited', code: 0, seconds: 1.5 }],
			},
			{ version: 1, type: 'supervisor', event: 'exit', status: 'not-started', steps: [] },
		];
		for (const line of lines) expect(SupervisorLineSchema.parse(line)).toEqual(line);
	});

	test.each([
		['an unknown type', { type: 'verdict', point: 'app.canvas.save', outcome: 'pass' }],
		[
			'a point verdict on an assertion',
			{
				type: 'assertion',
				point: 'app.canvas.save',
				name: 'x',
				outcome: 'pass',
				evidence: [],
				pointOutcome: 'pass',
			},
		],
		[
			'an outcome that is not one of the six',
			{ type: 'assertion', point: 'app.canvas.save', name: 'x', outcome: 'ok', evidence: [] },
		],
		['an unknown capture kind', { type: 'capture', kind: 'video', label: 'x' }],
		['a read of a path off the origin', { type: 'read', label: 'x', path: 'http://a/' }],
		[
			'a read with a method the recorder does not make',
			{ type: 'read', label: 'x', path: '/', method: 'POST' },
		],
		['an unknown phase', { type: 'phase', name: 'assert', state: 'start' }],
		['a note without text', { type: 'note' }],
	])('rejects %s', (_what, data) => {
		expect(RunnerEventSchema.safeParse(data).success).toBe(false);
	});
});

describe('the records koi writes', () => {
	test('a deployment identity names the build, with or without a merge', () => {
		expect(DeploymentIdentitySchema.parse(DEPLOYMENT)).toEqual(DEPLOYMENT);
		const { merge: _merge, ...tree } = DEPLOYMENT;
		expect(DeploymentIdentitySchema.parse(tree)).toEqual(tree);
		expect(
			DeploymentIdentitySchema.safeParse({ ...DEPLOYMENT, imageDigest: 'latest' }).success,
		).toBe(false);
		expect(
			DeploymentIdentitySchema.safeParse({ ...DEPLOYMENT, merge: { head: SHA, base: SHA } })
				.success,
		).toBe(false);
	});

	test('a record gives the identity of what serves, or none while nothing does', () => {
		const deployment = {
			requestId: ID,
			deploymentId: DEPLOYMENT.deploymentId,
			imageDigest: DEPLOYMENT.imageDigest,
			commit: DEPLOYMENT.commit,
			merge: DEPLOYMENT.merge,
			image: 'koi-preview/hello-pr-7:a',
			container: 'koi-hello-pr-7-a',
			port: 8080,
			healthPath: '/',
			healthTimeoutSeconds: 60,
			user: '65534:65534',
			env: {},
			deployedAt: '2026-10-06T00:00:00.000Z',
		};
		const record: PreviewRecord = {
			label: 'hello-pr-7',
			project: 'hello',
			repo: 'github.com/acme/hello',
			status: 'running',
			// The record's latest request is another build; the identity
			// describes the deployment, not the record.
			commit: 'f'.repeat(40),
			branch: 'feature',
			pr: 7,
			merge: { head: '1'.repeat(40), base: '2'.repeat(40), baseBranch: 'develop' },
			dirty: false,
			requestId: 'r'.repeat(16),
			attempt: 'b'.repeat(20),
			ttlDays: 7,
			createdAt: '2026-10-06T00:00:00.000Z',
			updatedAt: '2026-10-06T00:00:00.000Z',
			deployment,
		};
		expect(deploymentIdentity(record)).toEqual(DEPLOYMENT);
		// A merge the identity can carry needs its base branch.
		const { merge: _merge, ...tree } = DEPLOYMENT;
		const { baseBranch: _unnamed, ...unnamed } = DEPLOYMENT.merge as NonNullable<
			typeof DEPLOYMENT.merge
		>;
		expect(
			deploymentIdentity({ ...record, deployment: { ...deployment, merge: unnamed } }),
		).toEqual(tree);
		const { merge: _none, ...plain } = deployment;
		expect(deploymentIdentity({ ...record, deployment: plain })).toEqual(tree);
		// Nothing serves: no deployment, one stopped for disk use, an expired
		// preview, or a deployment from before koid kept ids and digests.
		const { deployment: _gone, ...bare } = record;
		expect(deploymentIdentity(bare)).toBeUndefined();
		expect(
			deploymentIdentity({ ...record, deployment: { ...deployment, halted: 'disk' } }),
		).toBeUndefined();
		expect(deploymentIdentity({ ...record, status: 'expired' })).toBeUndefined();
		const { deploymentId: _id, imageDigest: _digest, ...old } = deployment;
		expect(deploymentIdentity({ ...record, deployment: old })).toBeUndefined();
	});

	test('a plan lists each point once, taken or blocked, with its runner files', () => {
		const taken = {
			id: 'app.canvas.save',
			revision: 1,
			digest: DIGEST,
			runners: [{ path: '.koi/runners/storefront.mjs', digest: DIGEST }],
			why: 'always in profile pr',
		};
		const plan: Plan = {
			version: 1,
			planId: ID,
			deployment: DEPLOYMENT,
			profile: 'pr',
			points: [taken],
			blocked: [{ id: 'app.http-tool.whitelist', reason: 'capability missing: http-tool-dns' }],
			uncovered: ['src/payments/**'],
			planDigest: DIGEST,
		};
		expect(PlanSchema.parse(plan)).toEqual(plan);
		expect(PlanSchema.parse({ ...plan, points: [{ ...taken, runners: [] }] }).points).toEqual([
			{ ...taken, runners: [] },
		]);
		expect(
			PlanSchema.safeParse({ ...plan, blocked: [{ id: 'app.canvas.save', reason: 'twice' }] })
				.success,
		).toBe(false);
		expect(PlanSchema.safeParse({ ...plan, verdict: 'pass' }).success).toBe(false);
		// A runner file is always under .koi/, and a point always says which.
		const { runners: _runners, ...noRunners } = taken;
		expect(PlanSchema.safeParse({ ...plan, points: [noRunners] }).success).toBe(false);
		for (const path of ['runners/x.mjs', '/.koi/runners/x.mjs', '.koi/../x.mjs', '.koi']) {
			expect(RunnerFileSchema.safeParse({ path, digest: DIGEST }).success, path).toBe(false);
		}
		expect(RunnerFileSchema.safeParse({ path: '.koi/runners/x.mjs', digest: 'abc' }).success).toBe(
			false,
		);
	});

	test('a runner file path follows the rule of a files entry: what KoiPathSchema refuses, RunnerFileSchema refuses behind .koi/', () => {
		const refused = [
			'',
			'.',
			'./',
			'/etc/passwd',
			'../x.mjs',
			'runners/../../x.mjs',
			'runners\\x.mjs',
			'runners/x\u0000.mjs',
			'runners/x.mjs\n',
			'x'.repeat(256),
		];
		for (const inside of refused) {
			expect(KoiPathSchema.safeParse(inside).success, inside).toBe(false);
			expect(
				RunnerFileSchema.safeParse({ path: `.koi/${inside}`, digest: DIGEST }).success,
				inside,
			).toBe(false);
		}
		// What it accepts, in the form it gives, RunnerFileSchema accepts behind
		// .koi/: a colon, a leading dash, an @, a name 255 characters long.
		const accepted = [
			'runners/check:v1.sh',
			'runners/-x.sh',
			'a:b/c@d.sh',
			'x'.repeat(255),
			'./runners//x.sh',
		];
		for (const inside of accepted) {
			const path = `.koi/${KoiPathSchema.parse(inside)}`;
			expect(RunnerFileSchema.parse({ path, digest: DIGEST }).path).toBe(path);
		}
		// Only in that form: the loader writes no "." or empty segment, so a
		// path with one is not something the loader returned.
		for (const path of ['.koi/./x.mjs', '.koi//x.mjs', '.koi/x.mjs/']) {
			expect(RunnerFileSchema.safeParse({ path, digest: DIGEST }).success, path).toBe(false);
		}
	});

	test('a run has finishedAt exactly when it is no longer running', () => {
		const run: Run = {
			version: 1,
			runId: ID,
			planId: ID,
			deployment: DEPLOYMENT,
			planDigest: DIGEST,
			state: 'running',
			startedAt: '2026-10-31T10:00:00.000Z',
		};
		expect(RunSchema.parse(run)).toEqual(run);
		const done: Run = { ...run, state: 'completed', finishedAt: '2026-10-31T10:05:00.000Z' };
		expect(RunSchema.parse(done)).toEqual(done);
		expect(RunSchema.safeParse({ ...run, state: 'completed' }).success).toBe(false);
		expect(RunSchema.safeParse({ ...run, finishedAt: done.finishedAt }).success).toBe(false);
		expect(RunSchema.safeParse({ ...run, state: 'failed' }).success).toBe(false);
	});

	test('a result gives each point one outcome', () => {
		const result: Result = {
			version: 1,
			runId: ID,
			outcome: 'incomplete',
			points: [
				{ id: 'app.canvas.save', outcome: 'pass', evidence: ['artifact:image:14'] },
				{
					id: 'app.http-tool.whitelist',
					outcome: 'blocked',
					reason: 'capability missing: http-tool-dns',
					evidence: [],
				},
			],
			uncovered: ['HTTP tool positive request'],
		};
		expect(ResultSchema.parse(result)).toEqual(result);
		expect(
			ResultSchema.safeParse({ ...result, points: [...result.points, result.points[0]] }).success,
		).toBe(false);
		expect(ResultSchema.safeParse({ ...result, outcome: 'pass' }).success).toBe(false);
	});

	describe("a result's outcome follows from its points", () => {
		type PointResult = Result['points'][number];
		const result = (outcome: Result['outcome'], points: PointResult[]): Result => ({
			version: 1,
			runId: ID,
			outcome,
			points,
			uncovered: [],
		});
		const pass: PointResult = { id: 'a.one', outcome: 'pass', evidence: ['artifact:image:1'] };
		const fail: PointResult = {
			id: 'a.two',
			outcome: 'fail',
			reason: 'the body says goodbye',
			evidence: ['artifact:image:2'],
		};
		const blocked: PointResult = {
			id: 'a.three',
			outcome: 'blocked',
			reason: 'capability missing: browser',
			evidence: [],
		};
		const recovered: PointResult = {
			...pass,
			outcome: 'pass-with-recovery',
			reason: 'the first load needed one reconnect',
		};
		const noReason = ({ reason: _reason, ...p }: PointResult): PointResult => p;

		test('a blocked point leaves the run not passed, and a mask is no point id', () => {
			expect(ResultSchema.parse(result('incomplete', [pass, blocked]))).toBeDefined();
			expect(ResultSchema.safeParse(result('passed', [pass, blocked])).success).toBe(false);
			for (const id of ['refused:1', '[redacted]']) {
				expect(ResultSchema.safeParse(result('incomplete', [{ ...blocked, id }])).success).toBe(
					false,
				);
			}
		});

		test.each<[string, Result]>([
			['passed with every point passing', result('passed', [pass])],
			['passed with no points', result('passed', [])],
			['failed with a failed point among others', result('failed', [pass, blocked, fail])],
			['incomplete with a blocked point and no failed one', result('incomplete', [pass, blocked])],
			['incomplete with a recovery, which is not a plain pass', result('incomplete', [recovered])],
		])('accepts %s', (_what, data) => {
			expect(ResultSchema.parse(data)).toEqual(data);
		});

		test.each<[string, Result, PropertyKey[]]>([
			['passed with a blocked point', result('passed', [pass, blocked]), ['outcome']],
			['passed with a failed point', result('passed', [fail]), ['outcome']],
			['passed with a recovery', result('passed', [recovered]), ['outcome']],
			['failed with no failed point', result('failed', [pass, blocked]), ['outcome']],
			['failed with no points', result('failed', []), ['outcome']],
			['incomplete with a failed point', result('incomplete', [blocked, fail]), ['outcome']],
			['incomplete with every point passing', result('incomplete', [pass]), ['outcome']],
			['incomplete with no points', result('incomplete', []), ['outcome']],
			[
				'a failed point without a reason',
				result('failed', [noReason(fail)]),
				['points', 0, 'reason'],
			],
			[
				'a blocked point without a reason',
				result('incomplete', [pass, noReason(blocked)]),
				['points', 1, 'reason'],
			],
			[
				'a recovered point without a reason',
				result('incomplete', [noReason(recovered)]),
				['points', 0, 'reason'],
			],
			['an empty reason', result('failed', [{ ...fail, reason: '' }]), ['points', 0, 'reason']],
		])('rejects %s', (_what, data, path) => {
			const parsed = ResultSchema.safeParse(data);
			expect(parsed.success).toBe(false);
			expect(parsed.error?.issues[0]?.path).toEqual(path);
		});
	});

	test('a proof record names a failing and a passing run, not the same one', () => {
		const proof: ProofRecord = {
			pointId: 'app.canvas.save',
			revision: 1,
			mutation: { kind: 'patch', digest: DIGEST },
			failingRunId: ID,
			passingRunId: 'd'.repeat(20),
			provenAt: '2026-10-31T10:00:00.000Z',
		};
		expect(ProofRecordSchema.parse(proof)).toEqual(proof);
		expect(ProofRecordSchema.safeParse({ ...proof, passingRunId: ID }).success).toBe(false);
		expect(
			ProofRecordSchema.safeParse({ ...proof, mutation: { kind: 'manual', digest: DIGEST } })
				.success,
		).toBe(false);
	});

	test('a required policy names each point once, at a revision, and cannot waive proof', () => {
		const policy = RequiredPolicySchema.parse({
			version: 1,
			required: [
				{ id: 'app.canvas.save', revision: 2 },
				{ id: 'app.canvas.icons', revision: 1 },
			],
		});
		expect(policy.required).toEqual([
			{ id: 'app.canvas.save', revision: 2 },
			{ id: 'app.canvas.icons', revision: 1 },
		]);
		// Proof is always required of a required point; there is no field that
		// says otherwise.
		expect(
			RequiredPolicySchema.safeParse({
				version: 1,
				required: [{ id: 'app.canvas.icons', revision: 1, requireProof: false }],
			}).success,
		).toBe(false);
		expect(
			RequiredPolicySchema.safeParse({
				version: 1,
				required: [
					{ id: 'app.canvas.save', revision: 1 },
					{ id: 'app.canvas.save', revision: 2 },
				],
			}).success,
		).toBe(false);
		expect(
			RequiredPolicySchema.safeParse({ version: 1, required: [], exempt: ['docs/**'] }).success,
		).toBe(false);
	});
});

// A source tree with the given files under .koi/, by path relative to .koi/.
async function tree(files: Record<string, string>): Promise<string> {
	const root = await mkdtemp(join(tmpdir(), 'koi-verify-'));
	for (const [path, text] of Object.entries(files)) {
		const full = join(root, '.koi', path);
		await mkdir(dirname(full), { recursive: true });
		await writeFile(full, text);
	}
	return root;
}

const manifest = (extra = '') => `version: 1
points: [points/*.yaml]
profiles:
  pr: { always: [a.one], select: changed }
runner: { image: busybox:1.37 }
${extra}`;

const point = (id: string, extra = '') => `id: ${id}
revision: 1
claim: Something a user sees.
select: { paths: ["src/**"] }
run: { command: [sh, .koi/runners/x.sh] }
assertions:
  - { name: shows, description: It shows., evidence: [screenshot] }
${extra}`;

async function failure(root: string): Promise<VerifyConfigError> {
	const err = await loadVerifyConfig(root).catch((e: unknown) => e);
	expect(err).toBeInstanceOf(VerifyConfigError);
	return err as VerifyConfigError;
}

describe('loadVerifyConfig', () => {
	test('loads the hello example: its manifest, its one point, its runner and the digests of all three files', async () => {
		const config = await loadVerifyConfig(HELLO);
		expect(config.manifest.points).toEqual(['points/*.yaml']);
		expect(config.manifest.profiles.pr?.always).toEqual(['hello.home']);
		expect(config.manifest.runner.image).toBe('koi-verifier');
		expect(config.points.map((p) => p.path)).toEqual(['.koi/points/home.yaml']);
		const home = config.points[0]?.point;
		expect(home?.id).toBe('hello.home');
		expect(home?.assertions.map((a) => [a.name, a.evidence])).toEqual([
			['home-says-hello', ['screenshot', 'http-response']],
		]);
		// The command names the runner script, relative to the source root,
		// and that makes the script one of the point's runner files.
		expect(home?.run.command[1]).toBe('.koi/runners/home.py');
		expect(existsSync(join(HELLO, home?.run.command[1] ?? ''))).toBe(true);
		expect(config.points[0]?.runners).toEqual([
			{ path: '.koi/runners/home.py', digest: config.digests['.koi/runners/home.py'] ?? '' },
		]);
		expect(Object.keys(config.digests).sort()).toEqual([
			'.koi/points/home.yaml',
			'.koi/runners/home.py',
			'.koi/verify.yaml',
		]);
		for (const [path, sha] of Object.entries(config.digests)) {
			expect(sha).toBe(digest(new Uint8Array(await readFile(join(HELLO, path)))));
			expect(sha).toMatch(/^sha256:[0-9a-f]{64}$/);
		}
	});

	test('loads several points through several globs, sorted by path, each file once', async () => {
		const root = await tree({
			'verify.yaml': manifest().replace(
				'points: [points/*.yaml]',
				'points: [points/*.yaml, "points/**/*.yaml", more/b.yaml]',
			),
			'points/a.yaml': point('a.one'),
			'points/sub/c.yaml': point('a.three'),
			'more/b.yaml': point('a.two'),
			'README.md': 'not a point\n',
		});
		const config = await loadVerifyConfig(root);
		expect(config.points.map((p) => [p.path, p.point.id])).toEqual([
			['.koi/more/b.yaml', 'a.two'],
			['.koi/points/a.yaml', 'a.one'],
			['.koi/points/sub/c.yaml', 'a.three'],
		]);
		expect(Object.keys(config.digests)).toHaveLength(4);
	});

	describe('a runner.command prefix', () => {
		const prefixed = (command: string) =>
			manifest().replace(
				'runner: { image: busybox:1.37 }',
				`runner: { image: busybox:1.37, command: ${command} }`,
			);
		const files = (command: string) => ({
			'verify.yaml': prefixed(command),
			'points/a.yaml': point('a.one'),
			'points/b.yaml': point('a.two').replace('.koi/runners/x.sh', '.koi/runners/y.sh'),
			'runners/x.sh': 'true\n',
			'runners/y.sh': 'true\n',
			'runners/wrapper.py': 'print("wrapped")\n',
		});

		test('is a runner file of every point, and so in the digests a snapshot copies', async () => {
			const root = await tree(files('[python3, .koi/runners/wrapper.py]'));
			const config = await loadVerifyConfig(root);
			const digest = config.digests['.koi/runners/wrapper.py'];
			expect(digest).toBeDefined();
			expect(config.points.map((p) => p.runners.map((r) => r.path))).toEqual([
				['.koi/runners/wrapper.py', '.koi/runners/x.sh'],
				['.koi/runners/wrapper.py', '.koi/runners/y.sh'],
			]);
			for (const p of config.points) {
				expect(p.runners.find((r) => r.path === '.koi/runners/wrapper.py')?.digest).toBe(
					digest as string,
				);
			}
		});

		test('changing the wrapper changes the digest of each point it runs', async () => {
			const root = await tree(files('[python3, ./.koi/runners/wrapper.py]'));
			const before = await loadVerifyConfig(root);
			await writeFile(join(root, '.koi/runners/wrapper.py'), 'print("changed")\n');
			const after = await loadVerifyConfig(root);
			const of = (config: Awaited<ReturnType<typeof loadVerifyConfig>>) =>
				config.points.map((p) => p.runners.find((r) => r.path.endsWith('wrapper.py'))?.digest);
			expect(of(before).every((d) => d !== undefined)).toBe(true);
			expect(of(after)[0]).not.toBe(of(before)[0] as string);
			expect(of(after)[1]).not.toBe(of(before)[1] as string);
			// The point's own digest does not move, so this is the only place it shows.
			expect(after.digests['.koi/points/a.yaml']).toBe(
				before.digests['.koi/points/a.yaml'] as string,
			);
		});

		test('refuses a path under .koi/ that names no file, as a files entry is refused', async () => {
			const root = await tree(files('[python3, .koi/runners/missing.py]'));
			const err = await failure(root);
			expect(err.file).toBe('.koi/verify.yaml');
			expect(err.field).toBe('runner.command[1]');
			expect(err.message).toBe(
				'.koi/verify.yaml: runner.command[1]: no file runners/missing.py under .koi/',
			);
		});

		test('refuses a path that leaves the project, or .koi/ by way of ..', async () => {
			for (const arg of ['../wrapper.py', '.koi/../../wrapper.py', '.koi/runners/../x.sh']) {
				const err = await failure(await tree(files(`[python3, "${arg}"]`)));
				expect(err.message).toBe(
					'.koi/verify.yaml: runner.command[1]: must not contain a .. segment',
				);
			}
		});

		test('leaves what reads as no path in the project alone', async () => {
			const root = await tree(
				files('[/usr/bin/env, python3, -u, --config=../x, "sh -c cd ../x", scripts/run.py]'),
			);
			const config = await loadVerifyConfig(root);
			expect(config.points[0]?.runners.map((r) => r.path)).toEqual(['.koi/runners/x.sh']);
		});
	});

	test('refuses a symlink to a file, even one that stays inside .koi/', async () => {
		const root = await tree({
			'verify.yaml': manifest(),
			'shared/a.yaml': point('a.one'),
		});
		await mkdir(join(root, '.koi', 'points'));
		await symlink('../shared/a.yaml', join(root, '.koi', 'points', 'a.yaml'));
		expect((await failure(root)).message).toBe(
			'.koi/points/a.yaml: is a symlink; nothing under .koi/ may be one',
		);
	});

	test('refuses a symlink to a directory inside .koi/, which would hide a runner from the digests', async () => {
		// With alias -> runners, the command names runners/check.sh as
		// .koi/alias/check.sh. The script is there and would run, but the
		// loader lists it as runners/check.sh only, so the alias path matches
		// nothing it listed, and a change to the script would change no
		// digest. The tree is refused instead of the runner being skipped.
		const root = await tree({
			'verify.yaml': manifest(),
			'points/a.yaml': point('a.one').replace('.koi/runners/x.sh', '.koi/alias/check.sh'),
			'runners/check.sh': 'echo one\n',
		});
		await symlink('runners', join(root, '.koi', 'alias'));
		expect(existsSync(join(root, '.koi', 'alias', 'check.sh'))).toBe(true);
		expect((await failure(root)).message).toBe(
			'.koi/alias: is a symlink; nothing under .koi/ may be one',
		);
	});

	test('digests the runner files a point names in a command or lists in files, apart from the point itself', async () => {
		const root = await tree({
			'verify.yaml': manifest(),
			// run names .koi/runners/x.sh; setup lists a module its command
			// does not name; cleanup names the script another way, a file
			// outside .koi/, and a file under .koi/ that is not there.
			'points/a.yaml': point(
				'a.one',
				'setup: { command: [node, run.mjs, seed], files: [runners/lib.mjs] }\ncleanup: { command: [sh, ./.koi/runners/x.sh, Dockerfile, .koi/runners/none.sh] }\n',
			),
			'runners/x.sh': 'echo one\n',
			'runners/lib.mjs': 'export const n = 1;\n',
		});
		const before = await loadVerifyConfig(root);
		const runners = before.points[0]?.runners ?? [];
		expect(runners.map((r) => r.path)).toEqual(['.koi/runners/lib.mjs', '.koi/runners/x.sh']);
		for (const r of runners) expect(before.digests[r.path]).toBe(r.digest);
		expect(Object.keys(before.digests)).toHaveLength(4);
		// Changing only the script changes its digest and nothing else.
		await writeFile(join(root, '.koi/runners/x.sh'), 'echo two\n');
		const after = await loadVerifyConfig(root);
		expect(after.digests['.koi/points/a.yaml']).toBe(before.digests['.koi/points/a.yaml'] ?? '');
		expect(after.points[0]?.runners[0]).toEqual(runners[0] ?? { path: '', digest: '' });
		expect(after.points[0]?.runners[1]?.path).toBe('.koi/runners/x.sh');
		expect(after.points[0]?.runners[1]?.digest).not.toBe(runners[1]?.digest);
		expect(after.points[0]?.runners[1]?.digest).toBe(
			digest(new TextEncoder().encode('echo two\n')),
		);
	});

	test('returns runner paths a plan can hold, colon and all', async () => {
		// A files entry may hold a colon (runners/check:v1.sh), so the plan's
		// RunnerFileSchema must take one too, or a point the loader accepts
		// could not be planned. Both go through KoiPathSchema.
		const root = await tree({
			'verify.yaml': manifest(),
			'points/a.yaml': point('a.one').replace(
				'run: { command: [sh, .koi/runners/x.sh] }',
				'run: { command: [sh, ".koi/runners/check:v1.sh"], files: ["runners/lib:v1.mjs"] }',
			),
			'runners/check:v1.sh': 'echo one\n',
			'runners/lib:v1.mjs': 'export const n = 1;\n',
		});
		const config = await loadVerifyConfig(root);
		const runners = config.points[0]?.runners ?? [];
		expect(runners.map((r) => r.path)).toEqual([
			'.koi/runners/check:v1.sh',
			'.koi/runners/lib:v1.mjs',
		]);
		const plan = PlanSchema.parse({
			version: 1,
			planId: ID,
			deployment: DEPLOYMENT,
			profile: 'pr',
			points: [
				{
					id: 'a.one',
					revision: 1,
					digest: config.digests['.koi/points/a.yaml'],
					runners,
					why: 'always in profile pr',
				},
			],
			blocked: [],
			uncovered: [],
			planDigest: DIGEST,
		});
		expect(plan.points[0]?.runners).toEqual(runners);
	});

	test('rejects a runner file entry that is absolute, has .., or names no file', async () => {
		for (const [step, path, detail] of [
			['run', '/etc/passwd', 'must be relative to .koi/, not absolute'],
			['setup', '../home.sh', 'must not contain a .. segment'],
			['cleanup', 'runners/none.sh', 'no file runners/none.sh under .koi/'],
		]) {
			const line = `${step}: { command: [sh, x.sh], files: ["${path}"] }`;
			const text =
				step === 'run'
					? point('a.one').replace('run: { command: [sh, .koi/runners/x.sh] }', line)
					: `${point('a.one')}${line}\n`;
			const root = await tree({
				'verify.yaml': manifest(),
				'points/a.yaml': text,
				'runners/x.sh': 'echo\n',
			});
			const err = await failure(root);
			expect(err.message).toBe(`.koi/points/a.yaml: ${step}.files[0]: ${detail}`);
		}
	});

	test('refuses a listed file that is a symlink by the time it is read, and bounds what it reads', async () => {
		const root = await tree({ 'verify.yaml': manifest(), 'points/a.yaml': point('a.one') });
		// What was a regular file when listed is a symlink when opened: the
		// open must not follow it, wherever it points.
		await symlink('a.yaml', join(root, '.koi/points/link.yaml'));
		const err = await readVerifyFile(
			join(root, '.koi/points/link.yaml'),
			'.koi/points/link.yaml',
		).catch((e: unknown) => e);
		expect(err).toBeInstanceOf(VerifyConfigError);
		expect((err as Error).message).toBe(
			'.koi/points/link.yaml: is a symlink; it was listed as a regular file',
		);
		const bytes = await readVerifyFile(join(root, '.koi/points/a.yaml'), '.koi/points/a.yaml');
		expect(new TextDecoder().decode(bytes)).toBe(point('a.one'));
		await expect(readVerifyFile(join(root, '.koi/points'), '.koi/points')).rejects.toThrow(
			'.koi/points: is not a regular file',
		);
		// The size comes from the open descriptor, before any byte is read.
		await writeFile(join(root, '.koi/big'), 'x'.repeat(MAX_VERIFY_FILE_BYTES + 1));
		await expect(readVerifyFile(join(root, '.koi/big'), '.koi/big')).rejects.toThrow(
			`.koi/big: is ${MAX_VERIFY_FILE_BYTES + 1} bytes; the most koi reads is ${MAX_VERIFY_FILE_BYTES}`,
		);
		await writeFile(join(root, '.koi/edge'), 'x'.repeat(MAX_VERIFY_FILE_BYTES));
		expect((await readVerifyFile(join(root, '.koi/edge'), '.koi/edge')).length).toBe(
			MAX_VERIFY_FILE_BYTES,
		);
	});

	test('rejects two points with one id, naming both files', async () => {
		const root = await tree({
			'verify.yaml': manifest(),
			'points/a.yaml': point('a.one'),
			'points/b.yaml': point('a.one'),
		});
		const err = await failure(root);
		expect(err.file).toBe('.koi/points/b.yaml');
		expect(err.field).toBe('id');
		expect(err.message).toBe('.koi/points/b.yaml: id: a.one is also the id of .koi/points/a.yaml');
	});

	test('rejects a skill path that is absolute, has .., or names no file', async () => {
		for (const [path, detail] of [
			['/etc/passwd', 'must be relative to .koi/, not absolute'],
			['../koi.yaml', 'must not contain a .. segment'],
			['skills/x/SKILL.md', 'no file skills/x/SKILL.md under .koi/'],
		]) {
			const root = await tree({
				'verify.yaml': manifest(`skills: [{ id: x, path: "${path}" }]\n`),
				'points/a.yaml': point('a.one'),
			});
			const err = await failure(root);
			expect(err.message).toBe(`.koi/verify.yaml: skills[0].path: ${detail}`);
		}
	});

	test('rejects a point glob that is absolute, has .., or matches nothing', async () => {
		for (const [glob, detail] of [
			['/points/*.yaml', 'must be relative to .koi/, not absolute'],
			['../**/*.yaml', 'must not contain a .. segment'],
			['nowhere/*.yaml', 'matches no file under .koi/'],
		]) {
			const root = await tree({
				'verify.yaml': manifest().replace('[points/*.yaml]', `["${glob}"]`),
				'points/a.yaml': point('a.one'),
			});
			const err = await failure(root);
			expect(err.message).toBe(`.koi/verify.yaml: points[0]: ${detail}`);
		}
	});

	test('rejects a fixture path that is absolute, has .., or names no file', async () => {
		for (const [path, detail] of [
			['/etc/passwd', 'must be relative to .koi/, not absolute'],
			['../koi.yaml', 'must not contain a .. segment'],
			['fixtures/missing.txt', 'no file fixtures/missing.txt under .koi/'],
		]) {
			const root = await tree({
				'verify.yaml': manifest(),
				'points/a.yaml': point('a.one', `requires: { fixtures: ["${path}"] }\n`),
				'fixtures/probe.txt': 'probe\n',
			});
			const err = await failure(root);
			expect(err.message).toBe(`.koi/points/a.yaml: requires.fixtures[0]: ${detail}`);
		}
	});

	test('refuses a symlink that leaves .koi/, to a file or to a directory, like any other', async () => {
		const outside = await mkdtemp(join(tmpdir(), 'koi-outside-'));
		await writeFile(join(outside, 'evil.yaml'), point('a.one'));
		const file = await tree({ 'verify.yaml': manifest(), 'points/a.yaml': point('a.one') });
		await symlink(join(outside, 'evil.yaml'), join(file, '.koi', 'points', 'evil.yaml'));
		expect((await failure(file)).message).toBe(
			'.koi/points/evil.yaml: is a symlink; nothing under .koi/ may be one',
		);
		const dir = await tree({ 'verify.yaml': manifest(), 'points/a.yaml': point('a.one') });
		await symlink(outside, join(dir, '.koi', 'fixtures'));
		expect((await failure(dir)).message).toBe(
			'.koi/fixtures: is a symlink; nothing under .koi/ may be one',
		);
		// A symlink to a file the loader never reads is refused all the same.
		const linkToRoot = await tree({ 'verify.yaml': manifest(), 'points/a.yaml': point('a.one') });
		await writeFile(join(linkToRoot, 'koi.yaml'), 'port: 1\n');
		await symlink('../koi.yaml', join(linkToRoot, '.koi', 'koi.yaml'));
		expect((await failure(linkToRoot)).message).toBe(
			'.koi/koi.yaml: is a symlink; nothing under .koi/ may be one',
		);
	});

	test('rejects .koi/ itself being a symlink', async () => {
		const root = await mkdtemp(join(tmpdir(), 'koi-verify-'));
		const elsewhere = await tree({ 'verify.yaml': manifest(), 'points/a.yaml': point('a.one') });
		await symlink(join(elsewhere, '.koi'), join(root, '.koi'));
		expect((await failure(root)).message).toBe(
			'.koi: is a symlink; .koi/ must be a real directory',
		);
	});

	test('rejects a file over 256 KiB before reading it', async () => {
		const root = await tree({
			'verify.yaml': manifest(),
			'points/a.yaml': point('a.one'),
			'points/big.yaml': point('a.two', `# ${'x'.repeat(MAX_VERIFY_FILE_BYTES)}\n`),
		});
		const err = await failure(root);
		expect(err.file).toBe('.koi/points/big.yaml');
		expect(err.message).toMatch(
			/^\.koi\/points\/big\.yaml: is \d+ bytes; the most koi reads is 262144$/,
		);
	});

	test('rejects a profile that names a point that does not exist', async () => {
		const root = await tree({
			'verify.yaml': manifest().replace('always: [a.one]', 'always: [a.one, a.none]'),
			'points/a.yaml': point('a.one'),
		});
		expect((await failure(root)).message).toBe(
			'.koi/verify.yaml: profiles.pr.always[1]: no point a.none',
		);
		const include = await tree({
			'verify.yaml': manifest().replace(
				'select: changed }',
				'select: changed }\n  matrix: { include: [a.gone] }',
			),
			'points/a.yaml': point('a.one'),
		});
		expect((await failure(include)).message).toBe(
			'.koi/verify.yaml: profiles.matrix.include[0]: no point a.gone',
		);
	});

	test('names the file and field of a schema error', async () => {
		const bad = await tree({
			'verify.yaml': manifest(),
			'points/a.yaml': point('a.one').replace(
				'command: [sh, .koi/runners/x.sh]',
				'command: sh x.sh',
			),
		});
		const err = await failure(bad);
		expect(err.file).toBe('.koi/points/a.yaml');
		expect(err.field).toBe('run.command');
		const deep = await tree({
			'verify.yaml': manifest(),
			'points/a.yaml': point('a.one').replace('evidence: [screenshot]', 'evidence: []'),
		});
		expect((await failure(deep)).field).toBe('assertions[0].evidence');
		const unknown = await tree({
			'verify.yaml': manifest('required: [a.one]\n'),
			'points/a.yaml': point('a.one'),
		});
		expect((await failure(unknown)).message).toBe('.koi/verify.yaml: Unrecognized key: "required"');
	});

	test('rejects YAML that does not parse, naming the file', async () => {
		const root = await tree({
			'verify.yaml': manifest(),
			'points/a.yaml': 'id: [a.one\n',
		});
		const err = await failure(root);
		expect(err.file).toBe('.koi/points/a.yaml');
		expect(err.field).toBeUndefined();
	});

	test('says when there is no .koi/ or no verify.yaml', async () => {
		const none = await mkdtemp(join(tmpdir(), 'koi-verify-'));
		expect((await failure(none)).message).toBe('.koi/verify.yaml: not found');
		const empty = await tree({ 'points/a.yaml': point('a.one') });
		expect((await failure(empty)).message).toBe('.koi/verify.yaml: not found');
	});
});
