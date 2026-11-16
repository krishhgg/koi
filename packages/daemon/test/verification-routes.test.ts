import { describe, expect, test } from 'bun:test';
import {
	type ArtifactChunk,
	type EvidenceReply,
	type PlanReply,
	type RunAccepted,
	type RunEventsPage,
	type RunStatusReply,
	RunStatusReplySchema,
	VERIFICATION_ERROR_MESSAGE_MAX,
	VERIFICATION_REPLY_MAX_BYTES,
	VerificationErrorReplySchema,
} from '@koi/shared';
import { type ControlDeps, control, type VerificationApi } from '../src/control.ts';
import { VerificationError } from '../src/verification.ts';

// The verification routes over the control API, with the controller faked:
// what each route reads from the request, what it answers with, and how
// refusals come back.

const PLAN = 'p'.repeat(20);
const RUN = 'r'.repeat(20);
const DIGEST = `sha256:${'1'.repeat(64)}`;

const deployment = {
	label: 'hello-pr-7',
	deploymentId: 'd'.repeat(20),
	imageDigest: `sha256:${'2'.repeat(64)}`,
	commit: 'c'.repeat(40),
};

const plan: PlanReply = {
	version: 1,
	planId: PLAN,
	planDigest: DIGEST,
	label: 'hello-pr-7',
	deployment,
	profile: 'pr',
	advisory: false,
	counts: { selected: 1, blocked: 0, uncovered: 0, required: 0 },
	policy: { source: 'none' },
	limits: { runSeconds: 900, pointSeconds: 300, runRequests: 50, pointRequests: 20 },
	runnerImage: 'curlimages/curl:8.11.1',
	originMode: 'private-app',
	notes: [],
	points: [{ id: 'hello.home', revision: 1, why: 'always', proof: 'none', required: false }],
	blocked: [],
	uncovered: [],
	createdAt: '2026-10-06T12:00:00.000Z',
};

const accepted: RunAccepted = {
	version: 1,
	runId: RUN,
	planId: PLAN,
	planDigest: DIGEST,
	deployment,
	state: 'running',
	leaseExpiresAt: '2026-10-06T12:17:00.000Z',
	limits: plan.limits,
	startedAt: '2026-10-06T12:00:00.000Z',
};

const status: RunStatusReply = {
	version: 1,
	runId: RUN,
	planId: PLAN,
	planDigest: DIGEST,
	label: 'hello-pr-7',
	deployment,
	profile: 'pr',
	advisory: false,
	state: 'running',
	cancelRequested: false,
	readiness: { eligibleForMergeGate: false, reasons: ['the run is not finished'] },
	freshness: 'current',
	evidence: 'collecting',
	finalized: false,
	cleanup: 'unknown',
	limits: plan.limits,
	leaseExpiresAt: accepted.leaseExpiresAt,
	progress: { total: 1, done: 0 },
	points: [{ id: 'hello.home', state: 'pending', evidence: [] }],
	problems: [],
	problemCount: 0,
	startedAt: accepted.startedAt,
};

const events: RunEventsPage = {
	version: 1,
	runId: RUN,
	events: [{ seq: 1, at: accepted.startedAt, source: 'host', type: 'run-started' }],
	next: 1,
	more: false,
};

const evidence: EvidenceReply = {
	version: 1,
	runId: RUN,
	finalized: false,
	expired: false,
	status: {
		version: 1,
		runId: RUN,
		state: 'running',
		evidence: 'collecting',
		startedAt: accepted.startedAt,
		updatedAt: accepted.startedAt,
		counts: { events: 1, artifacts: 0, bytes: 0 },
		problems: [],
	},
	limitations: [],
	artifactCount: 0,
	artifacts: [],
};

const chunk: ArtifactChunk = {
	version: 1,
	runId: RUN,
	artifact: 'recorder:aria:2',
	kind: 'aria',
	mediaType: 'text/plain',
	size: 5,
	sha256: DIGEST,
	offset: 0,
	length: 5,
	dataBase64: Buffer.from('hello').toString('base64'),
	truncated: false,
};

function fake(): VerificationApi & { calls: string[] } {
	const calls: string[] = [];
	return {
		calls,
		async plan(request) {
			calls.push(`plan ${request.label} ${request.profile} ${request.expectedDeploymentId ?? '-'}`);
			if (request.label === 'nobody-pr-1') {
				throw new VerificationError(404, 'no_such_preview', 'no such preview');
			}
			if (request.label === 'huge-pr-1') {
				throw new VerificationError(409, 'inputs_invalid', 'x'.repeat(100_000));
			}
			return plan;
		},
		async planPage(planId, after) {
			calls.push(`plan-page ${planId} ${after ?? '-'}`);
			return plan;
		},
		async start(request) {
			calls.push(
				`start ${request.planId} ${request.planDigest} ${request.mode} ${request.idempotencyKey ?? '-'}`,
			);
			if (request.planDigest !== DIGEST) {
				throw new VerificationError(409, 'plan_stale', 'the plan changed');
			}
			return accepted;
		},
		async status(runId, after) {
			calls.push(`status ${runId} ${after}`);
			return status;
		},
		async events(runId, after, limit) {
			calls.push(`events ${runId} ${after} ${limit ?? '-'}`);
			return events;
		},
		async evidence(runId, after) {
			calls.push(`evidence ${runId} ${after}`);
			return evidence;
		},
		async artifact(runId, artifact, offset, length) {
			calls.push(`artifact ${runId} ${artifact} ${offset} ${length ?? '-'}`);
			if (artifact === 'recorder:trace:9') {
				throw new VerificationError(409, 'artifact_unavailable', 'withheld', false);
			}
			return chunk;
		},
		async cancel(runId) {
			calls.push(`cancel ${runId}`);
			return { ...status, cancelRequested: true };
		},
	};
}

function deps(verification: VerificationApi | undefined): ControlDeps {
	const unused = () => {
		throw new Error('not used');
	};
	return {
		deployer: { up: unused, down: unused, acquireLease: unused, releaseLease: unused },
		store: { get: unused, list: unused },
		docker: { logs: unused },
		buildLogs: { read: unused, tail: unused },
		keepAwake: async () => {},
		describe: unused,
		verification,
	};
}

async function call(d: ControlDeps, method: string, path: string, body?: unknown) {
	return control(
		new Request(`http://koid${path}`, {
			method,
			...(body === undefined
				? {}
				: {
						headers: { 'content-type': 'application/json' },
						body: typeof body === 'string' ? body : JSON.stringify(body),
					}),
		}),
		d,
	);
}

describe('verification routes', () => {
	test('POST /v1/verification-plans plans and answers 201 with the first page', async () => {
		const api = fake();
		const res = await call(deps(api), 'POST', '/v1/verification-plans', {
			version: 1,
			label: 'hello-pr-7',
			profile: 'pr',
		});
		expect(res.status).toBe(201);
		expect(await res.json()).toEqual(plan);
		expect(api.calls).toEqual(['plan hello-pr-7 pr -']);
	});

	test('GET /v1/verification-plans/:id pages a plan from a cursor', async () => {
		const api = fake();
		const d = deps(api);
		expect((await call(d, 'GET', `/v1/verification-plans/${PLAN}`)).status).toBe(200);
		expect((await call(d, 'GET', `/v1/verification-plans/${PLAN}?after=blocked:3`)).status).toBe(
			200,
		);
		expect(api.calls).toEqual([`plan-page ${PLAN} -`, `plan-page ${PLAN} blocked:3`]);
		const bad = await call(d, 'GET', `/v1/verification-plans/${PLAN}?after=points:x`);
		expect(bad.status).toBe(400);
		expect(VerificationErrorReplySchema.parse(await bad.json()).error.code).toBe('invalid_request');
	});

	test('POST /v1/verification-runs starts a run and answers 202', async () => {
		const api = fake();
		const res = await call(deps(api), 'POST', '/v1/verification-runs', {
			version: 1,
			planId: PLAN,
			planDigest: DIGEST,
			mode: 'runner',
			idempotencyKey: 'ci-run-42',
		});
		expect(res.status).toBe(202);
		expect(await res.json()).toEqual(accepted);
		expect(api.calls).toEqual([`start ${PLAN} ${DIGEST} runner ci-run-42`]);
	});

	test('reads: status, events, evidence, artifacts, each with its query', async () => {
		const api = fake();
		const d = deps(api);
		const cases: Array<[string, unknown, string]> = [
			[`/v1/verification-runs/${RUN}/status`, status, `status ${RUN} 0`],
			[`/v1/verification-runs/${RUN}/status?after=40`, status, `status ${RUN} 40`],
			[`/v1/verification-runs/${RUN}/events?after=7&limit=50`, events, `events ${RUN} 7 50`],
			[`/v1/verification-runs/${RUN}/events`, events, `events ${RUN} 0 -`],
			[`/v1/verification-runs/${RUN}/evidence?after=2`, evidence, `evidence ${RUN} 2`],
			[
				`/v1/verification-runs/${RUN}/artifacts/recorder%3Aaria%3A2?offset=6144&length=100`,
				chunk,
				`artifact ${RUN} recorder:aria:2 6144 100`,
			],
			[
				`/v1/verification-runs/${RUN}/artifacts/recorder:aria:2`,
				chunk,
				`artifact ${RUN} recorder:aria:2 0 -`,
			],
		];
		for (const [path, reply, expected] of cases) {
			api.calls.length = 0;
			const res = await call(d, 'GET', path);
			expect(res.status).toBe(200);
			expect(await res.json()).toEqual(reply);
			expect(api.calls).toEqual([expected]);
		}
	});

	test('POST /v1/verification-runs/:id/cancel records the cancel and answers 202 with the status', async () => {
		const api = fake();
		const res = await call(deps(api), 'POST', `/v1/verification-runs/${RUN}/cancel`);
		expect(res.status).toBe(202);
		expect(RunStatusReplySchema.parse(await res.json()).cancelRequested).toBe(true);
		expect(api.calls).toEqual([`cancel ${RUN}`]);
	});

	test("refusals come back in the versioned error shape with the controller's status and code", async () => {
		const api = fake();
		const d = deps(api);
		const missing = await call(d, 'POST', '/v1/verification-plans', {
			version: 1,
			label: 'nobody-pr-1',
			profile: 'pr',
		});
		expect(missing.status).toBe(404);
		expect(await missing.json()).toEqual({
			version: 1,
			error: { code: 'no_such_preview', message: 'no such preview', retryable: false },
		});
		const stale = await call(d, 'POST', '/v1/verification-runs', {
			version: 1,
			planId: PLAN,
			planDigest: `sha256:${'0'.repeat(64)}`,
			mode: 'runner',
		});
		expect(stale.status).toBe(409);
		expect(VerificationErrorReplySchema.parse(await stale.json()).error.code).toBe('plan_stale');
		const withheld = await call(
			d,
			'GET',
			`/v1/verification-runs/${RUN}/artifacts/recorder:trace:9`,
		);
		expect(withheld.status).toBe(409);
	});

	test('checks every argument before the controller sees it', async () => {
		const api = fake();
		const d = deps(api);
		const bad: Array<[string, string, unknown?]> = [
			['POST', '/v1/verification-plans', { version: 2, label: 'hello-pr-7', profile: 'pr' }],
			['POST', '/v1/verification-plans', { version: 1, label: 'Bad_Label', profile: 'pr' }],
			[
				'POST',
				'/v1/verification-plans',
				{ version: 1, label: 'hello-pr-7', profile: 'pr', extra: 1 },
			],
			['POST', '/v1/verification-plans', 'not json'],
			[
				'POST',
				'/v1/verification-runs',
				{ version: 1, planId: PLAN, planDigest: DIGEST, mode: 'exploratory' },
			],
			[
				'POST',
				'/v1/verification-runs',
				{ version: 1, planId: 'short', planDigest: DIGEST, mode: 'runner' },
			],
			['GET', `/v1/verification-runs/${RUN}/status?after=-1`],
			['GET', `/v1/verification-runs/${RUN}/events?limit=1e3`],
			['GET', `/v1/verification-runs/${RUN}/artifacts/..%2F..%2Fetc`],
			['GET', `/v1/verification-runs/${RUN}/artifacts/recorder:aria:2?offset=x`],
			['GET', '/v1/verification-runs/not-an-id/status'],
		];
		for (const [method, path, body] of bad) {
			const res = await call(d, method, path, body);
			expect(res.status).toBe(400);
			expect(VerificationErrorReplySchema.parse(await res.json()).error.code).toBe(
				'invalid_request',
			);
		}
		expect(api.calls).toEqual([]);
		for (const [method, path] of [
			['GET', `/v1/verification-runs/${RUN}`],
			['DELETE', `/v1/verification-runs/${RUN}/status`],
			['GET', `/v1/verification-runs/${RUN}/artifacts`],
			['GET', '/v1/verification-plans'],
		] as const) {
			expect((await call(d, method, path)).status).toBe(404);
		}
	});

	test('answers 404 with a versioned error when the koid has no controller', async () => {
		const res = await call(deps(undefined), 'POST', '/v1/verification-plans', {
			version: 1,
			label: 'hello-pr-7',
			profile: 'pr',
		});
		expect(res.status).toBe(404);
		expect(VerificationErrorReplySchema.parse(await res.json()).error.code).toBe(
			'verification_unavailable',
		);
	});

	test('error replies stay under the bound: a validation error names 20 issues, a message is cut', async () => {
		const api = fake();
		const d = deps(api);
		// Every point name is invalid, and there are too many of them: zod's
		// own message for this runs to hundreds of kilobytes.
		const invalid = await call(d, 'POST', '/v1/verification-plans', {
			version: 1,
			label: 'hello-pr-7',
			profile: 'pr',
			points: Array.from({ length: 1500 }, (_, i) => `Bad Point ${i}`),
		});
		expect(invalid.status).toBe(400);
		const text = await invalid.text();
		expect(Buffer.byteLength(text)).toBeLessThanOrEqual(VERIFICATION_REPLY_MAX_BYTES);
		const reply = VerificationErrorReplySchema.parse(JSON.parse(text));
		expect(reply.error.code).toBe('invalid_request');
		expect(reply.error.message).toMatch(/^points\.0: /);
		expect(reply.error.message).toMatch(/and \d+ more issues/);
		expect(Buffer.byteLength(JSON.stringify(reply.error.message))).toBeLessThanOrEqual(
			VERIFICATION_ERROR_MESSAGE_MAX,
		);
		expect(api.calls).toEqual([]);
		const huge = await call(d, 'POST', '/v1/verification-plans', {
			version: 1,
			label: 'huge-pr-1',
			profile: 'pr',
		});
		expect(huge.status).toBe(409);
		const hugeText = await huge.text();
		expect(Buffer.byteLength(hugeText)).toBeLessThanOrEqual(VERIFICATION_REPLY_MAX_BYTES);
		const cut = VerificationErrorReplySchema.parse(JSON.parse(hugeText));
		expect(cut.error.message).toEndWith(' [cut by koid]');
		expect(Buffer.byteLength(JSON.stringify(cut.error.message))).toBeLessThanOrEqual(
			VERIFICATION_ERROR_MESSAGE_MAX,
		);
	});

	test('refuses a body over 64 KiB', async () => {
		const api = fake();
		const res = await call(deps(api), 'POST', '/v1/verification-plans', {
			version: 1,
			label: 'hello-pr-7',
			profile: 'pr',
			points: Array.from({ length: 800 }, (_, i) => `p.${'x'.repeat(90)}${i}`),
		});
		expect(res.status).toBe(413);
		expect(VerificationErrorReplySchema.parse(await res.json()).error.code).toBe('body_too_large');
		expect(api.calls).toEqual([]);
	});
});
