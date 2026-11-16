import { describe, expect, test } from 'bun:test';
import {
	ArtifactChunkSchema,
	artifactFileName,
	BlockedPointSchema,
	ByteCountSchema,
	IndexCursorSchema,
	PlanCursorSchema,
	PlanPolicySchema,
	PlanRequestSchema,
	PointStatusSchema,
	RunControllerRecordSchema,
	RunRequestSchema,
	RunStatusReplySchema,
	runIdOfHolder,
	runLeaseHolder,
	VerificationErrorReplySchema,
} from '../src/verification.ts';

const RUN = 'r'.repeat(20);
const PLAN = 'p'.repeat(20);
const DIGEST = `sha256:${'1'.repeat(64)}`;

describe('verification request schemas', () => {
	test('a plan request names the preview and the profile, strictly', () => {
		expect(PlanRequestSchema.parse({ version: 1, label: 'hello-pr-7', profile: 'pr' })).toEqual({
			version: 1,
			label: 'hello-pr-7',
			profile: 'pr',
		});
		expect(
			PlanRequestSchema.parse({
				version: 1,
				label: 'hello-pr-7',
				profile: 'pr',
				expectedDeploymentId: 'd'.repeat(20),
				points: ['hello.home'],
			}).points,
		).toEqual(['hello.home']);
		for (const bad of [
			{ version: 2, label: 'hello-pr-7', profile: 'pr' },
			{ version: 1, label: 'Bad_Label', profile: 'pr' },
			{ version: 1, label: 'hello-pr-7', profile: 'Not a slug' },
			{ version: 1, label: 'hello-pr-7', profile: 'pr', points: [] },
			{ version: 1, label: 'hello-pr-7', profile: 'pr', outcome: 'passed' },
		]) {
			expect(PlanRequestSchema.safeParse(bad).success).toBe(false);
		}
	});

	test('a run request binds the plan by id and digest and takes no outcome', () => {
		expect(
			RunRequestSchema.parse({ version: 1, planId: PLAN, planDigest: DIGEST, mode: 'runner' }),
		).toEqual({ version: 1, planId: PLAN, planDigest: DIGEST, mode: 'runner' });
		for (const bad of [
			{ version: 1, planId: PLAN, planDigest: DIGEST, mode: 'exploratory' },
			{ version: 1, planId: PLAN, planDigest: 'sha256:short', mode: 'runner' },
			{ version: 1, planId: PLAN, planDigest: DIGEST, mode: 'runner', idempotencyKey: 'short' },
			{ version: 1, planId: PLAN, planDigest: DIGEST, mode: 'runner', outcome: 'passed' },
		]) {
			expect(RunRequestSchema.safeParse(bad).success).toBe(false);
		}
	});

	test('cursors and byte counts are plain digits', () => {
		expect(IndexCursorSchema.parse('42')).toBe(42);
		expect(ByteCountSchema.parse('0')).toBe(0);
		expect(PlanCursorSchema.parse('uncovered:12')).toBe('uncovered:12');
		for (const bad of ['-1', '1e3', '', ' 1', '01']) {
			expect(IndexCursorSchema.safeParse(bad).success).toBe(false);
		}
		for (const bad of ['points', 'points:', 'other:1', 'points:-1']) {
			expect(PlanCursorSchema.safeParse(bad).success).toBe(false);
		}
	});
});

describe('verification reply schemas', () => {
	test('errors carry a code, a message and whether to try again', () => {
		expect(
			VerificationErrorReplySchema.parse({
				version: 1,
				error: { code: 'plan_stale', message: 'plan again', retryable: false },
			}).error.code,
		).toBe('plan_stale');
		expect(
			VerificationErrorReplySchema.safeParse({
				version: 1,
				error: { code: 'Bad Code', message: '' },
			}).success,
		).toBe(false);
	});

	test('a controller record and a status reply hold a run as the controller sees it', () => {
		const deployment = {
			label: 'hello-pr-7',
			deploymentId: 'd'.repeat(20),
			imageDigest: DIGEST,
			commit: 'c'.repeat(40),
		};
		const record = RunControllerRecordSchema.parse({
			version: 1,
			runId: RUN,
			planId: PLAN,
			planDigest: DIGEST,
			label: 'hello-pr-7',
			deployment,
			profile: 'pr',
			advisory: false,
			state: 'completed',
			completion: 'evaluated',
			outcome: 'incomplete',
			cancelRequested: false,
			points: [
				{
					id: 'hello.home',
					state: 'done',
					outcome: 'blocked',
					reason: 'why',
					evidence: ['recorder:aria:2'],
				},
			],
			uncovered: [],
			policy: { source: 'none' },
			limits: { runSeconds: 900, pointSeconds: 300, runRequests: 50, pointRequests: 20 },
			lease: { leaseId: 'l'.repeat(20), expiresAt: '2026-10-06T12:17:00.000Z' },
			readiness: { eligibleForMergeGate: false, reasons: ['the run incomplete'] },
			freshness: 'current',
			cleanup: 'succeeded',
			startedAt: '2026-10-06T12:00:00.000Z',
			finishedAt: '2026-10-06T12:01:00.000Z',
			updatedAt: '2026-10-06T12:01:00.000Z',
		});
		expect(record.completion).toBe('evaluated');
		const { lease: _lease, updatedAt: _at, uncovered: _u, policy: _p, ...rest } = record;
		const status = RunStatusReplySchema.parse({
			...rest,
			evidence: 'complete',
			finalized: true,
			leaseExpiresAt: record.lease.expiresAt,
			progress: { total: 1, done: 1 },
			problems: [],
			problemCount: 0,
		});
		expect(status.leaseExpiresAt).toBe(record.lease.expiresAt);
		expect(RunStatusReplySchema.safeParse({ ...status, leaseId: 'x' }).success).toBe(false);
	});

	test('a point status names a point by its id, and by nothing else', () => {
		const point = {
			id: 'hello.home',
			state: 'done',
			outcome: 'blocked',
			reason: 'verifier_unavailable: nothing ran',
			evidence: [],
		};
		expect(PointStatusSchema.parse(point)).toEqual(point as never);
		for (const id of ['refused:1', 'not a point', '[redacted]']) {
			expect(PointStatusSchema.safeParse({ ...point, id }).success).toBe(false);
		}
	});

	test('a blocked list and a required list hold only point ids', () => {
		expect(BlockedPointSchema.safeParse({ id: 'refused:1', reason: 'x' }).success).toBe(false);
		expect(BlockedPointSchema.safeParse({ id: 'a.point', reason: 'x' }).success).toBe(true);
		const policy = (id: string) => ({
			source: 'none',
			advisory: { path: '.koi/required.yaml', required: [{ id, revision: 1 }] },
		});
		expect(PlanPolicySchema.safeParse(policy('refused:1')).success).toBe(false);
		expect(PlanPolicySchema.safeParse(policy('a.point')).success).toBe(true);
	});

	test('an artifact chunk is bounded base64 with the offset of the rest', () => {
		const chunk = ArtifactChunkSchema.parse({
			version: 1,
			runId: RUN,
			artifact: 'recorder:aria:2',
			kind: 'aria',
			mediaType: 'text/plain',
			size: 10,
			sha256: DIGEST,
			offset: 0,
			length: 6,
			dataBase64: Buffer.from('abcdef').toString('base64'),
			next: 6,
			truncated: true,
			note: 'the rest needs the channel (C2)',
		});
		expect(chunk.next).toBe(6);
	});
});

describe('names', () => {
	test('a run holds its lease as verify:<run id>', () => {
		expect(runLeaseHolder(RUN)).toBe(`verify:${RUN}`);
		expect(runIdOfHolder(`verify:${RUN}`)).toBe(RUN);
		expect(runIdOfHolder('dev@laptop')).toBeUndefined();
		expect(() => runLeaseHolder('short')).toThrow();
	});

	test('an exported artifact is named by kind, number and media type', () => {
		expect(artifactFileName('recorder:screenshot:7', 'image/png')).toBe('screenshot-7.png');
		expect(artifactFileName('recorder:aria:2', 'text/plain; charset=utf-8')).toBe('aria-2.txt');
		expect(artifactFileName('recorder:network:3', 'application/x-ndjson')).toBe('network-3.ndjson');
		expect(artifactFileName('recorder:http-response:4', 'application/json')).toBe(
			'http-response-4.json',
		);
		expect(artifactFileName('recorder:file:5', 'application/octet-stream')).toBe('file-5.bin');
		expect(() => artifactFileName('../x', 'text/plain')).toThrow();
	});
});
