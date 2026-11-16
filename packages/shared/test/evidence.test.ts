import { describe, expect, test } from 'bun:test';
import {
	type Artifact,
	ArtifactIdSchema,
	ArtifactSchema,
	canonicalDigest,
	canonicalJson,
	type EvidenceManifest,
	EvidenceManifestSchema,
	type ExecutionDescriptor,
	ExecutionDescriptorSchema,
	InputSnapshotSchema,
	type RunStatus,
	RunStatusSchema,
} from '../src/evidence.ts';
import {
	RecorderCaptureSchema,
	RecorderEventsPageSchema,
	RecorderHealthSchema,
} from '../src/recorder.ts';

const RUN = 'abcdefghijklmnop0123';
const DIGEST = `sha256:${'a'.repeat(64)}`;
const AT = '2026-10-06T12:00:00.000Z';

// The entry as the design gives it, with full ids and hashes.
const artifact: Artifact = {
	id: 'recorder:screenshot:7',
	runId: RUN,
	pointId: 'app.canvas.save',
	attempt: 1,
	kind: 'screenshot',
	mediaType: 'image/png',
	size: 154203,
	sha256: DIGEST,
	origin: 'recorder',
	capturedAt: AT,
	eventRange: { first: 31, last: 47 },
	redaction: {
		status: 'sanitized',
		policyDigest: `sha256:${'b'.repeat(64)}`,
		removedFields: ['authorization', 'cookies'],
		limitations: ['pixels may contain unknown application data'],
	},
	availability: 'available',
	retainedUntil: '2026-11-05T12:00:00.000Z',
};

const status: RunStatus = {
	version: 1,
	runId: RUN,
	state: 'completed',
	evidence: 'complete',
	startedAt: AT,
	updatedAt: AT,
	finishedAt: AT,
	counts: { events: 12, artifacts: 1, bytes: 154203 },
	problems: [],
};

describe('ArtifactSchema', () => {
	test("accepts the design's manifest entry and nothing more", () => {
		expect(ArtifactSchema.parse(artifact)).toEqual(artifact);
		expect(ArtifactSchema.safeParse({ ...artifact, path: '/var/lib/koi/x' }).success).toBe(false);
		expect(ArtifactSchema.safeParse({ ...artifact, origin: 'runner' }).success).toBe(false);
		expect(ArtifactSchema.safeParse({ ...artifact, kind: 'video' }).success).toBe(false);
		expect(
			ArtifactSchema.safeParse({ ...artifact, eventRange: { first: 47, last: 31 } }).success,
		).toBe(false);
		expect(
			ArtifactSchema.safeParse({ ...artifact, redaction: { ...artifact.redaction, status: 'raw' } })
				.success,
		).toBe(false);
	});

	test('ids are recorder:<kind>:<n> and name no path', () => {
		expect(ArtifactIdSchema.safeParse('recorder:http-response:12').success).toBe(true);
		for (const bad of [
			'recorder:screenshot:0',
			'recorder:screenshot',
			'runs/x/artifacts/1',
			'recorder:screenshot:7/..',
			'recorder:Screenshot:7',
		]) {
			expect(ArtifactIdSchema.safeParse(bad).success).toBe(false);
		}
	});
});

describe('RunStatusSchema', () => {
	test('a running run has no finishedAt, a finished one has', () => {
		expect(RunStatusSchema.parse(status)).toEqual(status);
		const { finishedAt: _f, ...running } = status;
		expect(
			RunStatusSchema.safeParse({ ...running, state: 'running', evidence: 'collecting' }).success,
		).toBe(true);
		expect(RunStatusSchema.safeParse({ ...running, state: 'completed' }).success).toBe(false);
		expect(RunStatusSchema.safeParse({ ...status, state: 'running' }).success).toBe(false);
	});

	test('a problem rules out complete evidence', () => {
		const problem = { code: 'cap_exceeded', detail: 'over 512 MiB', at: AT };
		expect(RunStatusSchema.safeParse({ ...status, problems: [problem] }).success).toBe(false);
		expect(
			RunStatusSchema.safeParse({ ...status, evidence: 'incomplete', problems: [problem] }).success,
		).toBe(true);
		expect(
			RunStatusSchema.safeParse({ ...status, problems: [{ ...problem, code: 'Cap Exceeded' }] })
				.success,
		).toBe(false);
	});
});

describe('EvidenceManifestSchema and ExecutionDescriptorSchema', () => {
	test('a manifest closes a run: status, artifacts, events, files, limits and retention', () => {
		const manifest: EvidenceManifest = {
			version: 1,
			runId: RUN,
			planId: 'planplanplanplan0001',
			planDigest: DIGEST,
			executionDigest: DIGEST,
			status,
			artifacts: [artifact],
			events: { count: 12, bytes: 4096, sha256: DIGEST },
			files: { 'status.json': { sha256: DIGEST, bytes: 300 } },
			limitations: ['a sanitized label means the stated policy ran'],
			finalizedAt: AT,
			retainedUntil: '2026-11-05T12:00:00.000Z',
			tombstoneUntil: '2027-04-04T12:00:00.000Z',
		};
		expect(EvidenceManifestSchema.parse(manifest)).toEqual(manifest);
		expect(
			EvidenceManifestSchema.safeParse({
				...manifest,
				files: { 'secrets.json': { sha256: DIGEST, bytes: 1 } },
			}).success,
		).toBe(false);
	});

	test('a descriptor freezes images, browser, policy, proofs, origin, limits and capabilities', () => {
		const descriptor: ExecutionDescriptor = {
			version: 1,
			runId: RUN,
			planId: 'planplanplanplan0001',
			runnerImage: { reference: 'curlimages/curl:8.11.1', digest: DIGEST },
			recorderImage: { reference: `sha256:${'7'.repeat(64)}`, digest: DIGEST },
			browser: { name: 'chromium', version: '142.0.7444.52' },
			playwright: '1.64.1',
			policy: { source: 'base-branch', commit: 'c'.repeat(40), digest: DIGEST },
			proofs: [
				{
					pointId: 'hello.home',
					revision: 1,
					failingRunId: 'f'.repeat(20),
					passingRunId: 'p'.repeat(20),
				},
			],
			originMode: 'private-app',
			origin: 'http://app.abcdefghijklmnop0123.invalid:8080',
			limits: {
				runSeconds: 900,
				pointSeconds: 300,
				runRequests: 50,
				pointRequests: 20,
				artifactBytes: 32 * 1024 ** 2,
				runBytes: 512 * 1024 ** 2,
				artifacts: 10_000,
				events: 10_000,
			},
			capabilities: ['raw-cdp'],
			executionDigest: DIGEST,
		};
		expect(ExecutionDescriptorSchema.parse(descriptor)).toEqual(descriptor);
		expect(
			ExecutionDescriptorSchema.safeParse({ ...descriptor, originMode: 'public' }).success,
		).toBe(false);
		// Nothing writes a mask here, so the browser's name is one word.
		const browser = (name: string, version = '142.0.7444.52') =>
			ExecutionDescriptorSchema.safeParse({ ...descriptor, browser: { name, version } }).success;
		expect(browser('[redacted]')).toBe(false);
		// What the recorder says of its versions has a version's form, or it is no record.
		expect(browser('chromium', 'see token=abc for details')).toBe(false);
		expect(browser('chromium', '142.0\nforged')).toBe(false);
		expect(browser('chromium', '[redacted]')).toBe(false);
		expect(
			ExecutionDescriptorSchema.safeParse({ ...descriptor, playwright: 'unknown' }).success,
		).toBe(true);
		expect(ExecutionDescriptorSchema.safeParse({ ...descriptor, playwright: 'a b' }).success).toBe(
			false,
		);
	});
});

describe('InputSnapshotSchema', () => {
	const base = {
		version: 1,
		deploymentId: 'd'.repeat(20),
		label: 'hello-pr-7',
		request: {
			id: 'r'.repeat(17),
			repo: 'github.com/acme/hello',
			commit: 'a'.repeat(40),
			branch: 'feature/x',
			pr: 7,
			dirty: false,
			createdAt: AT,
		},
		recipe: { kind: 'repo', digest: DIGEST },
		source: { archiveDigest: DIGEST, archiveBytes: 1234 },
		takenAt: AT,
	};

	test('says whether a project has verification files', () => {
		expect(InputSnapshotSchema.safeParse({ ...base, verify: { status: 'absent' } }).success).toBe(
			true,
		);
		expect(
			InputSnapshotSchema.safeParse({
				...base,
				verify: { status: 'invalid', error: '.koi/verify.yaml: version: Invalid input' },
			}).success,
		).toBe(true);
		const present = {
			status: 'present',
			digests: { '.koi/verify.yaml': DIGEST },
			points: [{ id: 'hello.home', revision: 1, path: '.koi/points/home.yaml' }],
			fixtures: [{ path: '.koi/fixtures/probe.txt', digest: DIGEST, size: 12 }],
			other: [],
		};
		expect(InputSnapshotSchema.safeParse({ ...base, verify: present }).success).toBe(true);
		expect(InputSnapshotSchema.safeParse({ ...base, verify: { status: 'present' } }).success).toBe(
			false,
		);
	});
});

describe('canonical JSON', () => {
	test('sorts keys at every level and drops undefined, so digests agree', () => {
		expect(canonicalJson({ b: 1, a: { d: [1, { z: 1, y: 2 }], c: undefined } })).toBe(
			'{"a":{"d":[1,{"y":2,"z":1}]},"b":1}',
		);
		expect(canonicalDigest({ b: 1, a: 2 })).toBe(canonicalDigest({ a: 2, b: 1 }));
		expect(canonicalDigest({ a: 1 })).not.toBe(canonicalDigest({ a: 2 }));
	});
});

describe('recorder replies', () => {
	test('health, captures and event pages are read strictly', () => {
		expect(
			RecorderHealthSchema.safeParse({
				ok: true,
				runId: RUN,
				origin: 'http://app.x.invalid:8080',
				browser: { name: 'chromium', version: '142.0' },
				playwright: '1.64.1',
				contexts: 0,
				captures: { count: 0, bytes: 0 },
				events: { next: 1, dropped: 0 },
			}).success,
		).toBe(true);
		expect(RecorderHealthSchema.safeParse({ ok: false, reason: 'starting' }).success).toBe(true);
		expect(
			RecorderCaptureSchema.safeParse({
				captureId: 'c1',
				kind: 'screenshot',
				mediaType: 'image/png',
				size: 10,
				sha256: DIGEST,
				pageId: 'p1',
				url: 'http://app.x.invalid:8080/',
				eventRange: { first: 3, last: 9 },
				capturedAt: AT,
			}).success,
		).toBe(true);
		expect(
			RecorderCaptureSchema.safeParse({
				captureId: '../x',
				kind: 'screenshot',
				mediaType: 'image/png',
				size: 10,
				sha256: DIGEST,
				eventRange: { first: 3, last: 9 },
				capturedAt: AT,
			}).success,
		).toBe(false);
		expect(
			RecorderEventsPageSchema.safeParse({
				events: [{ seq: 1, at: AT, type: 'denied', contextId: 'x1', url: 'http://example.com/' }],
				next: 1,
				dropped: 0,
			}).success,
		).toBe(true);
		expect(
			RecorderEventsPageSchema.safeParse({
				events: [{ seq: 1, at: AT, type: 'Denied!' }],
				next: 1,
				dropped: 0,
			}).success,
		).toBe(false);
	});
});
