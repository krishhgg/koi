import { describe, expect, test } from 'bun:test';
import { previewHostLabel, slugify } from '../src/slug.ts';

describe('slugify', () => {
	test('lowercases and replaces runs of other characters with one dash', () => {
		expect(slugify('Fix/Agent Timeout__v2')).toBe('fix-agent-timeout-v2');
	});

	test('strips leading and trailing dashes', () => {
		expect(slugify('--feature/x--')).toBe('feature-x');
	});

	test('caps at 63 characters without a trailing dash', () => {
		const long = `${'a'.repeat(62)}-bbbb`;
		expect(slugify(long)).toBe('a'.repeat(62));
	});

	test('rejects input with nothing usable', () => {
		expect(() => slugify('///')).toThrow();
	});
});

describe('previewHostLabel', () => {
	test('names pull requests by number', () => {
		expect(previewHostLabel('storefront', { pr: 2518 })).toBe('storefront-pr-2518');
	});

	test('names branches by slug and a digest of the exact branch name', () => {
		// Digest letters are the first eight bytes of SHA-256("storefront\0fix/SF-2148-agent-timeout"), each mod 26.
		expect(previewHostLabel('storefront', { branch: 'fix/SF-2148-agent-timeout' })).toBe(
			'storefront-fix-sf-2148-agent-timeout-sjhcpcij',
		);
	});

	test('gives the same branch the same label every time', () => {
		// The first eight bytes of SHA-256("storefront\0fix/agent-timeout"), each mod 26.
		const expected = 'storefront-fix-agent-timeout-dzpwwciu';
		expect(previewHostLabel('storefront', { branch: 'fix/agent-timeout' })).toBe(expected);
		expect(previewHostLabel('storefront', { branch: 'fix/agent-timeout' })).toBe(expected);
	});

	test('keeps branches with the same slug apart', () => {
		const a = previewHostLabel('storefront', { branch: 'feature/a' });
		const b = previewHostLabel('storefront', { branch: 'feature-a' });
		expect(a).toMatch(/^storefront-feature-a-[a-z]{8}$/);
		expect(b).toMatch(/^storefront-feature-a-[a-z]{8}$/);
		expect(a).not.toBe(b);
	});

	test('keeps long branches apart when they differ only after truncation', () => {
		const shared = `feature/${'x'.repeat(60)}`;
		const a = previewHostLabel('storefront', { branch: `${shared}-one` });
		const b = previewHostLabel('storefront', { branch: `${shared}-two` });
		expect(a.slice(0, -8)).toBe(b.slice(0, -8));
		expect(a).not.toBe(b);
	});

	test('keeps projects apart even when their label text lines up', () => {
		// "a" + "-b-b-...-b" and "a-b" + "-b-...-b" truncate to the same text.
		const branch = `${'b-'.repeat(60)}b`;
		const a = previewHostLabel('a', { branch });
		const ab = previewHostLabel('a-b', { branch });
		expect(a.slice(0, -8)).toBe(ab.slice(0, -8));
		expect(a).not.toBe(ab);
	});

	test('keeps apart a pair that collided under a five-letter digest', () => {
		// Found by a reviewer after 1,183 candidates; both gave ...-syakt.
		const prefix = `feature/${'x'.repeat(60)}`;
		expect(previewHostLabel('storefront', { branch: `${prefix}-757` })).not.toBe(
			previewHostLabel('storefront', { branch: `${prefix}-1182` }),
		);
	});

	test('never gives a branch the label of a pull request', () => {
		expect(previewHostLabel('storefront', { branch: 'pr-2518' })).not.toBe(
			previewHostLabel('storefront', { pr: 2518 }),
		);
		// With a hex digest, "PR__" would have been storefront-pr-39597.
		for (const branch of ['pr', 'PR__', 'pr-2518', '2518']) {
			expect(previewHostLabel('storefront', { branch })).toMatch(/-[a-z]{8}$/);
		}
		expect(previewHostLabel('storefront', { pr: 39597 })).toMatch(/-[0-9]+$/);
	});

	test('labels branches with no ASCII letters or digits, keeping them apart', () => {
		const labels = ['修复', '🔥', '___', '修理'].map((branch) =>
			previewHostLabel('hello', { branch }),
		);
		for (const label of labels) expect(label).toMatch(/^hello-branch-[a-z]{8}$/);
		expect(new Set(labels).size).toBe(labels.length);
	});

	test('truncates the branch so the label fits in 63 characters', () => {
		const label = previewHostLabel('storefront', { branch: 'b'.repeat(100) });
		expect(label.length).toBe(63);
		expect(label).toMatch(/^storefront-b+-[a-z]{8}$/);
	});

	test('fits the longest project name with any branch or pull request', () => {
		const longest = 'p'.repeat(31);
		expect(previewHostLabel(longest, { branch: 'b'.repeat(100) })).toHaveLength(63);
		expect(previewHostLabel(longest, { pr: Number.MAX_SAFE_INTEGER })).toBe(
			`${longest}-pr-9007199254740991`,
		);
	});

	test('uses the project name as given and rejects names that are not canonical', () => {
		expect(previewHostLabel('hello-world', { pr: 1 })).toBe('hello-world-pr-1');
		for (const project of ['hello--world', 'Hello', 'hello_world', '-hello', 'p'.repeat(32), '']) {
			expect(() => previewHostLabel(project, { pr: 1 })).toThrow(/project name/);
		}
	});

	test('rejects a bad pull request number', () => {
		expect(() => previewHostLabel('storefront', { pr: 0 })).toThrow();
		expect(() => previewHostLabel('storefront', { pr: 1.5 })).toThrow();
		expect(() => previewHostLabel('storefront', { pr: Number.NaN })).toThrow();
	});

	test('rejects pull request numbers beyond the safe integer range', () => {
		expect(() => previewHostLabel('hello', { pr: 1e21 })).toThrow(/pull request number/);
		expect(() => previewHostLabel('hello', { pr: Number.MAX_SAFE_INTEGER + 1 })).toThrow();
		expect(previewHostLabel('hello', { pr: Number.MAX_SAFE_INTEGER })).toBe(
			'hello-pr-9007199254740991',
		);
	});
});
