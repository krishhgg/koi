import { createHash } from 'node:crypto';
import { PreviewLabelSchema, PrNumberSchema } from './preview.ts';
import { PROJECT_NAME } from './recipe.ts';

// Hostname labels: RFC 1123 allows [a-z0-9-], 1..63 chars, no leading or
// trailing dash. Every preview name becomes one label under the base domain;
// these functions build it and PreviewLabelSchema has the final word on it.
const MAX_LABEL = 63;
const DIGEST_LENGTH = 8;

// Lowercase ASCII letters and digits with single dashes between runs; may be
// empty when the input has none.
function toSlug(input: string): string {
	return input
		.toLowerCase()
		.replace(/[^a-z0-9]+/g, '-')
		.replace(/^-+|-+$/g, '')
		.slice(0, MAX_LABEL)
		.replace(/-+$/g, '');
}

export function slugify(input: string): string {
	const slug = toSlug(input);
	if (slug.length === 0) {
		throw new Error(`cannot derive a hostname label from ${JSON.stringify(input)}`);
	}
	return slug;
}

export type PreviewRef = { pr: number } | { branch: string };

// "<project>-pr-<n>" for a pull request, "<project>-<branch>-<digest>" for a
// branch. The digest comes from the exact branch name, so feature/a and
// feature-a, or two long branches that truncate to the same slug, still get
// different labels. A PR label ends in digits and a branch label in letters,
// so the two can never be equal. Only the branch slug is truncated to fit 63
// characters; the project, PR number and digest carry the identity.
export function previewHostLabel(project: string, ref: PreviewRef): string {
	// The project name is used as given, never slugified: two names that
	// slugify alike (hello-world, hello--world) must not share labels, so only
	// canonical names are accepted.
	if (!PROJECT_NAME.test(project)) {
		throw new Error(`invalid project name ${JSON.stringify(project)}`);
	}
	const prefix = project;
	if ('pr' in ref) {
		const pr = PrNumberSchema.safeParse(ref.pr);
		if (!pr.success) {
			throw new Error(`invalid pull request number ${String(ref.pr)}`);
		}
		return checkedLabel(`${prefix}-pr-${pr.data}`);
	}
	const room = MAX_LABEL - prefix.length - DIGEST_LENGTH - 2;
	if (room < 1) {
		throw new Error(`project name ${JSON.stringify(project)} leaves no room for a branch`);
	}
	// Git allows branch names with no ASCII letters or digits (修复, ___). They
	// get the slug "branch"; the digest of the exact name still tells them apart.
	const branch = toSlug(ref.branch).slice(0, room).replace(/-+$/g, '') || 'branch';
	return checkedLabel(`${prefix}-${branch}-${branchDigest(project, ref.branch)}`);
}

// Eight letters a-z: byte i of the SHA-256 of "<project>\0<branch>" (UTF-8),
// mod 26, for i = 0..7. The project is part of the input because the label
// text alone does not separate them: project "a" with branch "b-b-...-b" and
// project "a-b" with the same branch truncate to the same text. Letters only,
// never digits, so that a branch label cannot look like a PR label. This keeps
// accidental collisions out of reach (26^8 values); it is not a defence
// against a branch name crafted to collide, so the daemon also refuses to
// replace a preview that belongs to another repo or ref.
function branchDigest(project: string, branch: string): string {
	const hash = createHash('sha256').update(`${project}\0${branch}`, 'utf8').digest();
	return Array.from(hash.subarray(0, DIGEST_LENGTH), (byte) =>
		String.fromCharCode(97 + (byte % 26)),
	).join('');
}

function checkedLabel(label: string): string {
	if (!PreviewLabelSchema.safeParse(label).success) {
		throw new Error(
			`${JSON.stringify(label)} is not a valid hostname label (at most ${MAX_LABEL} characters of a-z, 0-9 and inner dashes)`,
		);
	}
	return label;
}
