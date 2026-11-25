import { z } from 'zod';
import { LeaseReplySchema, ReleaseReplySchema } from './control.ts';
import {
	DeploymentSourceSchema,
	LeaseIdSchema,
	LoginKeySchema,
	PreviewLabelSchema,
	PrNumberSchema,
	PullRequestMergeSchema,
} from './preview.ts';
import { CommitSchema } from './request.ts';
import { DeploymentIdentitySchema } from './verify.ts';

// What `koi up`, `koi lease` and `koi release` print on stdout with --json,
// for programs that run the CLI. scripts/json-schemas.ts writes each one as a
// JSON Schema into schemas/ (cliOutputSchemaFiles below), for a caller to
// copy at the koi commit it pins.
//
// Each output carries its own schemaVersion. It changes only when a field is
// removed or changes meaning. Adding an optional field keeps it, so a caller
// that reads the fields it knows keeps working; a caller that validates with
// a copied schema copies the files again when it moves to a newer koi, since
// the schemas refuse fields they do not name.

// The version each output carries, with the rule above in its description.
function schemaVersion<V extends number>(version: V) {
	return z
		.literal(version)
		.describe(
			'Changes only when koi removes a field or changes what one means. Adding an optional field keeps it.',
		);
}

// The preview's address and its keys page: https, under the box's domain.
const HttpsUrlSchema = z.string().regex(/^https:\/\//);

// A deployment as koi up and koi lease print it: its identity, and what koid
// says it was built from, which koid's replies carry beside the identity
// (StatusReplySchema) and the CLI puts back in it.
const PrintedDeploymentSchema = DeploymentIdentitySchema.extend({
	source: DeploymentSourceSchema.optional().describe(
		'What the deployment was built from, as koid computed it from the source tarball it unpacked: koid vouches for it, not the CLI. Absent from a koid older than this field, and when koid could not compute it. To check that a preview is exactly a commit, compare source.tree with git rev-parse COMMIT^{tree}, or read source.matchesCommit.',
	),
});

// A deployment and the source beside it in one of koid's replies, as
// PrintedDeploymentSchema puts them together.
export function printedDeployment<D extends object>(
	deployment: D,
	source: z.infer<typeof DeploymentSourceSchema> | undefined,
): D & { source?: z.infer<typeof DeploymentSourceSchema> } {
	return source !== undefined ? { ...deployment, source } : deployment;
}

export const UpResultSchema = z
	.object({
		schemaVersion: schemaVersion(1),
		label: PreviewLabelSchema.describe("The preview's name, the first label of its hostname."),
		url: HttpsUrlSchema.describe("The preview's address."),
		status: z
			.enum(['running', 'failed'])
			.describe(
				'How the build koi up asked for ended: running once it deployed, failed when it did not. With --keep it is also failed when koid returned no slice, as a koid older than --keep does, since that build ran without the names. It does not say whether the container is up now.',
			),
		commit: CommitSchema.describe(
			"What koi built: for a pull request, the merge of it into its base, whose parents are in merge, or with --head the head as pushed; for a working tree, its HEAD commit. The merge is GitHub's (refs/pull/N/merge), or one koi made itself from the same two parents when GitHub's stayed out of date; koi makes its own the same way every time, so the parents give the commit.",
		),
		dirty: z
			.boolean()
			.optional()
			.describe(
				"Whether git saw changes in the working tree that commit does not have, untracked files included, when koi up packed it (git status): the CLI's own account, which koid does not check. Always false with --pr, which builds the commit as git archive gives it. koid's account of what the deployment read is deployment.source. Absent from a koi older than this field.",
			),
		pr: PrNumberSchema.optional().describe('The pull request built, with --pr.'),
		merge: PullRequestMergeSchema.optional().describe(
			'The parents of the merge in commit, when koi built a merge of a pull request. Absent for a working tree and with --head.',
		),
		deployment: PrintedDeploymentSchema.optional().describe(
			"The identity of the deployment koid has on record for the preview as koi up ended, when it has one: absent after a first build that failed. It says nothing about whether the preview's container is running. After a failed rebuild it can be the previous deployment, so a caller compares deployment.commit with commit before it trusts the preview, and deployment.source to tell a build of exactly that commit from one with changes not in it.",
		),
		loginKey: LoginKeySchema.optional().describe(
			'For apps with a sign-in, the key a reviewer types to get in. A secret: never copy it into evidence or logs.',
		),
		keysUrl: HttpsUrlSchema.describe(
			"The preview's keys page, where a reviewer registers provider keys and gets koi tokens that work only in this preview.",
		),
		slice: z
			.record(z.string(), z.unknown())
			.optional()
			.describe(
				"What the build of deployment kept of the project, as its recipe's build reported it, for a recipe that reports one: a JSON object of at most 16384 bytes, nested at most 16 levels deep, whose shape the recipe defines. koi reads it from the built image and never interprets it. It describes deployment, which after a failed rebuild is the previous build, not commit. The build ran the pull request's code, so it is the recipe's account, not koi's.",
			),
		error: z.string().optional().describe('Why the build failed, when status is failed.'),
		comment: z
			.string()
			.optional()
			.describe('With --comment, the address of the pull request comment koi posted or updated.'),
	})
	.meta({
		title: 'koi up --json',
		description:
			'What koi up --json prints once the build has finished. koi exits 0 when status is running and 1 when it is failed.',
	});

export type UpResult = z.infer<typeof UpResultSchema>;

export const LeaseResultSchema = z
	.object({
		schemaVersion: schemaVersion(1),
		lease: LeaseReplySchema.shape.lease.describe(
			'The lease koid took. While it lasts koid refuses a build of the preview, and koi down needs --force.',
		),
		deployment: PrintedDeploymentSchema.describe(
			'The deployment the lease holds. A caller stops when it is not the one koi up returned.',
		),
	})
	.meta({
		title: 'koi lease --json',
		description:
			'What koi lease NAME --minutes N --json prints: the lease koid took on the preview and the deployment it holds.',
	});

export type LeaseResult = z.infer<typeof LeaseResultSchema>;

export const ReleaseResultSchema = z
	.object({
		schemaVersion: schemaVersion(1),
		label: PreviewLabelSchema,
		leaseId: LeaseIdSchema,
		released: ReleaseReplySchema.shape.released,
	})
	.meta({
		title: 'koi release --json',
		description: 'What koi release NAME LEASE --json prints once koid has ended the lease.',
	});

export type ReleaseResult = z.infer<typeof ReleaseResultSchema>;

// The outputs above by the name of their file in schemas/.
export const CLI_OUTPUT_SCHEMAS = {
	'koi-up': UpResultSchema,
	'koi-lease': LeaseResultSchema,
	'koi-release': ReleaseResultSchema,
} as const;

// The files scripts/json-schemas.ts writes into schemas/, by file name: each
// output as JSON Schema draft 2020-12, with an $id that names the output and
// its schemaVersion. A test compares them with the committed files.
export function cliOutputSchemaFiles(): Record<string, string> {
	const files: Record<string, string> = {};
	for (const [name, schema] of Object.entries(CLI_OUTPUT_SCHEMAS)) {
		const { $schema, title, description, ...rest } = z.toJSONSchema(schema, {
			target: 'draft-2020-12',
		});
		const version = schema.shape.schemaVersion.value;
		const json = {
			$schema,
			$id: `https://github.com/krishhgg/koi/schemas/v${version}/${name}.schema.json`,
			title,
			description,
			...rest,
		};
		files[`${name}.schema.json`] = `${JSON.stringify(json, null, '\t')}\n`;
	}
	return files;
}
