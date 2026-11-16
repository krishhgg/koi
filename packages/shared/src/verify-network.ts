import { z } from 'zod';
import { VerifyIdSchema } from './verify.ts';

// A verification run's private network (docs/verify.md, "Run network"):
// what koid writes to disk for each run network it makes, what it sends the
// root-owned firewall helper (host/verify/koi_verify_net.py), and what that
// helper reports about the host. The helper checks the descriptor against
// the same shape in Python; both refuse anything outside it.

// The version of the helper's rules koid expects. The helper prints its own
// in attest; another one means the host and koid disagree on the policy.
export const VERIFY_POLICY_VERSION = 1;

// The bridge of a run network: kv and twelve hex digits. Interface names are
// at most 15 characters, and the firewall's defaults match kv+.
export const BridgeNameSchema = z.string().regex(/^kv[0-9a-f]{12}$/);

export const MacAddressSchema = z.string().regex(/^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$/);

// An IPv4 network with host bits clear, as "10.213.0.16/28".
export const Cidr4Schema = z.cidrv4().refine((cidr) => {
	const [address = '', prefix = ''] = cidr.split('/');
	const bits = address.split('.').reduce((n, octet) => n * 256 + Number(octet), 0);
	const host = 32 - Number(prefix);
	return host === 0 || bits % 2 ** host === 0;
}, 'has host bits set');

// The pool run networks are carved from, a /28 each. Between a /16 (4096
// runs) and a /28 (one).
export const VerifyPoolSchema = Cidr4Schema.refine((cidr) => {
	const prefix = Number(cidr.split('/')[1]);
	return prefix >= 16 && prefix <= 28;
}, 'must be between a /16 and a /28');

// Why `pool` is not a pool run networks can be carved from, as a clause
// after the value ("has host bits set"), or undefined when it is one. koid
// keeps KOI_VERIFY_POOL as written and reports this with the variable's
// name as a reason verification is unavailable (daemon host.ts), so a
// wrong value never stops it from serving previews.
export function verifyPoolProblem(pool: string): string | undefined {
	const result = VerifyPoolSchema.safeParse(pool);
	if (result.success) return undefined;
	const issue = result.error.issues[0];
	return issue?.code === 'custom' ? issue.message : 'is not an IPv4 network in CIDR form';
}

const DockerNameSchema = z.string().regex(/^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$/);

// The names koid gives a run's network, containers and input volumes.
// Cleanup trusts one as a run's only when its name and its labels agree: a
// preview's image can carry any label, but koid alone names these.
export function runNetworkName(runId: string): string {
	return `koi-v-${runId}`;
}

export const HELPER_ROLES = ['recorder', 'verifier'] as const;

export type HelperRole = (typeof HELPER_ROLES)[number];

export function helperName(runId: string, role: HelperRole): string {
	return `koi-verify-${runId}-${role}`;
}

// The containers koid names for a run: the two helpers, and the staging
// container a point's inputs are copied through (verifier.ts). The staging
// container is never started and is on no network.
export type KoidContainerRole = HelperRole | 'staging';

export function stagingName(runId: string): string {
	return `koi-verify-${runId}-staging`;
}

// A point's inputs reach its verifier through three Docker volumes koid
// creates for each point of the run, one per directory the verifier sees
// read-only: /koi (the supervisor and the point file), /workspace (the input
// snapshot) and /fixtures. The verifier's own root stays read-only, and
// nothing of the host is bind-mounted.
export const INPUT_VOLUME_PARTS = ['koi', 'workspace', 'fixtures'] as const;

export type InputVolumePart = (typeof INPUT_VOLUME_PARTS)[number];

// The koi.role label each of them carries, beside koi.run.
export const INPUT_VOLUME_ROLE = 'inputs';

export function inputVolumeName(runId: string, part: InputVolumePart): string {
	return `koi-verify-${runId}-inputs-${part}`;
}

const HELPER_NAME = /^koi-verify-([a-z0-9]{16,40})-(recorder|verifier|staging)$/;
const INPUT_VOLUME_NAME = /^koi-verify-([a-z0-9]{16,40})-inputs-(koi|workspace|fixtures)$/;
const RUN_NETWORK_NAME = /^koi-v-([a-z0-9]{16,40})$/;

// The run and role a container's name carries, or undefined for any other
// name.
export function parseHelperName(
	name: string,
): { runId: string; role: KoidContainerRole } | undefined {
	const match = HELPER_NAME.exec(name);
	if (match?.[1] === undefined || match[2] === undefined) return undefined;
	return { runId: match[1], role: match[2] as KoidContainerRole };
}

// The run and part an input volume's name carries, or undefined for any
// other name.
export function parseInputVolumeName(
	name: string,
): { runId: string; part: InputVolumePart } | undefined {
	const match = INPUT_VOLUME_NAME.exec(name);
	if (match?.[1] === undefined || match[2] === undefined) return undefined;
	return { runId: match[1], part: match[2] as InputVolumePart };
}

// The run a run network's name carries, or undefined for any other name.
export function parseRunNetworkName(name: string): string | undefined {
	return RUN_NETWORK_NAME.exec(name)?.[1];
}

export const EndpointRoleSchema = z.enum(['app', 'recorder', 'verifier']);

export type EndpointRole = z.infer<typeof EndpointRoleSchema>;

export const RunNetworkEndpointSchema = z.strictObject({
	role: EndpointRoleSchema,
	container: DockerNameSchema,
	ip: z.ipv4(),
	mac: MacAddressSchema,
});

export type RunNetworkEndpoint = z.infer<typeof RunNetworkEndpointSchema>;

// What koid hands the helper on apply: the run, its bridge and subnet, the
// app's port, and the three endpoints. The helper checks each endpoint
// against Docker itself before it installs anything.
export const RunNetworkDescriptorSchema = z
	.strictObject({
		version: z.literal(1),
		runId: VerifyIdSchema,
		bridge: BridgeNameSchema,
		subnet: Cidr4Schema.refine((c) => c.endsWith('/28'), 'must be a /28'),
		appPort: z.number().int().min(1).max(65535),
		endpoints: z.array(RunNetworkEndpointSchema).length(3),
	})
	.refine(
		(d) => new Set(d.endpoints.map((e) => e.role)).size === 3,
		'endpoints must cover app, recorder and verifier once each',
	);

export type RunNetworkDescriptor = z.infer<typeof RunNetworkDescriptorSchema>;

// A run network's record on disk, under <stateDir>/verification/networks.
// Written before Docker is asked for anything, so a crash leaves the
// allocation reserved and startup cleanup finds it. The subnet is held
// until the record goes, which is after the helper has acknowledged revoke
// and the network is gone.
export const RunNetworkRecordSchema = z.strictObject({
	version: z.literal(1),
	runId: VerifyIdSchema,
	network: DockerNameSchema,
	bridge: BridgeNameSchema,
	subnet: Cidr4Schema,
	gateway: z.ipv4(),
	appContainer: DockerNameSchema,
	appPort: z.number().int().min(1).max(65535),
	// creating: reserved, Docker objects may or may not exist yet; ready: the
	// permits are in and attested; destroying: teardown started and did not
	// finish.
	state: z.enum(['creating', 'ready', 'destroying']),
	endpoints: z.array(RunNetworkEndpointSchema).max(3),
	createdAt: z.iso.datetime(),
});

export type RunNetworkRecord = z.infer<typeof RunNetworkRecordSchema>;

// What `koi-verify-net attest` prints. Not strict: a newer helper may say
// more. koid reads the booleans and the problems: chains, that the three
// chains exist; defaults, that each ends in its default denies; jump, that
// each is reached before any rule that could let kv+ traffic past; permits,
// that nothing sits above the denies but the permits of recorded runs.
export const VerifyAttestationSchema = z.object({
	policy: z.number().int(),
	pool: z.string().nullable(),
	ipv4: z.object({
		chains: z.boolean(),
		jump: z.boolean(),
		defaults: z.boolean(),
		permits: z.boolean(),
		problems: z.array(z.string()),
	}),
	ipv6: z.object({ defaults: z.boolean(), problems: z.array(z.string()) }),
	sysctl: z.object({
		br_netfilter: z.boolean(),
		bridge_nf_call_iptables: z.boolean(),
		bridge_nf_call_ip6tables: z.boolean(),
	}),
	runs: z.array(z.string()),
	// For each run it holds, the bridge port each endpoint's permits are
	// bound to, by role, or null while the container has not run; null for
	// a run whose state the helper could not read. A helper from before
	// this field says nothing, and koid treats a port it needs as unbound.
	ports: z.record(z.string(), z.record(z.string(), z.string().nullable()).nullable()).optional(),
});

export type VerifyAttestation = z.infer<typeof VerifyAttestationSchema>;
