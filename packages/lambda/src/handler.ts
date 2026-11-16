import { DescribeInstancesCommand, EC2Client, StartInstancesCommand } from '@aws-sdk/client-ec2';
import { GetParameterCommand, SSMClient } from '@aws-sdk/client-ssm';
import { LivePreviewsSchema, labelFromHost, RESERVED_LABELS } from '@koi/shared';
import { wakePage } from './wake-page.ts';

// Lambda function URL event, reduced to what this handler reads.
export interface FunctionUrlEvent {
	rawPath: string;
	rawQueryString?: string | undefined;
	requestContext: { http: { method: string } };
}

export interface FunctionUrlResult {
	statusCode: number;
	headers: Record<string, string>;
	body: string;
}

const INSTANCE_STATES = [
	'pending',
	'running',
	'stopping',
	'stopped',
	'shutting-down',
	'terminated',
	'unknown',
] as const;
export type InstanceState = (typeof INSTANCE_STATES)[number];

// What the handler needs from AWS, so tests can supply fakes.
export interface WakeDeps {
	instanceState(): Promise<InstanceState>;
	startInstance(): Promise<void>;
	livePreviews(): Promise<string[]>;
}

export interface WakeConfig {
	domain: string;
}

const PATH_PREFIX = '/__koi-wake';

export function createHandler(deps: WakeDeps, config: WakeConfig) {
	return async (event: FunctionUrlEvent): Promise<FunctionUrlResult> => {
		const method = event.requestContext.http.method;
		if (method !== 'GET' && method !== 'HEAD') {
			return text(405, 'method not allowed');
		}
		const path = event.rawPath.startsWith(PATH_PREFIX)
			? event.rawPath.slice(PATH_PREFIX.length)
			: null;
		switch (path) {
			case '/index.html':
			case '/':
				return {
					statusCode: 200,
					headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' },
					body: wakePage(),
				};
			case '/wake':
				try {
					return await wake(new URLSearchParams(event.rawQueryString ?? '').get('host'));
				} catch (err) {
					// An AWS hiccup is not "no preview here": the page retries.
					console.error('wake failed', err);
					return json(503, { error: 'try again' });
				}
			case '/status':
				try {
					return json(200, { instance: await deps.instanceState() });
				} catch (err) {
					console.error('status failed', err);
					return json(503, { error: 'try again' });
				}
			default:
				return text(404, 'not found');
		}
	};

	async function wake(host: string | null): Promise<FunctionUrlResult> {
		const label = labelFromHost(host, config.domain);
		if (label === null) {
			return json(400, { known: false, error: 'host is not a preview address' });
		}
		// koi's own pages (the keys page) wake the box like any live preview.
		const live = await deps.livePreviews();
		if (!live.includes(label) && !(RESERVED_LABELS as readonly string[]).includes(label)) {
			return json(404, { known: false });
		}
		// Only a stopped box can be started. A box that is still stopping
		// reports its state; the page calls again on its next round, by which
		// time it has stopped and this branch starts it.
		let state = await deps.instanceState();
		if (state === 'stopped') {
			await deps.startInstance();
			state = 'pending';
		}
		return json(200, { known: true, instance: state });
	}
}

function json(statusCode: number, body: unknown): FunctionUrlResult {
	return {
		statusCode,
		headers: { 'content-type': 'application/json', 'cache-control': 'no-store' },
		body: JSON.stringify(body),
	};
}

function text(statusCode: number, body: string): FunctionUrlResult {
	return {
		statusCode,
		headers: { 'content-type': 'text/plain', 'cache-control': 'no-store' },
		body: `${body}\n`,
	};
}

// --- Real dependencies -----------------------------------------------------

function env(name: string): string {
	const value = process.env[name];
	if (value === undefined || value === '') throw new Error(`${name} is not set`);
	return value;
}

// The AWS calls the wake function makes. Clients are injectable so tests can
// check the requests and feed responses without AWS.
export interface AwsClients {
	ec2: Pick<EC2Client, 'send'>;
	ssm: Pick<SSMClient, 'send'>;
}

export function awsDeps(
	instanceId: string,
	previewsParam: string,
	clients: AwsClients = { ec2: new EC2Client({}), ssm: new SSMClient({}) },
): WakeDeps {
	const { ec2, ssm } = clients;
	return {
		async instanceState() {
			const out = await ec2.send(new DescribeInstancesCommand({ InstanceIds: [instanceId] }));
			const name = out.Reservations?.[0]?.Instances?.[0]?.State?.Name;
			return INSTANCE_STATES.find((state) => state === name) ?? 'unknown';
		},
		async startInstance() {
			await ec2.send(new StartInstancesCommand({ InstanceIds: [instanceId] }));
		},
		async livePreviews() {
			const out = await ssm.send(new GetParameterCommand({ Name: previewsParam }));
			return LivePreviewsSchema.parse(JSON.parse(out.Parameter?.Value ?? '[]'));
		},
	};
}

let real: ((event: FunctionUrlEvent) => Promise<FunctionUrlResult>) | undefined;

export async function handler(event: FunctionUrlEvent): Promise<FunctionUrlResult> {
	real ??= createHandler(awsDeps(env('KOI_INSTANCE_ID'), env('KOI_PREVIEWS_PARAM')), {
		domain: env('KOI_DOMAIN'),
	});
	return real(event);
}
