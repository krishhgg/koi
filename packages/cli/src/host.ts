import {
	type Env,
	type ResolvedTarget,
	resolveTarget,
	type Target,
	type TargetFlags,
	type TargetSource,
} from './config.ts';
import { SshClient } from './ssh.ts';
import { type HostTransport, UnsupportedCapabilityError, verifiedTransport } from './transport.ts';
import { awsTransport, type Clients, clients, resolveSettings } from './transports/aws.ts';
import { localTransport } from './transports/local.ts';
import { sshTransport } from './transports/ssh.ts';

// From the command line and the environment to an open, checked transport:
// resolve the target (config.ts), build the transport for its kind, and see
// that the host's descriptor is compared with the target before anything is
// sent to koid: the AWS transport is wrapped for it (transport.ts), the SSH
// and local transports do it themselves (transports/ssh.ts, local.ts).

export interface OpenHostOptions {
	flags: TargetFlags;
	env: Env;
	checkoutDir: string;
	// Where notices go: the selected target, the legacy-path hint, warnings.
	notice: (message: string) => void;
	// AWS clients for a profile and region; the real ones unless a test
	// passes its own.
	awsClients?: ((profile: string, region: string) => Clients) | undefined;
}

export interface OpenedHost {
	box: HostTransport;
	domain: string;
	resolved: ResolvedTarget;
}

export async function openHost(o: OpenHostOptions): Promise<OpenedHost> {
	const make = o.awsClients ?? clients;
	const resolved = await resolveTarget({
		flags: o.flags,
		env: o.env,
		checkoutDir: o.checkoutDir,
		notice: o.notice,
	});
	if (resolved.kind === 'legacy') {
		// --domain stands in for KOI_DOMAIN here; the legacy resolver reads
		// only the environment.
		const env = resolved.domain === undefined ? o.env : { ...o.env, KOI_DOMAIN: resolved.domain };
		const { settings, clients: c } = await resolveSettings(env, make);
		// What koi is about to use, before anything is sent: here the host and
		// domain are known only once discovery has run.
		o.notice(
			`no koi config file at ${resolved.configPath}; using the AWS deployment as KOI_AWS_PROFILE, KOI_AWS_REGION and the box's tags describe it: aws-ssm to ${settings.instanceId} in ${settings.region}, previews under ${settings.domain}. Run koi config import-aws --name NAME to write it down (see docs/configuration.md)`,
		);
		const box = verifiedTransport(
			awsTransport(settings, c),
			{ name: 'the koi box', domain: settings.domain, oldDaemonOk: true },
			o.notice,
		);
		return { box, domain: settings.domain, resolved };
	}
	const { name, target } = resolved;
	// The selected target, with the file it came from, so that a config file
	// or alias chosen by something other than the user shows up before any
	// source is uploaded.
	const transport =
		target.transport.kind === 'local'
			? `local, koid at ${target.transport.controlSocket}`
			: target.transport.kind;
	o.notice(
		resolved.source === 'local'
			? `target ${name} (--local, built in): ${transport}, previews under ${target.domain}`
			: `target ${name} (${describeSource(resolved.source)}) from ${resolved.configPath}: ${transport}, previews under ${target.domain}`,
	);
	return {
		box: transportFor(name, target, make, o.notice, o.env),
		domain: target.domain,
		resolved,
	};
}

function describeSource(source: TargetSource): string {
	switch (source) {
		case 'flag':
			return '--target';
		case 'env':
			return 'KOI_TARGET';
		case 'repo':
			return '.koi/target.yaml';
		case 'default':
			return 'defaultTarget';
		case 'local':
			return '--local';
	}
}

// The transport for a target, checked against the host. Kinds the schema
// accepts but this version cannot drive fail here with a plain message, so
// that a config written for a newer koi is an error and not a surprise.
// `env` is koi's environment, of which the SSH transport hands ssh its PATH
// and, for a key in ssh-agent, the agent's socket.
export function transportFor(
	name: string,
	target: Target,
	make: (profile: string, region: string) => Clients,
	notice: (message: string) => void,
	env: Env,
): HostTransport {
	const quoted = JSON.stringify(name);
	if (target.address.port !== 443) {
		throw new UnsupportedCapabilityError(
			'address',
			`target ${quoted} serves previews on port ${target.address.port}; this version of koi supports port 443 only`,
		);
	}
	switch (target.transport.kind) {
		case 'aws-ssm': {
			if (target.transport.channel !== undefined) {
				throw new UnsupportedCapabilityError(
					'channel',
					`target ${quoted} sets an SSH channel next to SSM; this version of koi does not support it yet. Remove transport.channel`,
				);
			}
			if (target.aws === undefined) throw new Error(`target ${quoted} has no aws section`);
			const { profile, region, instanceId, uploadsBucket } = target.aws;
			const settings = {
				profile,
				region,
				domain: target.domain,
				instanceId,
				bucket: uploadsBucket,
				power: target.power.kind,
			};
			return verifiedTransport(
				awsTransport(settings, make(profile, region)),
				{ name: `target ${quoted}`, domain: target.domain, oldDaemonOk: true },
				notice,
			);
		}
		case 'ssh': {
			// SSH cannot start a host. An ssh target with ec2 power would need
			// the EC2 wake next to it, which this version does not combine.
			if (target.power.kind !== 'always-on') {
				throw new UnsupportedCapabilityError(
					'power',
					`target ${quoted} reaches the host over ssh and manages its power with ${target.power.kind}; this version of koi can only reach an always-on host over ssh`,
				);
			}
			const { endpoint } = target.transport;
			const client = new SshClient({ target: endpoint, env });
			// The SSH transport checks the host's descriptor itself, in
			// ensureAwake and before an upload, since its uploads reach koid
			// directly; it takes no koid from before the descriptor.
			return sshTransport(
				{ name, host: endpoint.host, user: endpoint.user, domain: target.domain },
				client,
				{ progress: notice },
			);
		}
		case 'local': {
			// koid on this machine is on or off; koi neither starts nor stops it.
			if (target.power.kind !== 'always-on') {
				throw new UnsupportedCapabilityError(
					'power',
					`target ${quoted} reaches koid on this machine and manages its power with ${target.power.kind}; a local target takes power: always-on`,
				);
			}
			// Checks the host's descriptor itself, as the SSH transport does,
			// since its uploads reach koid directly.
			return localTransport(
				{ name, socket: target.transport.controlSocket, domain: target.domain },
				{ progress: notice },
			);
		}
	}
}
