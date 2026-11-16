import { z } from 'zod';

// How koid describes itself to the CLI (`koid ctl describe`). The CLI reads
// it before it hands a request to koid, so that a target that names the wrong
// host, or a host whose domain changed, stops the operation instead of
// publishing a preview under a domain nobody expected. Every transport
// returns this one shape: through SSM on AWS, and over the control socket for
// SSH and local hosts when those arrive.

// The version of the descriptor and of the control commands around it. The
// CLI refuses a host whose version it does not know.
export const HOST_PROTOCOL = 1;

// One DNS label: 1 to 63 lowercase letters, digits and hyphens, with no
// hyphen at either end.
const DNS_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

// A domain and nothing else: no scheme, port, path, wildcard, empty label or
// trailing dot, at most 253 characters, lowercase ASCII. At least two labels,
// since previews live at <label>.<domain> and the keys page at keys.<domain>,
// and a single label would put those directly under a top-level domain.
export const BareDomainSchema = z
	.string()
	.max(253)
	.refine(
		(s) => {
			const labels = s.split('.');
			return labels.length >= 2 && labels.every((label) => DNS_LABEL.test(label));
		},
		{
			message:
				'a bare domain: two or more lowercase DNS labels joined by dots, with no scheme, port, path, wildcard or trailing dot',
		},
	);

// koid makes an id on first use and keeps it in its state directory, so the
// id names the installation, not the machine or its address. The same
// alphabet as request ids, so it is safe on a command line and in a path.
export const HostIdSchema = z.string().regex(/^[a-z0-9]{16,40}$/);

// Where the host serves previews. HTTPS on 443 is the only address the CLI
// accepts for now; the port is here so a later version can agree on another.
export const HostAddressSchema = z.object({
	scheme: z.literal('https'),
	port: z.number().int().min(1).max(65535),
});

export const HostCapabilitiesSchema = z.object({
	// A two-way channel for calls and events, as against one bounded command
	// at a time.
	duplex: z.boolean(),
	// Build logs paged by attempt and byte offset (koid ctl status).
	buildLogCursor: z.boolean(),
	// A live container log, as against a bounded tail.
	runtimeLogStream: z.boolean(),
	// Artifact upload and download over the channel.
	artifactTransfer: z.boolean(),
});

export const HostInfoSchema = z.object({
	protocol: z.literal(HOST_PROTOCOL),
	hostId: HostIdSchema,
	domain: BareDomainSchema,
	address: HostAddressSchema,
	capabilities: HostCapabilitiesSchema,
});

export type HostInfo = z.infer<typeof HostInfoSchema>;
export type HostCapabilities = z.infer<typeof HostCapabilitiesSchema>;
