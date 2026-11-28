import { readFile } from 'node:fs/promises';
import { ExecError, type ExecOptions, type ExecResult, exec } from './exec.ts';

// How a preview reaches the internet: only through the egress proxy
// (host/egress), which it must also trust, since the proxy intercepts TLS to
// check which host each request is for. The daemon gives each preview
// container the proxy settings and a CA bundle; a container started without
// them has no way out at all.
export interface Egress {
	// e.g. http://172.18.0.1:3128
	proxy: string;
	// PEM: the system's trusted CAs plus the egress proxy's CA.
	caBundle: string;
	// PEM: the egress proxy's CA alone. Node adds NODE_EXTRA_CA_CERTS to its
	// own list rather than replacing it.
	caCert: string;
}

// Directly in /etc: docker cp does not create a missing directory, and Docker
// makes /etc in every container (for hosts, hostname and resolv.conf), even
// one whose image has no /etc, such as a static binary FROM scratch.
export const CA_BUNDLE_PATH = '/etc/koi-ca-bundle.pem';
export const CA_CERT_PATH = '/etc/koi-ca.pem';

const SYSTEM_BUNDLE = '/etc/ssl/certs/ca-certificates.crt';

export async function loadEgress(
	proxy: string,
	caPath: string,
	systemBundle = SYSTEM_BUNDLE,
): Promise<Egress> {
	const caCert = await readFile(caPath, 'utf8');
	if (!caCert.includes('BEGIN CERTIFICATE')) throw new Error(`${caPath} is not a PEM certificate`);
	const system = await readFile(systemBundle, 'utf8');
	return { proxy, caCert, caBundle: `${system.trimEnd()}\n${caCert.trimEnd()}\n` };
}

// Environment for a preview container. Both spellings of the proxy variables,
// because tools disagree on which they read. The proxy intercepts TLS to every
// host it allows, so whatever a preview uses must trust its CA: OpenSSL and
// Python's ssl module, httpx, uv and Hugging Face's hf_xet read SSL_CERT_FILE;
// requests reads REQUESTS_CA_BUNDLE, pip PIP_CERT, curl CURL_CA_BUNDLE, gRPC
// GRPC_DEFAULT_SSL_ROOTS_FILE_PATH, and Node NODE_EXTRA_CA_CERTS.
export function egressEnv(egress: Egress): Record<string, string> {
	return {
		HTTP_PROXY: egress.proxy,
		HTTPS_PROXY: egress.proxy,
		http_proxy: egress.proxy,
		https_proxy: egress.proxy,
		NO_PROXY: 'localhost,127.0.0.1',
		no_proxy: 'localhost,127.0.0.1',
		SSL_CERT_FILE: CA_BUNDLE_PATH,
		REQUESTS_CA_BUNDLE: CA_BUNDLE_PATH,
		CURL_CA_BUNDLE: CA_BUNDLE_PATH,
		PIP_CERT: CA_BUNDLE_PATH,
		GRPC_DEFAULT_SSL_ROOTS_FILE_PATH: CA_BUNDLE_PATH,
		NODE_EXTRA_CA_CERTS: CA_CERT_PATH,
	};
}

export function egressFiles(egress: Egress): Array<{ path: string; content: string }> {
	return [
		{ path: CA_BUNDLE_PATH, content: egress.caBundle },
		{ path: CA_CERT_PATH, content: egress.caCert },
	];
}

// The DNS server a preview uses: the egress proxy's DNS listener, on the
// address the proxy listens on (host/egress/install.sh). It answers only for
// names the proxy lets previews reach, with public addresses only.
export function egressDns(egress: Egress): string {
	return new URL(egress.proxy).hostname;
}

type Run = (cmd: string[], options?: ExecOptions) => Promise<ExecResult>;

// Gives a preview container just started a default route to its bridge, the
// way out for code in it that ignores the proxy setting, which the box's
// firewall sends to the same proxy. Through the root-owned helper
// (host/egress/koi-preview-route) and sudo: the sudoers rule provisioning
// installs names exactly this path (host/cloud-init.sh), and -n fails
// instead of waiting for a password.
export function previewRoute(path: string, run: Run = exec): (container: string) => Promise<void> {
	return async (container) => {
		const cmd = ['sudo', '-n', path, container];
		const r = await run(cmd, { timeoutMs: 30_000 });
		if (r.code !== 0 || r.timedOut) throw new ExecError(cmd, r);
	};
}
