import { createHash, createHmac } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import type { ParsedCli } from './args.ts';
import { configPath, type Env, loadUserConfig, type SshEndpoint, type Target } from './config.ts';
import { toYaml, writePrivate } from './config-command.ts';
import { exec } from './exec.ts';
import { withFileLock } from './lock.ts';
import type { Io } from './main.ts';

// `koi target`: what a target's endpoint is, and which host key koi trusts
// for an SSH target. Trust is given one way only: `koi target trust NAME
// --fingerprint SHA256:...` enrolls the key the host offers if, and only
// if, its fingerprint is the one given, which the operator read on the host
// or in the provider's console. ssh-keyscan collects the candidate; it does
// not vouch for it. There is no trust on first use, and a changed key is
// trusted again only the same way.

export interface TargetCommandDeps {
	env: Env;
	notice: (message: string) => void;
	// The host keys a host offers, as ssh-keyscan prints them; the real
	// ssh-keyscan unless a test passes its own.
	keyscan?: ((host: string, port: number) => Promise<string>) | undefined;
	// How trust waits for another trust's lock on the known_hosts file;
	// Bun.sleep unless a test passes its own.
	sleep?: ((ms: number) => Promise<void>) | undefined;
	// What ssh-keygen -F prints for the alias in a known_hosts file; the real
	// ssh-keygen unless a test passes its own.
	findHost?: ((alias: string, file: string) => Promise<string>) | undefined;
	// What ssh-keygen -l prints for key lines on its stdin; the real ssh-keygen
	// unless a test passes its own.
	listKeys?: ((keys: string) => Promise<string>) | undefined;
}

export async function targetCommand(
	cli: ParsedCli,
	io: Io,
	deps: TargetCommandDeps,
): Promise<number> {
	switch (cli.sub) {
		case 'show':
			return show(cli, io, deps);
		case 'trust':
			return trust(cli, io, deps);
		default:
			throw new Error('koi target needs a subcommand: show or trust');
	}
}

// The named target as the config file has it: no overrides, no repository
// alias, so that what trust writes is the file's own endpoint.
async function namedTarget(cli: ParsedCli, deps: TargetCommandDeps) {
	const name = cli.name;
	if (name === undefined) throw new Error('koi target needs a target name');
	const { path } = configPath({ config: cli.config }, deps.env);
	const loaded = await loadUserConfig(path, true, deps.notice);
	if (loaded === undefined) throw new Error(`no config file at ${path}`);
	const target = Object.hasOwn(loaded.config.targets, name)
		? loaded.config.targets[name]
		: undefined;
	if (target === undefined) {
		const names = Object.keys(loaded.config.targets);
		throw new Error(
			`${path} has no target ${JSON.stringify(name)}; it has ${names.length === 0 ? 'no targets' : names.join(', ')}`,
		);
	}
	return { name, path, target };
}

async function show(cli: ParsedCli, io: Io, deps: TargetCommandDeps): Promise<number> {
	const { name, path, target } = await namedTarget(cli, deps);
	const endpoint = sshEndpoint(target);
	const hostKeys =
		endpoint === undefined
			? null
			: await trustedKeys(endpoint.knownHostsFile, endpoint.hostKeyAlias, deps.listKeys);
	if (cli.json) {
		io.stdout(`${JSON.stringify({ file: path, target: name, settings: target, hostKeys })}\n`);
		return 0;
	}
	const lines = [`target ${name} in ${path}:`, ...indent(toYaml(settingsShown(target)))];
	if (endpoint !== undefined && hostKeys !== null) {
		lines.push(
			hostKeys.length === 0
				? `  host key: none trusted for ${endpoint.hostKeyAlias} in ${endpoint.knownHostsFile}; run koi target trust ${name} --fingerprint SHA256:... with the fingerprint from the host's operator`
				: `  host key: ${hostKeys.map((k) => `${k.fingerprint} (${k.type})`).join(', ')} as ${endpoint.hostKeyAlias} in ${endpoint.knownHostsFile}`,
		);
	}
	io.stdout(`${lines.join('\n')}\n`);
	return 0;
}

// The target without the defaults the schema filled in, as the file shows it.
function settingsShown(target: Target): Record<string, unknown> {
	const { address, ...rest } = target;
	return address.port === 443 ? rest : target;
}

function indent(text: string): string[] {
	return text
		.trimEnd()
		.split('\n')
		.map((line) => `  ${line}`);
}

function sshEndpoint(target: Target): SshEndpoint | undefined {
	return target.transport.kind === 'ssh' ? target.transport.endpoint : undefined;
}

async function trust(cli: ParsedCli, io: Io, deps: TargetCommandDeps): Promise<number> {
	const { name, path, target } = await namedTarget(cli, deps);
	const endpoint = sshEndpoint(target);
	if (endpoint === undefined) {
		throw new Error(
			`target ${JSON.stringify(name)} in ${path} uses the ${target.transport.kind} transport; only an ssh target has a host key to trust`,
		);
	}
	const wanted = cli.fingerprint;
	if (wanted === undefined) throw new Error('target trust needs --fingerprint');
	const { host, port, knownHostsFile, hostKeyAlias } = endpoint;
	const offered = parseKeyscan(await (deps.keyscan ?? keyscan)(host, port));
	if (offered.length === 0) {
		throw new Error(
			`ssh-keyscan got no host key from ${host}:${port}; check that the host is reachable and sshd listens there`,
		);
	}
	const match = offered.find((k) => k.fingerprint === wanted);
	if (match === undefined) {
		throw new Error(
			`none of the ${offered.length} host ${offered.length === 1 ? 'key' : 'keys'} ${host}:${port} offers has the fingerprint ${wanted}, so koi trusts nothing. Offered: ${offered.map((k) => `${k.fingerprint} (${k.type})`).join(', ')}. Check the fingerprint with the host's operator (ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub on the host) and run koi target trust again with the right one`,
		);
	}
	// The file is read and written under its lock: two trusts that share a
	// file, for two targets, would otherwise each read the old file, and
	// the last to write would erase the other's key.
	const replaced = await withFileLock(
		knownHostsFile,
		'koi target trust',
		deps.sleep ?? Bun.sleep,
		async () => {
			const kept: string[] = [];
			let had = false;
			for (const line of await knownHostsLines(knownHostsFile)) {
				const entry = parseKnownHostsLine(line);
				// A revocation only takes trust away, so it stays whatever it
				// matches. Removing the alias from it would let the revoked key
				// back in.
				if (entry === undefined || entry.revoked || !hostsMatch(entry.hosts, hostKeyAlias)) {
					kept.push(line);
					continue;
				}
				had = true;
				// A line the alias shares with other names (`team,prod ssh-ed25519
				// ...`) stays for them, with their key. koi's own line for the alias
				// is appended below.
				const others = hostsWithoutAlias(entry.hosts, hostKeyAlias);
				if (others !== '') kept.push(`${entry.marker}${others}${entry.rest}`);
			}
			kept.push(`${hostKeyAlias} ${match.type} ${match.key}`);
			// OpenSSH has the last word on what the new file means for the
			// alias. A line this code reads differently stops the rewrite, and
			// no old key stays trusted behind a report that it was replaced.
			const findHost = deps.findHost ?? sshKeygenFind;
			await writePrivate(knownHostsFile, `${kept.join('\n')}\n`, async (temp) => {
				const found: KnownHostsEntry[] = [];
				for (const line of (await findHost(hostKeyAlias, temp)).split('\n')) {
					const entry = parseKnownHostsLine(line);
					if (entry !== undefined) found.push(entry);
				}
				const revocations = await readKeys(
					found.filter((entry) => entry.revoked),
					deps.listKeys,
				);
				checkOnlyKey(found, revocations, knownHostsFile, hostKeyAlias, match);
			});
			return had;
		},
	);
	if (cli.json) {
		io.stdout(
			`${JSON.stringify({
				file: knownHostsFile,
				target: name,
				alias: hostKeyAlias,
				host,
				port,
				type: match.type,
				fingerprint: match.fingerprint,
				replaced,
			})}\n`,
		);
		return 0;
	}
	io.stdout(
		`${replaced ? 'replaced the host key of' : 'trusted'} ${host}:${port} as ${hostKeyAlias} in ${knownHostsFile}: ${match.type} ${match.fingerprint}\n`,
	);
	return 0;
}

export interface HostKey {
	type: string;
	// The key in base64, as a known_hosts line carries it.
	key: string;
	fingerprint: string;
}

// The keys ssh-keyscan printed: one `host type key` line each, comments on
// stderr and so not here. A line that is not one is skipped.
export function parseKeyscan(output: string): HostKey[] {
	const keys: HostKey[] = [];
	for (const line of output.split('\n')) {
		if (line.startsWith('#') || line.trim() === '') continue;
		const [, type, key] = line.trim().split(/\s+/);
		if (type === undefined || key === undefined || !BASE64.test(key)) continue;
		keys.push({ type, key, fingerprint: fingerprint(key) });
	}
	return keys;
}

const BASE64 = /^[A-Za-z0-9+/]+={0,2}$/;

// The SHA256 fingerprint of a key in base64, as ssh-keygen -l prints it.
export function fingerprint(key: string): string {
	const digest = createHash('sha256').update(Buffer.from(key, 'base64')).digest('base64');
	return `SHA256:${digest.replace(/=+$/, '')}`;
}

// The keys the known_hosts file trusts for `alias`, as OpenSSH reads the file: a
// wildcard and a hashed name count, and a key the file revokes for the alias does
// not. A line without a marker that holds a certificate trusts nothing either,
// since ssh wants the plain key there and reports the host's key as changed.
export async function trustedKeys(
	file: string,
	alias: string,
	listKeys?: TargetCommandDeps['listKeys'],
): Promise<HostKey[]> {
	const entries: KnownHostsEntry[] = [];
	for (const line of await knownHostsLines(file)) {
		const entry = parseKnownHostsLine(line);
		if (entry !== undefined && hostsMatch(entry.hosts, alias)) entries.push(entry);
	}
	const keys = await readKeys(entries, listKeys);
	const revoked = new Set(keys.filter((k) => k.entry.revoked).map((k) => k.fingerprint));
	const trusted: HostKey[] = [];
	for (const k of keys) {
		if (k.entry.revoked || revoked.has(k.fingerprint)) continue;
		if (k.certificate && k.entry.marker === '') continue;
		trusted.push({ type: k.entry.type, key: k.entry.key, fingerprint: k.fingerprint });
	}
	return trusted;
}

// Checks what ssh-keygen -F found for the alias in the rewritten file. No line
// may revoke the new key, since ssh would refuse it, the new key must be there,
// and no line may trust another key. A revocation of another key is fine.
//
// The two comparisons differ as OpenSSH's do. A revocation applies to the public
// key whatever form the line holds it in, so a line with a certificate revokes
// the key inside it (hostfile.c, check_key_not_revoked). That is why `revocations`
// carries OpenSSH's fingerprints. A line that trusts a key must hold that key
// itself, so there the bytes on the line are compared.
function checkOnlyKey(
	found: KnownHostsEntry[],
	revocations: ReadKey[],
	file: string,
	alias: string,
	wanted: HostKey,
): void {
	const revocation = revocations.find((k) => k.fingerprint === wanted.fingerprint);
	if (revocation !== undefined) {
		throw new Error(
			`${file} revokes the key ${wanted.fingerprint} for ${alias}, on the line "${revocation.entry.line}", so ssh would refuse it. koi changed nothing. If the key is good after all, remove that line by hand and run koi target trust again`,
		);
	}
	let present = false;
	for (const entry of found) {
		if (entry.revoked) continue;
		if (fingerprint(entry.key) !== wanted.fingerprint || entry.marker !== '') {
			throw new Error(
				`after the rewrite ${file} would still trust ${fingerprint(entry.key)} for ${alias}, on the line "${entry.line}", where only ${wanted.fingerprint} should be trusted. koi changed nothing. Remove that line by hand and run koi target trust again`,
			);
		}
		present = true;
	}
	if (!present) {
		throw new Error(
			`ssh-keygen does not find the key koi wrote for ${alias} in the rewritten ${file}, so koi changed nothing`,
		);
	}
}

// What ssh-keygen -F prints for the alias in the file. It exits 1 when it finds
// nothing, which checkOnlyKey reports.
async function sshKeygenFind(alias: string, file: string): Promise<string> {
	const r = await exec(['ssh-keygen', '-F', alias, '-f', file], { timeoutMs: 30_000 });
	if (r.timedOut) throw new Error('ssh-keygen did not answer within 30 seconds');
	if (r.code !== 0 && r.code !== 1) {
		throw new Error(`ssh-keygen -F exited ${r.code}: ${r.stderr.trim()}`);
	}
	return r.stdout;
}

// A known_hosts entry whose key OpenSSH can parse.
interface ReadKey {
	entry: KnownHostsEntry;
	// As ssh-keygen -l prints it. For a certificate, the fingerprint of the public
	// key inside it, which the hash of the line's bytes is not.
	fingerprint: string;
	certificate: boolean;
}

// The entries whose key OpenSSH can parse, in order. ssh passes over a line it
// cannot parse, so that line neither trusts nor revokes anything, and ssh-keygen
// leaves it out here for the same reason. A line left out shifts the output, so
// each key goes in with its entry's index as its comment, and the index comes
// back with the fingerprint.
async function readKeys(
	entries: KnownHostsEntry[],
	listKeys: TargetCommandDeps['listKeys'] = sshKeygenList,
): Promise<ReadKey[]> {
	if (entries.length === 0) return [];
	const listed = await listKeys(entries.map((e, i) => `${e.type} ${e.key} ${i}\n`).join(''));
	const keys: ReadKey[] = [];
	for (const line of listed.split('\n')) {
		const [, printed, index, cert] = /^\d+ (SHA256:\S+) (\d+) \(\S*?(-CERT)?\)$/.exec(line) ?? [];
		const entry = entries[Number(index)];
		if (printed !== undefined && entry !== undefined) {
			keys.push({ entry, fingerprint: printed, certificate: cert !== undefined });
		}
	}
	return keys;
}

// What ssh-keygen -l prints for the key lines on its stdin. It exits 255 when no
// line holds a key it can parse, which readKeys reads as no keys. Any other
// failure throws, so that a revocation koi could not read cannot pass as none.
async function sshKeygenList(keys: string): Promise<string> {
	const r = await exec(['ssh-keygen', '-E', 'sha256', '-l', '-f', '-'], {
		stdin: keys,
		timeoutMs: 30_000,
	});
	if (r.timedOut) throw new Error('ssh-keygen did not answer within 30 seconds');
	if (r.code !== 0 && !r.stderr.includes('is not a public key file')) {
		throw new Error(`ssh-keygen -l exited ${r.code}: ${r.stderr.trim()}`);
	}
	return r.stdout;
}

export async function knownHostsLines(file: string): Promise<string[]> {
	let text: string;
	try {
		text = await readFile(file, 'utf8');
	} catch (err) {
		if (err instanceof Error && 'code' in err && err.code === 'ENOENT') return [];
		throw err;
	}
	// OpenSSH and ssh-keygen read a line with a NUL byte differently, so a
	// revocation behind one could be missed here and still refuse the key later.
	if (text.includes('\0')) {
		throw new Error(
			`${file} has a NUL byte, so koi cannot tell what it trusts. Remove that line and run the command again`,
		);
	}
	const lines = text.split('\n');
	if (lines.at(-1) === '') lines.pop();
	return lines;
}

interface KnownHostsEntry {
	// The line as the file has it, for messages.
	line: string;
	// The marker with the blank after it, or empty.
	marker: string;
	revoked: boolean;
	// The host field as the file has it.
	hosts: string;
	type: string;
	key: string;
	// The line from the blank after the host field to its end, so that the
	// line can be written again with another host field and nothing else
	// changed.
	rest: string;
}

// A known_hosts line: an optional marker, the host field, the key type and the
// key. Comments and blank lines are not lines of this kind, and neither is a
// line with a marker OpenSSH does not know, which it skips. OpenSSH ends a marker
// at the first space on the line, and at the first tab only on a line with no
// space (hostfile.c, check_markers). So `@revoked<tab>* ssh-ed25519 KEY` has a
// marker it does not know, and revokes nothing.
function parseKnownHostsLine(line: string): KnownHostsEntry | undefined {
	const m = /^[ \t]*(@[^ \t]+[ \t]+)?([^ \t]+)([ \t]+([^ \t]+)[ \t]+([^ \t]+).*)$/s.exec(line);
	if (m === null) return undefined;
	const [, marker = '', hosts, rest, type, key] = m;
	if (hosts === undefined || hosts.startsWith('#') || rest === undefined) return undefined;
	if (type === undefined || key === undefined) return undefined;
	const name = marker.trim();
	if (name !== '' && name !== '@cert-authority' && name !== '@revoked') return undefined;
	if (marker.startsWith(`${name}\t`) && `${marker}${rest}`.includes(' ')) return undefined;
	return { line, marker, revoked: name === '@revoked', hosts, type, key, rest };
}

// Whether OpenSSH applies a host field to the alias (hostfile.c,
// match_maybe_hashed; match.c, match_pattern_list). A field that starts with
// `|` is one hashed name compared whole, so `|1|salt|hash,prod` matches nobody.
// Any other field is a list of patterns, read without regard to case, and one
// negated pattern that matches rules the line out wherever it stands. An alias
// is lower case by the config's schema.
function hostsMatch(field: string, alias: string): boolean {
	if (field.startsWith('|')) return hashedNameIs(field, alias);
	let positive = false;
	for (const pattern of field.toLowerCase().split(',')) {
		const negated = pattern.startsWith('!');
		if (!patternMatches(negated ? pattern.slice(1) : pattern, alias)) continue;
		if (negated) return false;
		positive = true;
	}
	return positive;
}

// A host field that hostsMatch says holds the alias, rewritten so that it does
// not, or empty when no name is left. A plain name leaves. A wildcard must stay
// for the other names it covers, so the list gains a negation of the alias.
// A hash here is a literal name that no host has. It leaves as well, since at
// the front of the field OpenSSH would start to read it as a hash and trust the
// line's key for a name that has no such trust today.
function hostsWithoutAlias(field: string, alias: string): string {
	if (field.startsWith('|')) return '';
	const kept: string[] = [];
	let wildcard = false;
	for (const pattern of field.split(',')) {
		if (pattern === '' || pattern.startsWith('|')) continue;
		const lower = pattern.toLowerCase();
		if (lower.startsWith('!') || !patternMatches(lower, alias)) {
			kept.push(pattern);
		} else if (/[*?]/.test(pattern)) {
			kept.push(pattern);
			wildcard = true;
		}
	}
	if (wildcard) kept.push(`!${alias}`);
	return kept.join(',');
}

// Whether `|1|salt|hash` is the alias: the HMAC-SHA1 of the name under the
// salt, compared on the whole text, as OpenSSH compares it. Its salts are 20
// bytes, and a salt of any other length matches no name.
function hashedNameIs(field: string, alias: string): boolean {
	const salt = /^\|1\|([^|]+)\|/.exec(field)?.[1];
	if (salt === undefined) return false;
	const bytes = Buffer.from(salt, 'base64');
	if (bytes.byteLength !== 20) return false;
	const hash = createHmac('sha1', bytes).update(alias).digest('base64');
	return field === `|1|${bytes.toString('base64')}|${hash}`;
}

// OpenSSH's match_pattern: `*` for any run of characters, `?` for one. A loop
// and not a regular expression, since backtracking on a line of many `*`s
// could run for a very long time.
function patternMatches(pattern: string, text: string): boolean {
	let p = 0;
	let t = 0;
	let star = -1;
	let resume = 0;
	while (t < text.length) {
		if (pattern[p] === '*') {
			star = p++;
			resume = t;
		} else if (p < pattern.length && (pattern[p] === '?' || pattern[p] === text[t])) {
			p++;
			t++;
		} else if (star >= 0) {
			p = star + 1;
			t = ++resume;
		} else {
			return false;
		}
	}
	while (pattern[p] === '*') p++;
	return p === pattern.length;
}

// ssh-keyscan against the host, with its comments left on stderr.
async function keyscan(host: string, port: number): Promise<string> {
	const r = await exec(['ssh-keyscan', '-p', String(port), '-T', '10', '--', host], {
		timeoutMs: 30_000,
	});
	if (r.timedOut)
		throw new Error(`ssh-keyscan did not answer for ${host}:${port} within 30 seconds`);
	if (r.code !== 0 && r.stdout.trim() === '') {
		throw new Error(
			`ssh-keyscan exited ${r.code} for ${host}:${port}${r.stderr.trim() === '' ? '' : `: ${r.stderr.trim().split('\n').at(-1)}`}`,
		);
	}
	return r.stdout;
}
