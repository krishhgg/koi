import { mkdir, readFile, unlink } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import {
	HOST_PROTOCOL,
	type HostCapabilities,
	HostIdSchema,
	type HostInfo,
	HostInfoSchema,
	randomId,
} from '@koi/shared';
import { createFileExclusive, removeIfEmpty, waitWhileEmpty } from './fsutil.ts';

// What this koid can do for the CLI. SSM carries one bounded command at a
// time, so there is no channel, no live log and no artifact transfer; those
// come with the SSH transport.
export const SSM_CAPABILITIES: HostCapabilities = {
	duplex: false,
	buildLogCursor: true,
	runtimeLogStream: false,
	artifactTransfer: false,
};

// The name of the file under the state directory that holds the host id.
export const HOST_ID_FILE = 'host-id';

// `koid ctl describe`'s answer for this installation. The id is made on the
// first call and kept in <stateDir>/host-id, so it survives restarts and a new
// instance address, and changes only with a fresh state directory.
export function hostDescriber(stateDir: string, domain: string): () => Promise<HostInfo> {
	let id: Promise<string> | undefined;
	return async () => {
		id ??= loadHostId(join(stateDir, HOST_ID_FILE)).catch((err: unknown) => {
			// Try again next time rather than keep a failure.
			id = undefined;
			throw err;
		});
		return HostInfoSchema.parse({
			protocol: HOST_PROTOCOL,
			hostId: await id,
			domain,
			address: { scheme: 'https', port: 443 },
			capabilities: SSM_CAPABILITIES,
		} satisfies HostInfo);
	};
}

// The id in `path`, or a new one written there. Two koids that start
// together both find no file and make an id each; the file is created
// exclusively, so one of them wins and the other reads the winner's id. A
// koid that arrives while the winner's file is still empty waits for its
// content; see readHostId.
//
// A file that stays empty was left behind: where the filesystem has no hard
// links, the file exists empty between a koid's exclusive open and its
// write, and a koid that dies or fails to write then leaves it so. No id can
// have come from an empty file, so it is removed, if it is still empty, and
// the creation tried once more. Without that, every later koid would stop
// on the file for good. Any other content that is not an id is an error,
// and the file is left alone: the id is what tells the CLI this is the host
// it configured, and koid cannot tell whether that content was ever handed
// out, so a new id must never appear by accident. `fs` is for tests; see
// removeIfEmpty. One koid owns a state directory (the preview store has the
// same assumption), so two koids racing over this file is not a case this
// handles.
export async function loadHostId(
	path: string,
	fs: { unlink: typeof unlink } = { unlink },
): Promise<string> {
	const found = await readHostId(path);
	if (found.kind === 'id') return found.id;
	if (found.kind === 'empty') await removeIfEmpty(path, fs);
	const id = randomId();
	await mkdir(dirname(path), { recursive: true });
	if (await createFileExclusive(path, `${id}\n`)) return id;
	const won = await readHostId(path);
	if (won.kind === 'absent') throw new Error(`${path} was created and removed while koid started`);
	if (won.kind === 'empty') {
		throw new Error(`${path} was created and left empty again while koid started`);
	}
	return won.id;
}

// What a read of the id file found: an id, no file, or a file that stayed
// empty for about a second.
type HostIdFile = { kind: 'id'; id: string } | { kind: 'absent' } | { kind: 'empty' };

// An empty file is most likely another koid's, opened exclusively and not
// written yet, which is how createFileExclusive leaves it for a moment where
// link() is refused. The read waits for its content as the loser of that
// open does, rather than call the file bad; one that stays empty is reported
// as such for loadHostId to judge. Other content that is not an id is an
// error whose message says what to do, since koid will not touch that file.
async function readHostId(path: string): Promise<HostIdFile> {
	let text = await readText(path);
	if (text === '') {
		await waitWhileEmpty(path);
		text = await readText(path);
	}
	if (text === undefined) return { kind: 'absent' };
	if (text === '') return { kind: 'empty' };
	const parsed = HostIdSchema.safeParse(text.trim());
	if (!parsed.success) {
		throw new Error(
			`${path} does not hold a host id. koid will not replace the file, since it cannot tell whether its content was ever handed out as this host's id. To let koid make a new id on its next command, remove the file by hand.`,
		);
	}
	return { kind: 'id', id: parsed.data };
}

// The text of `path`, or undefined without the file.
async function readText(path: string): Promise<string | undefined> {
	try {
		return await readFile(path, 'utf8');
	} catch (err) {
		if (isNotFound(err)) return undefined;
		throw err;
	}
}

function isNotFound(err: unknown): boolean {
	return err instanceof Error && 'code' in err && err.code === 'ENOENT';
}
