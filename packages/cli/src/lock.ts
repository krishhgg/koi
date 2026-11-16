import { mkdir, rmdir } from 'node:fs/promises';
import { dirname } from 'node:path';

// A lock on a file koi rewrites whole: `koi config import-aws` on the config
// file, `koi target trust` on a known_hosts file. Two runs that both read
// the file and write it back would each lose the other's change; the lock
// puts them in turn.
//
// The lock is a directory beside the file, made with mkdir, which either
// makes the directory or fails with EEXIST, with nothing in between: that
// is all the lock needs. There is no automatic takeover of a lock that
// looks abandoned. Telling a crashed holder's lock from a slow holder's is
// guesswork, and a wrong guess lets two runs write at once, which is the
// very thing the lock is for. So a contender waits for the lock to go away,
// up to LOCK_WAIT_MS, and then fails and asks the operator to remove it by
// hand. Only the run that made the directory ever removes it.

// How long a run waits for another to release the lock before it gives up,
// as the sum of its sleeps between looks.
export const LOCK_WAIT_MS = 60_000;

// How long a run sleeps between looks at a held lock.
const LOCK_POLL_MS = 200;

// Runs `task` while holding <path>.lock. `holder` names the command that
// takes this lock, for the message when it is held: "koi config", say.
export async function withFileLock<T>(
	path: string,
	holder: string,
	sleep: (ms: number) => Promise<void>,
	task: () => Promise<T>,
): Promise<T> {
	const lock = `${path}.lock`;
	await mkdir(dirname(path), { recursive: true, mode: 0o700 });
	await acquireLock(lock, holder, sleep);
	try {
		return await task();
	} finally {
		await releaseLock(lock);
	}
}

// Makes the lock directory, waiting while another holds it.
async function acquireLock(
	lock: string,
	holder: string,
	sleep: (ms: number) => Promise<void>,
): Promise<void> {
	for (let waited = 0; ; waited += LOCK_POLL_MS) {
		try {
			await mkdir(lock, { mode: 0o700 });
			return;
		} catch (err) {
			if (!isCode(err, 'EEXIST')) throw err;
		}
		if (waited >= LOCK_WAIT_MS) {
			throw new Error(
				`another ${holder} holds the lock ${lock}, and did not release it within ${LOCK_WAIT_MS / 1000} seconds. A previous ${holder} run may have crashed and left it behind. Check that no other ${holder} is running, then remove the directory ${lock} by hand and try again.`,
			);
		}
		await sleep(LOCK_POLL_MS);
	}
}

// Removes the lock directory this run made. One that is already gone was
// removed by hand, and there is nothing left to release.
async function releaseLock(lock: string): Promise<void> {
	try {
		await rmdir(lock);
	} catch (err) {
		if (!isCode(err, 'ENOENT')) throw err;
	}
}

function isCode(err: unknown, code: string): boolean {
	return err instanceof Error && 'code' in err && err.code === code;
}
