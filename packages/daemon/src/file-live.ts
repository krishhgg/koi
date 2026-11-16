import { mkdir } from 'node:fs/promises';
import { dirname } from 'node:path';
import { encodeLivePreviews } from '@koi/shared';
import { writeFileAtomic } from './fsutil.ts';
import type { LiveList } from './live.ts';

// The live list as a JSON file on the host, for a box with no wake function:
// whatever wakes or watches the box reads the file. The whole list is
// written to a temporary file and renamed into place, so a reader sees the
// old list or the new, never half of one. A file has no size cap, so there
// is always room for another label.
//
// The file is world readable: it holds only preview labels, which the
// previews' hostnames show anyway, and a helper under another user may
// need to read it.
export function fileLiveList(path: string): LiveList {
	let last: string | undefined;
	return {
		room: () => ({ ok: true }),
		async publish(labels) {
			const value = encodeLivePreviews(labels);
			if (value === last) return;
			await mkdir(dirname(path), { recursive: true });
			await writeFileAtomic(path, `${value}\n`, 0o644);
			last = value;
		},
	};
}
