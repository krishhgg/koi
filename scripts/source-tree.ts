// Prints what koid records as deployment.source for a build of a source
// tarball, as JSON: {"digest": ..., "tree": ..., "runtimeTree": ...}. FILE
// is a tar, gzipped or not, or - for one on stdin. The script unpacks it as
// koid does (extractTarball) and walks the result with koid's own code
// (hashSourceDir), so the two cannot disagree.
//
// To know which commit's content a preview read, compute the tree you
// expect from your own copy of the repository, as koi up --pr uploads the
// commit:
//
//   git archive COMMIT | bun scripts/source-tree.ts -
//
// and compare "tree" with deployment.source.tree. git archive must run with
// the core.autocrlf and attributes the build's did. "digest" is koid's only
// when tar here applies the umask koid's did. See "What a deployment was
// built from" in docs/design.md.
import { createReadStream, createWriteStream } from 'node:fs';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { createGzip } from 'node:zlib';
import { hashSourceTarball } from '../packages/daemon/src/source-tree.ts';

const file = process.argv[2];
if (file === undefined || process.argv.length > 3) {
	console.error('usage: bun scripts/source-tree.ts FILE|-');
	process.exit(2);
}
const input: AsyncIterable<Buffer> = file === '-' ? process.stdin : createReadStream(file);
const chunks = input[Symbol.asyncIterator]();
const first = await chunks.next();
// The stream again, with the chunk read to look for gzip's magic bytes.
const whole = Readable.from(
	(async function* () {
		if (!first.done) yield first.value;
		for (let next = await chunks.next(); !next.done; next = await chunks.next()) yield next.value;
	})(),
);
const gzipped = !first.done && first.value[0] === 0x1f && first.value[1] === 0x8b;
// koid unpacks a gzipped tarball from a file, so this one is made one.
const work = await mkdtemp(join(tmpdir(), 'koi-source-tree-'));
try {
	const tarball = join(work, 'source.tar.gz');
	if (gzipped) await pipeline(whole, createWriteStream(tarball));
	else await pipeline(whole, createGzip({ level: 1 }), createWriteStream(tarball));
	console.log(JSON.stringify(await hashSourceTarball(tarball)));
} finally {
	await rm(work, { recursive: true, force: true });
}
