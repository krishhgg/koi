// Prints the git tree ids koid records as deployment.source for a source
// tarball, as JSON: {"tree": ..., "runtimeTree": ...}. FILE is a tar, gzipped
// or not, or - for one on stdin. To check a preview built from a commit in a
// repository where git converts files on checkout (line endings, LFS), whose
// tree is then not the commit's, hash what git archive gives for it, as
// koi up --pr uploads it:
//
//   git archive COMMIT | bun scripts/source-tree.ts -
//
// and compare "tree" with deployment.source.tree. git archive must run with
// the core.autocrlf and attributes the build's did. See "What a deployment
// was built from" in docs/design.md.
import { createReadStream } from 'node:fs';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { createGunzip } from 'node:zlib';
import { SOURCE_LIMITS } from '../packages/daemon/src/fsutil.ts';
import { TreeReader } from '../packages/daemon/src/source-tree.ts';

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
const reader = new TreeReader(SOURCE_LIMITS);
const read = async (source: AsyncIterable<Buffer>) => {
	for await (const chunk of source) reader.push(chunk);
};
if (!first.done && first.value[0] === 0x1f && first.value[1] === 0x8b) {
	await pipeline(whole, createGunzip(), read);
} else {
	await pipeline(whole, read);
}
console.log(JSON.stringify(reader.finish()));
