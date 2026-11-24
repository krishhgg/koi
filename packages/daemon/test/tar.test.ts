import { describe, expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { tarFileText } from '../src/tar.ts';

// docker cp names the entry after the path's last part.
const NAME = 'koi-slice.json';
const LONG = `koi-slice-${'x'.repeat(110)}.json`;

// Archives in fixtures/docker-cp. The docker-* ones are what
// `docker cp CONTAINER:PATH -` printed (Docker 29.5) from an image holding
// koi-slice.json, a symlink to it, an empty directory, and a file with a
// 125-byte name, for which Docker writes a PAX header. The others are GNU
// tar 1.35's, `tar --format=gnu` or `--format=pax`, with `-b 1`: one
// koi-slice.json, it and a hard link to it, two files, a file with that long
// name (a GNU long-name entry), a PAX size record of 4 for the 28-byte file
// (`--pax-option=size:=4`), and an empty sparse file (`--sparse
// --sparse-version=1.0`). Every koi-slice.json holds SLICE.
const SLICE = '{"nodes":{"core":["core"]}}\n';

function fixture(name: string): Uint8Array {
	return readFileSync(join(import.meta.dir, 'fixtures', 'docker-cp', name));
}

// A copy of `archive` whose header at `at` `change` edits, with the checksum
// made right again.
function withHeader(
	archive: Uint8Array,
	at: number,
	change: (header: Uint8Array) => void,
): Uint8Array {
	const copy = archive.slice();
	const header = copy.subarray(at, at + 512);
	change(header);
	header.fill(0x20, 148, 156);
	const sum = header.reduce((a, b) => a + b, 0);
	header.set(new TextEncoder().encode(`${sum.toString(8).padStart(6, '0')}\0 `), 148);
	return copy;
}

const typeflag = (flag: string) => (header: Uint8Array) => {
	header[156] = flag.charCodeAt(0);
};

describe('tarFileText', () => {
	test('reads the one regular file, with or without a PAX header before it', () => {
		expect(tarFileText(fixture('docker-file.tar'), 100, NAME)).toBe(SLICE);
		expect(tarFileText(fixture('docker-file-pax.tar'), 100, LONG)).toBe('{"long":true}\n');
		expect(tarFileText(fixture('gnu-file.tar'), 100, NAME)).toBe(SLICE);
		expect(tarFileText(fixture('pax-file.tar'), 100, NAME)).toBe(SLICE);
		// A global PAX header, and the typeflag old archives write for a file.
		expect(tarFileText(withHeader(fixture('pax-file.tar'), 0, typeflag('g')), 100, NAME)).toBe(
			SLICE,
		);
		expect(tarFileText(withHeader(fixture('docker-file.tar'), 0, typeflag('\0')), 100, NAME)).toBe(
			SLICE,
		);
	});

	test('refuses anything at the path but a regular file', () => {
		expect(() => tarFileText(fixture('docker-symlink.tar'), 100, NAME)).toThrow(
			'it is a symlink, not a regular file',
		);
		expect(() => tarFileText(fixture('docker-directory.tar'), 100, NAME)).toThrow(
			'it is a directory, not a regular file',
		);
		// A hard link comes after the file it names.
		expect(() => tarFileText(fixture('gnu-hardlink.tar'), 100, NAME)).toThrow(
			'it is a hard link, not a regular file',
		);
		expect(() => tarFileText(fixture('gnu-long-name.tar'), 100, NAME)).toThrow(
			'it is an entry of tar type "L", not a regular file',
		);
		for (const flag of ['3', '4', '6', '7', 'K', 'S', 'V']) {
			expect(() =>
				tarFileText(withHeader(fixture('docker-file.tar'), 0, typeflag(flag)), 100, NAME),
			).toThrow('not a regular file');
		}
	});

	test('refuses two entries', () => {
		expect(() => tarFileText(fixture('gnu-two-files.tar'), 100, NAME)).toThrow(
			'docker cp printed a tar archive of more than one entry',
		);
	});

	test('refuses an archive cut short anywhere, or with anything after its end', () => {
		const whole = fixture('docker-file.tar');
		// In the header, in the data, and before or between the end blocks.
		for (const length of [0, 100, 512, 530, 1024, 1536]) {
			expect(() => tarFileText(whole.subarray(0, length), 100, NAME)).toThrow(
				'docker cp printed a tar archive that ends early',
			);
		}
		const after = new Uint8Array(whole.length + 512);
		after.set(whole);
		expect(tarFileText(after, 100, NAME)).toBe(SLICE);
		after[whole.length + 3] = 1;
		expect(() => tarFileText(after, 100, NAME)).toThrow('with data after its end');
		expect(() => tarFileText(new Uint8Array(1024), 100, NAME)).toThrow(
			'a tar archive with no file',
		);
	});

	test('refuses a header whose checksum or size field is wrong', () => {
		const bad = fixture('docker-file.tar').slice();
		bad[0] = (bad[0] ?? 0) + 1;
		expect(() => tarFileText(bad, 100, NAME)).toThrow('checksum does not match');
		for (const size of ['0000000003x\0', '\x80\0\0\0\0\0\0\0\0\0\0\x1c', '            ']) {
			const archive = withHeader(fixture('docker-file.tar'), 0, (header) => {
				header.set(new TextEncoder().encode(size).subarray(0, 12), 124);
				if (size.startsWith('\x80')) header[124] = 0x80;
			});
			expect(() => tarFileText(archive, 100, NAME)).toThrow('a tar header with no octal size');
		}
	});

	test('refuses a file over the limit, and text that is not UTF-8', () => {
		expect(tarFileText(fixture('docker-file.tar'), SLICE.length, NAME)).toBe(SLICE);
		expect(() => tarFileText(fixture('docker-file.tar'), SLICE.length - 1, NAME)).toThrow(
			`it is more than ${SLICE.length - 1} bytes`,
		);
		const binary = fixture('docker-file.tar').slice();
		binary.set([0xff, 0xfe, 0x00], 512);
		expect(() => tarFileText(binary, 100, NAME)).toThrow('it is not UTF-8 text');
	});

	test('refuses a PAX size or sparse record, a malformed record, and a PAX header with nothing after it', () => {
		// GNU tar takes the record's 4 over the header's 28; koid takes neither.
		expect(() => tarFileText(fixture('pax-size.tar'), 100, NAME)).toThrow(
			'docker cp printed a PAX record size, which koid does not read',
		);
		expect(() => tarFileText(fixture('pax-sparse.tar'), 100, NAME)).toThrow(
			'docker cp printed a PAX record GNU.sparse.major, which koid does not read',
		);
		// "30 atime=..." claiming one byte more than it has.
		const malformed = fixture('pax-file.tar').slice();
		expect(String.fromCharCode(...malformed.subarray(512, 515))).toBe('30 ');
		malformed[513] = '1'.charCodeAt(0);
		expect(() => tarFileText(malformed, 100, NAME)).toThrow(
			'docker cp printed a malformed PAX record',
		);
		const dangling = new Uint8Array(2048);
		dangling.set(fixture('pax-file.tar').subarray(0, 1024));
		expect(() => tarFileText(dangling, 100, NAME)).toThrow('a PAX header with no entry after it');
	});

	test('refuses an entry not named as asked, by its header or its PAX path', () => {
		expect(() => tarFileText(fixture('docker-file.tar'), 100, 'other.json')).toThrow(
			'docker cp printed an entry named "koi-slice.json", not "other.json"',
		);
		// The PAX path names the entry, not the header's 100-byte name field;
		// the error shows its first 120 characters.
		expect(() => tarFileText(fixture('docker-file-pax.tar'), 100, NAME)).toThrow(
			`an entry named "${LONG.slice(0, 120)}", not "${NAME}"`,
		);
		// An old-style regular file whose name ends in a slash is a directory to Go.
		const slashed = withHeader(fixture('docker-directory.tar'), 0, typeflag('\0'));
		expect(() => tarFileText(slashed, 100, 'emptydir')).toThrow(
			'an entry named "emptydir/", not "emptydir"',
		);
		const global = withHeader(fixture('docker-file-pax.tar'), 0, typeflag('g'));
		expect(() => tarFileText(global, 100, LONG)).toThrow(
			'docker cp printed a global PAX path record, which koid does not read',
		);
	});
});
