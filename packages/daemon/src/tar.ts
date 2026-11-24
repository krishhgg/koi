// Reads the one regular file in the tar archive that
// `docker cp CONTAINER:PATH -` prints. koid reads it in memory and never
// extracts what an image holds.
//
// Docker writes the archive with Go's archive/tar: a 512-byte header for
// each entry, the entry's data padded to whole blocks, and two zero blocks at
// the end. Before the file it may write a PAX extended header ('x'), whose
// data holds records for what a header cannot, such as a name over 100
// bytes or extended attributes. A global PAX header ('g') is allowed too.
//
// A PAX record can also set the file's size, and a reader that honours it
// finds the next header somewhere the header's own size field does not say.
// Go writes such a record only for a file of 8 GiB or more, so koid refuses
// any: the octal size field is the only size it reads. It refuses GNU's
// sparse records too, which make the data of a plain file a sparse map.
//
// The entry must also carry the name koid asked for: the last part of the
// path, as docker cp names it, after any PAX path record. A name with a
// trailing slash is a directory to Go's reader whatever its typeflag.
//
// Each refusal throws an Error that says why.

const BLOCK = 512;

const KINDS: Record<string, string> = {
	'1': 'a hard link',
	'2': 'a symlink',
	'3': 'a character device',
	'4': 'a block device',
	'5': 'a directory',
	'6': 'a fifo',
};

// The text of the only entry in `archive`, which must be a regular file
// (typeflag '0', or NUL as old archives write it) named `name` of at most
// `maxBytes` bytes of UTF-8.
export function tarFileText(archive: Uint8Array, maxBytes: number, name: string): string {
	let at = 0;
	let file: Uint8Array | undefined;
	// A PAX extended header was read, and the entry it describes not yet.
	let extended = false;
	// The name that header's path record gives that entry, if it has one.
	let paxPath: string | undefined;
	for (;;) {
		const header = archive.subarray(at, at + BLOCK);
		if (header.length < BLOCK) throw new Error('docker cp printed a tar archive that ends early');
		if (header.every((b) => b === 0)) break;
		if (octal(header.subarray(148, 156)) !== checksum(header)) {
			throw new Error('docker cp printed a tar header whose checksum does not match');
		}
		const size = octal(header.subarray(124, 136));
		if (size === undefined) throw new Error('docker cp printed a tar header with no octal size');
		const type = String.fromCharCode(header[156] ?? 0);
		const regular = type === '0' || type === '\0';
		if (regular && size > maxBytes) throw new Error(`it is more than ${maxBytes} bytes`);
		const start = at + BLOCK;
		if (start + size > archive.length) {
			throw new Error('docker cp printed a tar archive that ends early');
		}
		const data = archive.subarray(start, start + size);
		at = start + Math.ceil(size / BLOCK) * BLOCK;
		if (type === 'x' || type === 'g') {
			const path = checkPax(data);
			if (type === 'g' && path !== undefined) {
				throw new Error('docker cp printed a global PAX path record, which koid does not read');
			}
			if (type === 'x') {
				extended = true;
				paxPath = path;
			}
			continue;
		}
		if (!regular) {
			throw new Error(
				`it is ${KINDS[type] ?? `an entry of tar type ${JSON.stringify(type)}`}, not a regular file`,
			);
		}
		if (file !== undefined)
			throw new Error('docker cp printed a tar archive of more than one entry');
		const entry = paxPath ?? headerName(header);
		if (entry !== bytesText(new TextEncoder().encode(name))) {
			throw new Error(
				`docker cp printed an entry named ${JSON.stringify(entry.slice(0, 120))}, not ${JSON.stringify(name)}`,
			);
		}
		file = data;
		extended = false;
		paxPath = undefined;
	}
	// The zero block just read and a second one, then nothing but zeros:
	// GNU tar pads the last record with them.
	if (archive.length < at + 2 * BLOCK) {
		throw new Error('docker cp printed a tar archive that ends early');
	}
	if (!archive.subarray(at).every((b) => b === 0)) {
		throw new Error('docker cp printed a tar archive with data after its end');
	}
	if (extended) throw new Error('docker cp printed a PAX header with no entry after it');
	if (file === undefined) throw new Error('docker cp printed a tar archive with no file');
	try {
		return new TextDecoder('utf-8', { fatal: true }).decode(file);
	} catch {
		throw new Error('it is not UTF-8 text');
	}
}

// Bytes as a string of one character per byte, so names from headers and PAX
// records compare byte for byte.
function bytesText(bytes: Uint8Array): string {
	return new TextDecoder('latin1').decode(bytes);
}

// The name field up to its first NUL, after the prefix field and a slash when
// the header is POSIX ustar's and has one.
function headerName(header: Uint8Array): string {
	const field = (from: number, to: number) => {
		const bytes = header.subarray(from, to);
		const end = bytes.indexOf(0);
		return bytesText(end === -1 ? bytes : bytes.subarray(0, end));
	};
	const name = field(0, 100);
	const posix = bytesText(header.subarray(257, 263)) === 'ustar\0';
	const prefix = posix ? field(345, 500) : '';
	return prefix === '' ? name : `${prefix}/${name}`;
}

// The sum of a header's bytes, its checksum field counted as spaces.
function checksum(header: Uint8Array): number {
	let sum = 0;
	for (let i = 0; i < BLOCK; i++) sum += i >= 148 && i < 156 ? 0x20 : (header[i] ?? 0);
	return sum;
}

// A numeric header field: octal digits, which may have spaces before them
// and NULs or spaces after. Anything else, Go's base-256 form for numbers
// too large for the field included, is undefined.
function octal(field: Uint8Array): number | undefined {
	const text = new TextDecoder('latin1')
		.decode(field)
		.replace(/^ +/, '')
		.replace(/[\0 ]+$/, '');
	return /^[0-7]{1,12}$/.test(text) ? Number.parseInt(text, 8) : undefined;
}

// PAX records are "LENGTH KEY=VALUE\n", LENGTH in decimal counting the whole
// record. Refuses a malformed one, a size, and GNU's sparse records, and
// returns the value of the last path record, if any.
function checkPax(data: Uint8Array): string | undefined {
	const text = bytesText(data);
	let path: string | undefined;
	let at = 0;
	while (at < text.length) {
		const length = /^[1-9][0-9]{0,8} /.exec(text.slice(at, at + 10))?.[0];
		const end = length === undefined ? -1 : at + Number.parseInt(length, 10);
		if (length === undefined || end > text.length || text[end - 1] !== '\n') {
			throw new Error('docker cp printed a malformed PAX record');
		}
		const record = text.slice(at + length.length, end - 1);
		const equals = record.indexOf('=');
		if (equals < 1) throw new Error('docker cp printed a malformed PAX record');
		const key = record.slice(0, equals);
		if (key === 'size' || key.startsWith('GNU.sparse.')) {
			throw new Error(`docker cp printed a PAX record ${key}, which koid does not read`);
		}
		if (key === 'path') path = record.slice(equals + 1);
		at = end;
	}
	return path;
}
