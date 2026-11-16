// Masks text that looks like a credential before koid writes it to a build
// log, a preview record, its own log or a run's evidence. A pull request's
// Dockerfile and its container can print anything, a reviewer's koi token or
// provider key included. The patterns cover what the key proxy swaps (koi
// tokens, and the headers and query parameter SDKs send keys in), the
// providers' key formats, AWS key ids, preview login keys, and, after a word
// such as key or token, any long value that mixes upper case, lower case
// and digits. Digests stay readable: lower-case hex never matches, and
// neither do sha256:, sha384- or sha512- values, so a build log keeps the
// checksums npm and pip print when one does not match.
//
// The second half is for evidence (docs/verify.md, "Recorder and
// evidence"): a registry of the exact secret values koid knows, replaced in
// the forms a page or a log is likely to carry them in; a scrubber that
// takes text in chunks and finds a value split across them; and the
// stripping of a PNG's metadata chunks. What none of this can do is listed
// in TEXT_LIMITATIONS and copied into every manifest.
export const MASK = '[redacted]';

// Characters a key or token is made of.
const TOKEN = 'A-Za-z0-9_-';

// The start of a digest: sha256:<hex> as Docker prints it, or a
// subresource-integrity value such as sha512-<base64> as npm prints it.
const DIGEST = /^sha(?:1|224|256|384|512)[-:]/i;

// A value that names a credential has: long enough, and upper case, lower
// case and digits mixed, which a word or a hex hash does not have.
function keyShaped(value: string): boolean {
	return !DIGEST.test(value) && /[A-Z]/.test(value) && /[a-z]/.test(value) && /[0-9]/.test(value);
}

// Whether a value after a word that names a credential counts as one in what a
// project declares. The rules that take such a value mask anything, as a mask costs
// little. A refusal stops planning, and `--token=$TOKEN` or "password: must be long"
// is what a normal project writes. A path with a mixed-case name in it stays a path,
// but a base64 secret can hold a slash, so a long part with no dot still counts.
function namedCredential(value: string): boolean {
	if (value.length < 20 || value.startsWith('$') || !keyShaped(value)) return false;
	const parts = value.split('/');
	return parts.length === 1 || parts.some((part) => part.length >= 16 && !part.includes('.'));
}

// Whether a value that starts with a provider's prefix counts as a key in what a
// project declares. People start words with these too, as in sk-learn or xai-chat,
// and those are short words between dashes. A key has a long run of mixed characters,
// though it may be all lower-case hex, as DeepSeek's and Perplexity's are.
function prefixedCredential(value: string): boolean {
	return value.split(/[^A-Za-z0-9]+/).some((run) => {
		if (run.length < 16) return false;
		return /[0-9]/.test(run) ? /[A-Za-z]/.test(run) : /[a-z]/.test(run) && /[A-Z]/.test(run);
	});
}

// A format no project's own word has.
const anyMatch = () => true;

type Replacer = string | ((match: string, ...groups: string[]) => string);

// A pattern, what replaces its match, and whether a match counts as a credential
// when a project declares it (holdsCredential), given the rule's `value` group or
// else the whole match.
const RULES: Array<[RegExp, Replacer, (value: string) => boolean]> = [
	// A header, setting or variable that carries a secret: the name and any
	// Bearer or Basic scheme stay, the value goes. Only spaces and tabs may
	// sit around the separator, so a match never reaches into the next line.
	[
		/\b((?:proxy-)?authorization|x-api-key|x-goog-api-key|api-key)(["']?[ \t]*[:=][ \t]*["']?)((?:bearer|basic|token)[ \t]+)?(?<value>[^\s"',;&]+)/gi,
		`$1$2$3${MASK}`,
		namedCredential,
	],
	[
		/\b([A-Za-z0-9_]*(?:api_?key|secret|secret_?access_?key|token|password|passwd))(["']?[ \t]*[:=][ \t]*["']?)(?!sha(?:1|224|256|384|512)[-:])(?<value>[^\s"',;&]+)/gi,
		`$1$2${MASK}`,
		namedCredential,
	],
	// Gemini's ?key= query parameter.
	[/([?&]key=)(?<value>[^&\s"']+)/gi, `$1${MASK}`, namedCredential],
	// The space stays as it was: a rule only ever puts a mask in place of a credential, so
	// it cannot make a known value that the pass before it did not see.
	[/\b(bearer)([ \t]+)(?<value>[A-Za-z0-9._~+/=-]{8,})/gi, `$1$2${MASK}`, namedCredential],
	// koi tokens, as the keys page issues them.
	[/koi_[a-z0-9]{32}/g, MASK, anyMatch],
	// Preview login keys (LoginKeySchema).
	[/(?<![A-Za-z0-9-])koi-[a-z0-9]{24}(?![a-z0-9])/g, MASK, prefixedCredential],
	// OpenAI, Anthropic (sk-ant-), OpenRouter (sk-or-) and DeepSeek.
	[new RegExp(`(?<![A-Za-z0-9])sk-[${TOKEN}]{16,}`, 'g'), MASK, prefixedCredential],
	[/\b(?:gsk_|xai-|pplx-|tgp_v1_)[A-Za-z0-9_-]{20,}/g, MASK, prefixedCredential],
	// Hugging Face user tokens (hf_, often letters only) and old organisation
	// tokens (api_org_).
	[/(?<![A-Za-z0-9])(?:hf_|api_org_)[A-Za-z0-9]{20,}/g, MASK, prefixedCredential],
	[/\bAIza[0-9A-Za-z_-]{30,}/g, MASK, anyMatch],
	[/\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})/g, MASK, anyMatch],
	[/\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g, MASK, anyMatch],
	// JSON web tokens.
	[/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+/g, MASK, anyMatch],
	// A key-shaped value after a word that names a credential, with a colon,
	// an equals sign or only spaces between: "API key: ...", "token ...".
	// Mistral and Cohere keys have no prefix, so this is how they are found.
	[
		/\b((?:api[_ -]?)?key|token|secret|password|passwd|credentials?|auth)\b(["']?(?:[ \t]*[:=][ \t]*|[ \t]+)["']?)(?<value>[A-Za-z0-9_\-+/=.~]{20,})/gi,
		(match, word, separator, value) =>
			keyShaped(value ?? '') ? `${word}${separator}${MASK}` : match,
		namedCredential,
	],
];

function applyRules(text: string): string {
	let out = text;
	for (const [pattern, replacement] of RULES) {
		// One call for each of replace's two signatures.
		out =
			typeof replacement === 'string'
				? out.replace(pattern, replacement)
				: out.replace(pattern, replacement);
	}
	return out;
}

// The rules run until nothing changes, so a second scrub never changes what the first
// wrote. One pass can fall short because a mask can open the way for an earlier rule:
// masking a koi token that ran straight into "bearer xyz" leaves a word boundary before
// "bearer". This ends, since a change always puts a mask in place of other text.
export function redact(text: string): string {
	let out = text;
	for (;;) {
		const next = applyRules(out);
		if (next === out) return out;
		out = next;
	}
}

function anyRuleCounts(rules: typeof RULES, text: string): boolean {
	return rules.some(([pattern, , counts]) => {
		for (const match of text.matchAll(pattern)) {
			if (counts(match.groups?.value ?? match[0])) return true;
		}
		return false;
	});
}

// Whether a project's declared text holds what looks like a real credential. This is
// the pattern half of the scrub, for a refusal at planning, so each rule says what
// counts (RULES). It never looks at the registry: anyone who can reach the keys page
// can register any word, and that must not be able to stop a project from planning.
export function holdsCredential(text: string): boolean {
	return anyRuleCounts(RULES, text);
}

// The rules that know a credential by its own shape, and not by a word or header before it.
const SHAPE_RULES = RULES.filter(([, , counts]) => counts !== namedCredential);

// holdsCredential, for text with a fixed grammar of its own. In an image reference
// `token:` is a repository and a tag, not an assignment, so only a key's own shape counts.
export function holdsCredentialShape(text: string): boolean {
	return anyRuleCounts(SHAPE_RULES, text);
}

// `text` after `scrub`, in at most `max` characters when there is a limit. The cut comes
// after the scrub, since a cut first can leave half of a secret. It never stops inside a
// mask, and what it leaves is scrubbed again: a piece of a mask after "token=" would read
// differently to the next scrub, and a stored event would then differ from its reply.
export function scrubWithin(
	scrub: (text: string) => string,
	text: string,
	max: number | undefined,
): string {
	let out = scrub(text);
	while (max !== undefined && out.length > max) {
		const mask = out.lastIndexOf(MASK, max - 1);
		const inside = mask !== -1 && mask + MASK.length > max;
		out = scrub(out.slice(0, inside ? mask : max));
	}
	return out;
}

// --- Known values ----------------------------------------------------------------

// Raised when the rules or the forms change, so a manifest's policy digest
// changes with them. 2: PNG structure is enforced, and every string the
// application chose in a record is scrubbed, names included. 3: a value that
// would match the mask is not registered, and a scrub of a scrub changes nothing.
// 4: a value that holds the mask is not registered either.
export const REDACTION_POLICY_VERSION = 4;

// What the text sanitizer cannot promise. Every manifest copies this.
export const TEXT_LIMITATIONS: readonly string[] = [
	'known secret values and credential patterns were replaced; a secret in an unknown form or encoding is not found',
	'application text that is not a credential is kept as it was',
];

// A value shorter than this is not registered: it would match ordinary text.
export const MIN_SECRET_LENGTH = 8;

// The forms a known value is replaced in: as it is, URL-encoded, as JSON
// escapes it, and base64 in its three paddings. Nothing else: a transform
// not listed here is a limitation, not a promise.
export function secretForms(value: string): string[] {
	const forms = new Set<string>([
		value,
		encodeURIComponent(value),
		JSON.stringify(value).slice(1, -1),
	]);
	const base64 = Buffer.from(value, 'utf8').toString('base64');
	forms.add(base64);
	forms.add(base64.replace(/=+$/, ''));
	forms.add(Buffer.from(value, 'utf8').toString('base64url'));
	return [...forms].filter((form) => form.length >= MIN_SECRET_LENGTH);
}

// The most values the registry holds. Past it the oldest value goes, with
// every form of it, and the owner is told, so koid's log says that a
// sanitizer may now miss it. The bound is there because the keys page
// registers whatever a caller the egress proxy accepts sends it, so an
// unbounded registry would be a way to grow koid's memory from outside;
// 10,000 values is far more than a box's previews and keys come to.
export const MAX_SECRET_VALUES = 10_000;

export interface SecretRegistryOptions {
	// The bound, MAX_SECRET_VALUES unless a test lowers it.
	max?: number;
	// Called with how many values were forgotten to stay within the bound.
	onEvict?: (count: number) => void;
}

// The exact secret values koid knows while it runs: provider keys and koi
// tokens from the keys page, preview login keys. Kept in memory only, never
// written, hashed or counted anywhere a reader could learn from. Values are
// kept in the order they were added, and a value added again moves to the
// newest place, so what is in use is the last to go when the bound is hit.
export class SecretRegistry {
	// Each value to its forms, oldest first.
	private readonly values = new Map<string, string[]>();
	// Each form to how many values have it: two values can share one.
	private readonly forms = new Map<string, number>();
	// Longest first, so a form that contains another is replaced whole.
	private sorted: string[] = [];
	private readonly max: number;
	private readonly onEvict: (count: number) => void;

	constructor(options: SecretRegistryOptions = {}) {
		this.max = options.max ?? MAX_SECRET_VALUES;
		this.onEvict = options.onEvict ?? (() => {});
	}

	add(value: string): void {
		if (value.length < MIN_SECRET_LENGTH) return;
		const known = this.values.get(value);
		if (known !== undefined) {
			// Newest again, forms unchanged.
			this.values.delete(value);
			this.values.set(value, known);
			return;
		}
		const forms = secretForms(value);
		// A form inside the mask would match the mask itself, so each scrub would change
		// what the last one wrote: `docs/redacted.md`, then `docs/[[redacted]].md`. Anyone
		// who can reach the keys page could do that to a digest or an export. A form that
		// holds the mask would need the scrub to go round again, each time a mask completed
		// it, and a line built for that is a stall in koid. No real credential holds the
		// text `[redacted]`, so one scrub is enough.
		if (forms.some((form) => MASK.includes(form) || form.includes(MASK))) return;
		this.values.set(value, forms);
		for (const form of forms) this.forms.set(form, (this.forms.get(form) ?? 0) + 1);
		let evicted = 0;
		while (this.values.size > this.max) {
			const oldest = this.values.entries().next().value;
			if (oldest === undefined) break;
			this.values.delete(oldest[0]);
			for (const form of oldest[1]) {
				const left = (this.forms.get(form) ?? 1) - 1;
				if (left <= 0) this.forms.delete(form);
				else this.forms.set(form, left);
			}
			evicted += 1;
		}
		this.sorted = [...this.forms.keys()].sort((a, b) => b.length - a.length);
		if (evicted > 0) this.onEvict(evicted);
	}

	// How many forms are replaced.
	get size(): number {
		return this.forms.size;
	}

	// How many values are known.
	get count(): number {
		return this.values.size;
	}

	// Every known value in every form, then the patterns. One pass is enough: the text
	// between masks only ever gets shorter, so what a pass took out cannot come back.
	redact(text: string): string {
		return redact(this.replaceForms(text));
	}

	// A form is looked for only between masks, as one that overlaps a mask's edge
	// (`acted]tail`) would otherwise match text the last form's mask made, and a second
	// scrub would change the first's.
	private replaceForms(text: string): string {
		let out = text;
		for (const form of this.sorted) {
			if (!out.includes(form)) continue;
			out = out
				.split(MASK)
				.map((part) => part.split(form).join(MASK))
				.join(MASK);
		}
		return out;
	}
}

// --- Streaming text -----------------------------------------------------------------

// The most one line may hold before it is discarded instead of scrubbed. A
// longer line is as likely a dump of something as a line of text, and a
// pattern cannot be trusted across megabytes.
export const MAX_SCRUB_LINE_BYTES = 64 * 1024;

// The fixed diagnostic that stands in for a discarded line. It carries
// nothing of the line.
export function overlongLine(maxLineBytes: number): string {
	return `[koi: a line over ${maxLineBytes} bytes was discarded]`;
}

export const OVERLONG_LINE = overlongLine(MAX_SCRUB_LINE_BYTES);

// Scrubs text that arrives in chunks, one complete line at a time, so a
// value split across two chunks is seen whole. push() returns the sanitized
// lines the chunk completed, each ending in a newline; end() returns the
// last line, if the text did not end in one. Bytes that are not UTF-8
// become U+FFFD.
export class LineScrubber {
	private pending: Uint8Array[] = [];
	private pendingBytes = 0;
	private overlong = false;
	private readonly decoder = new TextDecoder('utf-8', { fatal: false });

	constructor(
		private readonly scrub: (text: string) => string,
		private readonly maxLineBytes = MAX_SCRUB_LINE_BYTES,
	) {}

	push(chunk: Uint8Array): string {
		let out = '';
		let start = 0;
		for (let i = 0; i < chunk.length; i++) {
			if (chunk[i] !== 0x0a) continue;
			out += this.finish(chunk.subarray(start, i));
			start = i + 1;
		}
		if (start < chunk.length) this.hold(chunk.subarray(start));
		return out;
	}

	end(): string {
		if (this.pendingBytes === 0 && !this.overlong) return '';
		return this.finish(new Uint8Array(0));
	}

	private hold(part: Uint8Array): void {
		if (this.overlong) return;
		if (this.pendingBytes + part.length > this.maxLineBytes) {
			// The line is already too long: what is held goes, and what
			// follows up to the newline is not kept either.
			this.overlong = true;
			this.pending = [];
			this.pendingBytes = 0;
			return;
		}
		this.pending.push(new Uint8Array(part));
		this.pendingBytes += part.length;
	}

	private finish(tail: Uint8Array): string {
		const tooLong = this.overlong || this.pendingBytes + tail.length > this.maxLineBytes;
		const parts = this.pending;
		this.pending = [];
		this.pendingBytes = 0;
		this.overlong = false;
		if (tooLong) return `${overlongLine(this.maxLineBytes)}\n`;
		const bytes = new Uint8Array(parts.reduce((n, p) => n + p.length, 0) + tail.length);
		let at = 0;
		for (const p of parts) {
			bytes.set(p, at);
			at += p.length;
		}
		bytes.set(tail, at);
		const text = this.decoder.decode(bytes).replace(/\r$/, '');
		return `${this.scrub(text)}\n`;
	}
}

// --- PNG metadata ----------------------------------------------------------------------

export class PngError extends Error {}

const PNG_SIGNATURE = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];

// The chunks a screenshot needs to show the same pixels: the header, a
// palette and its transparency, the image data and the end. Everything
// else, text, time, color profile, physical size, gamma, unknown types, is
// metadata and goes.
const KEPT_CHUNKS: ReadonlySet<string> = new Set(['IHDR', 'PLTE', 'tRNS', 'IDAT', 'IEND']);

// The most a PNG may be. A screenshot of one viewport is far below.
const MAX_PNG_BYTES = 64 * 1024 ** 2;

// The PNG with only its image chunks, and the names of the chunk types
// removed, sorted. The input is read chunk by chunk and its structure is
// enforced, so a file that is not a well-formed PNG is refused rather than
// passed through, and the caller withholds the artifact: the signature;
// exactly one IHDR, first, of 13 bytes; at least one IDAT; IEND last, empty,
// with nothing after it; every chunk's length within the file; and a valid
// CRC on every kept chunk. The image data itself is not decoded.
export function stripPngMetadata(bytes: Uint8Array): { bytes: Uint8Array; removed: string[] } {
	if (bytes.length > MAX_PNG_BYTES) throw new PngError('the image is too large');
	if (bytes.length < PNG_SIGNATURE.length + 12 || !PNG_SIGNATURE.every((b, i) => bytes[i] === b)) {
		throw new PngError('not a PNG');
	}
	const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
	const kept: Uint8Array[] = [bytes.subarray(0, PNG_SIGNATURE.length)];
	const removed = new Set<string>();
	let at = PNG_SIGNATURE.length;
	let headers = 0;
	let data = 0;
	let ended = false;
	while (at < bytes.length) {
		if (ended) throw new PngError('bytes after IEND');
		if (at + 12 > bytes.length) throw new PngError('truncated chunk');
		const length = view.getUint32(at);
		const type = String.fromCharCode(...bytes.subarray(at + 4, at + 8));
		if (!/^[A-Za-z]{4}$/.test(type)) throw new PngError('malformed chunk type');
		if (length > 0x7fffffff) throw new PngError(`${type} chunk length out of range`);
		const end = at + 12 + length;
		if (end > bytes.length) throw new PngError('truncated chunk');
		if (headers === 0 && type !== 'IHDR') throw new PngError('the first chunk is not IHDR');
		switch (type) {
			case 'IHDR':
				if (headers > 0) throw new PngError('a second IHDR');
				if (length !== 13) throw new PngError(`IHDR is ${length} bytes, not 13`);
				headers += 1;
				break;
			case 'IDAT':
				data += 1;
				break;
			case 'IEND':
				if (length !== 0) throw new PngError('IEND carries data');
				ended = true;
				break;
			default:
				break;
		}
		if (KEPT_CHUNKS.has(type)) {
			const crc = view.getUint32(end - 4);
			if (crc !== crc32(bytes.subarray(at + 4, end - 4))) throw new PngError(`bad CRC in ${type}`);
			kept.push(bytes.subarray(at, end));
		} else {
			removed.add(type);
		}
		at = end;
	}
	if (!ended) throw new PngError('no IEND chunk');
	if (data === 0) throw new PngError('no IDAT chunk');
	const out = new Uint8Array(kept.reduce((n, k) => n + k.length, 0));
	let offset = 0;
	for (const k of kept) {
		out.set(k, offset);
		offset += k.length;
	}
	return { bytes: out, removed: [...removed].sort() };
}

const CRC_TABLE = new Uint32Array(256).map((_, n) => {
	let c = n;
	for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
	return c >>> 0;
});

export function crc32(bytes: Uint8Array): number {
	let c = 0xffffffff;
	for (const b of bytes) c = (CRC_TABLE[(c ^ b) & 0xff] ?? 0) ^ (c >>> 8);
	return (c ^ 0xffffffff) >>> 0;
}
