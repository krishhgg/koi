import { describe, expect, test } from 'bun:test';
import { createHash } from 'node:crypto';
import {
	crc32,
	holdsCredential,
	LineScrubber,
	OVERLONG_LINE,
	PngError,
	redact,
	SecretRegistry,
	scrubWithin,
	secretForms,
	stripPngMetadata,
} from '../src/redact.ts';
import {
	CHANNELS,
	checkPng,
	chunk,
	encodePng,
	IDAT,
	IEND,
	IHDR,
	IMAGE,
	PNG_STRIPPED,
	PNG_WITH_METADATA,
	png,
	rawScanlineBytes,
	TEXT,
	TIME,
} from './png.ts';

const KOI_TOKEN = `koi_${'0123456789abcdefghijklmnopqrstuv'}`;

describe('redact', () => {
	test.each([
		['a koi token', `using ${KOI_TOKEN} now`, `using [redacted] now`],
		[
			'an Authorization header, keeping its scheme',
			'curl -H "Authorization: Bearer abc.def-123456" https://api.openai.com',
			'curl -H "Authorization: Bearer [redacted]" https://api.openai.com',
		],
		['an x-api-key header', 'x-api-key: abc123', 'x-api-key: [redacted]'],
		['a Gemini key header', 'X-Goog-Api-Key: abc123', 'X-Goog-Api-Key: [redacted]'],
		['an OpenAI project key', 'key sk-proj-AbCdEf0123456789abcdef0123 set', 'key [redacted] set'],
		['an Anthropic key', 'sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789-AAAA', '[redacted]'],
		['an OpenRouter key', `sk-or-v1-${'0a'.repeat(32)}`, '[redacted]'],
		['a Groq key', `gsk_${'Ab1'.repeat(10)}`, '[redacted]'],
		['an xAI key', `xai-${'Ab1'.repeat(10)}`, '[redacted]'],
		['a Perplexity key', `pplx-${'Ab1'.repeat(10)}`, '[redacted]'],
		[
			'a Hugging Face token of letters only',
			`login hf_${'AbCdEfGhIjKlMnOpQ'.repeat(2)} ok`,
			'login [redacted] ok',
		],
		['a Hugging Face organisation token', `api_org_${'AbCdEfGhIj'.repeat(3)}`, '[redacted]'],
		[
			'a Gemini key in a query',
			'GET /v1/models?key=AIzaSyA-abc HTTP/1.1',
			'GET /v1/models?key=[redacted] HTTP/1.1',
		],
		['a Gemini key alone', `AIza${'Ab1_-'.repeat(7)}`, '[redacted]'],
		['an AWS access key id', 'id AKIAIOSFODNN7EXAMPLE here', 'id [redacted] here'],
		['an AWS session key id', 'ASIAIOSFODNN7EXAMPLE', '[redacted]'],
		[
			'an AWS secret in a variable',
			'AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
			'AWS_SECRET_ACCESS_KEY=[redacted]',
		],
		['a variable named like a key', 'OPENAI_API_KEY=whatever', 'OPENAI_API_KEY=[redacted]'],
		['a JSON password', '{"password": "hunter2"}', '{"password": "[redacted]"}'],
		['a GitHub token', `GITHUB ghp_${'Ab1'.repeat(12)}`, 'GITHUB [redacted]'],
		[
			'a JSON web token',
			'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc_def-123',
			'[redacted]',
		],
		[
			'a key with no prefix, after the word key',
			'using the Mistral API key 8fJ2kQ9xLm3NpR7sT1vW5yZ0aB4cD6eF now',
			'using the Mistral API key [redacted] now',
		],
		[
			'a key with no prefix, after token and a colon',
			'token: 8fJ2kQ9xLm3NpR7sT1vW5yZ0aB4cD6eF',
			'token: [redacted]',
		],
	])('masks %s', (_what, text, masked) => {
		expect(redact(text)).toBe(masked);
	});

	test('leaves hashes, koi names and ordinary build output alone', () => {
		for (const text of [
			`commit ${'0123456789abcdef'.repeat(2)}01234567`,
			`sha256:${'9f'.repeat(32)}`,
			'koi-preview/hello-pr-7:aaaaaaaaaaaaaaaa1 koi-hello-pr-7-aaaaaaaaaaaaaaaa1',
			'request abcdefghij0123456789abcdefghij0123456789: github.com/acme/hello',
			'#5 [2/5] RUN npm ci --no-audit',
			'#7 DONE 12.3s',
			'max_tokens: 100, tokenizer=fast',
			'Successfully installed numpy-1.26.4-cp312-cp312-manylinux_2_17_x86_64',
			'disk-usage-report-generator-abcdefghijklmnop',
		]) {
			expect(redact(text)).toBe(text);
		}
	});

	// Base64 digests mix upper case, lower case and digits like a key does.
	const sri = (algorithm: string, text: string) =>
		`${algorithm}-${createHash(algorithm).update(text).digest('base64')}`;

	test('leaves the checksums in npm output alone', () => {
		const wanted = sri('sha512', 'wanted');
		const got = sri('sha512', 'got');
		for (const text of [
			'npm ERR! code EINTEGRITY',
			`npm ERR! ${wanted} integrity checksum failed when using sha512: wanted ${wanted} but got ${got}. (12345 bytes)`,
			`npm warn tarball tarball data for left-pad@1.3.0 (${wanted}) seems to be corrupted. Trying again.`,
			`      "integrity": "${wanted}",`,
			`<script src="x.js" integrity="${sri('sha384', 'x')}" crossorigin="anonymous"></script>`,
		]) {
			expect(redact(text)).toBe(text);
		}
	});

	test('leaves the hashes in pip output alone', () => {
		const hex = (text: string) => createHash('sha256').update(text).digest('hex');
		for (const text of [
			'ERROR: THESE PACKAGES DO NOT MATCH THE HASHES FROM THE REQUIREMENTS FILE.',
			'    requests==2.32.3 from https://files.pythonhosted.org/packages/f9/9b/335f9764261e915ed497fcdeb11df5dfd6f7bf257d4a6a2a686d80da4d54/requests-2.32.3-py3-none-any.whl:',
			`        Expected sha256 ${hex('expected')}`,
			`             Got        ${hex('got')}`,
			`requests==2.32.3 --hash=sha256:${hex('requests')}`,
			`#12 writing image sha256:${hex('image')} done`,
		]) {
			expect(redact(text)).toBe(text);
		}
	});

	test('leaves a digest alone even after a word like key or token', () => {
		const digest = sri('sha512', 'cache');
		expect(redact(`cache key ${digest}`)).toBe(`cache key ${digest}`);
		expect(redact(`token: sha256:${'ab'.repeat(32)}`)).toBe(`token: sha256:${'ab'.repeat(32)}`);
	});

	test('leaves a long mixed value alone when nothing says it is a credential', () => {
		const text = 'symbol AbstractSingletonProxyFactoryBean2Impl3 resolved';
		expect(redact(text)).toBe(text);
	});

	test('masks nothing past the end of a line', () => {
		expect(redact('password:\nthe next line')).toBe('password:\nthe next line');
	});
});

describe('login keys and known values', () => {
	const LOGIN_KEY = 'koi-abcdefghijklmnopqrstuvwx';

	test('masks a preview login key and leaves what only looks like one', () => {
		expect(redact(`APP_LOGIN_KEY=${LOGIN_KEY} set`)).toBe('APP_LOGIN_KEY=[redacted] set');
		expect(redact(`visit /?k=${LOGIN_KEY}`)).toBe('visit /?k=[redacted]');
		expect(redact('koi-abc is short')).toBe('koi-abc is short');
		expect(redact(`x${LOGIN_KEY}`)).toBe(`x${LOGIN_KEY}`);
	});

	test('a registered value is replaced in its plain, URL-encoded, JSON-escaped and base64 forms', () => {
		const registry = new SecretRegistry();
		const value = 'p@ss/word+12"34';
		registry.add(value);
		expect(registry.redact(`got ${value} here`)).toBe('got [redacted] here');
		expect(registry.redact(`q=${encodeURIComponent(value)}`)).toBe('q=[redacted]');
		expect(registry.redact(JSON.stringify({ k: value }))).toBe('{"k":"[redacted]"}');
		const base64 = Buffer.from(value).toString('base64');
		expect(registry.redact(`Basic ${base64}`)).toBe('Basic [redacted]');
		expect(registry.redact(base64.replace(/=+$/, ''))).toBe('[redacted]');
		expect(registry.redact(Buffer.from(value).toString('base64url'))).toBe('[redacted]');
		expect(secretForms(value)).toContain(value);
	});

	test('a short value is not registered, and the patterns still run', () => {
		const registry = new SecretRegistry();
		registry.add('short');
		expect(registry.size).toBe(0);
		expect(
			registry.redact('short and sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789-AAAA'),
		).toBe('short and [redacted]');
	});

	test('the registry is bounded: past the bound the oldest value goes, and the owner is told', () => {
		const evictions: number[] = [];
		const registry = new SecretRegistry({ max: 3, onEvict: (n) => evictions.push(n) });
		registry.add('first-value-0001');
		registry.add('second-value-0002');
		registry.add('third-value-0003');
		expect(registry.count).toBe(3);
		expect(evictions).toEqual([]);
		// A value added again is the newest, not a second copy.
		registry.add('first-value-0001');
		expect(registry.count).toBe(3);
		registry.add('fourth-value-0004');
		expect(evictions).toEqual([1]);
		expect(registry.count).toBe(3);
		// second went, first stayed, their forms with them.
		expect(registry.redact('second-value-0002 first-value-0001')).toBe(
			'second-value-0002 [redacted]',
		);
		const base64 = (v: string) => Buffer.from(v).toString('base64');
		expect(registry.redact(base64('second-value-0002'))).toBe(base64('second-value-0002'));
		expect(registry.redact(base64('fourth-value-0004'))).toBe('[redacted]');
		// A form two values share stays while either does.
		const shared = new SecretRegistry({ max: 2 });
		shared.add('shared-form-abc');
		shared.add('shared-form-abc!!!!!!!!!');
		shared.add('another-value-xyz');
		expect(shared.count).toBe(2);
		expect(shared.redact('shared-form-abc')).toBe('shared-form-abc');
		expect(shared.redact('shared-form-abc!!!!!!!!!')).toBe('[redacted]');
	});

	test('a longer form that contains a shorter one is replaced whole', () => {
		const registry = new SecretRegistry();
		registry.add('abcdefghij');
		registry.add('abcdefghijklmnop');
		expect(registry.redact('abcdefghijklmnop')).toBe('[redacted]');
	});
});

describe('a scrub of a scrub changes nothing', () => {
	const KEY = 'sk-proj-AbCdEf0123456789abcdef0123';

	test.each([
		['text with no secret', 'the page loaded fine'],
		['a koi token', `using ${KOI_TOKEN} now`],
		['a header', 'Authorization: Bearer abc.def-123456'],
		['a header with no scheme', 'x-api-key: "abc123"'],
		['a named value', 'password=hunter2, token: abc'],
		['a query key', 'GET /v1/models?key=AIzaSyA-abc&x=1'],
		['a provider key', `key ${KEY} set`],
		['a word and a key-shaped value', `API key: ${'Ab1'.repeat(10)}`],
		['an existing mask', 'it said [redacted] and token=[redacted]'],
		['a piece of a mask after a name', 'token=[reda'],
		['a mask run into a value', 'token=[redacted]tail'],
		['a token that ran into a header', `${KOI_TOKEN}authorization: abc`],
		['a token that ran into bearer', `${KOI_TOKEN}bearer abcdefghij`],
		['a key that ran into a name', `hf_${'a'.repeat(20)}-token=abc`],
	])('the patterns: %s', (_what, text) => {
		const once = redact(text);
		expect(redact(once)).toBe(once);
	});

	test('a mask that opens the way for an earlier rule is followed through in one scrub', () => {
		expect(redact(`${KOI_TOKEN}bearer abcdefghij`)).toBe('[redacted]bearer [redacted]');
		expect(redact(`${KOI_TOKEN}authorization: abc`)).toBe('[redacted]authorization: [redacted]');
	});

	test.each([
		['a plain value', 'private-value-1234'],
		['a path', '.koi/runners'],
		['a word', 'chromium'],
		['a value that overlaps the end of the mask', 'acted]tail'],
		['a value that overlaps the start of the mask', 'head[redac'],
		['a value that holds a credential', KEY],
		['a value with a quote in it', 'say"what"now'],
	])('the registry: %s', (_what, value) => {
		const secrets = new SecretRegistry();
		secrets.add(value);
		secrets.add('secret12');
		const texts = [
			value,
			`before ${value} after`,
			`${value}${value}`,
			`secret12${value}`,
			`${value}secret12`,
			`[redacted]${value}[redacted]`,
			'[redacted]tail',
			'head[redacted]',
			JSON.stringify({ value }),
			encodeURIComponent(value),
			Buffer.from(value).toString('base64'),
		];
		for (const text of texts) {
			const once = secrets.redact(text);
			expect(secrets.redact(once)).toBe(once);
		}
		// Wherever the value stands whole, in text no earlier scrub made, it is gone.
		for (const text of [
			value,
			`before ${value} after`,
			`${value}${value}`,
			`${value}secret12`,
			`[redacted]${value}[redacted]`,
		]) {
			expect(secrets.redact(text)).not.toContain(value);
		}
	});

	test.each([
		['in its middle', 'prefix-[redacted]-suffix'],
		['at its start', '[redacted]tail'],
		['at its end', 'head[redacted]'],
		['twice', '[redacted][redacted]'],
		['after a broken mask', ']x[redacted]'],
		['after an assignment', 'token=[redacted]'],
	])('a value that holds the mask %s is not registered', (_where, value) => {
		const secrets = new SecretRegistry();
		secrets.add(value);
		expect(secrets.count).toBe(0);
		expect(secrets.size).toBe(0);
		expect(secrets.redact(`the page printed ${value}`)).toBe(`the page printed ${value}`);
	});

	test('a pattern keeps the space it found, so it cannot make a known value', () => {
		const secrets = new SecretRegistry();
		secrets.add('x bearer ');
		const once = secrets.redact('x bearer\tabcdefgh');
		expect(once).toBe('x bearer\t[redacted]');
		expect(secrets.redact(once)).toBe(once);
	});

	test('one scrub is enough, so no line can make koid go round again', () => {
		const secrets = new SecretRegistry();
		// A value that a mask could complete, were it registered.
		secrets.add('x[redacted]');
		secrets.add('prefix-[redacted]-suffix');
		secrets.add('secret12');
		expect(secrets.count).toBe(1);
		const line = `${'x'.repeat(64 * 1024)}[redacted]`;
		expect(secrets.redact(line)).toBe(line);
		const once = secrets.redact('prefix-secret12-suffix');
		expect(once).toBe('prefix-[redacted]-suffix');
		expect(secrets.redact(once)).toBe(once);
	});

	test('a form that overlaps the mask does not reach into text a mask made', () => {
		const secrets = new SecretRegistry();
		secrets.add('acted]tail');
		secrets.add('secret12');
		// Scrubbed: the mask, and then the text after it. Scrubbed again: the same.
		expect(secrets.redact('secret12tail')).toBe('[redacted]tail');
		expect(secrets.redact('[redacted]tail')).toBe('[redacted]tail');
		// Where the value stands whole, it still goes.
		expect(secrets.redact('xacted]tailx')).toBe('x[redacted]x');
	});

	test.each([
		['redacted'],
		['[redacted]'],
		['[redacted'],
		['redacted]'],
		['[redacte'],
		['edacted]'],
	])('%s is not registered, since it would match the mask', (value) => {
		const secrets = new SecretRegistry();
		secrets.add(value);
		expect(secrets.count).toBe(0);
		expect(secrets.size).toBe(0);
		// docs/redacted.md once scrubbed to docs/[redacted].md, and then to
		// docs/[[redacted]].md on write, after a digest was taken.
		expect(secrets.redact('docs/redacted.md')).toBe('docs/redacted.md');
		expect(secrets.redact('it said [redacted]')).toBe('it said [redacted]');
	});

	test('a cut never stops inside a mask, and what it leaves scrubs to itself', () => {
		const scrub = (text: string) => redact(text);
		// As a long console message, with a value right at the limit.
		const text = `${'x'.repeat(90)}token=abcdef`;
		const out = scrubWithin(scrub, text, 100);
		expect(out).toBe(`${'x'.repeat(90)}token=`);
		expect(out.length).toBeLessThanOrEqual(100);
		expect(scrub(out)).toBe(out);
		// A value that the cut makes whole is scrubbed too, within the limit.
		const key = `${'y'.repeat(70)} koi-${'a1'.repeat(12)}zzzz`;
		const cut = scrubWithin(scrub, key, 99);
		expect(cut).toBe(`${'y'.repeat(70)} [redacted]`);
		expect(scrub(cut)).toBe(cut);
		// A mask that ends right at the limit stays.
		expect(scrubWithin(scrub, 'token=abcdef', 16)).toBe('token=[redacted]');
		expect(scrubWithin(scrub, 'plain text', undefined)).toBe('plain text');
	});
});

describe('holdsCredential', () => {
	const HEX40 = 'da39a3ee5e6b4b0d3255bfef95601890afd80709';
	const HEX64 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

	test.each([
		['a koi token', KOI_TOKEN],
		['a preview login key', `koi-${'a1b2c3d4'.repeat(3)}`],
		['an OpenAI key', 'sk-proj-AbCdEf0123456789abcdef0123'],
		['an Anthropic key', `sk-ant-api03-${'aB3dE6gH9jK2'.repeat(6)}-AAAA`],
		['an OpenRouter key', `sk-or-v1-${'0a'.repeat(32)}`],
		['a DeepSeek key, all lower-case hex', `sk-${'0123456789abcdef'.repeat(2)}`],
		['a Groq key', `gsk_${'Ab1'.repeat(10)}`],
		['an xAI key', `xai-${'Ab1'.repeat(10)}`],
		['a Perplexity key, all lower-case', `pplx-${'0a'.repeat(24)}`],
		['a Together key', `tgp_v1_${'Ab1'.repeat(10)}`],
		['a Hugging Face token of letters only', `hf_${'AbCdEfGhIjKlMnOpQ'.repeat(2)}`],
		['a Hugging Face organisation token', `api_org_${'AbCdEfGhIj'.repeat(3)}`],
		['a Google key', `AIza${'Ab1_-'.repeat(7)}`],
		['a GitHub token', `ghp_${'Ab1'.repeat(12)}`],
		['a GitHub fine-grained token', `github_pat_${'Ab1_'.repeat(10)}`],
		['an AWS access key id', 'AKIAIOSFODNN7EXAMPLE'],
		['a JSON web token', 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.dozjgNryP4J3jVmNHl0w5N'],
		['a key after a header', `Authorization: Bearer ${'Ab1'.repeat(10)}`],
		['a key after a setting', `API_KEY=${'Ab1'.repeat(10)}`],
		['a key after a flag', `--token=${'Ab1'.repeat(10)}`],
		['a key in a query', `/search?key=${'Ab1'.repeat(10)}`],
		['a key after a word', `api key ${'Ab1'.repeat(10)}`],
		[
			'a secret with a slash in it',
			'aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
		],
		['a key inside a command line', `curl -H "x-api-key: ${'Ab1'.repeat(10)}" /v1`],
	])('finds %s', (_what, text) => {
		expect(holdsCredential(text)).toBe(true);
	});

	test.each([
		// What every project declares.
		['an image digest', `ghcr.io/acme/runner@sha256:${HEX64}`],
		['a digest', `sha256:${HEX64}`],
		['a digest after a word', `token: sha256:${HEX64}`],
		['an integrity value', 'sha512-Abc123Def456Ghi789Jkl012Mno345Pqr678Stu901Vwx234Yz=='],
		['a commit id', HEX40],
		['a commit id after a word', `commit ${HEX40}`],
		['a hex value after a word, as a pin in a command', `token: ${HEX40}`],
		['a hex value in a query', `?key=${HEX40}`],
		['an image tag', 'curlimages/curl:8.11.1'],
		['an image named after a word', 'ghcr.io/acme/token:v1.2.3'],
		['an image named after a word, with a longer tag', 'ghcr.io/acme/secret:2024.01.02-build7'],
		// Ordinary paths, and what the general patterns match in them.
		['a runner path', '.koi/runners/home.sh'],
		['a path with a credential word', 'src/auth/token.ts'],
		['a path with a colon after one', 'src/token:refresh/index.ts'],
		['a glob', 'packages/secret-store/**'],
		[
			'a path with a mixed-case file after a word',
			'token: src/components/AuthenticationFormV2.tsx',
		],
		['a directory that starts like an OpenAI key', 'src/sk-learn-regression-tests/model.py'],
		['a file that starts like an xAI key', 'xai-provider-integration-tests/chat.ts'],
		['a file that starts like a Perplexity key', 'pplx-search-results-are-cited-v2.ts'],
		['a file that starts like a Hugging Face token', 'hf_downloadmodelfromthehub.py'],
		// Point ids.
		['a point about tokens', 'auth.token-refresh'],
		['a point that starts like an xAI key', 'xai-chat-completes-a-long-request'],
		['a point that starts like a Perplexity key', 'pplx-search-renders-citations-list'],
		['a point that starts like an OpenAI key', 'sk-learn-model-trains-on-fixture'],
		['a point that looks like a login key', 'koi-abcdefghijklmnopqrstuvwx'],
		// Commands that read a secret from where it belongs.
		['a flag from the environment', '--token=$KOI_TOKEN'],
		// biome-ignore lint/suspicious/noTemplateCurlyInString: a shell's braces, as a command has them
		['a flag from the environment, braced', '--token=${KOI_TOKEN}'],
		['a long name from the environment', '--token=$KOI_Long_Secret_Name_Number_1'],
		['a header from the environment', 'Authorization: Bearer $TOKEN'],
		// biome-ignore lint/suspicious/noTemplateCurlyInString: a shell's braces, as a command has them
		['a setting from the environment', 'API_KEY=${API_KEY}'],
		['a test password', 'password=test'],
		['a test header', 'x-api-key: test-key'],
		['a short query key', '/search?key=abc'],
		// Sentences.
		['a claim about bearer tokens', 'Bearer authentication is required.'],
		['a claim about passwords', 'password: must be at least 8 characters'],
		['a claim about an API key', 'Saves the API key and shows it masked.'],
		['a claim with a token in it', 'The token: it is refreshed.'],
	])('leaves %s', (_what, text) => {
		expect(holdsCredential(text)).toBe(false);
	});

	test('narrower than the general patterns, which still mask what it leaves', () => {
		// A mask costs little and a refusal stops planning, so these differ on purpose.
		for (const text of [
			'sk-learn-model-trains-on-fixture',
			'--token=$KOI_TOKEN',
			'password=test',
		]) {
			expect(holdsCredential(text)).toBe(false);
			expect(redact(text)).not.toBe(text);
		}
	});

	test('never looks at the registry', () => {
		const secrets = new SecretRegistry();
		secrets.add('chromium');
		expect(secrets.redact('chromium')).toBe('[redacted]');
		expect(holdsCredential('chromium')).toBe(false);
	});
});

describe('LineScrubber', () => {
	const encode = (text: string) => new TextEncoder().encode(text);

	test('scrubs complete lines and finds a value split across chunks', () => {
		const registry = new SecretRegistry();
		registry.add('supersecretvalue1');
		const scrubber = new LineScrubber((text) => registry.redact(text));
		const bytes = encode('a supersecretvalue1 b\nsecond koi_0123456789abcdefghijklmnopqrstuv\n');
		let out = '';
		for (let i = 0; i < bytes.length; i += 3) out += scrubber.push(bytes.subarray(i, i + 3));
		out += scrubber.end();
		expect(out).toBe('a [redacted] b\nsecond [redacted]\n');
	});

	test('a last line without a newline comes out of end() with one, and CR goes', () => {
		const scrubber = new LineScrubber((text) => text);
		expect(scrubber.push(encode('one\r\ntwo'))).toBe('one\n');
		expect(scrubber.end()).toBe('two\n');
		expect(scrubber.end()).toBe('');
	});

	test('discards an overlong line with the fixed diagnostic, however it arrives', () => {
		const diagnostic = `[koi: a line over ${16} bytes was discarded]`;
		const scrubber = new LineScrubber((text) => text, 16);
		expect(scrubber.push(encode(`${'x'.repeat(40)}\nok\n`))).toBe(`${diagnostic}\nok\n`);
		let out = '';
		for (let i = 0; i < 10; i++) out += scrubber.push(encode('yyyyy'));
		expect(out).toBe('');
		out += scrubber.push(encode('\nfine\n'));
		expect(out).toBe(`${diagnostic}\nfine\n`);
		scrubber.push(encode('z'.repeat(20)));
		expect(scrubber.end()).toBe(`${diagnostic}\n`);
		expect(OVERLONG_LINE).toBe('[koi: a line over 65536 bytes was discarded]');
	});

	test('bytes that are not UTF-8 become replacement characters', () => {
		const scrubber = new LineScrubber((text) => text);
		expect(scrubber.push(new Uint8Array([0x61, 0xff, 0x62, 0x0a]))).toBe('a�b\n');
	});
});

describe('stripPngMetadata', () => {
	test('the fixtures are valid PNGs: the IDAT inflates to the scanlines the header implies', () => {
		for (const bytes of [PNG_WITH_METADATA, PNG_STRIPPED]) {
			const read = checkPng(bytes);
			expect(read).toEqual({ width: 2, height: 2, color: 'rgba', inflated: 2 * (1 + 2 * 4) });
			expect(read.inflated).toBe(rawScanlineBytes(IMAGE));
		}
		const gray = {
			width: 3,
			height: 1,
			color: 'gray' as const,
			pixels: new Uint8Array([0, 128, 255]),
		};
		expect(checkPng(encodePng(gray)).inflated).toBe(1 * (1 + 3 * CHANNELS.gray));
	});

	test('keeps the image chunks and names the ones removed', () => {
		const result = stripPngMetadata(PNG_WITH_METADATA);
		expect(result.bytes).toEqual(PNG_STRIPPED);
		expect(result.removed).toEqual(['tEXt', 'tIME']);
		expect(stripPngMetadata(PNG_STRIPPED)).toEqual({ bytes: PNG_STRIPPED, removed: [] });
		// Image data in several IDAT chunks, with a palette, stays whole.
		const split = encodePng(IMAGE, [TEXT], 5);
		const stripped = stripPngMetadata(split);
		expect(stripped.removed).toEqual(['tEXt']);
		expect(checkPng(stripped.bytes).inflated).toBe(rawScanlineBytes(IMAGE));
		const rgb = encodePng(
			{ width: 1, height: 2, color: 'rgb', pixels: new Uint8Array([1, 2, 3, 4, 5, 6]) },
			[TIME],
		);
		expect(stripPngMetadata(rgb).bytes).toEqual(
			encodePng({
				...IMAGE,
				width: 1,
				height: 2,
				color: 'rgb',
				pixels: new Uint8Array([1, 2, 3, 4, 5, 6]),
			}),
		);
	});

	test('refuses what is not a well-formed PNG', () => {
		expect(() => stripPngMetadata(new TextEncoder().encode('GIF89a'))).toThrow(PngError);
		expect(() => stripPngMetadata(png(IDAT, IHDR, IEND))).toThrow('first chunk is not IHDR');
		expect(() => stripPngMetadata(png(IHDR, IDAT))).toThrow('no IEND');
		expect(() => stripPngMetadata(png(IHDR, IDAT, IEND, TEXT))).toThrow('after IEND');
		expect(() =>
			stripPngMetadata(PNG_WITH_METADATA.subarray(0, PNG_WITH_METADATA.length - 3)),
		).toThrow('truncated');
		const badCrc = png(chunk('IHDR', new Uint8Array(13), { badCrc: true }), IDAT, IEND);
		expect(() => stripPngMetadata(badCrc)).toThrow('bad CRC in IHDR');
		// A bad CRC in a chunk that goes anyway is not checked: the chunk is
		// not kept.
		expect(
			stripPngMetadata(png(IHDR, chunk('tEXt', new Uint8Array(3), { badCrc: true }), IDAT, IEND))
				.removed,
		).toEqual(['tEXt']);
	});

	test('enforces the structure, not just the chunk order', () => {
		// Two headers, a header of the wrong size, an empty header.
		expect(() => stripPngMetadata(png(IHDR, IHDR, IDAT, IEND))).toThrow('a second IHDR');
		expect(() => stripPngMetadata(png(IHDR, TEXT, IHDR, IDAT, IEND))).toThrow('a second IHDR');
		expect(() => stripPngMetadata(png(chunk('IHDR', new Uint8Array(12)), IDAT, IEND))).toThrow(
			'IHDR is 12 bytes, not 13',
		);
		expect(() => stripPngMetadata(png(chunk('IHDR', new Uint8Array(0)), IDAT, IEND))).toThrow(
			'IHDR is 0 bytes, not 13',
		);
		// No image data at all.
		expect(() => stripPngMetadata(png(IHDR, IEND))).toThrow('no IDAT chunk');
		expect(() => stripPngMetadata(png(IHDR, TEXT, IEND))).toThrow('no IDAT chunk');
		// A payload hidden inside IEND.
		expect(() =>
			stripPngMetadata(png(IHDR, IDAT, chunk('IEND', new TextEncoder().encode('secret')))),
		).toThrow('IEND carries data');
		// A chunk whose declared length runs past the file.
		const long = new Uint8Array(IDAT);
		new DataView(long.buffer).setUint32(0, 0x7fffffff);
		expect(() => stripPngMetadata(png(IHDR, long, IEND))).toThrow('truncated chunk');
		const huge = new Uint8Array(IDAT);
		new DataView(huge.buffer).setUint32(0, 0xffffffff);
		expect(() => stripPngMetadata(png(IHDR, huge, IEND))).toThrow('length out of range');
		expect(() => stripPngMetadata(png(IHDR, IDAT, IEND, new Uint8Array(0)))).not.toThrow();
	});

	test('crc32 matches the PNG specification', () => {
		expect(crc32(new TextEncoder().encode('IEND'))).toBe(0xae426082);
	});
});
