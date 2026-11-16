import { describe, expect, test } from 'bun:test';
import { originUrl, parseOrigin, proxyArgs, samePath, urlAllowed } from '../src/origin.ts';

const origin = parseOrigin('http://app.abcdefghijklmnop0123.invalid:8080');

describe('parseOrigin', () => {
	test('reads the host and port of the private URL', () => {
		expect(origin).toEqual({ host: 'app.abcdefghijklmnop0123.invalid', port: 8080 });
		expect(parseOrigin('http://app.x.invalid')).toEqual({ host: 'app.x.invalid', port: 80 });
		expect(originUrl(origin)).toBe('http://app.abcdefghijklmnop0123.invalid:8080');
		// The canonical form leaves the default port off.
		expect(originUrl({ host: 'app.x.invalid', port: 80 })).toBe('http://app.x.invalid');
	});

	test('refuses anything but plain http without credentials', () => {
		expect(() => parseOrigin('https://app.x.invalid')).toThrow('must be http://');
		expect(() => parseOrigin('http://user:pw@app.x.invalid')).toThrow('credentials');
		expect(() => parseOrigin('nonsense')).toThrow('not a URL');
	});
});

describe('urlAllowed', () => {
	test.each([
		['http://app.abcdefghijklmnop0123.invalid:8080/', true],
		['http://app.abcdefghijklmnop0123.invalid:8080/api/state?x=1#f', true],
		['HTTP://APP.abcdefghijklmnop0123.INVALID:8080/', true],
		['about:blank', true],
		['data:text/plain,hello', true],
		['blob:http://app.abcdefghijklmnop0123.invalid:8080/0a1b2c', true],
		// The app's own WebSocket endpoint is on the same origin.
		['ws://app.abcdefghijklmnop0123.invalid:8080/socket', true],
		['wss://app.abcdefghijklmnop0123.invalid:8080/socket', false],
		['ws://app.abcdefghijklmnop0123.invalid:8081/socket', false],
		['ws://example.com/socket', false],
		['blob:https://example.com/0a1b2c', false],
		['http://app.abcdefghijklmnop0123.invalid/', false],
		['http://app.abcdefghijklmnop0123.invalid:8081/', false],
		['https://app.abcdefghijklmnop0123.invalid:8080/', false],
		['http://example.com/', false],
		['http://10.213.0.2:8080/', false],
		['http://127.0.0.1:8080/', false],
		['http://[::1]:8080/', false],
		['http://localhost:8080/', false],
		['http://user:pw@app.abcdefghijklmnop0123.invalid:8080/', false],
		['file:///etc/passwd', false],
		['chrome://version', false],
		['not a url', false],
	])('%s -> %p', (url, allowed) => {
		expect(urlAllowed(url, origin)).toBe(allowed);
	});

	test('port 80 matches whether it is written or not', () => {
		const plain = parseOrigin('http://app.x.invalid');
		expect(urlAllowed('http://app.x.invalid/', plain)).toBe(true);
		expect(urlAllowed('http://app.x.invalid:80/', plain)).toBe(true);
		expect(urlAllowed('ws://app.x.invalid/socket', plain)).toBe(true);
		expect(urlAllowed('ws://app.x.invalid:80/socket', plain)).toBe(true);
		expect(urlAllowed('http://app.x.invalid:8080/', plain)).toBe(false);
		const written = parseOrigin('http://app.x.invalid:80');
		expect(urlAllowed('http://app.x.invalid/', written)).toBe(true);
	});
});

describe('samePath', () => {
	test('joins a path to the origin and refuses one that leaves it', () => {
		expect(samePath('/', origin)).toBe('http://app.abcdefghijklmnop0123.invalid:8080/');
		expect(samePath('/api/state?x=1', origin)).toBe(
			'http://app.abcdefghijklmnop0123.invalid:8080/api/state?x=1',
		);
		expect(samePath('//example.com/', origin)).toBeUndefined();
		expect(samePath('api', origin)).toBeUndefined();
		expect(samePath('/a\nb', origin)).toBeUndefined();
		expect(samePath('http://example.com/', origin)).toBeUndefined();
	});

	test('works on port 80', () => {
		expect(samePath('/', parseOrigin('http://app.x.invalid'))).toBe('http://app.x.invalid/');
		expect(samePath('/x', parseOrigin('http://app.x.invalid:80'))).toBe('http://app.x.invalid/x');
	});
});

describe('proxyArgs', () => {
	test('sends every host but the app to a dead proxy, loopback included', () => {
		expect(proxyArgs(origin)).toEqual([
			'--proxy-server=127.0.0.1:1',
			'--proxy-bypass-list=app.abcdefghijklmnop0123.invalid;<-loopback>',
			'--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE app.abcdefghijklmnop0123.invalid',
		]);
	});
});
