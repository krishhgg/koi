import { describe, expect, test } from 'bun:test';
import {
	ForgetTokenSchema,
	PROVIDERS,
	ProviderKeySchema,
	RegisterKeysSchema,
} from '../src/index.ts';

const TOKEN = `koi_${'a'.repeat(32)}`;

describe('the keys API schemas', () => {
	test('a provider key is one line of 1 to 512 characters', () => {
		expect(ProviderKeySchema.safeParse('sk-proj-abc').success).toBe(true);
		expect(ProviderKeySchema.safeParse('k'.repeat(512)).success).toBe(true);
		for (const bad of ['', 'k'.repeat(513), 'sk-1\r\nX-Injected: 1', 'sk-1\n', 7]) {
			expect(ProviderKeySchema.safeParse(bad).success).toBe(false);
		}
	});

	test('a registration names a preview and at least one known provider, and no token', () => {
		const keys = Object.fromEntries(PROVIDERS.map((p) => [p.id, 'k'.repeat(512)]));
		expect(RegisterKeysSchema.safeParse({ label: 'storefront-pr-7', keys }).success).toBe(true);
		for (const bad of [
			{ label: 'storefront-pr-7', keys: {} },
			{ label: 'storefront-pr-7', keys: { notaprovider: 'k' } },
			{ label: 'storefront-pr-7', keys: { openai: 'k\nx' } },
			{ label: 'Not_A_Label', keys: { openai: 'k' } },
			{ keys: { openai: 'k' } },
			{ label: 'storefront-pr-7', keys: { openai: 'k' }, token: TOKEN },
		]) {
			expect(RegisterKeysSchema.safeParse(bad).success).toBe(false);
		}
	});

	test('forgetting names one token the proxy made, and nothing else', () => {
		expect(ForgetTokenSchema.safeParse({ token: TOKEN }).success).toBe(true);
		for (const bad of [{ token: 'koi_short' }, { token: TOKEN, label: 'evil-pr-8' }, {}]) {
			expect(ForgetTokenSchema.safeParse(bad).success).toBe(false);
		}
	});
});
