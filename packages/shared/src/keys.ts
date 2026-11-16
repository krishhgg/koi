import { z } from 'zod';
import { PreviewLabelSchema } from './preview.ts';
import { KoiTokenSchema, ProviderIdSchema } from './providers.ts';

// What the keys page (keys.<domain>) sends koid, which koid checks before
// anything reaches the egress proxy.

// A reviewer's provider key: one line of at most 512 characters, as the
// egress proxy also requires (koi_egress.py, Registry.register).
export const ProviderKeySchema = z
	.string()
	.min(1)
	.max(512)
	.refine((key) => !/[\r\n]/.test(key), 'a key is one line');

// The keys of one registration, by provider: at least one.
export const ProviderKeysSchema = z
	.partialRecord(ProviderIdSchema, ProviderKeySchema)
	.refine((keys) => Object.values(keys).some((k) => k !== undefined), 'at least one key');

// POST /api/register: keys for one preview. Strict, so a body that names a
// token is refused: the proxy makes every token, and a caller never binds
// one to other keys or another preview.
export const RegisterKeysSchema = z.strictObject({
	label: PreviewLabelSchema,
	keys: ProviderKeysSchema,
});

export type RegisterKeys = z.infer<typeof RegisterKeysSchema>;

// POST /api/forget: one token the proxy made.
export const ForgetTokenSchema = z.strictObject({ token: KoiTokenSchema });
