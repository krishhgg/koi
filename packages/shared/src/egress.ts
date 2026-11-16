import { z } from 'zod';
import { KoiTokenSchema, ProviderIdSchema } from './providers.ts';

// What the egress proxy answers on its control socket
// (host/egress/koi_egress.py, handle_control): one JSON line per request,
// {"ok": true}, with "tokens" for a registration, or {"ok": false, "error":
// "..."}.
export const EgressReplySchema = z.discriminatedUnion('ok', [
	z.object({
		ok: z.literal(true),
		tokens: z.partialRecord(ProviderIdSchema, KoiTokenSchema).optional(),
	}),
	z.object({ ok: z.literal(false), error: z.string() }),
]);

export type EgressReply = z.infer<typeof EgressReplySchema>;
