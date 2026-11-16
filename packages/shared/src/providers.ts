import { z } from 'zod';

// LLM providers whose keys reviewers can register on the keys page. The egress
// proxy (host/egress/koi_egress.py, PROVIDERS) intercepts exactly these hosts
// and swaps a koi token for the registered key; a test keeps the two lists in
// step.
export const PROVIDERS = [
	{ id: 'openai', name: 'OpenAI', host: 'api.openai.com' },
	{ id: 'anthropic', name: 'Anthropic', host: 'api.anthropic.com' },
	{ id: 'gemini', name: 'Google Gemini', host: 'generativelanguage.googleapis.com' },
	{ id: 'mistral', name: 'Mistral', host: 'api.mistral.ai' },
	{ id: 'groq', name: 'Groq', host: 'api.groq.com' },
	{ id: 'together', name: 'Together', host: 'api.together.xyz' },
	{ id: 'cohere', name: 'Cohere', host: 'api.cohere.com' },
	{ id: 'deepseek', name: 'DeepSeek', host: 'api.deepseek.com' },
	{ id: 'xai', name: 'xAI', host: 'api.x.ai' },
	{ id: 'openrouter', name: 'OpenRouter', host: 'openrouter.ai' },
	{ id: 'perplexity', name: 'Perplexity', host: 'api.perplexity.ai' },
] as const;

export type ProviderId = (typeof PROVIDERS)[number]['id'];

export const ProviderIdSchema = z.enum(PROVIDERS.map((p) => p.id) as [ProviderId, ...ProviderId[]]);

// A koi token, as the egress proxy makes them: one per registered key, good
// for that key's provider and one preview, derived from the three under a
// secret on the box (koi_egress.py, derive_token: 160 bits of an HMAC in
// lowercase base32, so a-z and 2-7), the same each time the key is
// registered.
export const KOI_TOKEN = /^koi_[a-z0-9]{32}$/;

export const KoiTokenSchema = z.string().regex(KOI_TOKEN);

// Some apps check a key's prefix before they send anything, and refuse one
// that does not begin the way the provider's keys do: "sk-ant" for
// Anthropic, "sk-" for DeepSeek, "xai-" for xAI. The keys page shows each
// token after its provider's prefix so such an app takes it, and the egress
// proxy (koi_egress.py, TOKEN_PREFIXES) accepts a token with or without one.
export const TOKEN_PREFIXES: Partial<Record<ProviderId, string>> = {
	openai: 'sk-',
	anthropic: 'sk-ant-',
	deepseek: 'sk-',
	xai: 'xai-',
};

// Subdomains that are koi's own pages, never previews. Preview labels always
// contain a dash, so they cannot collide with these.
export const RESERVED_LABELS = ['keys'] as const;
