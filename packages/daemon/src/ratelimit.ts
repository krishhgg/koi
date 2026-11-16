// Counts calls per source in fixed windows, under a ceiling for all sources
// together. A new window starts with no counts, and a call refused for the
// ceiling counts nothing, so at most `total` sources are held at a time.
export interface RateLimits {
	perSource: number;
	total: number;
	windowMs: number;
}

export class RateLimit {
	private windowStart = Number.NEGATIVE_INFINITY;
	private all = 0;
	private readonly bySource = new Map<string, number>();

	constructor(
		private readonly limits: RateLimits,
		private readonly now: () => number = Date.now,
	) {}

	// Counts one call from `source`; false, counting nothing, when that would
	// pass either limit.
	take(source: string): boolean {
		const at = this.now();
		if (at - this.windowStart >= this.limits.windowMs) {
			this.windowStart = at;
			this.all = 0;
			this.bySource.clear();
		}
		const used = this.bySource.get(source) ?? 0;
		if (this.all >= this.limits.total || used >= this.limits.perSource) return false;
		this.all += 1;
		this.bySource.set(source, used + 1);
		return true;
	}
}
