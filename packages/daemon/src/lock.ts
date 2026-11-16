// Serialises work per key. Two `up` calls for the same label run one after the
// other; different labels proceed independently.
export class KeyedLock {
	private readonly tails = new Map<string, Promise<unknown>>();

	run<T>(key: string, task: () => Promise<T>): Promise<T> {
		const previous = this.tails.get(key) ?? Promise.resolve();
		const next = previous.then(task, task);
		const tail = next.catch(() => undefined);
		this.tails.set(key, tail);
		void tail.then(() => {
			if (this.tails.get(key) === tail) {
				this.tails.delete(key);
			}
		});
		return next;
	}

	busy(key: string): boolean {
		return this.tails.has(key);
	}
}

// At most `limit` tasks at a time across all keys. Builds share one box.
// A finishing task hands its permit straight to the first waiter, so a
// caller arriving before that waiter resumes finds no vacancy to take.
export class Semaphore {
	private active = 0;
	private readonly waiting: Array<() => void> = [];

	constructor(private readonly limit: number) {}

	async run<T>(task: () => Promise<T>): Promise<T> {
		if (this.active < this.limit) this.active += 1;
		else await new Promise<void>((resolve) => this.waiting.push(resolve));
		try {
			return await task();
		} finally {
			const next = this.waiting.shift();
			if (next === undefined) this.active -= 1;
			else next();
		}
	}

	get inUse(): number {
		return this.active;
	}
}

// One task at a time, in call order. A task given a signal that fired
// while it waited is not run: its caller stopped waiting at a deadline, and
// work the caller will not see must not start. The task's own completion
// still chains the next one, so a skipped task costs nothing.
export class Mutex {
	private tail: Promise<unknown> = Promise.resolve();

	run<T>(task: () => Promise<T>, signal?: AbortSignal): Promise<T> {
		const next = this.tail.then(() => {
			if (signal?.aborted) {
				throw signal.reason instanceof Error
					? signal.reason
					: new Error('the wait for the lock was abandoned');
			}
			return task();
		});
		this.tail = next.catch(() => undefined);
		return next;
	}
}
