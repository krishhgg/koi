import { mkdir, readdir, readFile, rename, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { PreviewLabelSchema, type PreviewRecord, PreviewRecordSchema, randomId } from '@koi/shared';
import { KeyedLock } from './lock.ts';

// Preview records, one JSON file per label under <stateDir>/previews. Writes go
// to a temporary file and are renamed into place, so a crash mid-write leaves
// the previous record rather than half a file.
//
// Every write to a label holds that label's mutex, and update() reads the
// record inside it, so two read-modify-write changes (a visit and a cutover,
// say) never interleave and lose one another's fields.
export class PreviewStore {
	private readonly dir: string;
	private readonly locks = new KeyedLock();

	constructor(stateDir: string) {
		this.dir = join(stateDir, 'previews');
	}

	// Also gives each record from before koid named attempts, which has no
	// attempt or an empty one, an attempt of its own. Build logs are kept by
	// attempt, so this is where BuildLogs.upgrade puts the record's old log,
	// and where koi logs --build finds it. A file that does not parse is left
	// for list() to report.
	async init(): Promise<void> {
		await mkdir(this.dir, { recursive: true });
		for (const name of await readdir(this.dir)) {
			if (!name.endsWith('.json')) continue;
			try {
				// A record from before attempts parses with an empty one.
				const stored = PreviewRecordSchema.parse(
					JSON.parse(await readFile(join(this.dir, name), 'utf8')),
				);
				if (stored.attempt !== '') continue;
				const record = { ...stored, attempt: randomId() };
				await this.locks.run(record.label, () => this.write(record));
			} catch {}
		}
	}

	private path(label: string): string {
		return join(this.dir, `${PreviewLabelSchema.parse(label)}.json`);
	}

	async get(label: string): Promise<PreviewRecord | undefined> {
		let text: string;
		try {
			text = await readFile(this.path(label), 'utf8');
		} catch (err) {
			if (isNotFound(err)) return undefined;
			throw err;
		}
		return PreviewRecordSchema.parse(JSON.parse(text));
	}

	// Replaces the whole record. Prefer update() for a change to an existing one.
	async put(record: PreviewRecord): Promise<PreviewRecord> {
		const valid = PreviewRecordSchema.parse(record);
		return this.locks.run(valid.label, () => this.write(valid));
	}

	// Applies `change` to the record as it is now. Returns the result, or
	// undefined when there is no record. When `change` returns its argument
	// unchanged nothing is written.
	async update(
		label: string,
		change: (current: PreviewRecord) => PreviewRecord,
	): Promise<PreviewRecord | undefined> {
		return this.locks.run(PreviewLabelSchema.parse(label), async () => {
			const current = await this.get(label);
			if (current === undefined) return undefined;
			const next = change(current);
			return next === current ? current : this.write(next);
		});
	}

	// Like update(), and also called (with undefined) when there is no record yet.
	async upsert(
		label: string,
		change: (current: PreviewRecord | undefined) => PreviewRecord,
	): Promise<PreviewRecord> {
		return this.locks.run(PreviewLabelSchema.parse(label), async () => {
			const current = await this.get(label);
			const next = change(current);
			return next === current ? next : this.write(next);
		});
	}

	async remove(label: string): Promise<void> {
		await this.locks.run(PreviewLabelSchema.parse(label), () =>
			rm(this.path(label), { force: true }),
		);
	}

	// Caller holds the label's lock.
	private async write(record: PreviewRecord): Promise<PreviewRecord> {
		const valid = PreviewRecordSchema.parse(record);
		const target = this.path(valid.label);
		const temp = `${target}.${process.pid}.${Date.now()}.tmp`;
		await writeFile(temp, `${JSON.stringify(valid, null, '\t')}\n`, { mode: 0o640 });
		await rename(temp, target);
		return valid;
	}

	// Every record that parses. A file that does not parse is reported and
	// skipped rather than taking the whole list down.
	async list(onBad: (file: string, err: unknown) => void = () => {}): Promise<PreviewRecord[]> {
		const names = await readdir(this.dir).catch((err: unknown) => {
			if (isNotFound(err)) return [] as string[];
			throw err;
		});
		const records: PreviewRecord[] = [];
		for (const name of names.sort()) {
			if (!name.endsWith('.json')) continue;
			try {
				const text = await readFile(join(this.dir, name), 'utf8');
				records.push(PreviewRecordSchema.parse(JSON.parse(text)));
			} catch (err) {
				onBad(name, err);
			}
		}
		return records;
	}
}

function isNotFound(err: unknown): boolean {
	return typeof err === 'object' && err !== null && 'code' in err && err.code === 'ENOENT';
}
