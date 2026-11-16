import { readdir } from 'node:fs/promises';
import { join } from 'node:path';

// The repository's recipes/ directory, which scripts/deploy-host.sh installs
// on the box.
export const RECIPES = join(import.meta.dir, '../../../recipes');

// A Dockerfile as instructions: continued lines joined, comments dropped,
// split into stages at each FROM.
export interface Stage {
	name: string;
	from: string;
	lines: string[];
}

export function stages(dockerfile: string): Stage[] {
	const lines: string[] = [];
	let current = '';
	for (const raw of dockerfile.split('\n')) {
		const line = raw.trim();
		if (line.startsWith('#') || (line === '' && current === '')) continue;
		if (line.endsWith('\\')) {
			current += `${line.slice(0, -1)} `;
			continue;
		}
		lines.push(current + line);
		current = '';
	}
	const out: Stage[] = [];
	for (const line of lines) {
		const from = /^FROM\s+(\S+)(?:\s+AS\s+(\S+))?/i.exec(line);
		if (from) out.push({ from: from[1] ?? '', name: from[2] ?? '', lines: [] });
		else out.at(-1)?.lines.push(line);
	}
	return out;
}

// Stages that hold the pull request's source: those that copy from the build
// context, and those built on such a stage.
export function sourceStages(all: Stage[]): Set<string> {
	const holding = new Set<string>();
	for (const s of all) {
		const copies = s.lines.some(
			(l) => /^(COPY|ADD)\s/i.test(l) && !/--from=/.test(l) && !/^ADD\s+https:/i.test(l),
		);
		if (copies || holding.has(s.from)) holding.add(s.name);
	}
	return holding;
}

// The --mount options in `all` that let a pull request's build write what
// another build sees: a cache mount that is not read-only, and any mount
// marked rw or readwrite.
export function writableMounts(all: Stage[]): string[] {
	const out: string[] = [];
	for (const s of all) {
		for (const line of s.lines) {
			for (const [, mount = ''] of line.matchAll(/--mount=(\S+)/g)) {
				const opts = mount.split(',');
				const readOnly = opts.some((o) => o === 'ro' || o === 'readonly');
				const writable = opts.includes('rw') || opts.includes('readwrite');
				if ((opts.includes('type=cache') && !readOnly) || writable) out.push(mount);
			}
		}
	}
	return out;
}

// Every recipe in `dir` (recipes/ unless given) that brings a Dockerfile, by
// directory name.
export async function recipeDockerfiles(dir = RECIPES): Promise<Array<[string, Stage[]]>> {
	const out: Array<[string, Stage[]]> = [];
	for (const name of (await readdir(dir)).sort()) {
		const file = Bun.file(join(dir, name, 'Dockerfile'));
		if (await file.exists()) out.push([name, stages(await file.text())]);
	}
	return out;
}
