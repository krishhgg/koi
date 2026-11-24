import { describe, expect, test } from 'bun:test';
import { readdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { CLI_OUTPUT_SCHEMAS, cliOutputSchemaFiles } from '../src/cli-output.ts';

const SCHEMAS_DIR = join(import.meta.dir, '..', '..', '..', 'schemas');

describe('schemas/', () => {
	// When this fails, run `bun scripts/json-schemas.ts` and commit what it writes.
	test('holds what scripts/json-schemas.ts writes from the zod schemas, and nothing else', async () => {
		const files = cliOutputSchemaFiles();
		const committed = (await readdir(SCHEMAS_DIR)).sort();
		expect(committed).toEqual(Object.keys(files).sort());
		for (const [name, text] of Object.entries(files)) {
			expect({ name, text: await readFile(join(SCHEMAS_DIR, name), 'utf8') }).toEqual({
				name,
				text,
			});
		}
	});

	test('each schema is draft 2020-12, requires schemaVersion and names it in its $id', () => {
		for (const [name, text] of Object.entries(cliOutputSchemaFiles())) {
			const schema = JSON.parse(text);
			expect(schema.$schema).toBe('https://json-schema.org/draft/2020-12/schema');
			expect(schema.$id).toBe(`https://github.com/krishhgg/koi/schemas/v1/${name}`);
			expect(schema.properties.schemaVersion).toMatchObject({ type: 'number', const: 1 });
			expect(schema.required).toContain('schemaVersion');
			expect(schema.additionalProperties).toBe(false);
		}
		expect(Object.keys(CLI_OUTPUT_SCHEMAS).sort()).toEqual(['koi-lease', 'koi-release', 'koi-up']);
	});

	test('the up schema keeps loginKey and says it is a secret kept out of evidence and logs', () => {
		const up = JSON.parse(cliOutputSchemaFiles()['koi-up.schema.json'] ?? '{}');
		expect(up.properties.loginKey.pattern).toBe('^koi-[a-z0-9]{24}$');
		expect(up.properties.loginKey.description).toContain(
			'A secret: never copy it into evidence or logs.',
		);
		expect(up.required).not.toContain('loginKey');
	});
});
