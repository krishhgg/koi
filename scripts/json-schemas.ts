// Writes schemas/*.schema.json, the JSON Schemas of what koi up, koi lease and
// koi release print with --json, from the zod schemas in
// packages/shared/src/cli-output.ts. Run it after changing those schemas:
//
//   bun scripts/json-schemas.ts
//
// packages/shared/test/cli-output.test.ts fails while the committed files
// differ from what this writes.
import { mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { cliOutputSchemaFiles } from '../packages/shared/src/cli-output.ts';

const dir = join(import.meta.dir, '..', 'schemas');
const files = cliOutputSchemaFiles();
await mkdir(dir, { recursive: true });
for (const [name, text] of Object.entries(files)) {
	await writeFile(join(dir, name), text);
	console.log(`wrote schemas/${name}`);
}
