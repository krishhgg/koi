import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { Ajv2020, type ErrorObject, type ValidateFunction } from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';

// The JSON Schemas in schemas/, loaded as a program that runs koi would load
// them, with a validator that knows none of koi's types: what the CLI prints
// with --json is checked against the published files, not the zod schemas
// they were made from.
const SCHEMAS_DIR = join(import.meta.dir, '..', '..', '..', 'schemas');

const ajv = new Ajv2020({ strict: true, allErrors: true });
addFormats(ajv);

const validators = new Map<string, ValidateFunction>();

export type OutputSchema = 'koi-up' | 'koi-lease' | 'koi-release';

// Where `value` breaks schemas/<name>.schema.json; none when it matches.
export function schemaErrors(name: OutputSchema, value: unknown): ErrorObject[] {
	let validate = validators.get(name);
	if (validate === undefined) {
		const text = readFileSync(join(SCHEMAS_DIR, `${name}.schema.json`), 'utf8');
		validate = ajv.compile(JSON.parse(text));
		validators.set(name, validate);
	}
	return validate(value) ? [] : [...(validate.errors ?? [])];
}
