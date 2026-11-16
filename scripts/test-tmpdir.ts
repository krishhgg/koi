// Test files make scratch directories under the system temp directory, and most
// leave them there, so each run used to add thousands of entries to /tmp. Give a
// run one directory of its own and remove it when the run ends.
import { afterAll } from 'bun:test';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const root = mkdtempSync(join(tmpdir(), 'koi-test-run-'));
process.env.TMPDIR = root;

// In a preload, afterAll runs once after the last test file. A process exit
// handler does not run under bun test, so it would leave the directory behind.
afterAll(() => rmSync(root, { recursive: true, force: true }));
