import { z } from 'zod';

// A path inside a source tree, written relative to its root: ".", "Dockerfile",
// "./docker/app.Dockerfile". Parsing drops "." segments and repeated or trailing
// slashes, so "./Dockerfile" becomes "Dockerfile" and "./" becomes ".".
//
// This is a syntax check only. Whatever uses the path must join it to the root,
// resolve symlinks, check that the result is still inside the root, and pass
// that absolute path on (never the raw string, which Docker may read as a
// remote context or as stdin).
export const RelativePathSchema = z
	.string()
	.min(1)
	.refine((p) => !/\p{Cc}/u.test(p), 'must not contain control characters')
	.refine((p) => !p.includes('\\'), 'must use forward slashes')
	.refine((p) => !p.startsWith('/'), 'must be relative to the source root')
	.refine((p) => !p.startsWith('-'), 'must not start with a dash')
	// A colon covers URL schemes (http:, file:) and scp-style remotes
	// (git@host:repo). Docker also treats git@ and github.com/ prefixes as
	// remote git contexts.
	.refine(
		(p) => !p.includes(':') && !/^(?:git@|github\.com\/)/i.test(p),
		'must be a path, not a URL or git remote',
	)
	.refine((p) => !p.split('/').includes('..'), 'must not contain a .. segment')
	.transform(
		(p) =>
			p
				.split('/')
				.filter((segment) => segment !== '' && segment !== '.')
				.join('/') || '.',
	)
	// Normalising can expose a prefix the checks above saw behind "./", so the
	// prefix rules run again on the result: "./-" must not become "-".
	.refine((p) => !p.startsWith('-'), 'must not start with a dash')
	.refine((p) => !/^(?:git@|github\.com\/)/i.test(p), 'must be a path, not a URL or git remote');
