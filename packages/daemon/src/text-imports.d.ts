// Files the daemon embeds as text, as Bun's `with { type: 'text' }` import
// gives them (and `bun build --compile` carries them into the binary).
declare module '*.py' {
	const text: string;
	export default text;
}
