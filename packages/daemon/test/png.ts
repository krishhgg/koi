import { deflateSync, inflateSync } from 'node:zlib';
import { crc32 } from '../src/redact.ts';

// A small PNG encoder for the sanitizer tests, so every fixture is a valid
// image by the specification rather than a chunk sequence that only looks
// like one: the IHDR describes the pixels, the IDAT is a zlib stream of
// filtered scanlines whose length follows from the header, and each chunk
// carries its CRC. Tests also build broken files from the same pieces.

export const PNG_SIGNATURE = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

export function chunk(
	type: string,
	data: Uint8Array,
	options: { badCrc?: boolean } = {},
): Uint8Array {
	const typeBytes = new TextEncoder().encode(type);
	const out = new Uint8Array(12 + data.length);
	const view = new DataView(out.buffer);
	view.setUint32(0, data.length);
	out.set(typeBytes, 4);
	out.set(data, 8);
	const body = out.subarray(4, 8 + data.length);
	view.setUint32(8 + data.length, options.badCrc ? crc32(body) ^ 1 : crc32(body));
	return out;
}

// PNG colour types and their samples per pixel at bit depth 8.
export const CHANNELS = { gray: 1, rgb: 3, rgba: 4 } as const;
const COLOR_TYPE = { gray: 0, rgb: 2, rgba: 6 } as const;

export interface Image {
	width: number;
	height: number;
	color: keyof typeof CHANNELS;
	// Samples row by row, width * height * channels of them.
	pixels: Uint8Array;
}

// The IHDR chunk for an 8-bit image: width, height, bit depth 8, the
// colour type, and compression, filter and interlace all 0.
export function ihdr(image: Omit<Image, 'pixels'>): Uint8Array {
	const data = new Uint8Array(13);
	const view = new DataView(data.buffer);
	view.setUint32(0, image.width);
	view.setUint32(4, image.height);
	data[8] = 8;
	data[9] = COLOR_TYPE[image.color];
	return chunk('IHDR', data);
}

// The bytes an IDAT stream must inflate to for an image: one filter byte
// and then the samples of each scanline.
export function rawScanlineBytes(image: Omit<Image, 'pixels'>): number {
	return image.height * (1 + image.width * CHANNELS[image.color]);
}

// The filtered scanlines (filter type 0 on each) of an image, as the
// specification lays them out before compression.
export function scanlines(image: Image): Uint8Array {
	const channels = CHANNELS[image.color];
	const stride = image.width * channels;
	if (image.pixels.length !== stride * image.height) {
		throw new Error(`expected ${stride * image.height} samples, got ${image.pixels.length}`);
	}
	const raw = new Uint8Array(rawScanlineBytes(image));
	for (let y = 0; y < image.height; y++) {
		raw[y * (stride + 1)] = 0;
		raw.set(image.pixels.subarray(y * stride, (y + 1) * stride), y * (stride + 1) + 1);
	}
	return raw;
}

// One IDAT chunk, or several when `split` says how many bytes each may
// carry, over the zlib stream of the image's scanlines.
export function idat(image: Image, split?: number): Uint8Array[] {
	const stream = new Uint8Array(deflateSync(scanlines(image)));
	if (split === undefined) return [chunk('IDAT', stream)];
	const chunks: Uint8Array[] = [];
	for (let at = 0; at < stream.length; at += split) {
		chunks.push(chunk('IDAT', stream.subarray(at, at + split)));
	}
	return chunks;
}

export const IEND = chunk('IEND', new Uint8Array(0));

export function png(...chunks: Uint8Array[]): Uint8Array {
	const out = new Uint8Array(PNG_SIGNATURE.length + chunks.reduce((n, c) => n + c.length, 0));
	out.set(PNG_SIGNATURE, 0);
	let at = PNG_SIGNATURE.length;
	for (const c of chunks) {
		out.set(c, at);
		at += c.length;
	}
	return out;
}

// A complete, valid PNG of the image: signature, IHDR, the IDAT chunks,
// IEND, with any extra chunks placed after IHDR and before IEND.
export function encodePng(image: Image, extra: Uint8Array[] = [], split?: number): Uint8Array {
	return png(ihdr(image), ...extra, ...idat(image, split), IEND);
}

// Reads a PNG back far enough to check it against the specification: the
// header's dimensions and colour type, and that the concatenated IDAT
// streams inflate to exactly the scanline bytes the header implies.
export function checkPng(bytes: Uint8Array): Omit<Image, 'pixels'> & { inflated: number } {
	let at = PNG_SIGNATURE.length;
	const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
	let header: Omit<Image, 'pixels'> | undefined;
	const streams: Uint8Array[] = [];
	while (at < bytes.length) {
		const length = view.getUint32(at);
		const type = String.fromCharCode(...bytes.subarray(at + 4, at + 8));
		const data = bytes.subarray(at + 8, at + 8 + length);
		if (type === 'IHDR') {
			const colorByte = data[9];
			const color = (Object.keys(COLOR_TYPE) as Array<keyof typeof COLOR_TYPE>).find(
				(c) => COLOR_TYPE[c] === colorByte,
			);
			if (color === undefined)
				throw new Error(`colour type ${colorByte} is not one the test encodes`);
			const hv = new DataView(data.buffer, data.byteOffset, data.byteLength);
			header = { width: hv.getUint32(0), height: hv.getUint32(4), color };
		} else if (type === 'IDAT') streams.push(data);
		at += 12 + length;
	}
	if (header === undefined) throw new Error('no IHDR');
	const inflated = inflateSync(Buffer.concat(streams)).length;
	return { ...header, inflated };
}

// The images the tests share: a 2 by 2 RGBA gradient, kept with and
// without metadata chunks.
export const IMAGE: Image = {
	width: 2,
	height: 2,
	color: 'rgba',
	pixels: new Uint8Array([255, 0, 0, 255, 0, 255, 0, 255, 0, 0, 255, 255, 255, 255, 255, 128]),
};

export const IHDR = ihdr(IMAGE);
export const IDAT = idat(IMAGE)[0] as Uint8Array;
export const TEXT = chunk('tEXt', new TextEncoder().encode('Comment\u0000made by koi'));
export const TIME = chunk('tIME', new Uint8Array([7, 234, 10, 6, 12, 0, 0]));

// A PNG with text and time metadata, and the same without.
export const PNG_WITH_METADATA = png(IHDR, TEXT, IDAT, TIME, IEND);
export const PNG_STRIPPED = png(IHDR, IDAT, IEND);
