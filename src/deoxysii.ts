// SPDX-License-Identifier: MIT
// Copyright (c) 2019 Oasis Labs Inc. <info@oasislabs.com>
// Copyright (c) 2024 Oasis Protocol Foundation <info@oasisprotocol.org>
//
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to
// the following conditions:
//
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
// BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
// ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

import {
	addRoundKey,
	load4xU32,
	load8xU32,
	mixColumns,
	newQ,
	ortho,
	rkeyOrtho,
	shiftRows,
	store4xU32,
	store8xU32,
	subBytes,
} from "./aes.js";

import { uint32_xor2, uint32_xor3 } from "./uint32.js";

export const KeySize = 32;
export const NonceSize = 15;
export const TagSize = 16;

const stkSize = 16;
const rounds = 16;
const blockSize = 16;
const tweakSize = 16;

const prefixADBlock = 0x02;
const prefixADFinal = 0x06;
const prefixMsgBlock = 0x00;
const prefixMsgFinal = 0x04;
const prefixTag = 0x01;
const prefixShift = 4;

function xorBytes(dst: Uint8Array, a: Uint8Array, b: Uint8Array, n: number) {
	for (let i = 0; i < n; i++) {
		dst[i] = a[i] ^ b[i];
	}
}

//
// TWEAKEY routines
//

const rcons = new Uint8Array([
	0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef,
	0xc5, 0x91, 0x39, 0x72,
]);

function h(t: Uint8Array) {
	t.set(
		new Uint8Array([
			t[1],
			t[6],
			t[11],
			t[12],
			t[5],
			t[10],
			t[15],
			t[0],
			t[9],
			t[14],
			t[3],
			t[4],
			t[13],
			t[2],
			t[7],
			t[8],
		]),
	);
}

function lfsr2(t: Uint8Array) {
	for (let i = 0; i < stkSize; i++) {
		const x = t[i];

		const x7 = x >> 7;
		const x5 = (x >> 5) & 1;
		t[i] = (x << 1) | (x7 ^ x5);
	}
}

function lfsr3(t: Uint8Array) {
	for (let i = 0; i < stkSize; i++) {
		const x = t[i];

		const x0 = x & 1;
		const x6 = (x >> 6) & 1;
		t[i] = (x >> 1) | ((x0 ^ x6) << 7);
	}
}

function xorRC(t: Uint8Array, i: number) {
	t[0] ^= 1;
	t[1] ^= 2;
	t[2] ^= 4;
	t[3] ^= 8;
	t[4] ^= rcons[i];
	t[5] ^= rcons[i];
	t[6] ^= rcons[i];
	t[7] ^= rcons[i];
}

function stkDeriveK(key: Uint8Array, derivedKs: Uint8Array[]) {
	const tk2 = key.subarray(16, 32);
	const tk3 = key.subarray(0, 16);

	xorBytes(derivedKs[0], tk2, tk3, stkSize);
	xorRC(derivedKs[0], 0);

	for (let i = 1; i <= rounds; i++) {
		lfsr2(tk2);
		h(tk2);
		lfsr3(tk3);
		h(tk3);

		xorBytes(derivedKs[i], tk2, tk3, stkSize);
		xorRC(derivedKs[i], i);
	}
}

function deriveSubTweakKeys(
	stks: Uint8Array[],
	derivedKs: Uint8Array[],
	tweak: Uint8Array,
) {
	const tk1 = new Uint8Array(tweak);

	xorBytes(stks[0], derivedKs[0], tk1, stkSize);

	for (let i = 1; i <= rounds; i++) {
		h(tk1);
		xorBytes(stks[i], derivedKs[i], tk1, stkSize);
	}
}

function newStks() {
	const stks: Uint8Array[] = [];
	for (let i = 0; i <= rounds; i++) {
		stks.push(new Uint8Array(16));
	}
	return stks;
}

//
// Deoxys-BC-384
//

function ct32_bcEncrypt(
	ciphertext: Uint8Array,
	derivedKs: Uint8Array[],
	tweak: Uint8Array,
	plaintext: Uint8Array,
) {
	const stks = newStks();
	deriveSubTweakKeys(stks, derivedKs, tweak);

	const q = newQ();
	const stk = newQ();
	load4xU32(q, plaintext);
	load4xU32(stk, stks[0]);
	addRoundKey(q, stk);

	for (let i = 1; i <= rounds; i++) {
		subBytes(q);
		shiftRows(q);
		mixColumns(q);

		load4xU32(stk, stks[i]);
		addRoundKey(q, stk);
	}

	store4xU32(ciphertext, q);
}

function ct32_bcKeystreamx2(
	ciphertext: Uint8Array,
	derivedKs: Uint8Array[],
	tweaks: Uint8Array[],
	nonce: Uint8Array,
) {
	const stks = [newStks(), newStks()];
	for (let i = 0; i < 2; i++) {
		deriveSubTweakKeys(stks[i], derivedKs, tweaks[i]);
	}

	const q = newQ();
	const stk = newQ();
	rkeyOrtho(q, nonce);
	load8xU32(stk, stks[0][0], stks[1][0]);
	addRoundKey(q, stk);

	for (let i = 1; i <= rounds; i++) {
		subBytes(q);
		shiftRows(q);
		mixColumns(q);

		load8xU32(stk, stks[0][i], stks[1][i]);
		addRoundKey(q, stk);
	}
	store8xU32(ciphertext.subarray(0, 16), ciphertext.subarray(16, 32), q);
}

function ct32_bcTagx1(
	tag: Uint8Array,
	derivedKs: Uint8Array[],
	tweak: Uint8Array,
	plaintext: Uint8Array,
) {
	const stks = newStks();
	deriveSubTweakKeys(stks, derivedKs, tweak);

	const q = newQ();
	const stk = newQ();
	load4xU32(q, plaintext);
	load4xU32(stk, stks[0]);
	addRoundKey(q, stk);

	for (let i = 1; i <= rounds; i++) {
		subBytes(q);
		shiftRows(q);
		mixColumns(q);

		load4xU32(stk, stks[i]);
		addRoundKey(q, stk);
	}

	const tagView = new DataView(tag.buffer);
	let tag0 = tagView.getUint32(0, true);
	let tag1 = tagView.getUint32(4, true);
	let tag2 = tagView.getUint32(8, true);
	let tag3 = tagView.getUint32(12, true);

	ortho(q);
	tag0 = uint32_xor2(tag0, q[0]);
	tag1 = uint32_xor2(tag1, q[2]);
	tag2 = uint32_xor2(tag2, q[4]);
	tag3 = uint32_xor2(tag3, q[6]);

	tagView.setUint32(0, tag0, true);
	tagView.setUint32(4, tag1, true);
	tagView.setUint32(8, tag2, true);
	tagView.setUint32(12, tag3, true);
}

function ct32_bcTagx2(
	tag: Uint8Array,
	derivedKs: Uint8Array[],
	tweaks: Uint8Array[],
	plaintext: Uint8Array,
) {
	const stks = [newStks(), newStks()];
	for (let i = 0; i < 2; i++) {
		deriveSubTweakKeys(stks[i], derivedKs, tweaks[i]);
	}

	const q = newQ();
	const stk = newQ();
	load8xU32(q, plaintext.subarray(0, 16), plaintext.subarray(16, 32));
	load8xU32(stk, stks[0][0], stks[1][0]);
	addRoundKey(q, stk);

	for (let i = 1; i <= rounds; i++) {
		subBytes(q);
		shiftRows(q);
		mixColumns(q);

		load8xU32(stk, stks[0][i], stks[1][i]);
		addRoundKey(q, stk);
	}

	const tagView = new DataView(tag.buffer);
	let tag0 = tagView.getUint32(0, true);
	let tag1 = tagView.getUint32(4, true);
	let tag2 = tagView.getUint32(8, true);
	let tag3 = tagView.getUint32(12, true);

	ortho(q);
	tag0 = uint32_xor3(tag0, q[0], q[1]);
	tag1 = uint32_xor3(tag1, q[2], q[3]);
	tag2 = uint32_xor3(tag2, q[4], q[5]);
	tag3 = uint32_xor3(tag3, q[6], q[7]);

	tagView.setUint32(0, tag0, true);
	tagView.setUint32(4, tag1, true);
	tagView.setUint32(8, tag2, true);
	tagView.setUint32(12, tag3, true);
}

function encodeTagTweak(out: Uint8Array, prefix: number, blockNr: number) {
	out.set(new Uint8Array(12));
	new DataView(out.buffer).setUint32(12 + out.byteOffset, blockNr, false);
	out[0] = prefix << prefixShift;
}

function encodeEncTweak(out: Uint8Array, tag: Uint8Array, blockNr: number) {
	const tmp = new Uint8Array(4);
	new DataView(tmp.buffer).setUint32(0, blockNr, false);

	out.set(tag);
	out[0] |= 0x80;

	xorBytes(out.subarray(12, 16), out.subarray(12, 16), tmp, 4);
}

function newTweaks() {
	return [new Uint8Array(tweakSize), new Uint8Array(tweakSize)];
}

function e(
	derivedKs: Uint8Array[],
	nonce: Uint8Array,
	dst: Uint8Array,
	ad: Uint8Array,
	msg: Uint8Array,
) {
	const tweaks = newTweaks();
	let i = 0;
	let j = 0;

	// Associated data.
	let adLen = ad.length;
	const auth = new Uint8Array(TagSize);
	for (i = 0; adLen >= 2 * blockSize; i += 2) {
		encodeTagTweak(tweaks[0], prefixADBlock, i);
		encodeTagTweak(tweaks[1], prefixADBlock, i + 1);
		ct32_bcTagx2(
			auth,
			derivedKs,
			tweaks,
			ad.subarray(i * blockSize, (i + 2) * blockSize),
		);

		adLen -= 2 * blockSize;
	}
	for (; adLen >= blockSize; i++) {
		encodeTagTweak(tweaks[0], prefixADBlock, i);
		ct32_bcTagx1(
			auth,
			derivedKs,
			tweaks[0],
			ad.subarray(i * blockSize, (i + 1) * blockSize),
		);

		adLen -= blockSize;
	}
	if (adLen > 0) {
		encodeTagTweak(tweaks[0], prefixADFinal, i);

		const aStar = new Uint8Array(blockSize);
		aStar.set(ad.subarray(ad.length - adLen));
		aStar[adLen] = 0x80;

		ct32_bcTagx1(auth, derivedKs, tweaks[0], aStar);
	}

	// Message authentication and tag generation.
	let msgLen = msg.length;
	for (j = 0; msgLen >= 2 * blockSize; j += 2) {
		encodeTagTweak(tweaks[0], prefixMsgBlock, j);
		encodeTagTweak(tweaks[1], prefixMsgBlock, j + 1);
		ct32_bcTagx2(
			auth,
			derivedKs,
			tweaks,
			msg.subarray(j * blockSize, (j + 2) * blockSize),
		);

		msgLen -= 2 * blockSize;
	}
	for (; msgLen >= blockSize; j++) {
		encodeTagTweak(tweaks[0], prefixMsgBlock, j);
		ct32_bcTagx1(
			auth,
			derivedKs,
			tweaks[0],
			msg.subarray(j * blockSize, (j + 1) * blockSize),
		);

		msgLen -= blockSize;
	}
	if (msgLen > 0) {
		encodeTagTweak(tweaks[0], prefixMsgFinal, j);

		const mStar = new Uint8Array(blockSize);
		mStar.set(msg.subarray(msg.length - msgLen));
		mStar[msgLen] = 0x80;

		ct32_bcTagx1(auth, derivedKs, tweaks[0], mStar);
	}

	// Generate the tag.
	const encNonce = new Uint8Array(blockSize);
	encNonce.set(nonce, 1);
	encNonce[0] = prefixTag << prefixShift;
	ct32_bcEncrypt(auth, derivedKs, encNonce, auth);

	// Message encryption.
	encNonce[0] = 0;
	msgLen = msg.length;
	const encBlks = new Uint8Array(2 * blockSize);
	for (j = 0; msgLen >= 2 * blockSize; j += 2) {
		encodeEncTweak(tweaks[0], auth, j);
		encodeEncTweak(tweaks[1], auth, j + 1);

		ct32_bcKeystreamx2(encBlks, derivedKs, tweaks, encNonce);
		xorBytes(
			dst.subarray(j * blockSize, (j + 2) * blockSize),
			msg.subarray(j * blockSize, (j + 2) * blockSize),
			encBlks,
			2 * blockSize,
		);

		msgLen -= 2 * blockSize;
	}
	for (; msgLen >= blockSize; j++) {
		encodeEncTweak(tweaks[0], auth, j);
		ct32_bcEncrypt(encBlks, derivedKs, tweaks[0], encNonce);
		xorBytes(
			dst.subarray(j * blockSize, (j + 1) * blockSize),
			msg.subarray(j * blockSize, (j + 1) * blockSize),
			encBlks,
			blockSize,
		);

		msgLen -= blockSize;
	}
	if (msgLen > 0) {
		encodeEncTweak(tweaks[0], auth, j);

		ct32_bcEncrypt(encBlks, derivedKs, tweaks[0], encNonce);
		xorBytes(
			dst.subarray(j * blockSize, msg.length),
			msg.subarray(j * blockSize),
			encBlks,
			msgLen,
		);
	}

	// Write the tag to the tail.
	dst.set(auth, msg.length);
}

function d(
	derivedKs: Uint8Array[],
	nonce: Uint8Array,
	dst: Uint8Array,
	ad: Uint8Array,
	ct: Uint8Array,
) {
	let ctLen = ct.length - TagSize;
	const ciphertext = ct.subarray(0, ctLen);
	const tag = ct.subarray(ctLen);

	// Message decryption.
	let j = 0;
	const decTweaks = newTweaks();
	const decNonce = new Uint8Array(blockSize);
	decNonce.set(nonce, 1);
	const decBlks = new Uint8Array(2 * blockSize);
	for (j = 0; ctLen >= 2 * blockSize; j += 2) {
		encodeEncTweak(decTweaks[0], tag, j);
		encodeEncTweak(decTweaks[1], tag, j + 1);

		ct32_bcKeystreamx2(decBlks, derivedKs, decTweaks, decNonce);
		xorBytes(
			dst.subarray(j * blockSize, (j + 2) * blockSize),
			ciphertext.subarray(j * blockSize, (j + 2) * blockSize),
			decBlks,
			2 * blockSize,
		);

		ctLen -= 2 * blockSize;
	}
	for (; ctLen >= blockSize; j++) {
		encodeEncTweak(decTweaks[0], tag, j);

		ct32_bcEncrypt(decBlks, derivedKs, decTweaks[0], decNonce);
		xorBytes(
			dst.subarray(j * blockSize, (j + 1) * blockSize),
			ciphertext.subarray(j * blockSize, (j + 1) * blockSize),
			decBlks,
			blockSize,
		);

		ctLen -= blockSize;
	}
	if (ctLen > 0) {
		encodeEncTweak(decTweaks[0], tag, j);

		ct32_bcEncrypt(decBlks, derivedKs, decTweaks[0], decNonce);
		xorBytes(
			dst.subarray(j * blockSize),
			ciphertext.subarray(j * blockSize),
			decBlks,
			ctLen,
		);
	}

	// Associated data.
	let i = 0;
	let adLen = ad.length;
	const tweaks = newTweaks();
	const auth = new Uint8Array(TagSize);
	for (i = 0; adLen >= 2 * blockSize; i += 2) {
		encodeTagTweak(tweaks[0], prefixADBlock, i);
		encodeTagTweak(tweaks[1], prefixADBlock, i + 1);
		ct32_bcTagx2(
			auth,
			derivedKs,
			tweaks,
			ad.subarray(i * blockSize, (i + 2) * blockSize),
		);

		adLen -= 2 * blockSize;
	}
	for (; adLen >= blockSize; i++) {
		encodeTagTweak(tweaks[0], prefixADBlock, i);
		ct32_bcTagx1(
			auth,
			derivedKs,
			tweaks[0],
			ad.subarray(i * blockSize, (i + 1) * blockSize),
		);

		adLen -= blockSize;
	}
	if (adLen > 0) {
		encodeTagTweak(tweaks[0], prefixADFinal, i);

		const aStar = new Uint8Array(blockSize);

		aStar.set(ad.subarray(ad.length - adLen));
		aStar[adLen] = 0x80;

		ct32_bcTagx1(auth, derivedKs, tweaks[0], aStar);
	}

	// Message authentication and tag generation.
	let msgLen = dst.length;
	for (j = 0; msgLen >= 2 * blockSize; j += 2) {
		encodeTagTweak(tweaks[0], prefixMsgBlock, j);
		encodeTagTweak(tweaks[1], prefixMsgBlock, j + 1);
		ct32_bcTagx2(
			auth,
			derivedKs,
			tweaks,
			dst.subarray(j * blockSize, (j + 2) * blockSize),
		);

		msgLen -= 2 * blockSize;
	}
	for (; msgLen >= blockSize; j++) {
		encodeTagTweak(tweaks[0], prefixMsgBlock, j);
		ct32_bcTagx1(
			auth,
			derivedKs,
			tweaks[0],
			dst.subarray(j * blockSize, (j + 1) * blockSize),
		);

		msgLen -= blockSize;
	}
	if (msgLen > 0) {
		encodeTagTweak(tweaks[0], prefixMsgFinal, j);

		const mStar = new Uint8Array(blockSize);
		mStar.set(dst.subarray(dst.length - msgLen));
		mStar[msgLen] = 0x80;

		ct32_bcTagx1(auth, derivedKs, tweaks[0], mStar);
	}

	decNonce[0] = prefixTag << prefixShift;
	ct32_bcEncrypt(auth, derivedKs, decNonce, auth);

	// crypto.timingSafeEqual is not implemented on typed arrays.
	if (auth.length !== tag.length) {
		// Note, this should never happen!
		return false;
	}
	let eql = true;
	for (i = 0; i < auth.length; i++) {
		// @ts-expect-error TODO: should this return a boolean
		eql &= !(auth[i] ^ tag[i]);
	}

	return eql;
}

/**
 * The AEAD implementation.
 * As much as possible (as long as the key does not change), instances should
 * be reused as deriving the K contribution of the Sub-Tweak Key is relatively
 * expensive.
 */
export class AEAD {
	protected derivedKs: Uint8Array[];

	constructor(key: Uint8Array) {
		if (key.length !== KeySize) {
			throw ErrKeySize;
		}
		this.derivedKs = newStks();
		stkDeriveK(key, this.derivedKs);
	}

	public encrypt(
		nonce: Uint8Array,
		plaintext: Uint8Array | null = null,
		associatedData: Uint8Array | null = null,
	) {
		if (nonce.length !== NonceSize) {
			throw ErrNonceSize;
		}

		if (plaintext == null) {
			// biome-ignore lint/style/noParameterAssign:
			plaintext = zeroBuffer;
		}
		if (associatedData == null) {
			// biome-ignore lint/style/noParameterAssign:
			associatedData = zeroBuffer;
		}

		const dst = new Uint8Array(plaintext.length + TagSize);
		e(this.derivedKs, nonce, dst, associatedData, plaintext);

		return dst;
	}

	public decrypt(
		nonce: Uint8Array,
		ciphertext: Uint8Array,
		associatedData: Uint8Array | null = null,
	) {
		if (nonce.length !== NonceSize) {
			throw ErrNonceSize;
		}
		if (ciphertext.length < TagSize) {
			throw ErrOpen;
		}

		if (associatedData == null) {
			// biome-ignore lint/style/noParameterAssign:
			associatedData = zeroBuffer;
		}

		const dst = new Uint8Array(ciphertext.length - TagSize);
		if (!d(this.derivedKs, nonce, dst, associatedData, ciphertext)) {
			dst.set(new Uint8Array(dst.length));
			throw ErrOpen;
		}

		return dst;
	}
}

const zeroBuffer = new Uint8Array(0);

export const ErrKeySize = "deoxysii: invalid key size";
export const ErrNonceSize = "deoxysii: invalid nonce size";
export const ErrOpen = "deoxysii: message authentication failure";
