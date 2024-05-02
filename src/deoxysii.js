// Copyright (c) 2019 Oasis Labs Inc. <info@oasislabs.com>
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

// @ts-expect-error TODO: missing types
var aes = require('bsaes');
var uint32 = require('uint32');
// @ts-expect-error TODO: missing types
var unsafe = require('bsaes/unsafe');

const KeySize = 32;
const NonceSize = 15;
const TagSize = 16;

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

/**
 * @param {Uint8Array} dst
 * @param {Uint8Array} a
 * @param {Uint8Array} b
 * @param {number} n
 */
function xorBytes(dst, a, b, n) {
	for (let i = 0; i < n; i++) {
		dst[i] = a[i] ^ b[i];
	}
}

//
// TWEAKEY routines
//

const rcons = new Uint8Array([
	0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a,
	0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39,
	0x72
]);

/**
 * @param {Uint8Array} t
 */
function h(t) {
	const tmp = new Uint8Array([
		t[1], t[6], t[11], t[12], t[5], t[10], t[15], t[0], t[9], t[14], t[3], t[4], t[13], t[2], t[7], t[8]
	]);
	t.set(tmp);
}

/**
 * @param {Uint8Array} t
 */
function lfsr2(t) {
	for (let i = 0; i < stkSize; i++) {
		const x = t[i];

		const x7 = x >> 7;
		const x5 = (x >> 5) & 1;
		t[i] = (x << 1) | (x7 ^ x5);
	}
}

/**
 * @param {Uint8Array} t
 */
function lfsr3(t) {
	for (let i = 0; i < stkSize; i++) {
		const x = t[i];

		const x0 = x & 1;
		const x6 = (x >> 6) & 1;
		t[i] = (x >> 1) | ((x0 ^ x6) << 7);
	}
}

/**
 * @param {Uint8Array} t
 * @param {number} i
 */
function xorRC(t, i) {
	t[0] ^= 1;
	t[1] ^= 2;
	t[2] ^= 4;
	t[3] ^= 8;
	t[4] ^= rcons[i];
	t[5] ^= rcons[i];
	t[6] ^= rcons[i];
	t[7] ^= rcons[i];
}

/**
 * @param {Uint8Array} key
 * @param {Uint8Array[]} derivedKs
 */
function stkDeriveK(key, derivedKs) {
	let tk2 = key.subarray(16, 32);
	let tk3	= key.subarray(0, 16);

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

/**
 * @param {Uint8Array[]} stks
 * @param {Uint8Array[]} derivedKs
 * @param {Uint8Array} tweak
 */
function deriveSubTweakKeys(stks, derivedKs, tweak) {
	let tk1 = new Uint8Array(tweak);

	xorBytes(stks[0], derivedKs[0], tk1, stkSize);

	for (let i = 1; i <= rounds; i++) {
		h(tk1);
		xorBytes(stks[i], derivedKs[i], tk1, stkSize);
	}
}

function newStks() {
	let stks = [];
	for (let i = 0; i <= rounds; i++) {
		stks.push(new Uint8Array(16));
	}
	return stks;
}

//
// Deoxys-BC-384
//

class implCt32 {
	/**
	 * @param {Uint8Array} ciphertext
	 * @param {Uint8Array[]} derivedKs
	 * @param {Uint8Array} tweak
	 * @param {Uint8Array} plaintext
	 */
	static bcEncrypt(ciphertext, derivedKs, tweak, plaintext) {
		let stks = newStks();
		deriveSubTweakKeys(stks, derivedKs, tweak);

		let q = aes.newQ(), stk = aes.newQ();
		aes.load4xU32(q, plaintext);
		aes.load4xU32(stk, stks[0]);
		aes.addRoundKey(q, stk);

		for (let i = 1; i <= rounds; i++) {
			aes.subBytes(q);
			aes.shiftRows(q);
			aes.mixColumns(q);

			aes.load4xU32(stk, stks[i]);
			aes.addRoundKey(q, stk);
		}

		aes.store4xU32(ciphertext, q);
	}

	/**
	 * @param {Uint8Array} ciphertext
	 * @param {Uint8Array[]} derivedKs
	 * @param {Uint8Array[]} tweaks
	 * @param {Uint8Array} nonce
	 */
	static bcKeystreamx2(ciphertext, derivedKs, tweaks, nonce) {
		let stks = [ newStks(), newStks() ];
		for (let i = 0; i < 2; i++) {
			deriveSubTweakKeys(stks[i], derivedKs, tweaks[i]);
		}

		let q = aes.newQ(), stk = aes.newQ();
		aes.rkeyOrtho(q, nonce);
		aes.load8xU32(stk, stks[0][0], stks[1][0]);
		aes.addRoundKey(q, stk);

		for (let i = 1; i <= rounds; i++) {
			aes.subBytes(q);
			aes.shiftRows(q);
			aes.mixColumns(q);

			aes.load8xU32(stk, stks[0][i], stks[1][i]);
			aes.addRoundKey(q, stk);
		}
		aes.store8xU32(ciphertext.subarray(0, 16), ciphertext.subarray(16, 32), q);
	}
	/**
	 * @param {Uint8Array} tag
	 * @param {Uint8Array[]} derivedKs
	 * @param {Uint8Array} tweak
	 * @param {Uint8Array} plaintext
	 */
	static bcTagx1(tag, derivedKs, tweak, plaintext) {
		let stks = newStks();
		deriveSubTweakKeys(stks, derivedKs, tweak);

		let q = aes.newQ(), stk = aes.newQ();
		aes.load4xU32(q, plaintext);
		aes.load4xU32(stk, stks[0]);
		aes.addRoundKey(q, stk);

		for (let i = 1; i <= rounds; i++) {
			aes.subBytes(q);
			aes.shiftRows(q);
			aes.mixColumns(q);

			aes.load4xU32(stk, stks[i]);
			aes.addRoundKey(q, stk);
		}

		const tagView = new DataView(tag.buffer);
		let tag0 = tagView.getUint32(0, true);
		let tag1 = tagView.getUint32(4, true);
		let tag2 = tagView.getUint32(8, true);
		let tag3 = tagView.getUint32(12, true);

		aes.ortho(q);
		tag0 = uint32.xor(tag0, q[0]);
		tag1 = uint32.xor(tag1, q[2]);
		tag2 = uint32.xor(tag2, q[4]);
		tag3 = uint32.xor(tag3, q[6]);

		tagView.setUint32(0, tag0, true);
		tagView.setUint32(4, tag1, true);
		tagView.setUint32(8, tag2, true);
		tagView.setUint32(12, tag3, true);
	}

	/**
	 * @param {Uint8Array} tag
	 * @param {Uint8Array[]} derivedKs
	 * @param {Uint8Array[]} tweaks
	 * @param {Uint8Array} plaintext
	 */
	static bcTagx2(tag, derivedKs, tweaks, plaintext) {
		let stks = [ newStks(), newStks() ];
		for (let i = 0; i < 2; i++) {
			deriveSubTweakKeys(stks[i], derivedKs, tweaks[i]);
		}

		let q = aes.newQ(), stk = aes.newQ();
		aes.load8xU32(q, plaintext.subarray(0, 16), plaintext.subarray(16, 32));
		aes.load8xU32(stk, stks[0][0], stks[1][0]);
		aes.addRoundKey(q, stk);

		for (let i = 1; i <= rounds; i++) {
			aes.subBytes(q);
			aes.shiftRows(q);
			aes.mixColumns(q);

			aes.load8xU32(stk, stks[0][i], stks[1][i]);
			aes.addRoundKey(q, stk);
		}

		const tagView = new DataView(tag.buffer);
		let tag0 = tagView.getUint32(0, true);
		let tag1 = tagView.getUint32(4, true);
		let tag2 = tagView.getUint32(8, true);
		let tag3 = tagView.getUint32(12, true);

		aes.ortho(q);
		tag0 = uint32.xor(tag0, q[0], q[1]);
		tag1 = uint32.xor(tag1, q[2], q[3]);
		tag2 = uint32.xor(tag2, q[4], q[5]);
		tag3 = uint32.xor(tag3, q[6], q[7]);

		tagView.setUint32(0, tag0, true);
		tagView.setUint32(4, tag1, true);
		tagView.setUint32(8, tag2, true);
		tagView.setUint32(12, tag3, true);
	}
}

class implUnsafeVartime {
	/**
	 * @param {Uint8Array} ciphertext
	 * @param {Uint8Array[]} derivedKs
	 * @param {Uint8Array} tweak
	 * @param {Uint8Array} plaintext
	 */
	static bcEncrypt(ciphertext, derivedKs, tweak, plaintext) {
		let stks = newStks();
		deriveSubTweakKeys(stks, derivedKs, tweak);

		const plainView = new DataView(plaintext.buffer);
		let s0 = plainView.getUint32(0 + plaintext.byteOffset, false);
		let s1 = plainView.getUint32(4 + plaintext.byteOffset, false);
		let s2 = plainView.getUint32(8 + plaintext.byteOffset, false);
		let s3 = plainView.getUint32(12 + plaintext.byteOffset, false);


		const stksView = new DataView(stks[0].buffer);
		s0 = uint32.xor(s0, stksView.getUint32(0 + stks[0].byteOffset, false));
		s1 = uint32.xor(s1, stksView.getUint32(4 + stks[0].byteOffset, false));
		s2 = uint32.xor(s2, stksView.getUint32(8 + stks[0].byteOffset, false));
		s3 = uint32.xor(s3, stksView.getUint32(12 + stks[0].byteOffset, false));

		for (let i = 1; i <= rounds; i++) {
			[s0, s1, s2, s3] = unsafe.aesencVartime(s0, s1, s2, s3, stks[i]);
		}

		const cipherView = new DataView(ciphertext.buffer);
		cipherView.setUint32(0 + ciphertext.byteOffset, s0, false);
		cipherView.setUint32(4 + ciphertext.byteOffset, s1, false);
		cipherView.setUint32(8 + ciphertext.byteOffset, s2, false);
		cipherView.setUint32(12 + ciphertext.byteOffset, s3, false);
	}
	/**
	 * @param {Uint8Array} ciphertext
	 * @param {Uint8Array[]} derivedKs
	 * @param {Uint8Array[]} tweaks
	 * @param {Uint8Array} nonce
	 */
	static bcKeystreamx2(ciphertext, derivedKs, tweaks, nonce) {
		this.bcEncrypt(ciphertext.subarray(0, 16), derivedKs, tweaks[0], nonce);
		this.bcEncrypt(ciphertext.subarray(16, 32), derivedKs, tweaks[1], nonce);
	}
	/**
	 * @param {Uint8Array} tag
	 * @param {Uint8Array[]} derivedKs
	 * @param {Uint8Array} tweak
	 * @param {Uint8Array} plaintext
	 */
	static bcTagx1(tag, derivedKs, tweak, plaintext) {
		let tmp = new Uint8Array(blockSize);
		this.bcEncrypt(tmp, derivedKs, tweak, plaintext);
		xorBytes(tag, tag, tmp, blockSize);
	}
	/**
 * @param {Uint8Array} tag
 * @param {Uint8Array[]} derivedKs
 * @param {Uint8Array[]} tweaks
 * @param {Uint8Array} plaintext
 */
	static bcTagx2(tag, derivedKs, tweaks, plaintext) {
		let tmp = new Uint8Array(2*blockSize);
		this.bcEncrypt(tmp.subarray(0, 16), derivedKs, tweaks[0], plaintext.subarray(0, 16));
		this.bcEncrypt(tmp.subarray(16, 32), derivedKs, tweaks[1], plaintext.subarray(16, 32));
		xorBytes(tag, tag, tmp.subarray(0, 16), blockSize);
		xorBytes(tag, tag, tmp.subarray(16, 32), blockSize);
	}
}

//
// Put it all together
//

/**
 * @param {Uint8Array} out
 * @param {number} prefix
 * @param {number} blockNr
 */
function encodeTagTweak(out, prefix, blockNr) {
	out.set(new Uint8Array(12));
	new DataView(out.buffer).setUint32(12 + out.byteOffset, blockNr, false);
	out[0] = prefix << prefixShift;
}

/**
 * @param {Uint8Array} out
 * @param {Uint8Array} tag
 * @param {number} blockNr
 */
function encodeEncTweak(out, tag, blockNr) {
	var tmp = new Uint8Array(4);
	new DataView(tmp.buffer).setUint32(0, blockNr, false);

	out.set(tag)
	out[0] |= 0x80;

	xorBytes(out.subarray(12, 16), out.subarray(12, 16), tmp, 4);
}

function newTweaks() {
	let tweaks = [];
	for (let i = 0; i < 2; i++) {
		tweaks.push(new Uint8Array(tweakSize));
	}
	return tweaks;
}

/**
 * @param {typeof implUnsafeVartime | typeof implCt32} impl
 * @param {Uint8Array[]} derivedKs
 * @param {Uint8Array} nonce
 * @param {Uint8Array} dst
 * @param {Uint8Array} ad
 * @param {Uint8Array} msg
 */
function e(impl, derivedKs, nonce, dst, ad, msg) {
	let tweaks = newTweaks();
	let i = 0, j = 0;

	// Associated data.
	let adLen = ad.length;
	let auth = new Uint8Array(TagSize);
	for (i = 0; adLen >= 2*blockSize; i += 2) {
		encodeTagTweak(tweaks[0], prefixADBlock, i);
		encodeTagTweak(tweaks[1], prefixADBlock, i+1);
		impl.bcTagx2(auth, derivedKs, tweaks, ad.subarray(i*blockSize, (i+2)*blockSize));

		adLen -= 2*blockSize;
	}
	for (; adLen >= blockSize; i++) {
		encodeTagTweak(tweaks[0], prefixADBlock, i)
		impl.bcTagx1(auth, derivedKs, tweaks[0], ad.subarray(i*blockSize, (i+1)*blockSize));

		adLen -= blockSize;
	}
	if (adLen > 0) {
		encodeTagTweak(tweaks[0], prefixADFinal, i);

		let aStar = new Uint8Array(blockSize);
		aStar.set(ad.subarray(ad.length - adLen));
		aStar[adLen] = 0x80;

		impl.bcTagx1(auth, derivedKs, tweaks[0], aStar);
	}

	// Message authentication and tag generation.
	let msgLen = msg.length;
	for (j = 0; msgLen >= 2*blockSize; j += 2) {
		encodeTagTweak(tweaks[0], prefixMsgBlock, j);
		encodeTagTweak(tweaks[1], prefixMsgBlock, j+1);
		impl.bcTagx2(auth, derivedKs, tweaks, msg.subarray(j*blockSize, (j+2)*blockSize));

		msgLen -= 2*blockSize;
	}
	for (; msgLen >= blockSize; j++) {
		encodeTagTweak(tweaks[0], prefixMsgBlock, j);
		impl.bcTagx1(auth, derivedKs, tweaks[0], msg.subarray(j*blockSize, (j+1)*blockSize));

		msgLen -= blockSize;
	}
	if (msgLen > 0) {
		encodeTagTweak(tweaks[0], prefixMsgFinal, j);

		let mStar = new Uint8Array(blockSize);
		mStar.set(msg.subarray(msg.length - msgLen));
		mStar[msgLen] = 0x80;

		impl.bcTagx1(auth, derivedKs, tweaks[0], mStar);
	}

	// Generate the tag.
	let encNonce = new Uint8Array(blockSize);
	encNonce.set(nonce, 1);
	encNonce[0] = prefixTag << prefixShift;
	impl.bcEncrypt(auth, derivedKs, encNonce, auth);

	// Message encryption.
	encNonce[0] = 0;
	msgLen = msg.length;
	let encBlks = new Uint8Array(2*blockSize);
	for (j = 0; msgLen >= 2*blockSize; j += 2) {
		encodeEncTweak(tweaks[0], auth, j);
		encodeEncTweak(tweaks[1], auth, j+1);

		impl.bcKeystreamx2(encBlks, derivedKs, tweaks, encNonce);
		xorBytes(dst.subarray(j*blockSize, (j+2)*blockSize), msg.subarray(j*blockSize, (j+2)*blockSize), encBlks, 2*blockSize);

		msgLen -= 2*blockSize;
	}
	for (; msgLen >= blockSize; j++) {
		encodeEncTweak(tweaks[0], auth, j);
		impl.bcEncrypt(encBlks, derivedKs, tweaks[0], encNonce);
		xorBytes(dst.subarray(j*blockSize, (j+1)*blockSize), msg.subarray(j*blockSize, (j+1)*blockSize), encBlks, blockSize);

		msgLen -= blockSize;
	}
	if (msgLen > 0) {
		encodeEncTweak(tweaks[0], auth, j);

		impl.bcEncrypt(encBlks, derivedKs, tweaks[0], encNonce);
		xorBytes(dst.subarray(j*blockSize, msg.length), msg.subarray(j*blockSize), encBlks, msgLen);
	}

	// Write the tag to the tail.
	dst.set(auth, msg.length);
}

/**
 * @param {typeof implUnsafeVartime | typeof implCt32} impl
 * @param {Uint8Array[]} derivedKs
 * @param {Uint8Array} nonce
 * @param {Uint8Array} dst
 * @param {Uint8Array} ad
 * @param {Uint8Array} ct
 */
function d(impl, derivedKs, nonce, dst, ad, ct) {
	let ctLen = ct.length - TagSize;
	const ciphertext = ct.subarray(0, ctLen);
	const tag = ct.subarray(ctLen);

	// Message decryption.
	let j = 0;
	let decTweaks = newTweaks();
	let decNonce = new Uint8Array(blockSize);
	decNonce.set(nonce, 1);
	let decBlks = new Uint8Array(2*blockSize);
	for (j = 0; ctLen >= 2*blockSize; j+=2) {
		encodeEncTweak(decTweaks[0], tag, j);
		encodeEncTweak(decTweaks[1], tag, j+1);

		impl.bcKeystreamx2(decBlks, derivedKs, decTweaks, decNonce);
		xorBytes(dst.subarray(j*blockSize, (j+2)*blockSize), ciphertext.subarray(j*blockSize, (j+2)*blockSize), decBlks, 2*blockSize);

		ctLen -= 2*blockSize;
	}
	for (; ctLen >= blockSize; j++) {
		encodeEncTweak(decTweaks[0], tag, j);

		impl.bcEncrypt(decBlks, derivedKs, decTweaks[0], decNonce);
		xorBytes(dst.subarray(j*blockSize, (j+1)*blockSize), ciphertext.subarray(j*blockSize, (j+1)*blockSize), decBlks, blockSize);

		ctLen -= blockSize;
	}
	if (ctLen > 0) {
		encodeEncTweak(decTweaks[0], tag, j);

		impl.bcEncrypt(decBlks, derivedKs, decTweaks[0], decNonce);
		xorBytes(dst.subarray(j*blockSize), ciphertext.subarray(j*blockSize), decBlks, ctLen);
	}

	// Associated data.
	let i = 0;
	let adLen = ad.length;
	let tweaks = newTweaks();
	let auth = new Uint8Array(TagSize);
	for (i = 0; adLen >= 2*blockSize; i += 2) {
		encodeTagTweak(tweaks[0], prefixADBlock, i);
		encodeTagTweak(tweaks[1], prefixADBlock, i+1);
		impl.bcTagx2(auth, derivedKs, tweaks, ad.subarray(i*blockSize, (i+2)*blockSize));

		adLen -= 2*blockSize;
	}
	for (; adLen >= blockSize; i++) {
		encodeTagTweak(tweaks[0], prefixADBlock, i)
		impl.bcTagx1(auth, derivedKs, tweaks[0], ad.subarray(i*blockSize, (i+1)*blockSize));

		adLen -= blockSize;
	}
	if (adLen > 0) {
		encodeTagTweak(tweaks[0], prefixADFinal, i);

		let aStar = new Uint8Array(blockSize);

		aStar.set(ad.subarray(ad.length - adLen));
		aStar[adLen] = 0x80;

		impl.bcTagx1(auth, derivedKs, tweaks[0], aStar);
	}

	// Message authentication and tag generation.
	let msgLen = dst.length;
	for (j = 0; msgLen >= 2*blockSize; j += 2) {
		encodeTagTweak(tweaks[0], prefixMsgBlock, j);
		encodeTagTweak(tweaks[1], prefixMsgBlock, j+1);
		impl.bcTagx2(auth, derivedKs, tweaks, dst.subarray(j*blockSize, (j+2)*blockSize));

		msgLen -= 2*blockSize;
	}
	for (; msgLen >= blockSize; j++) {
		encodeTagTweak(tweaks[0], prefixMsgBlock, j);
		impl.bcTagx1(auth, derivedKs, tweaks[0], dst.subarray(j*blockSize, (j+1)*blockSize));

		msgLen -= blockSize;
	}
	if (msgLen > 0) {
		encodeTagTweak(tweaks[0], prefixMsgFinal, j);

		let mStar = new Uint8Array(blockSize);
		mStar.set(dst.subarray(dst.length - msgLen));
		mStar[msgLen] = 0x80;

		impl.bcTagx1(auth, derivedKs, tweaks[0], mStar);
	}

	decNonce[0] = prefixTag << prefixShift;
	impl.bcEncrypt(auth, derivedKs, decNonce, auth);

	// crypto.timingSafeEqual is not implemented on typed arrays.
	if (auth.length != tag.length) {
		return false;
	}
	let eql = true;
	for (i = 0; i < auth.length; i++) {
		// @ts-expect-error TODO: should this return a boolean
		eql &= !(auth[i] ^ tag[i]);
	}

	return eql;
}

// The AEAD implementation.
//
// As much as possible (as long as the key does not change), instances should
// be reused as deriving the K contribution of the Sub-Tweak Key is relatively
// expensive.
class AEAD {
	/**
	 * @param {Uint8Array} key
	 * @param {boolean} useUnsafeVartime
	 */
	constructor(key, useUnsafeVartime = false) {
		if (key.length != KeySize) {
			throw ErrKeySize;
		}

		/** @type {typeof implUnsafeVartime | typeof implCt32} */
		this.impl = useUnsafeVartime ? implUnsafeVartime : implCt32
		this.derivedKs = newStks();
		stkDeriveK(key, this.derivedKs);
	}

	/**
	 * @param {Uint8Array} nonce
	 * @param {Uint8Array | null} plaintext
	 * @param {Uint8Array | null} associatedData
	 */
	encrypt(nonce, plaintext = null, associatedData = null) {
		if (nonce.length != NonceSize) {
			throw ErrNonceSize;
		}

		if (plaintext == null) {
			plaintext = zeroBuffer;
		}
		if (associatedData == null) {
			associatedData = zeroBuffer;
		}

		let dst = new Uint8Array(plaintext.length + TagSize);
		e(this.impl, this.derivedKs, nonce, dst, associatedData, plaintext);

		return dst;
	}

	/**
	 * @param {Uint8Array} nonce
	 * @param {Uint8Array} ciphertext
	 * @param {Uint8Array | null} associatedData
	 */
	decrypt(nonce, ciphertext, associatedData = null) {
		if (nonce.length != NonceSize) {
			throw ErrNonceSize;
		}
		if (ciphertext.length < TagSize) {
			throw ErrOpen;
		}

		if (associatedData == null) {
			associatedData = zeroBuffer;
		}

		let dst = new Uint8Array(ciphertext.length - TagSize);
		if (!d(this.impl, this.derivedKs, nonce, dst, associatedData, ciphertext)) {
			dst.set(new Uint8Array(dst.length));
			throw ErrOpen;
		}

		return dst;
	}
}

const zeroBuffer = new Uint8Array(0);

const ErrKeySize = 'deoxysii: invalid key size';
const ErrNonceSize = 'deoxysii: invalid nonce size';
const ErrOpen = 'deoxysii: message authentication failure'

module.exports = {
	KeySize: KeySize,
	NonceSize: NonceSize,
	TagSize: TagSize,

	ErrNonceSize: ErrNonceSize,
	ErrKeySize: ErrKeySize,
	ErrOpen: ErrOpen,

	AEAD: AEAD,
}
