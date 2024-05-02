// Copyright (c) 2016 Thomas Pornin <pornin@bolet.org>
// Copyright (c) 2017 Yawning Angel <yawning at schwanenlied dot me>
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

var uint32 = require('uint32');

const rcon = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36];
const oddsMask = uint32.fromBytesBigEndian(0x55, 0x55, 0x55, 0x55);
const evensMask = uint32.fromBytesBigEndian(0xaa, 0xaa, 0xaa, 0xaa);
const cl4 = uint32.fromBytesBigEndian(0x33, 0x33, 0x33, 0x33);
const ch4 = uint32.fromBytesBigEndian(0xcc, 0xcc, 0xcc, 0xcc);
const cl8 = uint32.fromBytesBigEndian(0x0f, 0x0f, 0x0f, 0x0f);
const ch8 = uint32.fromBytesBigEndian(0xf0, 0xf0, 0xf0, 0xf0);

const shiftRowsMask0 = uint32.fromBytesBigEndian(0x00, 0x00, 0x00, 0xff);
const shiftRowsMask1 = uint32.fromBytesBigEndian(0x00, 0x00, 0xfc, 0x00);
const shiftRowsMask2 = uint32.fromBytesBigEndian(0x00, 0x00, 0x03, 0x00);
const shiftRowsMask3 = uint32.fromBytesBigEndian(0x00, 0xf0, 0x00, 0x00);
const shiftRowsMask4 = uint32.fromBytesBigEndian(0x00, 0x0f, 0x00, 0x00);
const shiftRowsMask5 = uint32.fromBytesBigEndian(0xc0, 0x00, 0x00, 0x00);
const shiftRowsMask6 = uint32.fromBytesBigEndian(0x3f, 0x00, 0x00, 0x00);

function newQ() {
	return new Uint32Array(8); // q
}

// AddRoundKey
function addRoundKey(q, sk) {
	q[0] = uint32.xor(q[0], sk[0])
	q[1] = uint32.xor(q[1], sk[1])
	q[2] = uint32.xor(q[2], sk[2])
	q[3] = uint32.xor(q[3], sk[3])
	q[4] = uint32.xor(q[4], sk[4])
	q[5] = uint32.xor(q[5], sk[5])
	q[6] = uint32.xor(q[6], sk[6])
	q[7] = uint32.xor(q[7], sk[7])
}

// SubBytes
function subBytes(q) {
	// This S-box implementation is a straightforward translation of
	// the circuit described by Boyar and Peralta in "A new
	// combinational logic minimization technique with applications
	// to cryptology" (https://eprint.iacr.org/2009/191.pdf).
	//
	// Note that variables x* (input) and s* (output) are numbered
	// in "reverse" order (x0 is the high bit, x7 is the low bit).

	const x0 = q[7];
	const x1 = q[6];
	const x2 = q[5];
	const x3 = q[4];
	const x4 = q[3];
	const x5 = q[2];
	const x6 = q[1];
	const x7 = q[0];

	//
	// Top linear transformation.
	//
	const y14 = uint32.xor(x3, x5);
	const y13 = uint32.xor(x0, x6);
	const y9 = uint32.xor(x0, x3);
	const y8 = uint32.xor(x0, x5);
	const t0 = uint32.xor(x1, x2);
	const y1 = uint32.xor(t0, x7);
	const y4 = uint32.xor(y1, x3);
	const y12 = uint32.xor(y13, y14);
	const y2 = uint32.xor(y1, x0);
	const y5 = uint32.xor(y1, x6);
	const y3 = uint32.xor(y5, y8);
	const t1 = uint32.xor(x4, y12);
	const y15 = uint32.xor(t1, x5);
	const y20 = uint32.xor(t1, x1);
	const y6 = uint32.xor(y15, x7);
	const y10 = uint32.xor(y15, t0);
	const y11 = uint32.xor(y20, y9);
	const y7 = uint32.xor(x7, y11);
	const y17 = uint32.xor(y10, y11);
	const y19 = uint32.xor(y10, y8);
	const y16 = uint32.xor(t0, y11);
	const y21 = uint32.xor(y13, y16);
	const y18 = uint32.xor(x0, y16);

	//
	// Non-linear section.
	//
	const t2 = uint32.and(y12, y15);
	const t3 = uint32.and(y3, y6);
	const t4 = uint32.xor(t3, t2);
	const t5 = uint32.and(y4, x7);
	const t6 = uint32.xor(t5, t2);
	const t7 = uint32.and(y13, y16);
	const t8 = uint32.and(y5, y1);
	const t9 = uint32.xor(t8, t7);
	const t10 = uint32.and(y2, y7);
	const t11 = uint32.xor(t10, t7);
	const t12 = uint32.and(y9, y11);
	const t13 = uint32.and(y14, y17);
	const t14 = uint32.xor(t13, t12);
	const t15 = uint32.and(y8, y10);
	const t16 = uint32.xor(t15, t12);
	const t17 = uint32.xor(t4, t14);
	const t18 = uint32.xor(t6, t16);
	const t19 = uint32.xor(t9, t14);
	const t20 = uint32.xor(t11, t16);
	const t21 = uint32.xor(t17, y20);
	const t22 = uint32.xor(t18, y19);
	const t23 = uint32.xor(t19, y21);
	const t24 = uint32.xor(t20, y18);

	const t25 = uint32.xor(t21, t22);
	const t26 = uint32.and(t21, t23);
	const t27 = uint32.xor(t24, t26);
	const t28 = uint32.and(t25, t27);
	const t29 = uint32.xor(t28, t22);
	const t30 = uint32.xor(t23, t24);
	const t31 = uint32.xor(t22, t26);
	const t32 = uint32.and(t31, t30);
	const t33 = uint32.xor(t32, t24);
	const t34 = uint32.xor(t23, t33);
	const t35 = uint32.xor(t27, t33);
	const t36 = uint32.and(t24, t35);
	const t37 = uint32.xor(t36, t34);
	const t38 = uint32.xor(t27, t36);
	const t39 = uint32.and(t29, t38);
	const t40 = uint32.xor(t25, t39);

	const t41 = uint32.xor(t40, t37);
	const t42 = uint32.xor(t29, t33);
	const t43 = uint32.xor(t29, t40);
	const t44 = uint32.xor(t33, t37);
	const t45 = uint32.xor(t42, t41);
	const z0 = uint32.and(t44, y15);
	const z1 = uint32.and(t37, y6);
	const z2 = uint32.and(t33, x7);
	const z3 = uint32.and(t43, y16);
	const z4 = uint32.and(t40, y1);
	const z5 = uint32.and(t29, y7);
	const z6 = uint32.and(t42, y11);
	const z7 = uint32.and(t45, y17);
	const z8 = uint32.and(t41, y10);
	const z9 = uint32.and(t44, y12);
	const z10 = uint32.and(t37, y3);
	const z11 = uint32.and(t33, y4);
	const z12 = uint32.and(t43, y13);
	const z13 = uint32.and(t40, y5);
	const z14 = uint32.and(t29, y2);
	const z15 = uint32.and(t42, y9);
	const z16 = uint32.and(t45, y14);
	const z17 = uint32.and(t41, y8);

	//
	// Bottom linear transformation.
	//
	const t46 = uint32.xor(z15, z16);
	const t47 = uint32.xor(z10, z11);
	const t48 = uint32.xor(z5, z13);
	const t49 = uint32.xor(z9, z10);
	const t50 = uint32.xor(z2, z12);
	const t51 = uint32.xor(z2, z5);
	const t52 = uint32.xor(z7, z8);
	const t53 = uint32.xor(z0, z3);
	const t54 = uint32.xor(z6, z7);
	const t55 = uint32.xor(z16, z17);
	const t56 = uint32.xor(z12, t48);
	const t57 = uint32.xor(t50, t53);
	const t58 = uint32.xor(z4, t46);
	const t59 = uint32.xor(z3, t54);
	const t60 = uint32.xor(t46, t57);
	const t61 = uint32.xor(z14, t57);
	const t62 = uint32.xor(t52, t58);
	const t63 = uint32.xor(t49, t58);
	const t64 = uint32.xor(z4, t59);
	const t65 = uint32.xor(t61, t62);
	const t66 = uint32.xor(z1, t63);
	const s0 = uint32.xor(t59, t63);
	const s6 = uint32.xor(t56, uint32.not(t62));
	const s7 = uint32.xor(t48, uint32.not(t60));
	const t67 = uint32.xor(t64, t65);
	const s3 = uint32.xor(t53, t66);
	const s4 = uint32.xor(t51, t66);
	const s5 = uint32.xor(t47, t65);
	const s1 = uint32.xor(t64, uint32.not(s3));
	const s2 = uint32.xor(t55, uint32.not(t67));

	q[7] = s0;
	q[6] = s1;
	q[5] = s2;
	q[4] = s3;
	q[3] = s4;
	q[2] = s5;
	q[1] = s6;
	q[0] = s7;
}

// ShiftRows
function shiftRows(q) {
	for (let i = 0; i < 8; i++) {
		const x = q[i];

		q[i] = uint32.or(
			uint32.and(x, shiftRowsMask0),
			uint32.shiftRight(uint32.and(x, shiftRowsMask1), 2),
			uint32.shiftLeft(uint32.and(x, shiftRowsMask2), 6),
			uint32.shiftRight(uint32.and(x, shiftRowsMask3), 4),
			uint32.shiftLeft(uint32.and(x, shiftRowsMask4), 4),
			uint32.shiftRight(uint32.and(x, shiftRowsMask5), 6),
			uint32.shiftLeft(uint32.and(x, shiftRowsMask6), 2)
		);
	}
}

// MixColumns
function mixColumns(q) {
	const q0 = q[0];
	const q1 = q[1];
	const q2 = q[2];
	const q3 = q[3];
	const q4 = q[4];
	const q5 = q[5];
	const q6 = q[6];
	const q7 = q[7];

	const r0 = uint32.or(uint32.shiftRight(q0, 8), uint32.shiftLeft(q0, 24));
	const r1 = uint32.or(uint32.shiftRight(q1, 8), uint32.shiftLeft(q1, 24));
	const r2 = uint32.or(uint32.shiftRight(q2, 8), uint32.shiftLeft(q2, 24));
	const r3 = uint32.or(uint32.shiftRight(q3, 8), uint32.shiftLeft(q3, 24));
	const r4 = uint32.or(uint32.shiftRight(q4, 8), uint32.shiftLeft(q4, 24));
	const r5 = uint32.or(uint32.shiftRight(q5, 8), uint32.shiftLeft(q5, 24));
	const r6 = uint32.or(uint32.shiftRight(q6, 8), uint32.shiftLeft(q6, 24));
	const r7 = uint32.or(uint32.shiftRight(q7, 8), uint32.shiftLeft(q7, 24));

	q[0] = uint32.xor(q7, r7, r0, uint32.rotateRight(uint32.xor(q0, r0), 16));
	q[1] = uint32.xor(q0, r0, q7, r7, r1, uint32.rotateRight(uint32.xor(q1, r1), 16));
	q[2] = uint32.xor(q1, r1, r2, uint32.rotateRight(uint32.xor(q2, r2), 16));
	q[3] = uint32.xor(q2, r2, q7, r7, r3, uint32.rotateRight(uint32.xor(q3, r3), 16));
	q[4] = uint32.xor(q3, r3, q7, r7, r4, uint32.rotateRight(uint32.xor(q4, r4), 16));
	q[5] = uint32.xor(q4, r4, r5, uint32.rotateRight(uint32.xor(q5, r5), 16));
	q[6] = uint32.xor(q5, r5, r6, uint32.rotateRight(uint32.xor(q6, r6), 16));
	q[7] = uint32.xor(q6, r6, r7, uint32.rotateRight(uint32.xor(q7, r7), 16));
}

function load4xU32(q, src) {
	const srcView = new DataView(src.buffer);
	q[0] = srcView.getUint32(0 + src.byteOffset, true);
	q[2] = srcView.getUint32(4 + src.byteOffset, true);
	q[4] = srcView.getUint32(8 + src.byteOffset, true);
	q[6] = srcView.getUint32(12 + src.byteOffset, true);
	q[1] = 0;
	q[3] = 0;
	q[5] = 0;
	q[7] = 0;
	ortho(q)
}

function load8xU32(q, src0, src1) {
	const src0View = new DataView(src0.buffer);
	const src1View = new DataView(src1.buffer);
	q[0] = src0View.getUint32(0 + src0.byteOffset, true);
	q[2] = src0View.getUint32(4 + src0.byteOffset, true);
	q[4] = src0View.getUint32(8 + src0.byteOffset, true);
	q[6] = src0View.getUint32(12 + src0.byteOffset, true);
	q[1] = src1View.getUint32(0 + src1.byteOffset, true);
	q[3] = src1View.getUint32(4 + src1.byteOffset, true);
	q[5] = src1View.getUint32(8 + src1.byteOffset, true);
	q[7] = src1View.getUint32(12 + src1.byteOffset, true);
	ortho(q)
}

function store4xU32(dst, q) {
	ortho(q);
	const dstView = new DataView(dst.buffer);
	dstView.setUint32(0 + dst.byteOffset, q[0], true);
	dstView.setUint32(4 + dst.byteOffset, q[2], true);
	dstView.setUint32(8 + dst.byteOffset, q[4], true);
	dstView.setUint32(12 + dst.byteOffset, q[6], true);
}

function store8xU32(dst0, dst1, q) {
	ortho(q);
	const dst0View = new DataView(dst0.buffer);
	const dst1View = new DataView(dst1.buffer);
	dst0View.setUint32(0 + dst0.byteOffset, q[0], true);
	dst0View.setUint32(4 + dst0.byteOffset, q[2], true);
	dst0View.setUint32(8 + dst0.byteOffset, q[4], true);
	dst0View.setUint32(12 + dst0.byteOffset, q[6], true);
	dst1View.setUint32(0 + dst1.byteOffset, q[1], true);
	dst1View.setUint32(4 + dst1.byteOffset, q[3], true);
	dst1View.setUint32(8 + dst1.byteOffset, q[5], true);
	dst1View.setUint32(12 + dst1.byteOffset, q[7], true);
}

function ortho(q) {
	for (let i = 0; i < 8; i += 2) {
		const q0 = q[i];
		const q1 = q[i+1];

		q[i] = uint32.or(uint32.and(q0, oddsMask), uint32.shiftLeft(uint32.and(q1, oddsMask), 1));
		q[i+1] = uint32.or(uint32.shiftRight(uint32.and(q0, evensMask), 1), uint32.and(q1, evensMask));
	}

	for (let i = 0; i < 8; i += 4) {
		const q0 = q[i]
		const q1 = q[i+1];
		const q2 = q[i+2];
		const q3 = q[i+3];

		q[i] = uint32.or(uint32.and(q0, cl4), uint32.shiftLeft(uint32.and(q2, cl4), 2));
		q[i+2] = uint32.or(uint32.shiftRight(uint32.and(q0, ch4), 2), uint32.and(q2, ch4));
		q[i+1] = uint32.or(uint32.and(q1, cl4), uint32.shiftLeft(uint32.and(q3, cl4), 2));
		q[i+3] = uint32.or(uint32.shiftRight(uint32.and(q1, ch4), 2), uint32.and(q3, ch4));
	}

	for (let i = 0; i < 4; i++) {
		const q0 = q[i];
		const q4 = q[i+4];

		q[i] = uint32.or(uint32.and(q0, cl8), uint32.shiftLeft(uint32.and(q4, cl8), 4));
		q[i+4] = uint32.or(uint32.shiftRight(uint32.and(q0, ch8), 4), uint32.and(q4, ch8));
	}
}

function rkeyOrtho(q, key) {
	const keyView = new DataView(key.buffer);
	for (let i = 0; i < 4; i++) {
		const x = keyView.getUint32(i*4 + key.byteOffset, true);
		q[i*2] = x;
		q[i*2+1] = x;
	}
	ortho(q);

	for (let i = 0, j = 0; i < 4; i = i + 1, j = j + 2) {
		let x = uint32.or(uint32.and(q[j+0], oddsMask), uint32.and(q[j+1], evensMask))
		let y = x;

		x = uint32.and(x, oddsMask);
		q[j] = uint32.or(x, uint32.shiftLeft(x, 1));
		y = uint32.and(y, evensMask);
		q[j+1] = uint32.or(y, uint32.shiftRight(y, 1));
	}
}

function skeyExpand(skey, numRounds, compSkey) {
	const n = (numRounds + 1) * 4;

	for (let u = 0, v = 0; u < n; u = u + 1, v = v + 2) {
		let x = compSkey[u];
		let y = compSkey[u];

		x = uint32.and(x, oddsMask);
		skey[v] = uint32.or(x, uint32.shiftLeft(x, 1));
		y = uint32.and(y, evensMask);
		skey[v+1] = uint32.or(y, uint32.shiftRight(y, 1));
	}
}

//
// ECB-AES (example/testing), and associated package private helpers.
//

function _subWord(x) {
	let q = new	Uint32Array([x, x, x, x, x, x, x, x]);
	ortho(q);
	subBytes(q);
	ortho(q);
	return q[0];
}

function keySched(compSkey, key) {
	let numRounds = 0;
	const keyLen = key.byteLength;
	switch (keyLen) {
	case 16:
		numRounds = 10;
		break;
	case 24:
		numRounds = 12;
		break;
	case 32:
		numRounds = 14;
		break;
	default:
		throw 'aes: invalid key length';
	}

	let skey = new Uint32Array(120);
	let tmp = 0;
	const nk = keyLen / 4;
	const nkf = (numRounds + 1) * 4;
	const keyView = new DataView(key.buffer);
	for (let i = 0; i < nk; i++) {
		tmp = keyView.getUint32(i*4 + key.byteOffset, true);
		skey[i*2] = tmp;
		skey[i*2+1] = tmp;
	}
	for (let i = nk, j = 0, k = 0; i < nkf; i++) {
		if (j == 0) {
			tmp = uint32.or(uint32.shiftLeft(tmp, 24), uint32.shiftRight(tmp, 8));
			tmp = uint32.xor(_subWord(tmp), uint32.fromBytesBigEndian(0x00, 0x00, 0x00, rcon[k]));
		} else if (nk > 6 && j == 4) {
			tmp = _subWord(tmp);
		}
		tmp = uint32.xor(tmp, skey[(i-nk)*2]);
		skey[i*2] = tmp;
		skey[i*2+1] = tmp;
		j++;
		if (j == nk) {
			j = 0;
			k++;
		}
	}
	for (let i = 0; i < nkf; i += 4) {
		let stmp = skey.slice(i*2, i*2+8);
		ortho(stmp);
		for (let j = 0; j < 8; j++) {
			skey[i*2+j] = stmp[j];
		}
	}
	for (let i = 0, j = 0; i < nkf; i = i + 1, j = j + 2) {
		compSkey[i] = uint32.or(uint32.and(skey[j], oddsMask), uint32.and(skey[j+1], evensMask));
	}
	return numRounds;
}

function _encrypt(numRounds, skey, q) {
	addRoundKey(q, skey);
	for (let u = 1; u < numRounds; u++) {
		subBytes(q);
		shiftRows(q);
		mixColumns(q);
		addRoundKey(q, skey.slice(u*8, u*8+8));
	}
	subBytes(q);
	shiftRows(q);
	addRoundKey(q, skey.slice(numRounds*8, numRounds*8+8));
}

class ECB {
	constructor(key) {
		let skey = new Uint32Array(60);

		this.numRounds = keySched(skey, key);
		this.skeyExpanded = new Uint32Array(120);
		skeyExpand(this.skeyExpanded, this.numRounds, skey);
	}

	encrypt(dst, src) {
		let q = newQ();

		load4xU32(q, src);
		_encrypt(this.numRounds, this.skeyExpanded, q);
		store4xU32(dst, q);
	}

	encrypt2x(dst0, dst1, src0, src1) {
		let q = newQ();

		load8xU32(q, src0, src1);
		_encrypt(this.numRounds, this.skeyExpanded, q);
		store8xU32(dst0, dst1, q);
	}
}

module.exports = {
	// ECB-AES, probably shouldn't be used for more than testing.
	ECB: ECB,

	// Implementation internals, exposed for the purpose of constructing
	// things based on the AES round function.
	newQ,
	load4xU32,
	load8xU32,
	store4xU32,
	store8xU32,
	ortho,
	rkeyOrtho,
	addRoundKey,
	subBytes,
	shiftRows,
	mixColumns,

	skeyExpand,
	keySched,
};
