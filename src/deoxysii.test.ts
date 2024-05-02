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

import { expect, test } from "vitest";
import {
	AEAD,
	ErrKeySize,
	ErrNonceSize,
	ErrOpen,
	NonceSize,
	TagSize,
} from "./index";

test("should throw on invalid key size", () => {
	expect(() => {
		new AEAD(new Uint8Array(10));
	}).toThrow(ErrKeySize);
});

test("ct32: should match unofficial test vectors", () => {
	const vectors = require("../test/Deoxys-II-256-128.json");

	const key = new Uint8Array(Buffer.from(vectors.Key, "base64"));
	const nonce = new Uint8Array(Buffer.from(vectors.Nonce, "base64"));
	const aad = new Uint8Array(Buffer.from(vectors.AADData, "base64"));
	const msg = new Uint8Array(Buffer.from(vectors.MsgData, "base64"));

	const aead = new AEAD(key);

	for (let i = 0; i < vectors.KnownAnswers.length; i++) {
		const vector = vectors.KnownAnswers[i];

		const m = msg.subarray(0, vector.Length);
		const a = aad.subarray(0, vector.Length);

		const ciphertext = aead.encrypt(nonce, m, a);

		const vecCt = new Uint8Array(Buffer.from(vector.Ciphertext, "base64"));
		const vecTag = new Uint8Array(Buffer.from(vector.Tag, "base64"));

		const expectedCipher = new Uint8Array(vecCt.length + vecTag.length);
		expectedCipher.set(vecCt, 0);
		expectedCipher.set(vecTag, vecCt.length);
		expect(ciphertext, `Ciphertext + Tag: ${i}`).toStrictEqual(expectedCipher);

		const plaintext = aead.decrypt(nonce, ciphertext, a);
		expect(plaintext, `Plaintext: ${i}`).toStrictEqual(m);

		// Test malformed ciphertext.
		const badC = new Uint8Array(ciphertext);
		badC[i] ^= 0x23;
		expect(() => {
			aead.decrypt(nonce, badC, a);
		}).toThrow(ErrOpen);

		// Test malformed AD.
		if (i === 0) continue;

		const badA = new Uint8Array(a);
		badA[i - 1] ^= 0x23;
		expect(() => {
			aead.decrypt(nonce, ciphertext, badA);
		}).toThrow(ErrOpen);
	}
}, 5000);

test("ct32: should match official test vectors", () => {
	const vectors = require("../test/TestVectors.json");

	for (let i = 0; i < vectors.length; i++) {
		const vector = vectors[i];

		const key = new Uint8Array(Buffer.from(vector.Key, "hex"));
		const nonce = new Uint8Array(Buffer.from(vector.Nonce, "hex"));
		const sealed = new Uint8Array(Buffer.from(vector.Sealed, "hex"));
		const associatedData =
			vector.AssociatedData != null
				? new Uint8Array(Buffer.from(vector.AssociatedData, "hex"))
				: null;
		const message =
			vector.Message != null
				? new Uint8Array(Buffer.from(vector.Message, "hex"))
				: null;

		const aead = new AEAD(key);

		const ciphertext = aead.encrypt(nonce, message, associatedData);
		expect(ciphertext, `Ciphertext: ${vector.Name}`).toStrictEqual(sealed);
	}
});

test("parameter semantics", () => {
	const vectors = require("../test/Deoxys-II-256-128.json");

	const key = new Uint8Array(Buffer.from(vectors.Key, "base64"));
	const nonce = new Uint8Array(Buffer.from(vectors.Nonce, "base64"));
	const aad = new Uint8Array(Buffer.from(vectors.AADData, "base64"));
	const msg = new Uint8Array(Buffer.from(vectors.MsgData, "base64"));

	const aead = new AEAD(key);

	// encrypt with wrong nonce length
	expect(() => aead.encrypt(nonce)).not.toThrow();
	expect(() => aead.encrypt(nonce.subarray(0, NonceSize - 1))).toThrow(
		ErrNonceSize,
	);

	// decrypt with wrong nonce length
	const ciphertext = aead.encrypt(nonce, msg, aad);
	expect(() =>
		aead.decrypt(nonce.subarray(0, NonceSize - 1), ciphertext, aad),
	).toThrow(ErrNonceSize);
	expect(aead.decrypt(nonce, ciphertext, aad)).toStrictEqual(msg);

	// more variations of decrypt
	expect(() => aead.decrypt(nonce, ciphertext, aad)).not.toThrow();
	expect(() =>
		aead.decrypt(nonce, ciphertext.subarray(0, TagSize), aad),
	).toThrow(ErrOpen);
	expect(() =>
		aead.decrypt(nonce, ciphertext.subarray(0, TagSize - 1), aad),
	).toThrow(ErrOpen);
	expect(() => aead.decrypt(nonce, ciphertext)).toThrow(ErrOpen);
	expect(() =>
		aead.decrypt(nonce.subarray(0, NonceSize - 1), ciphertext, aad),
	).toThrow(ErrNonceSize);
});
