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

/* globals describe,it */
var assert = require('chai').assert;
var deoxysii = require('../deoxysii');

function testVectorsUnofficial(useUnsafeVartime) {
	const vectors = require('./Deoxys-II-256-128.json');

	let key = Buffer.from(vectors.Key, 'base64');
	let nonce = Buffer.from(vectors.Nonce, 'base64');
	let aad = Buffer.from(vectors.AADData, 'base64');
	let msg = Buffer.from(vectors.MsgData, 'base64');

	let aead = new deoxysii.AEAD(key, useUnsafeVartime);

	for (let i = 0; i < vectors.KnownAnswers.length; i++) {
		const vector = vectors.KnownAnswers[i];

		const m = msg.slice(0, vector.Length);
		const a = aad.slice(0, vector.Length);

		let ciphertext = aead.encrypt(nonce, m, a);

		const vecCt = Buffer.from(vector.Ciphertext, 'base64');
		const vecTag = Buffer.from(vector.Tag, 'base64');

		assert.deepEqual(ciphertext, Buffer.concat([vecCt, vecTag]), 'Ciphertext + Tag: ' + i);

		let plaintext = aead.decrypt(nonce, ciphertext, a);
		assert.deepEqual(plaintext, m, 'Plaintext: ' + i);

		// Test malformed ciphertext.
		let badC = Buffer.from(ciphertext);
		badC[i] ^= 0x23;
		assert.throws(function() {
			let foo = aead.decrypt(nonce, badC, a); // eslint-disable-line no-unused-vars
		}, deoxysii.ErrOpen);

		// Test malformed AD.
		if (i == 0)
			continue;

		let badA = Buffer.from(a);
		badA[i-1] ^= 0x23;
		assert.throws(function() {
			let foo = aead.decrypt(nonce, ciphertext, badA); // eslint-disable-line no-unused-vars
		}, deoxysii.ErrOpen);
	}
}

function testVectorsOfficial(useUnsafeVartime) {
	const vectors = require('./TestVectors.json');

	for (let i = 0; i < vectors.length; i++) {
		const vector = vectors[i];

		let key = Buffer.from(vector.Key, 'hex');
		let nonce = Buffer.from(vector.Nonce, 'hex');
		let sealed = Buffer.from(vector.Sealed, 'hex');
		let associatedData = vector.AssociatedData;
		if (associatedData != null) {
			associatedData = Buffer.from(associatedData, 'hex');
		}
		let message = vector.Message;
		if (message != null) {
			message = Buffer.from(message, 'hex');
		}

		let aead = new deoxysii.AEAD(key, useUnsafeVartime);

		let ciphertext = aead.encrypt(nonce, message, associatedData);
		assert.deepEqual(ciphertext, sealed, 'Ciphertext: ' + vector.Name);
	}
}

describe('AEAD', function() {
	it('should throw on invalid key size', function() {
		assert.throws(function() {
			let foo = new deoxysii.AEAD(Buffer.alloc(10)); // eslint-disable-line no-unused-vars
		}, deoxysii.ErrKeySize);
	});

	it('ct32: should match unofficial test vectors', function() {
		testVectorsUnofficial(false);
	});
	it('vartime: should match unofficial test vectors', function() {
		testVectorsUnofficial(true);
	});

	it('ct32: should match official test vectors', function() {
		testVectorsOfficial(false);
	});
	it('vartime: should match official test vectors', function() {
		testVectorsOfficial(true);
	});
});
