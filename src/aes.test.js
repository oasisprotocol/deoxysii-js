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
var aes = require('../aes');

//
// ECB-AES based tests.
//
describe('ECB-AES', function() {
	it('should throw on invalid key size', function() {
		assert.throws(function() {
			let foo = new aes.ECB(Buffer.alloc(10)); // eslint-disable-line no-unused-vars
		});
	});

	const ecbVectors = [
		// ECB-AES128
		{
			'key': Buffer.from('2b7e151628aed2a6abf7158809cf4f3c', 'hex'),
			'plaintext': Buffer.from('6bc1bee22e409f96e93d7e117393172a', 'hex'),
			'ciphertext': Buffer.from('3ad77bb40d7a3660a89ecaf32466ef97', 'hex')
		},
		{
			'key': Buffer.from('2b7e151628aed2a6abf7158809cf4f3c', 'hex'),
			'plaintext': Buffer.from('ae2d8a571e03ac9c9eb76fac45af8e51', 'hex'),
			'ciphertext': Buffer.from('f5d3d58503b9699de785895a96fdbaaf', 'hex')
		},
		{
			'key': Buffer.from('2b7e151628aed2a6abf7158809cf4f3c', 'hex'),
			'plaintext': Buffer.from('30c81c46a35ce411e5fbc1191a0a52ef', 'hex'),
			'ciphertext': Buffer.from('43b1cd7f598ece23881b00e3ed030688', 'hex')
		},
		{
			'key': Buffer.from('2b7e151628aed2a6abf7158809cf4f3c', 'hex'),
			'plaintext': Buffer.from('f69f2445df4f9b17ad2b417be66c3710', 'hex'),
			'ciphertext': Buffer.from('7b0c785e27e8ad3f8223207104725dd4', 'hex')
		},

		// ECB-AES192
		{
			'key': Buffer.from('8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b', 'hex'),
			'plaintext': Buffer.from('6bc1bee22e409f96e93d7e117393172a', 'hex'),
			'ciphertext': Buffer.from('bd334f1d6e45f25ff712a214571fa5cc', 'hex')
		},
		{
			'key': Buffer.from('8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b', 'hex'),
			'plaintext': Buffer.from('ae2d8a571e03ac9c9eb76fac45af8e51', 'hex'),
			'ciphertext': Buffer.from('974104846d0ad3ad7734ecb3ecee4eef', 'hex')
		},
		{
			'key': Buffer.from('8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b', 'hex'),
			'plaintext': Buffer.from('30c81c46a35ce411e5fbc1191a0a52ef', 'hex'),
			'ciphertext': Buffer.from('ef7afd2270e2e60adce0ba2face6444e', 'hex')
		},
		{
			'key': Buffer.from('8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b', 'hex'),
			'plaintext': Buffer.from('f69f2445df4f9b17ad2b417be66c3710', 'hex'),
			'ciphertext': Buffer.from('9a4b41ba738d6c72fb16691603c18e0e', 'hex')
		},

		// ECB-AES256
		{
			'key': Buffer.from('603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4', 'hex'),
			'plaintext': Buffer.from('6bc1bee22e409f96e93d7e117393172a', 'hex'),
			'ciphertext': Buffer.from('f3eed1bdb5d2a03c064b5a7e3db181f8', 'hex')
		},
		{
			'key': Buffer.from('603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4', 'hex'),
			'plaintext': Buffer.from('ae2d8a571e03ac9c9eb76fac45af8e51', 'hex'),
			'ciphertext': Buffer.from('591ccb10d410ed26dc5ba74a31362870', 'hex')
		},
		{
			'key': Buffer.from('603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4', 'hex'),
			'plaintext': Buffer.from('30c81c46a35ce411e5fbc1191a0a52ef', 'hex'),
			'ciphertext': Buffer.from('b6ed21b99ca6f4f9f153e7b1beafed1d', 'hex')
		},
		{
			'key': Buffer.from('603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4', 'hex'),
			'plaintext': Buffer.from('f69f2445df4f9b17ad2b417be66c3710', 'hex'),
			'ciphertext': Buffer.from('23304b7a39f9f3ff067d8d8f9e24ecc7', 'hex')
		},
	];

	it('should match NIST SP 800-38A test vectors', function() {
		const numVectors = ecbVectors.length;
		for (let i = 0; i < numVectors; i++) {
			const vector = ecbVectors[i];

			let ecb = new aes.ECB(new Uint8Array(vector.key));
			let dst = new Uint8Array(16);
			ecb.encrypt(dst, new Uint8Array(vector.plaintext));
			assert.deepEqual(dst, new Uint8Array(vector.ciphertext));
		}
	});

	it('should handle 2 blocks at once', function() {
		let ecb = new aes.ECB(new Uint8Array(ecbVectors[0].key));
		let dst0 = new Uint8Array(16), dst1 = new Uint8Array(16);
		ecb.encrypt2x(dst0, dst1, new Uint8Array(ecbVectors[0].plaintext), new Uint8Array(ecbVectors[1].plaintext));
		assert.deepEqual(dst0, new Uint8Array(ecbVectors[0].ciphertext));
		assert.deepEqual(dst1, new Uint8Array(ecbVectors[1].ciphertext));
	});
});
