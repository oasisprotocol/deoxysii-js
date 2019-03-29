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

var deoxysii = require('../deoxysii');
var Benchmark = require('benchmark');

var aeadCt32 = new deoxysii.AEAD(Buffer.alloc(deoxysii.KeySize));
var aeadVartime = new deoxysii.AEAD(Buffer.alloc(deoxysii.KeySize), true);
const nonce = Buffer.alloc(deoxysii.NonceSize);
var src = Buffer.alloc(1024768);

var suite = new Benchmark.Suite;
suite.add('ct32: Encrypt 8', function() {
	aeadCt32.encrypt(nonce, src.slice(0, 8), null);
})
	.add('ct32: Encrypt 32', function() {
		aeadCt32.encrypt(nonce, src.slice(0, 32), null);
	})
	.add('ct32: Encrypt 64', function() {
		aeadCt32.encrypt(nonce, src.slice(0, 64), null);
	})
	.add('ct32: Encrypt 576', function() {
		aeadCt32.encrypt(nonce, src.slice(0, 576), null);
	})
	.add('ct32: Encrypt 1536', function() {
		aeadCt32.encrypt(nonce, src.slice(0, 1536), null);
	})
	.add('ct32: Encrypt 4096', function() {
		aeadCt32.encrypt(nonce, src.slice(0, 4096), null);
	})
	.add('ct32: Encrypt 1024768', function() {
		aeadCt32.encrypt(nonce, src.slice(0, 1024768), null);
	})
	.add('vartime: Encrypt 8', function() {
		aeadVartime.encrypt(nonce, src.slice(0, 8), null);
	})
	.add('vartime: Encrypt 32', function() {
		aeadVartime.encrypt(nonce, src.slice(0, 32), null);
	})
	.add('vartime: Encrypt 64', function() {
		aeadVartime.encrypt(nonce, src.slice(0, 64), null);
	})
	.add('vartime: Encrypt 576', function() {
		aeadVartime.encrypt(nonce, src.slice(0, 576), null);
	})
	.add('vartime: Encrypt 1536', function() {
		aeadVartime.encrypt(nonce, src.slice(0, 1536), null);
	})
	.add('vartime: Encrypt 4096', function() {
		aeadVartime.encrypt(nonce, src.slice(0, 4096), null);
	})
	.add('vartime: Encrypt 1024768', function() {
		aeadVartime.encrypt(nonce, src.slice(0, 1024768), null);
	})
	.on('cycle', function(event) {
		console.log(String(event.target)); // eslint-disable-line no-console
	})
	.run();
