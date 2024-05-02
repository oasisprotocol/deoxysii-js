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

var aes = require('../aes');
var Benchmark = require('benchmark');


var ecb128 = new aes.ECB(new Uint8Array(16));
var ecb192 = new aes.ECB(new Uint8Array(24));
var ecb256 = new aes.ECB(new Uint8Array(32));
var src = new Uint8Array(16);
var dst = new Uint8Array(16);

var suite = new Benchmark.Suite;
suite.add('ECB-AES128', function() {
	ecb128.encrypt(dst, src);
})
	.add('ECB-AES192', function() {
		ecb192.encrypt(dst, src);
	})
	.add('ECB-AES256', function() {
		ecb256.encrypt(dst, src);
	})
	.on('cycle', function(event) {
		console.log(String(event.target)); // eslint-disable-line no-console
	})
	.run();
