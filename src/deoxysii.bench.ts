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

import { bench } from "vitest";
import { AEAD, KeySize, NonceSize } from "./deoxysii";

const aeadCt32 = new AEAD(Buffer.alloc(KeySize));
const nonce = Buffer.alloc(NonceSize);
const src = Buffer.alloc(1024768);

bench(
	"ct32: Encrypt 8",
	() => {
		aeadCt32.encrypt(nonce, src.subarray(0, 8), null);
	},
	{ time: 1000 },
);

bench(
	"ct32: Encrypt 32",
	() => {
		aeadCt32.encrypt(nonce, src.subarray(0, 32), null);
	},
	{ time: 1000 },
);

bench(
	"ct32: Encrypt 64",
	() => {
		aeadCt32.encrypt(nonce, src.subarray(0, 64), null);
	},
	{ time: 1000 },
);

bench(
	"ct32: Encrypt 576",
	() => {
		aeadCt32.encrypt(nonce, src.subarray(0, 576), null);
	},
	{ time: 1000 },
);

bench(
	"ct32: Encrypt 1536",
	() => {
		aeadCt32.encrypt(nonce, src.subarray(0, 1536), null);
	},
	{ time: 1000 },
);

bench(
	"ct32: Encrypt 4096",
	() => {
		aeadCt32.encrypt(nonce, src.subarray(0, 4096), null);
	},
	{ time: 1000 },
);

bench(
	"ct32: Encrypt 1024768",
	() => {
		aeadCt32.encrypt(nonce, src.subarray(0, 1024768), null);
	},
	{ time: 5000 },
);
