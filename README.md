### deoxysii.js - JavaScript Deoxys-II-256-128
![GitHub CI](https://github.com/oasisprotocol/deoxysii-js/actions/workflows/config.yml/badge.svg)
[![version][deoxysii-version]][deoxysii-npm]
[![size][deoxysii-size]][deoxysii-bundlephobia]
![downloads][deoxysii-downloads]
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

[deoxysii-npm]: https://www.npmjs.com/package/@oasisprotocol/deoxysii
[deoxysii-version]: https://img.shields.io/npm/v/@oasisprotocol/deoxysii
[deoxysii-size]: https://img.shields.io/bundlephobia/minzip/@oasisprotocol/deoxysii
[deoxysii-bundlephobia]: https://bundlephobia.com/package/@oasisprotocol/deoxysii
[deoxysii-downloads]: https://img.shields.io/npm/dm/@oasisprotocol/deoxysii.svg

This package provides a pure-JavaScript implementation of the
[Deoxys-II-256-128 v1.43][1] algorithm from the [final CAESAR portfolio][2].

> Deoxys is an authenticated encryption scheme based on a 128-bit lightweight
> ad-hoc tweakable block cipher. It may be used in two modes to handle
> nonce-respecting users (Deoxys-I) or nonce-reusing user (Deoxys-II).
>
> It has been designed by [Jérémy Jean][3], [Ivica Nikolić][4], [Thomas Peyrin][5] and [Yannick Seurin][6].

[1]: https://sites.google.com/view/deoxyscipher
[2]: https://competitions.cr.yp.to/caesar-submissions.html
[3]: http://jeremy.jean.free.fr/
[4]: https://sites.google.com/view/ivica-nikolic-sg/home
[5]: https://thomaspeyrin.github.io/web/
[6]: https://yannickseurin.github.io/

## Usage

Install the package as a dependency of your project:

```shell
npm add '@oasisprotocol/deoxysii'
```

The `AEAD` class can then be used to encrypt and decrypt, with an optional
authenticated data field which can be very useful when constructing protocols.

```typescript
import { AEAD, KeySize, NonceSize } from '@oasisprotocol/deoxysii';

// Define a key (ensure the size matches requirements)
const key = crypto.getRandomValues(new Uint8Array(KeySize));
const aead = new AEAD(key);

// Encryption
const nonce = crypto.getRandomValues(new Uint8Array(NonceSize));
const plaintext = new TextEncoder().encode("Hello World");
const associatedData = new Uint8Array([0x1, 0x2, 0x3]);

const encrypted = aead.encrypt(nonce, plaintext, associatedData);
console.log('Encrypted:', encrypted);

// Decryption
try {
    const decrypted = aead.decrypt(nonce, encrypted, associatedData);
    console.log('Decrypted:', new TextDecoder().decode(decrypted));
} catch (error) {
    console.error('Decryption failed:', error);
}
```

## Notes

> [!WARNING]
> It is unclear what the various JavaScript implementations will do to the
> `ct32` code or the underlying bitsliced AES round function, and it is
> quite possible that it may be vulnerable to side channels.
>
> Users that require a more performant and secure implementation are suggested
> to investigate WebAssembly, or (even better) calling native code.

#### Development

 * [Node.js](https://nodejs.org/en/about/previous-releases) - version 18+
 * [typescript](https://www.typescriptlang.org/) - version 5.x, for type safety
 * [pnpm](https://pnpm.io/) - package manager
 * [`gh act`](https://github.com/nektos/act) - run GitHub actions locally
 * [vitest](https://vitest.dev/) - tests, benchmarking & coverage
 * [biome](https://biomejs.dev/) - lint & formatting
 * [tsup](https://tsup.egoist.dev/) - compilation & bundling
 * [publint](https://publint.dev/) - packaging checks

#### License & Acknowledgements

This project is released under the MIT License.

This project utilizes modified code originally developed by Franz X Antesberger.
The original code for `uint32.js` is available at [fxa/uint32.js]. We have
adapted this code for TypeScript. We appreciate the contributions of Franz X
Antesberger to the open-source community.

[fxa/uint32.js]: https://github.com/fxa/uint32.js
