### deoxysii.js - JavaScript Deoxys-II-256-128
![GitHub CI](https://github.com/oasisprotocol/deoxysii-js/actions/workflows/config.yml/badge.svg)

> When I find my code in tons of trouble,
> Friends and colleagues come to me,
> Speaking words of wisdom:
> "Write in C."

This package provides a pure-JavaScript implementation of the
[Deoxys-II-256-128 v1.43][1] algorithm from the [final CAESAR portfolio][2].

#### Implementations

 * (`ct32`) Bitsliced implementation.

 * (`vartime`) Variable time implementation with a table driven
   AES round function.

#### Notes

It is unclear what the various JavaScript implementations will do to the
`ct32` code or the underlying bitsliced AES round function, and it is
quite possible that it may be vulnerable to side channels.

Performance for both implementation are utterly abysimal, however `vartime`
is approximately twice the speed of `ct32`.

Users that require a more performant implementation are suggested to
investigate WebAssembly, or (even better) calling native code.

[1]: https://sites.google.com/view/deoxyscipher
[2]: https://competitions.cr.yp.to/caesar-submissions.html
