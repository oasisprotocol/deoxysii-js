// Do, what You want. This library was designed to be a copy/paste template. It would be nice to hear from You, if You used this library or if You just copy/pasted some source. It would be nice, if you added a "contains code of Franz X Antesberger" or something like that or a ref to the github project to your license information or elsewhere.
// https://github.com/fxa/uint32.js

/**
 * @license (c) Franz X Antesberger 2013
 */

const POW_2_32 = 0x0100000000 as const;

//
//  Creating and Extracting
//

/**
 *  Creates an uint32 from the given bytes in big endian order.
 *  @param highByte the high byte
 *  @param secondHighByte the 2nd high byte
 *  @param thirdHighByte the 3rd high byte
 *  @param lowByte the low byte
 *  @returns highByte concat secondHighByte concat thirdHighByte concat lowByte
 */
export function uint32_fromBytesBigEndian(
	highByte: number,
	secondHighByte: number,
	thirdHighByte: number,
	lowByte: number,
) {
	return (
		((highByte << 24) |
			(secondHighByte << 16) |
			(thirdHighByte << 8) |
			lowByte) >>>
		0
	);
}

/**
 *  Returns the byte.
 *  e.g. when byteNo is 0, the high byte is returned, when byteNo = 3 the low byte is returned.
 *  @param uint32value the source to be extracted
 *  @param byteNo 0-3 the byte number, 0 is the high byte, 3 the low byte
 *  @returns the 0-255 byte according byteNo
 */
export function uint32_getByteBigEndian(
	uint32value: number,
	byteNo: number,
): number {
	return (uint32value >>> (8 * (3 - byteNo))) & 0xff;
}

/**
 *  Returns the bytes as array.
 *  @param uint32value the source to be extracted
 *  @returns the array [highByte, 2ndHighByte, 3rdHighByte, lowByte]
 */
export function uint32_getBytesBigEndian(uint32value: number): number[] {
	return [
		uint32_getByteBigEndian(uint32value, 0),
		uint32_getByteBigEndian(uint32value, 1),
		uint32_getByteBigEndian(uint32value, 2),
		uint32_getByteBigEndian(uint32value, 3),
	];
}

/**
 *  Converts a given uin32 to a hex string including leading zeros.
 *  @param uint32value the uint32 to be stringified
 *  @param optionalMinLength the optional (default 8)
 */
export function uint32_toHex(uint32value: number, optionalMinLength?: number) {
	const minLength = optionalMinLength || 8;
	let result = uint32value.toString(16);
	if (result.length < minLength) {
		result = new Array(minLength - result.length + 1).join("0") + result;
	}
	return result;
}

/**
 *  Converts a number to an uint32.
 *  @param n the number to be converted.
 *  @return an uint32 value
 */
export function toUint32(n: number): number {
	// the shift operator forces js to perform the internal ToUint32 (see ecmascript spec 9.6)
	return n >>> 0;
}

/**
 *  Returns the part above the uint32 border.
 *  Depending to the javascript engine, that are the 54-32 = 22 high bits
 *  @param number the number to extract the high part
 *  @return the high part of the number
 */
export function uint32_highPart(number: number): number {
	return toUint32(number / POW_2_32);
}

//
//  Bitwise Logical Operators
//

/**
 *  Returns a bitwise OR operation on two or more values.
 *  @param uint32val0 first uint32 value
 *  @param argv one or more uint32 values
 *  @return the bitwise OR uint32 value
 */
export function uint32_or(uint32val0: number, ...argv: number[]): number {
	let result = uint32val0;
	for (const x of argv) {
		result = result | x;
	}
	return result >>> 0;
}

/**
 *  Returns a bitwise AND operation on two or more values.
 *  @param uint32val0 first uint32 value
 *  @param argv one or more uint32 values
 *  @return the bitwise AND uint32 value
 */
export function uint32_and(uint32val0: number, ...argv: number[]): number {
	let result = uint32val0;
	for (const x of argv) {
		result = result & x;
	}
	return result >>> 0;
}

/**
 * Returns a bitwise XOR operation on three values.
 */
export function uint32_xor3(a: number, b: number, c: number) {
	return (a ^ b ^ c) >>> 0;
}

/**
 * Returns a bitwise XOR operation on two values.
 */
export function uint32_xor2(a: number, b: number) {
	return (a ^ b) >>> 0;
}

/**
 *  Returns a bitwise XOR operation on two or more values.
 *  @param uint32val0 first uint32 value
 *  @param argv one or more uint32 values
 *  @return the bitwise XOR uint32 value
 */
export function uint32_xor(uint32val0: number, ...argv: number[]): number {
	let result = uint32val0;
	for (const x of argv) {
		result = result ^ x;
	}
	return result >>> 0;
}

export function uint32_not(uint32val: number) {
	return ~uint32val >>> 0;
}

//
// Shifting and Rotating
//

/**
 *  Returns the uint32 representation of a << operation.
 *  @param uint32val the word to be shifted
 *  @param numBits the number of bits to be shifted (0-31)
 *  @returns the uint32 value of the shifted word
 */
export function uint32_shiftLeft(uint32val: number, numBits: number): number {
	return (uint32val << numBits) >>> 0;
}

/**
 *  Returns the uint32 representation of a >>> operation.
 *  @param uint32val the word to be shifted
 *  @param numBits the number of bits to be shifted (0-31)
 *  @returns the uint32 value of the shifted word
 */
export function uint32_shiftRight(uint32val: number, numBits: number): number {
	return uint32val >>> numBits;
}

export function uint32_rotateLeft(uint32val: number, numBits: number): number {
	return (
		(((uint32val << numBits) >>> 0) | (uint32val >>> (32 - numBits))) >>> 0
	);
}

export function uint32_rotateRight(uint32val: number, numBits: number): number {
	return (
		((uint32val >>> numBits) | ((uint32val << (32 - numBits)) >>> 0)) >>> 0
	);
}

//
// Logical Gates
//

/**
 *  Bitwise choose bits from y or z, as a bitwise x ? y : z
 */
export function uint32_choose(x: number, y: number, z: number) {
	return ((x & (y ^ z)) ^ z) >>> 0;
}

/**
 * Majority gate for three parameters. Takes bitwise the majority of x, y and z,
 * @see https://en.wikipedia.org/wiki/Majority_function
 */
export function uint32_majority(x: number, y: number, z: number): number {
	return ((x & (y | z)) | (y & z)) >>> 0;
}

//
//  Arithmetic
//

/**
 *  Adds the given values modulus 2^32.
 *  @returns the sum of the given values modulus 2^32
 */
export function uint32_addMod32(uint32val0: number, ...args: number[]) {
	let result = uint32val0;
	for (const x of args) {
		result += x;
	}
	return result >>> 0;
}

/**
 *  Returns the log base 2 of the given value. That is the number of the highest set bit.
 *  @param uint32val the value, the log2 is calculated of
 *  @return the logarithm base 2, an integer between 0 and 31
 */
export function uint32_log2(uint32val: number): number {
	return Math.floor(Math.log(uint32val) / Math.LN2);
}

/**
 *  Returns the the low and the high uint32 of the multiplication.
 *  @param factor1 an uint32
 *  @param factor2 an uint32
 *  @param resultUint32Array2 the Array, where the result will be written to
 */
export function uint32_mult(
	factor1: number,
	factor2: number,
	resultUint32Array2: Uint32Array,
) {
	const high16 = ((factor1 & 0xffff0000) >>> 0) * factor2;
	const low16 = (factor1 & 0x0000ffff) * factor2;
	// the addition is dangerous, because the result will be rounded, so the result depends on the lowest bits, which will be cut away!
	const carry = toUint32(high16) + toUint32(low16) >= POW_2_32 ? 1 : 0;
	resultUint32Array2[0] =
		(uint32_highPart(high16) + uint32_highPart(low16) + carry) >>> 0;
	resultUint32Array2[1] = (high16 >>> 0) + (low16 >>> 0); // >>> 0;
}
