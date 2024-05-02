// https://github.com/fxa/uint32.js
// Do, what You want. This library was designed to be a copy/paste template. It would be nice to hear from You, if You used this library or if You just copy/pasted some source. It would be nice, if you added a "contains code of Franz X Antesberger" or something like that or a ref to the github project to your license information or elsewhere.

import { assert, describe, expect, it } from "vitest";
import {
	toUint32,
	uint32_addMod32,
	uint32_and,
	uint32_choose,
	uint32_fromBytesBigEndian,
	uint32_getByteBigEndian,
	uint32_getBytesBigEndian,
	uint32_log2,
	uint32_majority,
	uint32_mult,
	uint32_not,
	uint32_or,
	uint32_rotateLeft,
	uint32_rotateRight,
	uint32_shiftLeft,
	uint32_toHex,
	uint32_xor,
	uint32_xor2,
	uint32_xor3,
} from "./uint32";

function toHex(ui32: number) {
	const tmp = ui32.toString(16);
	const neededZeros = 8 - tmp.length;
	return new Array(neededZeros + 1).join("0") + tmp;
}

describe("Creating and Extracting", () => {
	describe("fromBytesBigEndian()", () => {
		it("should create an uint32 of given bytes", () => {
			expect(uint32_fromBytesBigEndian(1, 2, 3, 4)).toStrictEqual(0x01020304);
		});
	});

	describe("getBytesBigEndian()", () => {
		it("should extract bytes in the correct order", () => {
			expect(uint32_getBytesBigEndian(0xffffffff)).toStrictEqual([
				0xff, 0xff, 0xff, 0xff,
			]);
			expect(uint32_getBytesBigEndian(123456789)).toStrictEqual([
				7, 91, 205, 21,
			]);
		});
		it("should roundtrip", () => {
			for (let i = 0; i < 10; i += 1) {
				const a = Math.floor(Math.random() * 2 ** 32);
				const b = uint32_getBytesBigEndian(a);
				assert.isArray(b);
				expect(b.length).toStrictEqual(4);
				const c = uint32_fromBytesBigEndian(b[0], b[1], b[2], b[3]);
				expect(c).toStrictEqual(a);
			}
		});
	});

	describe("getByteBigEndian()", () => {
		it("should extract the high byte", () => {
			expect(uint32_getByteBigEndian(0xf1f2f3f4, 0)).toStrictEqual(0xf1);
		});
		it("should extract the 2nd high byte", () => {
			expect(uint32_getByteBigEndian(0xf1f2f3f4, 1)).toStrictEqual(0xf2);
		});
		it("should extract the 3rd high byte", () => {
			expect(uint32_getByteBigEndian(0xf1f2f3f4, 2)).toStrictEqual(0xf3);
		});
		it("should extract the low byte", () => {
			expect(uint32_getByteBigEndian(0xf1f2f3f4, 3)).toStrictEqual(0xf4);
		});
	});

	describe("toHex()", () => {
		it("should fill with leading zeros", () => {
			expect(uint32_toHex(0x01)).toStrictEqual("00000001");
		});
		it("should use the optionalLength parameter", () => {
			expect(uint32_toHex(0x01, 2)).toStrictEqual("01");
		});
	});

	describe("toUint32()", () => {
		it("should convert an uint32 value", () => {
			expect(toUint32(0xf1f2f3f4)).toStrictEqual(0xf1f2f3f4);
		});
		it("should convert a negative value", () => {
			expect(toUint32(-1)).toStrictEqual(0xffffffff);
		});
		it("should convert a high value", () => {
			expect(toUint32(0x010000000004)).toStrictEqual(4);
		});
		it("should ignore values after decimal point", () => {
			expect(toUint32(3.5)).toStrictEqual(3);
		});
	});
});

describe("Bitwise Logical Operations", () => {
	describe("or()", () => {
		it("should handle low bits", () => {
			expect(uint32_or(1, 1)).toStrictEqual(1);
			expect(uint32_or(1, 0)).toStrictEqual(1);
			expect(uint32_or(1, 2)).toStrictEqual(3);
		});
		it("should handle high bits", () => {
			expect(uint32_or(0xffffffff, 0)).toStrictEqual(0xffffffff);
		});
		it("should handle more than two values", () => {
			expect(uint32_or(1, 2, 4)).toStrictEqual(7);
			expect(uint32_or(1, 2, 4, 8)).toStrictEqual(15);
		});
	});

	describe("and()", () => {
		it("should handle low bits", () => {
			expect(uint32_and(1, 1)).toStrictEqual(1);
			expect(uint32_and(1, 0)).toStrictEqual(0);
			expect(uint32_and(1, 2)).toStrictEqual(0);
		});
		it("should handle high bits", () => {
			expect(uint32_or(0xffffffff, 0xffffffff)).toStrictEqual(0xffffffff);
		});
		it("should handle more than two values", () => {
			expect(uint32_and(1, 3, 5)).toStrictEqual(1);
			expect(uint32_and(3, 11, 19, 35)).toStrictEqual(3);
		});
	});

	describe("xor()", () => {
		it("should xor high bit to off", () => {
			expect(uint32_xor(0x80000000, 0xffffffff)).toStrictEqual(0x7fffffff);
			expect(uint32_xor2(0x80000000, 0xffffffff)).toStrictEqual(0x7fffffff);
		});
		it("should xor high bit to on", () => {
			expect(uint32_xor(0x40000000, 0x80000000)).toStrictEqual(0xc0000000);
			expect(uint32_xor2(0x40000000, 0x80000000)).toStrictEqual(0xc0000000);
		});
		it("should xor more than two values", () => {
			expect(uint32_xor(1, 2, 4)).toStrictEqual(7);
			expect(uint32_xor(1, 3, 5)).toStrictEqual(7);
			expect(uint32_xor3(1, 2, 4)).toStrictEqual(7);
			expect(uint32_xor3(1, 3, 5)).toStrictEqual(7);
			expect(uint32_xor(1, 2, 4, 8)).toStrictEqual(15);
		});
	});

	describe("not()", () => {
		it("should negate 0", () => {
			expect(uint32_not(0)).toStrictEqual(0xffffffff);
		});
		it("should negate negative values", () => {
			expect(uint32_not(-1)).toStrictEqual(0);
		});
		it("should negate values with high bit set", () => {
			expect(uint32_not(0xc0000000)).toStrictEqual(0x3fffffff);
		});
	});
});

describe("Shifting and Rotating", () => {
	describe("shiftLeft()", () => {
		it("should handle the high bit", () => {
			expect(uint32_shiftLeft(3, 30)).toStrictEqual(0xc0000000);
			expect(uint32_shiftLeft(0x40000000, 1)).toStrictEqual(0x80000000);
			expect(uint32_shiftLeft(0x40000000, 2)).toStrictEqual(0);
			expect(uint32_shiftLeft(0x80000000, 1)).toStrictEqual(0);
		});
	});
	describe("shiftRight()", () => {
		it("should handle the high bit", () => {
			expect(uint32_shiftLeft(0x40000000, 1)).toStrictEqual(0x80000000);
			expect(uint32_shiftLeft(0x80000000, 1)).toStrictEqual(0);
		});
	});

	describe("rotateLeft()", () => {
		it("should rotate little values", () => {
			expect(uint32_rotateLeft(0x01, 1)).toStrictEqual(0x02);
			expect(uint32_rotateLeft(0x02, 1)).toStrictEqual(0x04);
		});
		it("should rotate big values", () => {
			expect(uint32_rotateLeft(0x40000000, 1)).toStrictEqual(0x80000000);
			expect(uint32_rotateLeft(0x80000000, 1)).toStrictEqual(0x00000001);
		});
	});

	describe("rotateRight()", () => {
		it("should rotate little values", () => {
			expect(uint32_rotateRight(0x01, 1)).toStrictEqual(0x80000000);
			expect(uint32_rotateRight(0x02, 1)).toStrictEqual(0x01);
		});
		it("should rotate big values", () => {
			expect(uint32_rotateRight(0x40000000, 1)).toStrictEqual(0x20000000);
			expect(uint32_rotateRight(0x80000000, 1)).toStrictEqual(0x40000000);
		});
	});
});

describe("Logical Gates", () => {
	describe("choose()", () => {
		it("should use y, if x flag is set", () => {
			expect(uint32_choose(1, 0, 0)).toStrictEqual(0);
			expect(uint32_choose(1, 0, 1)).toStrictEqual(0);
			expect(uint32_choose(1, 1, 0)).toStrictEqual(1);
			expect(uint32_choose(1, 1, 1)).toStrictEqual(1);

			expect(uint32_choose(0xffffffff, 0, 0)).toStrictEqual(0);
			expect(uint32_choose(0xffffffff, 0, 0xffffffff)).toStrictEqual(0);
			expect(uint32_choose(0xffffffff, 0xffffffff, 0)).toStrictEqual(
				0xffffffff,
			);
			expect(uint32_choose(0xffffffff, 0xffffffff, 0xffffffff)).toStrictEqual(
				0xffffffff,
			);
		});
		it("should use z, if x flag is not set", () => {
			expect(uint32_choose(0, 0, 0)).toStrictEqual(0);
			expect(uint32_choose(0, 0, 1)).toStrictEqual(1);
			expect(uint32_choose(0, 1, 0)).toStrictEqual(0);
			expect(uint32_choose(0, 1, 1)).toStrictEqual(1);

			expect(uint32_choose(0, 0, 0)).toStrictEqual(0);
			expect(uint32_choose(0, 0, 0xffffffff)).toStrictEqual(0xffffffff);
			expect(uint32_choose(0, 0xffffffff, 0)).toStrictEqual(0);
			expect(uint32_choose(0, 0xffffffff, 0xffffffff)).toStrictEqual(
				0xffffffff,
			);
		});
		it("should use the proper y or z", () => {
			expect(uint32_choose(0x01010202, 0x00010001, 0x01000100)).toStrictEqual(
				0x00010100,
			);
		});
	});
	describe("majority()", () => {
		it("should return 0, if all parameters are 0", () => {
			expect(uint32_majority(0, 0, 0)).toStrictEqual(0);
		});
		it("should return 0, if all but one parameters are 0", () => {
			expect(uint32_majority(0xffffffff, 0, 0)).toStrictEqual(0);
			expect(uint32_majority(0, 0xffffffff, 0)).toStrictEqual(0);
			expect(uint32_majority(0, 0, 0xffffffff)).toStrictEqual(0);
		});
		it("should return 0xffffffff, if two parameters are 0xffffffff", () => {
			expect(uint32_majority(0xffffffff, 0xffffffff, 0)).toStrictEqual(
				0xffffffff,
			);
			expect(uint32_majority(0xffffffff, 0, 0xffffffff)).toStrictEqual(
				0xffffffff,
			);
			expect(uint32_majority(0, 0xffffffff, 0xffffffff)).toStrictEqual(
				0xffffffff,
			);
		});
		it("should return 0xffffffff, if all parameters are 0xffffffff", () => {
			expect(uint32_majority(0xffffffff, 0xffffffff, 0xffffffff)).toStrictEqual(
				0xffffffff,
			);
		});
		it("should work bitwise", () => {
			// all above tests bitwise
			expect(uint32_majority(0b01001101, 0b00101011, 0b00010111)).toStrictEqual(
				0b00001111,
			);
		});
	});
});

describe("Arithmetic", () => {
	describe("addMod32()", () => {
		it("should add values below 2^32", () => {
			expect(uint32_addMod32(0x40000000, 0x40000000)).toStrictEqual(0x80000000);
		});
		it("should add an arbitrary number of arguments", () => {
			expect(uint32_addMod32(1, 2, 3)).toStrictEqual(6);
			expect(uint32_addMod32(1, 2, 3, 4)).toStrictEqual(10);
			expect(uint32_addMod32(1, 2, 3, 4, 5)).toStrictEqual(15);
			expect(uint32_addMod32(1, 2, 3, 4, 5, 6)).toStrictEqual(21);
		});
		it("should add negative values", () => {
			expect(uint32_addMod32(-1, -1)).toStrictEqual(0xfffffffe);
		});
		it("should calc mod32", () => {
			expect(uint32_addMod32(0x80000001, 0x80000001)).toStrictEqual(2);
		});
	});
	describe("log2()", () => {
		it("should work for 0", () => {
			expect(uint32_log2(0)).toStrictEqual(Number.NEGATIVE_INFINITY);
		});
		it("should work for 1", () => {
			expect(uint32_log2(1)).toStrictEqual(0);
		});
		it("should work for 2", () => {
			expect(uint32_log2(2)).toStrictEqual(1);
		});
		it("should work for values between 2 and 2^31", () => {
			for (let exp = 2; exp < 32; exp += 1) {
				const pow = 2 ** exp;
				expect(uint32_log2(pow - 1)).toStrictEqual(exp - 1);
				expect(uint32_log2(pow)).toStrictEqual(exp);
			}
		});
		it("should work for 2^32-1", () => {
			expect(uint32_log2(0xffffffff)).toStrictEqual(31);
		});
	});
	describe("mult()", () => {
		it("should work, if the product is less than 2^32", () => {
			const result = new Uint32Array(2);
			uint32_mult(0xffff, 0xffff, result);
			expect(result[0]).toStrictEqual(0);
			expect(result[1]).toStrictEqual(0xfffe0001);
		});
		it("should work, if the product is smaller than 2^52", () => {
			const result = new Uint32Array(2);
			uint32_mult(0x04000000, 0x03ffffff, result);
			expect(result[0]).toStrictEqual(0xfffff);
			expect(result[1]).toStrictEqual(0xfc000000);
		});
		it("should work, if the product is 2^52", () => {
			const result = new Uint32Array(2);
			uint32_mult(0x04000000, 0x04000000, result);
			expect(result[0]).toStrictEqual(0x00100000);
			expect(result[1]).toStrictEqual(0);
		});
		it("should work, if the product is greater than 2^52", () => {
			const result = new Uint32Array(2);
			uint32_mult(0xff030201, 0xff030201, result);
			expect(toHex(result[0])).toStrictEqual(toHex(0xfe06fe07));
			expect(toHex(result[1])).toStrictEqual(toHex(0x0a0a0401));

			uint32_mult(0xffffffff, 0xffffffff, result);
			expect(result[0]).toStrictEqual(0xfffffffe);
			expect(result[1]).toStrictEqual(1);

			// (2**15 + 1) ** 2 = 2**30 + 2 * 2**15 + 1 = 0x40 00 00 01 00 00 00 01
			uint32_mult(0x80000001, 0x80000001, result);
			expect(toHex(result[0])).toStrictEqual(toHex(0x40000001));
			expect(toHex(result[1])).toStrictEqual(toHex(0x00000001));
		});
		it("should not make the rounding error the 0.1.3 version did", () => {
			const result = new Uint32Array(2);
			uint32_mult(0xfa93896b, 0xa1a9f539, result);
			expect(toHex(result[1])).toStrictEqual(toHex(0xffffffd3));
			expect(toHex(result[0])).toStrictEqual(toHex(0x9e3d24d8));
		});
	});
});
