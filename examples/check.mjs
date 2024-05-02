import * as deoxysii from "@oasisprotocol/deoxysii";
console.log("star", deoxysii.AEAD);

import deoxysiiDefault from "@oasisprotocol/deoxysii";
console.log("default", deoxysiiDefault.AEAD);

import { AEAD } from "@oasisprotocol/deoxysii";
console.log("AEAD", AEAD);

import { KeySize, NonceSize } from "@oasisprotocol/deoxysii";

// Define a key (ensure the size matches requirements)
const key = crypto.getRandomValues(new Uint8Array(KeySize));
const aead = new AEAD(key);

// Encryption
const nonce = crypto.getRandomValues(new Uint8Array(NonceSize));
const plaintext = new TextEncoder().encode("Hello World");
const associatedData = new Uint8Array([0x1, 0x2, 0x3]);

const encrypted = aead.encrypt(nonce, plaintext, associatedData);
console.log("Encrypted:", encrypted);

// Decryption
try {
	const decrypted = aead.decrypt(nonce, encrypted, associatedData);
	console.log("Decrypted:", new TextDecoder().decode(decrypted));
} catch (error) {
	console.error("Decryption failed:", error);
}
