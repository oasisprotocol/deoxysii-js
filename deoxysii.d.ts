export const KeySize: 32;
export const NonceSize: 15;
export const TagSize: 16;
export const ErrNonceSize: "deoxysii: invalid nonce size";
export const ErrKeySize: "deoxysii: invalid key size";
export const ErrOpen: "deoxysii: message authentication failure";
export class AEAD {
    constructor(key: Uint8Array, useUnsafeVartime?: boolean);
    impl: typeof implUnsafeVartime | typeof implCt32;
    derivedKs: Uint8Array[];
    encrypt(nonce: Uint8Array, plaintext?: Uint8Array | null, associatedData?: Uint8Array | null): Uint8Array;
    decrypt(nonce: Uint8Array, ciphertext: Uint8Array, associatedData?: Uint8Array | null): Uint8Array;
}
declare class implUnsafeVartime {
    static bcEncrypt(ciphertext: Uint8Array, derivedKs: Uint8Array[], tweak: Uint8Array, plaintext: Uint8Array): void;
    static bcKeystreamx2(ciphertext: Uint8Array, derivedKs: Uint8Array[], tweaks: Uint8Array[], nonce: Uint8Array): void;
    static bcTagx1(tag: Uint8Array, derivedKs: Uint8Array[], tweak: Uint8Array, plaintext: Uint8Array): void;
    static bcTagx2(tag: Uint8Array, derivedKs: Uint8Array[], tweaks: Uint8Array[], plaintext: Uint8Array): void;
}
declare class implCt32 {
    static bcEncrypt(ciphertext: Uint8Array, derivedKs: Uint8Array[], tweak: Uint8Array, plaintext: Uint8Array): void;
    static bcKeystreamx2(ciphertext: Uint8Array, derivedKs: Uint8Array[], tweaks: Uint8Array[], nonce: Uint8Array): void;
    static bcTagx1(tag: Uint8Array, derivedKs: Uint8Array[], tweak: Uint8Array, plaintext: Uint8Array): void;
    static bcTagx2(tag: Uint8Array, derivedKs: Uint8Array[], tweaks: Uint8Array[], plaintext: Uint8Array): void;
}
export {};
