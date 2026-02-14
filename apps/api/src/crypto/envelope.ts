/**
 * Envelope Encryption using AES-256-GCM.
 *
 * Flow:
 * 1. Generate random 32-byte DEK (Data Encryption Key)
 * 2. Encrypt payload with DEK using AES-256-GCM
 * 3. Wrap (encrypt) DEK with Master Key using AES-256-GCM
 * 4. Store everything as hex strings
 */

import { randomBytes, createCipheriv, createDecipheriv } from "node:crypto";
import type { TxSecureRecord, EncryptInput } from "./types.js";
import { validateRecord } from "./validate.js";

/** Convert a Buffer to hex string */
function toHex(buffer: Buffer): string {
    return buffer.toString("hex");
}

/** Convert a hex string to Buffer */
function fromHex(hex: string): Buffer {
    return Buffer.from(hex, "hex");
}

/** Generate a random UUID-like ID */
function generateId(): string {
    return randomBytes(16).toString("hex");
}

/**
 * Encrypt a payload using AES-256-GCM with a given key.
 * Returns { nonce, ciphertext, tag } as Buffers.
 */
function aes256GcmEncrypt(
    plaintext: Buffer,
    key: Buffer
): { nonce: Buffer; ciphertext: Buffer; tag: Buffer } {
    const nonce = randomBytes(12); // 96-bit IV for GCM
    const cipher = createCipheriv("aes-256-gcm", key, nonce);
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag(); // 16 bytes
    return { nonce, ciphertext, tag };
}

/**
 * Decrypt AES-256-GCM encrypted data.
 * Returns the plaintext Buffer.
 */
function aes256GcmDecrypt(
    ciphertext: Buffer,
    key: Buffer,
    nonce: Buffer,
    tag: Buffer
): Buffer {
    const decipher = createDecipheriv("aes-256-gcm", key, nonce);
    decipher.setAuthTag(tag);
    const plaintext = Buffer.concat([
        decipher.update(ciphertext),
        decipher.final(),
    ]);
    return plaintext;
}

/**
 * Encrypt a transaction payload using Envelope Encryption.
 *
 * @param input - The partyId and JSON payload to encrypt
 * @param masterKeyHex - The master key as a 64-character hex string (32 bytes)
 * @returns A complete TxSecureRecord with all fields as hex strings
 */
export function encrypt(
    input: EncryptInput,
    masterKeyHex: string
): TxSecureRecord {
    if (!input.partyId || typeof input.partyId !== "string") {
        throw new Error("partyId is required and must be a non-empty string");
    }
    if (!input.payload || typeof input.payload !== "object") {
        throw new Error("payload is required and must be an object");
    }

    const masterKey = fromHex(masterKeyHex);
    if (masterKey.length !== 32) {
        throw new Error("Master key must be 32 bytes (64 hex characters)");
    }

    // Step 1: Generate random DEK (32 bytes)
    const dek = randomBytes(32);

    // Step 2: Encrypt the payload with DEK
    const payloadBuffer = Buffer.from(JSON.stringify(input.payload), "utf-8");
    const payloadEncrypted = aes256GcmEncrypt(payloadBuffer, dek);

    // Step 3: Wrap (encrypt) the DEK with the Master Key
    const dekWrapped = aes256GcmEncrypt(dek, masterKey);

    // Step 4: Assemble the record
    const record: TxSecureRecord = {
        id: generateId(),
        partyId: input.partyId,
        createdAt: new Date().toISOString(),

        payload_nonce: toHex(payloadEncrypted.nonce),
        payload_ct: toHex(payloadEncrypted.ciphertext),
        payload_tag: toHex(payloadEncrypted.tag),

        dek_wrap_nonce: toHex(dekWrapped.nonce),
        dek_wrapped: toHex(dekWrapped.ciphertext),
        dek_wrap_tag: toHex(dekWrapped.tag),

        alg: "AES-256-GCM",
        mk_version: 1,
    };

    return record;
}

/**
 * Decrypt a TxSecureRecord back to the original payload.
 *
 * @param record - The encrypted record to decrypt
 * @param masterKeyHex - The master key as a 64-character hex string (32 bytes)
 * @returns The original JSON payload
 */
export function decrypt(
    record: TxSecureRecord,
    masterKeyHex: string
): Record<string, unknown> {
    // Validate all fields before attempting decryption
    validateRecord(record);

    const masterKey = fromHex(masterKeyHex);
    if (masterKey.length !== 32) {
        throw new Error("Master key must be 32 bytes (64 hex characters)");
    }

    // Step 1: Unwrap the DEK using the Master Key
    const dek = aes256GcmDecrypt(
        fromHex(record.dek_wrapped),
        masterKey,
        fromHex(record.dek_wrap_nonce),
        fromHex(record.dek_wrap_tag)
    );

    // Step 2: Decrypt the payload using the DEK
    const payloadBuffer = aes256GcmDecrypt(
        fromHex(record.payload_ct),
        dek,
        fromHex(record.payload_nonce),
        fromHex(record.payload_tag)
    );

    // Step 3: Parse and return the JSON payload
    return JSON.parse(payloadBuffer.toString("utf-8"));
}
