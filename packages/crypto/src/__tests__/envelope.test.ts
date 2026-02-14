import { describe, it, expect } from "vitest";
import { encrypt, decrypt, validateRecord } from "../index.js";
import type { TxSecureRecord } from "../index.js";

const MASTER_KEY =
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const DIFFERENT_KEY =
    "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

const SAMPLE_INPUT = {
    partyId: "party_123",
    payload: { amount: 100, currency: "AED" },
};

describe("Envelope Encryption", () => {
    it("should encrypt and decrypt a payload correctly (round-trip)", () => {
        const record = encrypt(SAMPLE_INPUT, MASTER_KEY);

        expect(record.id).toBeDefined();
        expect(record.partyId).toBe("party_123");
        expect(record.alg).toBe("AES-256-GCM");
        expect(record.mk_version).toBe(1);

        const decrypted = decrypt(record, MASTER_KEY);
        expect(decrypted).toEqual({ amount: 100, currency: "AED" });
    });

    it("should fail decryption when ciphertext is tampered", () => {
        const record = encrypt(SAMPLE_INPUT, MASTER_KEY);

        // Tamper with the payload ciphertext (flip a character)
        const tampered = { ...record };
        const ct = tampered.payload_ct;
        tampered.payload_ct =
            ct.charAt(0) === "a"
                ? "b" + ct.slice(1)
                : "a" + ct.slice(1);

        expect(() => decrypt(tampered, MASTER_KEY)).toThrow();
    });

    it("should fail decryption when tag is tampered", () => {
        const record = encrypt(SAMPLE_INPUT, MASTER_KEY);

        // Tamper with the payload authentication tag
        const tampered = { ...record };
        const tag = tampered.payload_tag;
        tampered.payload_tag =
            tag.charAt(0) === "a"
                ? "b" + tag.slice(1)
                : "a" + tag.slice(1);

        expect(() => decrypt(tampered, MASTER_KEY)).toThrow();
    });

    it("should fail validation when nonce length is wrong", () => {
        const record = encrypt(SAMPLE_INPUT, MASTER_KEY);

        // Set nonce to wrong length (10 bytes instead of 12)
        const tampered = { ...record };
        tampered.payload_nonce = "aabbccddee0011223344";  // 10 bytes = 20 hex chars

        expect(() => validateRecord(tampered)).toThrow("nonce must be 12 bytes");
    });

    it("should fail validation when hex is invalid", () => {
        const record = encrypt(SAMPLE_INPUT, MASTER_KEY);

        // Inject non-hex characters
        const tampered = { ...record };
        tampered.payload_ct = "ZZZZ_not_hex!";

        expect(() => validateRecord(tampered)).toThrow("invalid hex");
    });

    it("should fail decryption with a different master key", () => {
        const record = encrypt(SAMPLE_INPUT, MASTER_KEY);
        expect(() => decrypt(record, DIFFERENT_KEY)).toThrow();
    });

    it("should reject empty partyId", () => {
        expect(() =>
            encrypt({ partyId: "", payload: { test: true } }, MASTER_KEY)
        ).toThrow("partyId is required");
    });
});
