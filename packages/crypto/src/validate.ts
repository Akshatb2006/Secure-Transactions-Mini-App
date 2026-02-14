/**
 * Validation utilities for encrypted records.
 * Ensures nonces, tags, and hex strings are well-formed.
 */

const HEX_REGEX = /^[0-9a-f]*$/i;

/** Validate that a string is valid hex encoding */
export function isValidHex(value: string): boolean {
    return HEX_REGEX.test(value) && value.length % 2 === 0;
}

/** Validate nonce is exactly 12 bytes (24 hex characters) */
export function validateNonce(hexNonce: string, label: string): void {
    if (!isValidHex(hexNonce)) {
        throw new Error(`${label}: invalid hex encoding`);
    }
    const byteLength = hexNonce.length / 2;
    if (byteLength !== 12) {
        throw new Error(
            `${label}: nonce must be 12 bytes, got ${byteLength} bytes`
        );
    }
}

/** Validate tag is exactly 16 bytes (32 hex characters) */
export function validateTag(hexTag: string, label: string): void {
    if (!isValidHex(hexTag)) {
        throw new Error(`${label}: invalid hex encoding`);
    }
    const byteLength = hexTag.length / 2;
    if (byteLength !== 16) {
        throw new Error(
            `${label}: tag must be 16 bytes, got ${byteLength} bytes`
        );
    }
}

/** Validate an entire TxSecureRecord has well-formed fields */
export function validateRecord(record: {
    payload_nonce: string;
    payload_tag: string;
    payload_ct: string;
    dek_wrap_nonce: string;
    dek_wrap_tag: string;
    dek_wrapped: string;
}): void {
    validateNonce(record.payload_nonce, "payload_nonce");
    validateTag(record.payload_tag, "payload_tag");
    if (!isValidHex(record.payload_ct)) {
        throw new Error("payload_ct: invalid hex encoding");
    }

    validateNonce(record.dek_wrap_nonce, "dek_wrap_nonce");
    validateTag(record.dek_wrap_tag, "dek_wrap_tag");
    if (!isValidHex(record.dek_wrapped)) {
        throw new Error("dek_wrapped: invalid hex encoding");
    }
}
