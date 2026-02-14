/**
 * TxSecureRecord — encrypted transaction record using envelope encryption.
 * All binary values are stored as hex strings.
 */
export type TxSecureRecord = {
    /** Unique record identifier */
    id: string;
    /** Party identifier */
    partyId: string;
    /** ISO 8601 creation timestamp */
    createdAt: string;

    /** Nonce used to encrypt the payload (12 bytes → 24 hex chars) */
    payload_nonce: string;
    /** Encrypted payload ciphertext (hex) */
    payload_ct: string;
    /** Authentication tag from payload encryption (16 bytes → 32 hex chars) */
    payload_tag: string;

    /** Nonce used to wrap the DEK (12 bytes → 24 hex chars) */
    dek_wrap_nonce: string;
    /** Wrapped (encrypted) DEK (hex) */
    dek_wrapped: string;
    /** Authentication tag from DEK wrapping (16 bytes → 32 hex chars) */
    dek_wrap_tag: string;

    /** Encryption algorithm */
    alg: "AES-256-GCM";
    /** Master key version */
    mk_version: 1;
};

export interface EncryptInput {
    partyId: string;
    payload: Record<string, unknown>;
}
