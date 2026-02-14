import Fastify from "fastify";
import cors from "@fastify/cors";
import { randomBytes, createCipheriv, createDecipheriv } from "node:crypto";

// --- TYPES ---

type TxSecureRecord = {
    id: string;
    partyId: string;
    createdAt: string;
    payload_nonce: string;
    payload_ct: string;
    payload_tag: string;
    dek_wrap_nonce: string;
    dek_wrapped: string;
    dek_wrap_tag: string;
    alg: "AES-256-GCM";
    mk_version: 1;
};

interface EncryptInput {
    partyId: string;
    payload: Record<string, unknown>;
}

// --- VALIDATION HELPERS ---

const HEX_REGEX = /^[0-9a-f]*$/i;

function isValidHex(value: string): boolean {
    return HEX_REGEX.test(value) && value.length % 2 === 0;
}

function validateNonce(hexNonce: string, label: string): void {
    if (!isValidHex(hexNonce)) throw new Error(`${label}: invalid hex encoding`);
    if (hexNonce.length !== 24) throw new Error(`${label}: nonce must be 12 bytes (24 hex chars)`);
}

function validateTag(hexTag: string, label: string): void {
    if (!isValidHex(hexTag)) throw new Error(`${label}: invalid hex encoding`);
    if (hexTag.length !== 32) throw new Error(`${label}: tag must be 16 bytes (32 hex chars)`);
}

function validateRecord(record: TxSecureRecord): void {
    validateNonce(record.payload_nonce, "payload_nonce");
    validateTag(record.payload_tag, "payload_tag");
    if (!isValidHex(record.payload_ct)) throw new Error("payload_ct: invalid hex encoding");
    validateNonce(record.dek_wrap_nonce, "dek_wrap_nonce");
    validateTag(record.dek_wrap_tag, "dek_wrap_tag");
    if (!isValidHex(record.dek_wrapped)) throw new Error("dek_wrapped: invalid hex encoding");
}

// --- CRYPTO HELPERS ---

function toHex(buffer: Buffer): string { return buffer.toString("hex"); }
function fromHex(hex: string): Buffer { return Buffer.from(hex, "hex"); }
function generateId(): string { return randomBytes(16).toString("hex"); }

function aes256GcmEncrypt(plaintext: Buffer, key: Buffer) {
    const nonce = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", key, nonce);
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();
    return { nonce, ciphertext, tag };
}

function aes256GcmDecrypt(ciphertext: Buffer, key: Buffer, nonce: Buffer, tag: Buffer): Buffer {
    const decipher = createDecipheriv("aes-256-gcm", key, nonce);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

// --- CORE LOGIC ---

function encrypt(input: EncryptInput, masterKeyHex: string): TxSecureRecord {
    if (!input.partyId || typeof input.partyId !== "string") throw new Error("partyId required");
    if (!input.payload || typeof input.payload !== "object") throw new Error("payload required");

    const masterKey = fromHex(masterKeyHex);
    if (masterKey.length !== 32) throw new Error("Master key must be 32 bytes");

    const dek = randomBytes(32);
    const payloadBuffer = Buffer.from(JSON.stringify(input.payload), "utf-8");
    const payloadEncrypted = aes256GcmEncrypt(payloadBuffer, dek);
    const dekWrapped = aes256GcmEncrypt(dek, masterKey);

    return {
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
}

function decrypt(record: TxSecureRecord, masterKeyHex: string): Record<string, unknown> {
    validateRecord(record);
    const masterKey = fromHex(masterKeyHex);
    if (masterKey.length !== 32) throw new Error("Master key must be 32 bytes");

    const dek = aes256GcmDecrypt(
        fromHex(record.dek_wrapped),
        masterKey,
        fromHex(record.dek_wrap_nonce),
        fromHex(record.dek_wrap_tag)
    );

    const payloadBuffer = aes256GcmDecrypt(
        fromHex(record.payload_ct),
        dek,
        fromHex(record.payload_nonce),
        fromHex(record.payload_tag)
    );

    return JSON.parse(payloadBuffer.toString("utf-8"));
}

// --- SERVER SETUP ---

const store = new Map<string, TxSecureRecord>();
const app = Fastify({ logger: true });

// Register CORS immediately
await app.register(cors, {
    origin: true, // Allow all origins (reflects request origin)
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"]
});

// Runtime Env Check
const getMasterKey = () => {
    const key = process.env.MASTER_KEY_HEX;
    if (!key) throw new Error("Server Misconfiguration: MASTER_KEY_HEX is missing");
    return key;
};

// Routes
app.post<{ Body: EncryptInput }>("/tx/encrypt", async (request, reply) => {
    try {
        const { partyId, payload } = request.body;
        // Basic validation
        if (!partyId || !payload) return reply.status(400).send({ error: "Missing partyId or payload" });

        const record = encrypt({ partyId, payload }, getMasterKey());
        store.set(record.id, record);
        return reply.status(201).send(record);
    } catch (err: any) {
        request.log.error(err);
        return reply.status(500).send({ error: err.message });
    }
});

app.get<{ Params: { id: string } }>("/tx/:id", async (request, reply) => {
    const record = store.get(request.params.id);
    if (!record) return reply.status(404).send({ error: "Record not found" });
    return reply.send(record);
});

app.post<{ Params: { id: string } }>("/tx/:id/decrypt", async (request, reply) => {
    const record = store.get(request.params.id);
    if (!record) return reply.status(404).send({ error: "Record not found" });
    try {
        const payload = decrypt(record, getMasterKey());
        return reply.send({ id: record.id, partyId: record.partyId, payload });
    } catch (err: any) {
        request.log.error(err);
        return reply.status(500).send({ error: err.message });
    }
});

app.get("/health", async () => ({ status: "ok", recordCount: store.size }));

await app.ready();

export default async function handler(req: any, res: any) {
    app.server.emit("request", req, res);
}
