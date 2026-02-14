import Fastify from "fastify";
import cors from "@fastify/cors";
import dotenv from "dotenv";
import { encrypt, decrypt } from "@repo/crypto";
import type { TxSecureRecord, EncryptInput } from "@repo/crypto";

// Load env vars from root .env
dotenv.config({ path: "../../.env" });

const MASTER_KEY = process.env.MASTER_KEY_HEX;
if (!MASTER_KEY) {
    console.error("❌ MASTER_KEY_HEX environment variable is required");
    process.exit(1);
}

// ─── In-memory storage ──────────────────────────────────────────────────────
const store = new Map<string, TxSecureRecord>();

// ─── Server setup ───────────────────────────────────────────────────────────
const app = Fastify({ logger: true });

await app.register(cors, {
    origin: true, // Allow all origins for development
});

// ─── Routes ─────────────────────────────────────────────────────────────────

/**
 * POST /tx/encrypt
 * Encrypt & store a transaction payload.
 */
app.post<{ Body: EncryptInput }>("/tx/encrypt", async (request, reply) => {
    try {
        const { partyId, payload } = request.body;

        if (!partyId || typeof partyId !== "string") {
            return reply.status(400).send({
                error: "partyId is required and must be a non-empty string",
            });
        }
        if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
            return reply.status(400).send({
                error: "payload is required and must be a JSON object",
            });
        }

        const record = encrypt({ partyId, payload }, MASTER_KEY);
        store.set(record.id, record);

        return reply.status(201).send(record);
    } catch (err: unknown) {
        const message = err instanceof Error ? err.message : "Encryption failed";
        return reply.status(500).send({ error: message });
    }
});

/**
 * GET /tx/:id
 * Return stored encrypted record (no decryption).
 */
app.get<{ Params: { id: string } }>("/tx/:id", async (request, reply) => {
    const { id } = request.params;
    const record = store.get(id);

    if (!record) {
        return reply.status(404).send({ error: `Record ${id} not found` });
    }

    return reply.send(record);
});

/**
 * POST /tx/:id/decrypt
 * Decrypt and return the original payload.
 */
app.post<{ Params: { id: string } }>(
    "/tx/:id/decrypt",
    async (request, reply) => {
        const { id } = request.params;
        const record = store.get(id);

        if (!record) {
            return reply.status(404).send({ error: `Record ${id} not found` });
        }

        try {
            const payload = decrypt(record, MASTER_KEY);
            return reply.send({ id: record.id, partyId: record.partyId, payload });
        } catch (err: unknown) {
            const message =
                err instanceof Error ? err.message : "Decryption failed";
            return reply.status(400).send({ error: message });
        }
    }
);

/**
 * Health check
 */
app.get("/health", async () => {
    return { status: "ok", recordCount: store.size };
});

// ─── Start ──────────────────────────────────────────────────────────────────
const PORT = parseInt(process.env.PORT || "3001", 10);

try {
    await app.listen({ port: PORT, host: "0.0.0.0" });
    console.log(`🚀 API server running on http://localhost:${PORT}`);
} catch (err) {
    app.log.error(err);
    process.exit(1);
}

export default app;
