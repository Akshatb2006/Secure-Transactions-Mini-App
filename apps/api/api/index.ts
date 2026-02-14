import Fastify from "fastify";
import cors from "@fastify/cors";
import { encrypt, decrypt } from "../src/crypto/index.js";
import type { TxSecureRecord, EncryptInput } from "../src/crypto/index.js";

// MASTER_KEY check moved inside handlers to prevent startup crash
const MASTER_KEY = process.env.MASTER_KEY_HEX;

// In-memory storage (note: resets on cold start in serverless)
const store = new Map<string, TxSecureRecord>();

const app = Fastify({ logger: true });

await app.register(cors, { origin: true });

app.post<{ Body: EncryptInput }>("/tx/encrypt", async (request, reply) => {
    try {
        const { partyId, payload } = request.body;
        if (!partyId || typeof partyId !== "string") {
            return reply.status(400).send({ error: "partyId is required and must be a non-empty string" });
        }
        if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
            return reply.status(400).send({ error: "payload is required and must be a JSON object" });
        }
        if (!MASTER_KEY) throw new Error("Server Misconfiguration: MASTER_KEY_HEX is missing");
        const record = encrypt({ partyId, payload }, MASTER_KEY);
        store.set(record.id, record);
        return reply.status(201).send(record);
    } catch (err: unknown) {
        const message = err instanceof Error ? err.message : "Encryption failed";
        return reply.status(500).send({ error: message });
    }
});

app.get<{ Params: { id: string } }>("/tx/:id", async (request, reply) => {
    const record = store.get(request.params.id);
    if (!record) return reply.status(404).send({ error: `Record ${request.params.id} not found` });
    return reply.send(record);
});

app.post<{ Params: { id: string } }>("/tx/:id/decrypt", async (request, reply) => {
    const record = store.get(request.params.id);
    if (!record) return reply.status(404).send({ error: `Record ${request.params.id} not found` });
    try {
        if (!MASTER_KEY) throw new Error("Server Misconfiguration: MASTER_KEY_HEX is missing");
        const payload = decrypt(record, MASTER_KEY);
        return reply.send({ id: record.id, partyId: record.partyId, payload });
    } catch (err: unknown) {
        const message = err instanceof Error ? err.message : "Decryption failed";
        return reply.status(400).send({ error: message });
    }
});

app.get("/health", async () => ({ status: "ok", recordCount: store.size }));

await app.ready();

export default async function handler(req: any, res: any) {
    app.server.emit("request", req, res);
}
