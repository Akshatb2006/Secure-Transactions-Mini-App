"use client";

import { useState } from "react";

const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:3001";

type ResultState = {
    type: "success" | "error";
    data: unknown;
} | null;

export default function Home() {
    const [partyId, setPartyId] = useState("party_123");
    const [payload, setPayload] = useState(
        JSON.stringify({ amount: 100, currency: "AED" }, null, 2)
    );
    const [txId, setTxId] = useState<string>("");
    const [result, setResult] = useState<ResultState>(null);
    const [loading, setLoading] = useState<string>("");

    async function handleEncrypt() {
        setLoading("encrypt");
        setResult(null);
        try {
            const parsed = JSON.parse(payload);
            const res = await fetch(`${API_URL}/tx/encrypt`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ partyId, payload: parsed }),
            });
            const data: any = await res.json();
            if (!res.ok) throw new Error(data.error || "Encryption failed");
            setTxId(data.id);
            setResult({ type: "success", data });
        } catch (err: unknown) {
            const message = err instanceof Error ? err.message : "Encryption failed";
            setResult({ type: "error", data: { error: message } });
        } finally {
            setLoading("");
        }
    }

    async function handleFetch() {
        if (!txId) return;
        setLoading("fetch");
        setResult(null);
        try {
            const res = await fetch(`${API_URL}/tx/${txId}`);
            const data: any = await res.json();
            if (!res.ok) throw new Error(data.error || "Fetch failed");
            setResult({ type: "success", data });
        } catch (err: unknown) {
            const message = err instanceof Error ? err.message : "Fetch failed";
            setResult({ type: "error", data: { error: message } });
        } finally {
            setLoading("");
        }
    }

    async function handleDecrypt() {
        if (!txId) return;
        setLoading("decrypt");
        setResult(null);
        try {
            const res = await fetch(`${API_URL}/tx/${txId}/decrypt`, {
                method: "POST",
            });
            const data: any = await res.json();
            if (!res.ok) throw new Error(data.error || "Decryption failed");
            setResult({ type: "success", data });
        } catch (err: unknown) {
            const message = err instanceof Error ? err.message : "Decryption failed";
            setResult({ type: "error", data: { error: message } });
        } finally {
            setLoading("");
        }
    }

    return (
        <main className="container">
            <div className="header">
                <div className="badge">AES-256-GCM</div>
                <h1>Secure Transactions</h1>
                <p>Enterprise-grade envelope encryption for secure JSON payloads.</p>
            </div>

            {/* ─── Input Card ──────────────────────────────────────────────────── */}
            <div className="card">
                <div className="card-title">Create Transaction</div>

                <div className="form-group">
                    <label htmlFor="partyId">Party ID</label>
                    <input
                        id="partyId"
                        className="input"
                        type="text"
                        placeholder="e.g. party_123"
                        value={partyId}
                        onChange={(e: React.ChangeEvent<HTMLInputElement>) => setPartyId(e.target.value)}
                    />
                </div>

                <div className="form-group">
                    <label htmlFor="payload">JSON Payload</label>
                    <textarea
                        id="payload"
                        className="textarea"
                        placeholder='{ "amount": 100, "currency": "AED" }'
                        value={payload}
                        onChange={(e: React.ChangeEvent<HTMLTextAreaElement>) => setPayload(e.target.value)}
                    />
                </div>

                <button
                    className="btn btn-primary"
                    onClick={handleEncrypt}
                    disabled={loading === "encrypt" || !partyId}
                >
                    {loading === "encrypt" ? (
                        <>
                            <span className="spinner" /> Encrypting…
                        </>
                    ) : (
                        "🔒 Encrypt & Save"
                    )}
                </button>
            </div>

            {/* ─── Actions Card ────────────────────────────────────────────────── */}
            {txId && (
                <div className="card">
                    <div className="card-title">Manage Record</div>

                    <div className="tx-id">
                        <span className="tx-id-label">TX ID:</span>
                        {txId}
                    </div>

                    <div className="btn-row">
                        <button
                            className="btn btn-secondary"
                            onClick={handleFetch}
                            disabled={!!loading}
                        >
                            {loading === "fetch" ? (
                                <>
                                    <span className="spinner" /> Fetching…
                                </>
                            ) : (
                                "📄 Fetch Record"
                            )}
                        </button>

                        <button
                            className="btn btn-success"
                            onClick={handleDecrypt}
                            disabled={!!loading}
                        >
                            {loading === "decrypt" ? (
                                <>
                                    <span className="spinner" /> Decrypting…
                                </>
                            ) : (
                                "🔓 Decrypt"
                            )}
                        </button>
                    </div>
                </div>
            )}

            {/* ─── Result ──────────────────────────────────────────────────────── */}
            {result && (
                <div
                    className={`result ${result.type === "success" ? "result-success" : "result-error"
                        }`}
                >
                    <pre>{JSON.stringify(result.data, null, 2)}</pre>
                </div>
            )}
        </main>
    );
}
