# 🔐 Secure Transactions Mini-App

> A minimal secure transaction service demonstrating **envelope encryption**, **monorepo architecture**, and **production deployment** using modern TypeScript tooling.

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Architecture](#-architecture)
- [Tech Stack](#-tech-stack)
- [Encryption Design](#-encryption-design)
- [Data Model](#-data-model)
- [API Endpoints](#-api-endpoints)
- [Frontend](#-frontend)
- [Validation & Security](#-validation--security)
- [Tests](#-tests)
- [Key Design Decisions](#-key-design-decisions)
- [Deployment](#-deployment)
- [Running Locally](#-running-locally)

---

## 🧭 Overview

This project simulates a **real engineering task** involving:

- Monorepo architecture with TurboRepo
- Secure API design with Fastify
- AES-256-GCM envelope encryption
- Next.js frontend integration
- Production deployment to Vercel

---

## 🧱 Architecture

The project uses a **TurboRepo monorepo** to share code between applications.

```
secure-tx-app/
│
├── apps/
│   ├── web/        # Next.js frontend
│   └── api/        # Fastify backend
│
├── packages/
│   └── crypto/     # Shared encryption logic
│
├── turbo.json
├── pnpm-workspace.yaml
└── package.json
```

### Apps

| App | Description |
|-----|-------------|
| `apps/web` | Next.js UI for creating and retrieving transactions |
| `apps/api` | Fastify server exposing encryption endpoints |

### Packages

| Package | Description |
|---------|-------------|
| `packages/crypto` | Envelope encryption implementation using AES-256-GCM |

---

## ⚙️ Tech Stack

| Tool | Version | Purpose |
|------|---------|---------|
| Node.js | 20 | Runtime |
| TypeScript | Latest | Type safety |
| pnpm | Latest | Package management |
| TurboRepo | Latest | Monorepo orchestration |
| Fastify | Latest | Backend API server |
| Next.js | Latest | Frontend framework |
| Vercel | — | Deployment |

---

## 🔐 Encryption Design

The system uses **Envelope Encryption**. Instead of encrypting data directly with a master key, a **Data Encryption Key (DEK)** is generated per transaction.

### Flow

```
Payload
  │
  ▼
Generate DEK (32 bytes)
  │
  ▼
Encrypt payload with DEK (AES-256-GCM)
  │
  ▼
Wrap DEK with Master Key (AES-256-GCM)
  │
  ▼
Store encrypted payload + wrapped DEK
```

### Why AES-256-GCM?

AES-GCM provides:

- **Confidentiality** — data is encrypted
- **Integrity** — authentication tag detects tampering
- **Tamper detection** — any modification to ciphertext or tag causes decryption to fail

---

## 📦 Data Model

```ts
export type TxSecureRecord = {
  id: string
  partyId: string
  createdAt: string

  payload_nonce: string
  payload_ct: string
  payload_tag: string

  dek_wrap_nonce: string
  dek_wrapped: string
  dek_wrap_tag: string

  alg: "AES-256-GCM"
  mk_version: 1
}
```

> All binary values are stored as **hex strings**.

---

## 🚀 API Endpoints

### `POST /tx/encrypt` — Encrypt Transaction

**Request**
```json
{
  "partyId": "party_123",
  "payload": {
    "amount": 100,
    "currency": "AED"
  }
}
```

**Response** — Encrypted `TxSecureRecord` object.

---

### `GET /tx/:id` — Get Encrypted Record

Returns the stored encrypted data **without decrypting**.

---

### `POST /tx/:id/decrypt` — Decrypt Record

Returns the **original payload** after decryption.

---

## 💻 Frontend

The frontend is a single-page Next.js UI with the following features:

- Input field for `partyId`
- JSON textarea for the transaction payload
- Action buttons:
  - **Encrypt & Save**
  - **Fetch Record**
  - **Decrypt**
- Display panels for encrypted and decrypted results

> UI is intentionally minimal — functionality is the focus.

---

## 🛡️ Validation & Security

The system rejects requests when:

- Nonce is not 12 bytes
- Tag is not 16 bytes
- Hex values are invalid
- Ciphertext has been tampered with
- Authentication tag has been modified
- Decryption fails for any reason

These checks ensure **data integrity** and **cryptographic correctness** at every step.

---

## 🧪 Tests

Example test cases included:

- `encrypt → decrypt` returns original payload
- Tampered ciphertext fails decryption
- Tampered tag fails decryption
- Invalid nonce length is rejected
- Invalid hex input is rejected

---

## 🧠 Key Design Decisions

### Shared Crypto Package

Encryption logic lives in `packages/crypto`, keeping it:

- **Reusable** across apps
- **Independently testable**
- **Decoupled** from business logic

### In-Memory Storage

Transactions are stored in a `Map<string, TxSecureRecord>` for:

- **Simplicity** — no external setup required
- **Portability** — works out of the box for demos

This can be swapped for a persistent store (PostgreSQL, SQLite, Redis) with minimal changes.

---

## 🚀 Deployment

Both applications are deployed via **Vercel**.

| Service | URL |
|---------|-----|
| Web | `https://your-web-url.vercel.app` |
| API | `https://your-api-url.vercel.app` |

---

## 🧑‍💻 Running Locally

### 1. Install dependencies

```bash
pnpm install
```

### 2. Start development

```bash
pnpm dev
```

This concurrently runs both:

- ⚡ Next.js frontend (`apps/web`)
- 🔧 Fastify API server (`apps/api`)

---
