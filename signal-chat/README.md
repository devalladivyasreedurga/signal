# UIC Signal Chat

End-to-end encrypted chat implementing the Signal Protocol from scratch.
Built for CS 487 — University of Illinois Chicago.

---

## What was built

A full chat application where the server is a blind relay — it stores and
delivers messages but can never read them. Only the two people in a
conversation hold the keys needed to decrypt.

### Crypto layer

| File | What it does |
|---|---|
| `crypto/dh.py` | Diffie-Hellman from scratch — RFC 3526 Group 14 (2048-bit), square-and-multiply modular exponentiation, no library |
| `crypto/x3dh.py` | Extended Triple Diffie-Hellman — establishes a shared secret between two parties without transmitting it |
| `crypto/ratchet.py` | Double Ratchet — per-message AES-256-GCM keys, forward secrecy, break-in recovery |
| `frontend/src/crypto/dh.js` | Exact mirror of dh.py in JavaScript using BigInt — same prime, same algorithm |
| `frontend/src/crypto/x3dh.js` | X3DH in the browser — runs locally, shared key never leaves the device |
| `frontend/src/crypto/ratchet.js` | Double Ratchet in the browser — AES-256-GCM via WebCrypto API |

The Python and JavaScript implementations use the same RFC 3526 Group 14
prime and the same square-and-multiply algorithm. The only library calls
allowed are AES-256-GCM and HKDF.

### Server layer (Flask + Redis + SQLite)

The server never imports or calls any crypto code.

- **SQLite** — stores users, public key bundles, and ciphertext blobs permanently
- **Redis** — temporary offline message queue, drained on recipient login
- **WebSocket** — real-time delivery when recipient is online

### Frontend (React + Vite + Tailwind)

- Generates real DH key pairs on registration; private keys stay in `localStorage`
- Runs X3DH locally on first message to establish shared key
- Encrypts every message with AES-256-GCM before sending
- Decrypts on receive; stores plaintext in `localStorage` (your device only)
- Server only ever receives and stores hex ciphertext

### Guarantees

| Property | How |
|---|---|
| E2E encryption | Private keys never leave the browser; AES-256-GCM in browser |
| Forward secrecy | Chain keys deleted after use; past messages irrecoverable |
| Break-in recovery | DH ratchet generates fresh keys on every reply |
| Server blindness | Server stores ciphertext only; has no keys |
| No double delivery | Redis drain-on-read; every message has a UUID |

---

## How to run

### Prerequisites

```bash
brew install redis node python3
```

### Start everything

```bash
cd signal-chat
./run.sh
```

This will:
1. Start Redis
2. Create a Python venv and install dependencies
3. Start Flask backend on `http://localhost:5001`
4. Install frontend dependencies and start Vite on `http://localhost:3000`

Open two browser tabs at `http://localhost:3000`, register a user in each,
and start chatting.

### Run the test suite

```bash
cd signal-chat
./test.sh
```

Or run just the crypto tests directly:

```bash
source .venv/bin/activate
python tests/demo.py
```

Tests verify: DH correctness, X3DH key agreement, Double Ratchet
encryption/decryption, forward secrecy, server blindness, and offline
delivery without double-delivery.

### Verify encryption manually

```bash
# Messages in Redis (offline queue) — should be hex ciphertext only
redis-cli lrange inbox:<netid> 0 -1

# Messages in SQLite — should be hex ciphertext only
sqlite3 server/signal.db "SELECT sender, payload FROM messages ORDER BY id DESC LIMIT 5;"

# Who is currently online
curl http://localhost:5001/online
```

---

## Project structure

```
signal-chat/
├── crypto/
│   ├── dh.py          # DH from scratch (Python)
│   ├── x3dh.py        # X3DH key agreement
│   └── ratchet.py     # Double Ratchet, AES-256-GCM
├── server/
│   ├── app.py         # Flask + WebSocket server
│   ├── database.py    # SQLite: users, prekeys, messages
│   └── queue.py       # Redis offline queue
├── frontend/src/
│   ├── crypto/
│   │   ├── dh.js      # DH from scratch (JavaScript, BigInt)
│   │   ├── x3dh.js    # X3DH in the browser
│   │   └── ratchet.js # Double Ratchet, WebCrypto AES-256-GCM
│   ├── App.jsx        # Login, register, key generation
│   ├── Chat.jsx       # Real-time chat UI
│   └── socket.js      # WebSocket client
├── tests/
│   └── demo.py        # Proves all five protocol guarantees
├── requirements.txt
├── run.sh             # Starts all services
└── test.sh            # Full test suite
```
