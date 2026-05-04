import { useState } from "react";
import { DHKeyPair, bigIntToHex } from "./crypto/dh.js";
import Chat from "./Chat";

const API = "http://localhost:5001";

// ── Key storage ───────────────────────────────────────────────────

function storeKeys(netId, keys, signData = null) {
  localStorage.setItem(`signal_keys_${netId}`, JSON.stringify({
    ik:   keys.ik.toJSON(),
    spk:  keys.spk.toJSON(),
    opks: keys.opks.map(k => k.toJSON()),
    ...(signData && { signPrivJwk: signData.privJwk, ikSignPub: signData.ikSignPub }),
  }));
}

export function loadKeys(netId) {
  const raw = localStorage.getItem(`signal_keys_${netId}`);
  if (!raw) return null;
  const d = JSON.parse(raw);
  const opks = d.opks
    ? d.opks.map(k => DHKeyPair.fromJSON(k))
    : [DHKeyPair.fromJSON(d.opk)];
  return {
    ik:   DHKeyPair.fromJSON(d.ik),
    spk:  DHKeyPair.fromJSON(d.spk),
    opks,
    get opk() { return opks[0]; },
  };
}

export function findOpk(netId, opkPubHex) {
  const keys = loadKeys(netId);
  if (!keys) return null;
  return keys.opks.find(k => bigIntToHex(k.publicKey) === opkPubHex) ?? null;
}

function clearSessionState(netId) {
  const toDelete = [];
  for (let i = 0; i < localStorage.length; i++) {
    const key = localStorage.key(i);
    if (key.startsWith(`ratchet_${netId}_`) ||
        key.startsWith(`init_sent_${netId}_`) ||
        key.startsWith(`messages_${netId}_`)) {
      toDelete.push(key);
    }
  }
  toDelete.forEach(k => localStorage.removeItem(k));
}

// ── App ───────────────────────────────────────────────────────────

export default function App() {
  const [user, setUser]         = useState(null);
  const [mode, setMode]         = useState("login");
  const [netId, setNetId]       = useState("");
  const [password, setPassword] = useState("");
  const [error, setError]       = useState("");
  const [loading, setLoading]   = useState(false);

  async function handleRegister(e) {
    e.preventDefault();
    setError(""); setLoading(true);
    try {
      const ik   = new DHKeyPair();
      const spk  = new DHKeyPair();
      const opks = Array.from({ length: 10 }, () => new DHKeyPair());

      // Generate an ECDSA P-256 signing key pair.  This is used to sign the SPK
      // so that anyone who fetches our pre-key bundle can verify the SPK is genuine
      // and was not swapped by the server (SPK signature per Signal spec).
      const signingKeyPair = await crypto.subtle.generateKey(
        { name: "ECDSA", namedCurve: "P-256" },
        true,
        ["sign", "verify"]
      );

      // Sign the SPK public key hex string with the signing private key
      const spkPubHex = bigIntToHex(spk.publicKey);
      const sigBytes  = await crypto.subtle.sign(
        { name: "ECDSA", hash: { name: "SHA-256" } },
        signingKeyPair.privateKey,
        new TextEncoder().encode(spkPubHex)
      );

      // Export signing public key as raw bytes (65 bytes, uncompressed P-256 point)
      const rawPub    = await crypto.subtle.exportKey("raw", signingKeyPair.publicKey);
      const ikSignPub = btoa(String.fromCharCode(...new Uint8Array(rawPub)));
      const spkSig    = btoa(String.fromCharCode(...new Uint8Array(sigBytes)));

      // Export signing private key as JWK so we can re-sign if SPK is rotated later
      const signPrivJwk = await crypto.subtle.exportKey("jwk", signingKeyPair.privateKey);

      const res = await fetch(`${API}/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          net_id:      netId.trim().toLowerCase(),
          password,
          ik_pub:      bigIntToHex(ik.publicKey),
          spk_pub:     spkPubHex,
          opk_pubs:    opks.map(k => bigIntToHex(k.publicKey)),
          ik_sign_pub: ikSignPub,
          spk_sig:     spkSig,
        }),
      });
      const data = await res.json();
      if (!res.ok) { setError(data.error); return; }

      clearSessionState(netId.trim().toLowerCase());
      storeKeys(netId.trim().toLowerCase(), { ik, spk, opks }, { privJwk: signPrivJwk, ikSignPub });
      setMode("login");
      setError("Registered! Please log in.");
    } catch {
      setError("Server unreachable");
    } finally {
      setLoading(false);
    }
  }

  async function handleLogin(e) {
    e.preventDefault();
    setError(""); setLoading(true);
    const id = netId.trim().toLowerCase();
    try {
      const keys = loadKeys(id);
      if (!keys) {
        setError("No keys found for this NetID on this device. Register first.");
        return;
      }
      const res = await fetch(`${API}/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ net_id: id, password }),
      });
      const data = await res.json();
      if (!res.ok) { setError(data.error); return; }
      setUser({ net_id: data.net_id, fingerprint: data.fingerprint });
    } catch {
      setError("Server unreachable");
    } finally {
      setLoading(false);
    }
  }

  if (user) return <Chat user={user} onLogout={() => setUser(null)} />;

  return (
    <div className="min-h-screen flex items-center justify-center font-mono"
         style={{ background: "linear-gradient(to bottom, #0284c7 0%, #0ea5e9 20%, #38bdf8 48%, #7dd3fc 72%, #bae6fd 100%)" }}>
      <div className="w-full max-w-sm">
        <div className="text-center mb-8">
          <div className="text-white text-4xl font-bold tracking-tight drop-shadow-md">UIC Signal</div>
          <div className="text-white/80 text-sm mt-1">End-to-end encrypted chat</div>
          <div className="text-white/60 text-xs mt-1">University of Illinois Chicago</div>
        </div>

        <div className="bg-white border border-sky-200 rounded-xl p-8 shadow-sm">
          <div className="flex mb-6 border-b border-sky-100">
            {["login", "register"].map(m => (
              <button
                key={m}
                onClick={() => { setMode(m); setError(""); }}
                className={`flex-1 pb-2 text-sm capitalize transition
                  ${mode === m
                    ? "text-sky-500 border-b-2 border-sky-500"
                    : "text-slate-400 hover:text-slate-600"}`}
              >
                {m}
              </button>
            ))}
          </div>

          <form onSubmit={mode === "login" ? handleLogin : handleRegister} className="space-y-4">
            <div>
              <label className="block text-xs text-slate-500 mb-1">NetID</label>
              <input
                value={netId}
                onChange={e => setNetId(e.target.value)}
                placeholder="e.g. jdoe3"
                required
                className="w-full bg-sky-50 border border-sky-200 rounded px-3 py-2 text-sm
                           text-black placeholder-slate-400 focus:outline-none focus:border-sky-400"
              />
            </div>
            <div>
              <label className="block text-xs text-slate-500 mb-1">Password</label>
              <input
                type="password"
                value={password}
                onChange={e => setPassword(e.target.value)}
                required
                className="w-full bg-sky-50 border border-sky-200 rounded px-3 py-2 text-sm
                           text-black placeholder-slate-400 focus:outline-none focus:border-sky-400"
              />
            </div>

            {error && (
              <div className={`text-xs px-3 py-2 rounded ${
                error.startsWith("Registered")
                  ? "text-green-700 bg-green-50 border border-green-200"
                  : "text-red-400 bg-red-50 border border-red-200"
              }`}>
                {error}
              </div>
            )}

            <button
              type="submit"
              disabled={loading}
              className="w-full bg-sky-500 hover:bg-sky-600 disabled:opacity-50
                         py-2 rounded text-sm font-bold text-white transition"
            >
              {loading ? "…" : mode === "login" ? "Sign In" : "Create Account"}
            </button>
          </form>
        </div>

        <div className="text-center mt-4 text-white/70 text-xs">
          🔒 Signal Protocol · Double Ratchet · X3DH · AES-256-GCM
        </div>
      </div>
    </div>
  );
}
