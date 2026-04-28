import { useState } from "react";
import { DHKeyPair, bigIntToHex } from "./crypto/dh.js";
import Chat from "./Chat";

const API = "http://localhost:5001";

// ── Key storage ───────────────────────────────────────────────────

function storeKeys(netId, keys) {
  localStorage.setItem(`signal_keys_${netId}`, JSON.stringify({
    ik:  keys.ik.toJSON(),
    spk: keys.spk.toJSON(),
    opk: keys.opk.toJSON(),
  }));
}

export function loadKeys(netId) {
  const raw = localStorage.getItem(`signal_keys_${netId}`);
  if (!raw) return null;
  const d = JSON.parse(raw);
  return {
    ik:  DHKeyPair.fromJSON(d.ik),
    spk: DHKeyPair.fromJSON(d.spk),
    opk: DHKeyPair.fromJSON(d.opk),
  };
}

// ── App ───────────────────────────────────────────────────────────

export default function App() {
  const [user, setUser]       = useState(null);
  const [mode, setMode]       = useState("login");
  const [netId, setNetId]     = useState("");
  const [password, setPassword] = useState("");
  const [error, setError]     = useState("");
  const [loading, setLoading] = useState(false);

  async function handleRegister(e) {
    e.preventDefault();
    setError(""); setLoading(true);
    try {
      // Generate real DH key pairs in the browser
      const ik  = new DHKeyPair();
      const spk = new DHKeyPair();
      const opk = new DHKeyPair();

      // Generate a pool of one-time prekeys so bundle fetches don't exhaust supply
      const opks = Array.from({ length: 10 }, () => new DHKeyPair());

      const res = await fetch(`${API}/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          net_id:  netId.trim().toLowerCase(),
          password,
          ik_pub:  bigIntToHex(ik.publicKey),
          spk_pub: bigIntToHex(spk.publicKey),
          opk_pubs: opks.map(k => bigIntToHex(k.publicKey)),
        }),
      });
      const data = await res.json();
      if (!res.ok) { setError(data.error); return; }

      // Private keys never leave the browser — stored in localStorage only
      storeKeys(netId.trim().toLowerCase(), { ik, spk, opk: opks[0] });
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
      // Check private keys exist on this device before even hitting the server
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
    <div className="min-h-screen bg-[#0a1628] flex items-center justify-center font-mono">
      <div className="w-full max-w-sm">
        <div className="text-center mb-8">
          <div className="text-[#cc0000] text-4xl font-bold tracking-tight">UIC Signal</div>
          <div className="text-gray-400 text-sm mt-1">End-to-end encrypted chat</div>
          <div className="text-gray-600 text-xs mt-1">University of Illinois Chicago</div>
        </div>

        <div className="bg-[#0f1f3d] border border-[#cc0000]/30 rounded-xl p-8">
          <div className="flex mb-6 border-b border-[#cc0000]/20">
            {["login", "register"].map(m => (
              <button
                key={m}
                onClick={() => { setMode(m); setError(""); }}
                className={`flex-1 pb-2 text-sm capitalize transition
                  ${mode === m
                    ? "text-[#cc0000] border-b-2 border-[#cc0000]"
                    : "text-gray-500 hover:text-gray-300"}`}
              >
                {m}
              </button>
            ))}
          </div>

          <form onSubmit={mode === "login" ? handleLogin : handleRegister} className="space-y-4">
            <div>
              <label className="block text-xs text-gray-400 mb-1">NetID</label>
              <input
                value={netId}
                onChange={e => setNetId(e.target.value)}
                placeholder="e.g. jdoe3"
                required
                className="w-full bg-[#0a1628] border border-[#cc0000]/30 rounded px-3 py-2 text-sm
                           text-white placeholder-gray-600 focus:outline-none focus:border-[#cc0000]"
              />
            </div>
            <div>
              <label className="block text-xs text-gray-400 mb-1">Password</label>
              <input
                type="password"
                value={password}
                onChange={e => setPassword(e.target.value)}
                required
                className="w-full bg-[#0a1628] border border-[#cc0000]/30 rounded px-3 py-2 text-sm
                           text-white placeholder-gray-600 focus:outline-none focus:border-[#cc0000]"
              />
            </div>

            {error && (
              <div className={`text-xs px-3 py-2 rounded ${
                error.startsWith("Registered")
                  ? "text-green-400 bg-green-900/20"
                  : "text-[#cc0000] bg-[#cc0000]/10"
              }`}>
                {error}
              </div>
            )}

            <button
              type="submit"
              disabled={loading}
              className="w-full bg-[#cc0000] hover:bg-[#aa0000] disabled:opacity-50
                         py-2 rounded text-sm font-bold transition"
            >
              {loading ? "…" : mode === "login" ? "Sign In" : "Create Account"}
            </button>
          </form>
        </div>

        <div className="text-center mt-4 text-gray-600 text-xs">
          🔒 Signal Protocol · Double Ratchet · X3DH · AES-256-GCM
        </div>
      </div>
    </div>
  );
}
