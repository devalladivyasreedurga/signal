import { useState, useEffect } from "react";
import { loadKeys } from "./App";

const API = "http://localhost:5001";

// ── tiny shared components ────────────────────────────────────────────────────

function CopyBtn({ value }) {
  const [copied, setCopied] = useState(false);
  function copy() {
    navigator.clipboard.writeText(value ?? "");
    setCopied(true);
    setTimeout(() => setCopied(false), 1200);
  }
  return (
    <button onClick={copy}
      className="text-[9px] text-gray-600 hover:text-gray-300 flex-shrink-0 mt-0.5 ml-2">
      {copied ? "✓" : "copy"}
    </button>
  );
}

function Row({ label, value, mono = true, highlight }) {
  const colourClass = highlight === "green"  ? "text-green-400"
                    : highlight === "yellow" ? "text-yellow-400"
                    : highlight === "red"    ? "text-red-400"
                    : "text-green-400";
  return (
    <div className="flex flex-col gap-0.5 py-1 border-b border-white/5">
      <span className="text-[10px] text-gray-500 uppercase tracking-wider">{label}</span>
      <div className="flex items-start">
        <span className={`text-[11px] break-all flex-1 ${mono ? "font-mono" : ""} ${colourClass}`}>
          {value ?? "—"}
        </span>
        <CopyBtn value={value} />
      </div>
    </div>
  );
}

function Section({ title, children, colour = "cc0000" }) {
  return (
    <div className="mb-5">
      <div className={`text-[10px] text-[#${colour}] font-bold uppercase tracking-widest mb-1`}>
        {title}
      </div>
      {children}
    </div>
  );
}

function Badge({ label, colour }) {
  const cls = colour === "green"  ? "bg-green-900/50 text-green-400"
            : colour === "yellow" ? "bg-yellow-900/50 text-yellow-400"
            : colour === "blue"   ? "bg-blue-900/50 text-blue-400"
            :                       "bg-[#cc0000]/30 text-[#cc0000]";
  return (
    <span className={`text-[9px] px-2 py-0.5 rounded font-bold ${cls}`}>{label}</span>
  );
}

// ── individual tabs ───────────────────────────────────────────────────────────

function KeysTab({ user, selected, sess }) {
  const keys = loadKeys(user.net_id);

  return (
    <>
      <Section title="Your Identity Keys (localStorage — never leave browser)">
        <Row label="Identity Key (IK) — public"
             value={keys ? keys.ik.publicKey.toString(16) : "not found"} />
        <Row label="Identity Key (IK) — private  ⚠ NEVER sent to server"
             value={keys ? "0x" + keys.ik.privateKey.toString(16).slice(0, 20) + "… [hidden for security]" : "not found"}
             highlight="yellow" />
        <Row label="Signed Pre-Key (SPK) — public"
             value={keys ? keys.spk.publicKey.toString(16) : "not found"} />
        <Row label="Signed Pre-Key (SPK) — private  ⚠ stays in browser"
             value={keys ? "0x" + keys.spk.privateKey.toString(16).slice(0, 20) + "… [hidden]" : "not found"}
             highlight="yellow" />
        <Row label="One-Time Pre-Key (OPK) — public"
             value={keys ? keys.opk.publicKey.toString(16) : "not found"} />
        <Row label="Fingerprint (IK[:8]:SPK[:8])" value={user.fingerprint} highlight="green" />
      </Section>

      <Section title="Diffie-Hellman Parameters (RFC 3526 Group 14)">
        <Row label="Group" value="MODP Group 14 — 2048-bit prime" mono={false} />
        <Row label="Generator (g)" value="2" />
        <Row label="Prime (p) — first 64 hex chars"
             value="ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74…" />
        <Row label="Operation" value="g^private mod p  (square-and-multiply, NO library)" mono={false} />
        <Row label="Shared secret size" value="2048 bits (256 bytes)" mono={false} />
        <Row label="JS implementation" value="dh.js — BigInt, no crypto library" mono={false} />
        <Row label="Python implementation" value="crypto/dh.py — pow() only for modexp" mono={false} />
      </Section>

      {sess?._peerBundle && (
        <Section title={`Peer Public Bundle — @${selected} (received from server)`}>
          <Row label="Peer IK (public)"  value={String(sess._peerBundle.ik_pub)} />
          <Row label="Peer SPK (public)" value={String(sess._peerBundle.spk_pub)} />
          <Row label="Peer OPK (public)" value={String(sess._peerBundle.opk_pub ?? "exhausted")} />
          <Row label="Peer Fingerprint"  value={sess._peerBundle.fingerprint} highlight="green" />
          <div className="mt-2 text-[10px] text-gray-600">
            The server only ever stores these <em>public</em> keys.
            Private keys are generated in the browser and never transmitted.
          </div>
        </Section>
      )}
    </>
  );
}

function X3DHTab({ user, selected, sess }) {
  const debug = sess?._x3dhDebug;
  const keys  = loadKeys(user.net_id);

  return (
    <>
      <div className="mb-4 text-[11px] text-gray-400 leading-relaxed">
        X3DH (Extended Triple Diffie-Hellman) establishes a shared secret between two parties
        who have never spoken before — using only public keys exchanged via an untrusted server.
        Four DH operations are combined, giving both authentication and forward secrecy.
      </div>

      {!selected && (
        <div className="text-gray-600 text-[11px] mt-4 text-center">
          Select a conversation to see X3DH details
        </div>
      )}

      {selected && !sess && (
        <div className="text-gray-600 text-[11px] mt-4 text-center">
          No session yet — send a message first
        </div>
      )}

      {sess && !debug && (
        <div className="text-gray-600 text-[11px] mt-4 text-center">
          X3DH debug data not captured — start a fresh conversation
        </div>
      )}

      {debug && (
        <>
          <Section title="Role in this session">
            <div className="flex items-center gap-3 py-2">
              <Badge
                label={debug.role === "initiator" ? "INITIATOR (Alice)" : "RESPONDER (Bob)"}
                colour={debug.role === "initiator" ? "green" : "blue"}
              />
              <span className="text-[10px] text-gray-500">
                {debug.role === "initiator"
                  ? "You sent the first message and ran X3DH sender-side"
                  : "You received the first message and ran X3DH receiver-side"}
              </span>
            </div>
          </Section>

          <Section title="Four DH Operations (all computed in browser)">
            {[
              { key: "dh1", colour: "green" },
              { key: "dh2", colour: "yellow" },
              { key: "dh3", colour: "green" },
              { key: "dh4", colour: "blue" },
            ].map(({ key, colour }) => (
              <Row
                key={key}
                label={`${key.toUpperCase()} — ${debug[key]?.label}`}
                value={debug[key]?.hex}
                highlight={colour}
              />
            ))}
            <div className="mt-2 text-[10px] text-gray-600">
              Each DH output is g^(priv_a · priv_b) mod p — a 256-byte value.
              All four are concatenated (with 0xFF padding) and fed into HKDF.
            </div>
          </Section>

          <Section title="Shared Secret (SK) — derived via HKDF-SHA256">
            <Row label="SK (full 32 bytes / 64 hex chars)" value={debug.sk} highlight="green" />
            <div className="mt-2 text-[10px] text-gray-600">
              Alice and Bob compute this independently from different DH halves.
              They arrive at the same SK without ever transmitting it.
              The server never sees any of the inputs or outputs above.
            </div>
          </Section>

          <Section title="HKDF Input Construction">
            <Row label="Input" value="0xFF×32 || DH1 || DH2 || DH3 || DH4 (1056 bytes)" />
            <Row label="Salt"  value="0x00×32 (32 zero bytes)" />
            <Row label="Info"  value='"UIC-Signal-X3DH-v1" (UTF-8)' />
            <Row label="Hash"  value="SHA-256 (WebCrypto HKDF)" mono={false} />
            <Row label="Output" value="32 bytes = session SK" mono={false} />
          </Section>

          {sess._initHeader && (
            <Section title="X3DH Header (sent in first message to bootstrap Bob)">
              <Row label="Ephemeral Key (EK) public — sent to server"
                   value={String(sess._initHeader.ek_pub)} />
              <Row label="Sender IK public — sent to server"
                   value={String(sess._initHeader.sender_ik_pub)} />
              <div className="mt-2 text-[10px] text-gray-600">
                Bob uses EK_pub + Sender_IK_pub (plus his own private keys) to derive
                the same four DH values and reconstruct SK — without any help from the server.
              </div>
            </Section>
          )}
        </>
      )}
    </>
  );
}

function RatchetTab({ selected, sess }) {
  function hex8(val) {
    if (!val) return "—";
    if (val instanceof Uint8Array) return Array.from(val).map(b => b.toString(16).padStart(2,"0")).join("").slice(0, 16) + "…";
    if (typeof val === "bigint")   return val.toString(16).slice(0, 16) + "…";
    return String(val).slice(0, 16) + "…";
  }

  return (
    <>
      <div className="mb-4 text-[11px] text-gray-400 leading-relaxed">
        The Double Ratchet combines a <em>symmetric-key ratchet</em> (one key per message,
        forward secrecy) with a <em>DH ratchet</em> (new ephemeral key per reply, break-in recovery).
      </div>

      {!selected && (
        <div className="text-gray-600 text-[11px] mt-4 text-center">Select a conversation</div>
      )}
      {selected && !sess && (
        <div className="text-gray-600 text-[11px] mt-4 text-center">
          No session yet — send a message first
        </div>
      )}

      {sess && (
        <>
          <Section title="Ratchet Keys (rotate on every reply)">
            <Row label="Send ratchet public key"
                 value={sess.sendRatchet ? sess.sendRatchet.publicKey.toString(16).slice(0, 64) + "…" : "—"} />
            <Row label="Recv ratchet public key"
                 value={sess.recvRatchetPub ? sess.recvRatchetPub.toString(16).slice(0, 64) + "…" : "—"} />
          </Section>

          <Section title="Chain Keys (advance every message → forward secrecy)">
            <Row label="Root Key (RK)"          value={hex8(sess.rootKey)} highlight="yellow" />
            <Row label="Sending Chain Key (CKs)" value={hex8(sess.sendingChainKey)} highlight="green" />
            <Row label="Recv Chain Key (CKr)"    value={hex8(sess.recvChainKey)} highlight="blue" />
            <div className="mt-2 text-[10px] text-gray-600">
              Each chain key produces one message key (MK) then advances to the next CK.
              The previous CK is deleted — a compromised device cannot decrypt past messages.
            </div>
          </Section>

          <Section title="Message Counters">
            <Row label="Messages sent (Ns)"     value={String(sess.sendMsgNum)} />
            <Row label="Messages received (Nr)" value={String(sess.recvMsgNum)} />
            <Row label="Skipped keys buffered"  value={String(Object.keys(sess.skipped || {}).length)} />
          </Section>

          <Section title="Per-Message Encryption">
            <Row label="Algorithm"     value="AES-256-GCM" mono={false} />
            <Row label="Message key"   value="32 bytes from HKDF(chain key)" mono={false} />
            <Row label="Nonce"         value="12-byte random, prepended to ciphertext" mono={false} />
            <Row label="Header fields" value="dh (ratchet pub), n (msg #), pn (prev chain #)" mono={false} />
            <Row label="KDF"           value="HKDF-SHA256 (WebCrypto)" mono={false} />
          </Section>

          <Section title="Security Properties">
            <Row label="Forward secrecy"    value="Yes — old chain keys deleted after each message" mono={false} highlight="green" />
            <Row label="Break-in recovery"  value="Yes — new DH ratchet key on each reply" mono={false} highlight="green" />
            <Row label="Out-of-order msgs"  value="Yes — skipped keys buffered by (ratchet_pub, n)" mono={false} highlight="green" />
          </Section>
        </>
      )}
    </>
  );
}

function MessagesTab({ selected, messageLog }) {
  return (
    <>
      <div className="text-[10px] text-gray-600 mb-3">
        Wire-level log — what actually travels over the network to/from the server.
        Plaintext never appears here; this is exactly what the server stores.
      </div>

      {(!messageLog || messageLog.length === 0) && (
        <div className="text-gray-600 text-[11px] text-center mt-4">
          No messages yet — send one to see the encrypted wire format
        </div>
      )}

      {(messageLog || []).map((entry, i) => (
        <div key={i} className="mb-3 border border-white/5 rounded p-2 bg-black/20">
          <div className="flex items-center gap-2 mb-2">
            <Badge label={entry.dir === "out" ? "SENT" : "RECV"}
                   colour={entry.dir === "out" ? "red" : "blue"} />
            <span className="text-[10px] text-gray-500">{new Date(entry.ts).toLocaleTimeString()}</span>
            <Badge label="AES-256-GCM" colour="green" />
          </div>

          <div className="text-[10px] text-gray-500 mb-0.5">
            Ciphertext (base64 — what server stores, cannot read):
          </div>
          <div className="text-[11px] text-green-400 break-all font-mono mb-2 bg-black/30 p-1 rounded">
            {entry.ciphertext
              ? entry.ciphertext.slice(0, 80) + (entry.ciphertext.length > 80 ? "…" : "")
              : "—"}
          </div>

          <div className="text-[10px] text-gray-500 mb-0.5">Double Ratchet header:</div>
          <div className="text-[10px] text-yellow-500 font-mono bg-black/30 p-1 rounded">
            msg_n={entry.header?.n ?? "?"}&nbsp;&nbsp;
            prev_n={entry.header?.pn ?? "?"}&nbsp;&nbsp;
            ratchet_pub={String(entry.header?.dh ?? "").slice(0, 16)}…
          </div>

          <div className="text-[10px] text-gray-600 mt-1.5 italic">
            {entry.dir === "out"
              ? "↑ Encrypted in browser before leaving device — server sees only bytes above"
              : "↓ Arrived as bytes above — decrypted in browser after receipt"}
          </div>
        </div>
      ))}
    </>
  );
}

function ServerTab({ user, selected }) {
  const [history, setHistory] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError]     = useState(null);

  useEffect(() => {
    if (!selected) { setHistory(null); return; }
    setLoading(true);
    setError(null);
    fetch(`${API}/history/${user.net_id}/${selected}`)
      .then(r => r.json())
      .then(data => { setHistory(data); setLoading(false); })
      .catch(e  => { setError(e.message); setLoading(false); });
  }, [selected, user.net_id]);

  return (
    <>
      <div className="mb-3 text-[11px] text-gray-400 leading-relaxed">
        This is exactly what the server has stored in SQLite — raw ciphertext blobs.
        The server has no keys and cannot decrypt any of these messages.
      </div>

      {!selected && (
        <div className="text-gray-600 text-[11px] text-center mt-4">
          Select a conversation to query the server
        </div>
      )}

      {loading && (
        <div className="text-gray-500 text-[11px] text-center mt-4 animate-pulse">
          Fetching from server…
        </div>
      )}

      {error && (
        <div className="text-red-500 text-[11px] text-center mt-4">
          Error: {error}
        </div>
      )}

      {history && history.length === 0 && (
        <div className="text-gray-600 text-[11px] text-center mt-4">
          No messages stored on server yet
        </div>
      )}

      {history && history.length > 0 && (
        <>
          <div className="text-[10px] text-gray-500 mb-3">
            {history.length} message{history.length !== 1 ? "s" : ""} stored in SQLite
            — sender / recipient visible, payload opaque
          </div>
          {history.slice().reverse().map((m, i) => (
            <div key={i} className="mb-2 border border-white/5 rounded p-2 bg-black/20">
              <div className="flex items-center gap-2 mb-1">
                <span className="text-[10px] text-gray-400 font-mono">
                  {m.sender} → {m.recipient}
                </span>
                <span className="ml-auto text-[9px] text-gray-600">
                  {m.sent_at ? new Date(m.sent_at * 1000).toLocaleTimeString() : ""}
                </span>
              </div>
              <div className="text-[10px] text-gray-500 mb-0.5">Stored payload (server-side view):</div>
              <div className="text-[11px] text-green-400 font-mono break-all bg-black/30 p-1 rounded">
                {(() => {
                  try {
                    const p = typeof m.payload === "string" ? JSON.parse(m.payload) : m.payload;
                    const ct = p?.ciphertext ?? JSON.stringify(p);
                    return ct.slice(0, 100) + (ct.length > 100 ? "…" : "");
                  } catch {
                    return String(m.payload ?? "—").slice(0, 100) + "…";
                  }
                })()}
              </div>
              {(() => {
                try {
                  const p = typeof m.payload === "string" ? JSON.parse(m.payload) : m.payload;
                  if (p?.header) return (
                    <div className="text-[10px] text-yellow-600 font-mono mt-1">
                      header: msg_n={p.header.n} prev_n={p.header.pn}
                    </div>
                  );
                } catch {}
                return null;
              })()}
              <div className="text-[10px] text-gray-700 mt-1 italic">
                Server sees routing metadata only — payload is encrypted ciphertext
              </div>
            </div>
          ))}
        </>
      )}
    </>
  );
}

// ── main panel ────────────────────────────────────────────────────────────────

const TABS = ["keys", "x3dh", "ratchet", "messages", "server"];

export default function DevPanel({ user, selected, sessions, messageLog }) {
  const [open, setOpen] = useState(false);
  const [tab, setTab]   = useState("keys");

  const sess = selected ? sessions[selected] : null;

  return (
    <div className="fixed bottom-0 right-0 z-50 font-mono">
      {/* Toggle button */}
      <button
        onClick={() => setOpen(o => !o)}
        className="absolute bottom-0 right-0 bg-[#0a1628] border border-[#cc0000]/40
                   text-[#cc0000] text-[11px] px-3 py-1.5 rounded-tl-lg hover:bg-[#cc0000]/10 transition"
      >
        {open ? "✕ dev panel" : "⚙ dev panel"}
      </button>

      {open && (
        <div className="w-[460px] h-[600px] bg-[#080f1e] border border-[#cc0000]/30 rounded-tl-xl
                        flex flex-col shadow-2xl mb-7 mr-0">
          {/* Header */}
          <div className="px-4 py-2 border-b border-[#cc0000]/20 flex items-center gap-2">
            <span className="text-[#cc0000] text-xs font-bold">
              Signal Protocol — Developer View
            </span>
            <span className="ml-auto text-[10px] text-gray-600">@{user.net_id}</span>
          </div>

          {/* Tabs */}
          <div className="flex border-b border-white/5 text-[11px] overflow-x-auto">
            {TABS.map(t => (
              <button key={t} onClick={() => setTab(t)}
                className={`px-3 py-1.5 capitalize whitespace-nowrap transition
                  ${tab === t
                    ? "text-[#cc0000] border-b-2 border-[#cc0000]"
                    : "text-gray-600 hover:text-gray-400"}`}>
                {t === "x3dh"   ? "X3DH"
                 : t === "keys" ? "Keys"
                 : t === "server" ? "Server View"
                 : t.charAt(0).toUpperCase() + t.slice(1)}
              </button>
            ))}
          </div>

          {/* Content */}
          <div className="flex-1 overflow-y-auto p-4 text-xs">
            {tab === "keys"     && <KeysTab     user={user} selected={selected} sess={sess} />}
            {tab === "x3dh"     && <X3DHTab     user={user} selected={selected} sess={sess} />}
            {tab === "ratchet"  && <RatchetTab  selected={selected} sess={sess} />}
            {tab === "messages" && <MessagesTab selected={selected} messageLog={messageLog} />}
            {tab === "server"   && <ServerTab   user={user} selected={selected} />}
          </div>
        </div>
      )}
    </div>
  );
}
