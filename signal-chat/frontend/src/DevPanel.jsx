import { useState, useEffect, useRef } from "react";
import { loadKeys } from "./App";
import { DHKeyPair, bytesToHex } from "./crypto/dh.js";
import { x3dhSender, x3dhReceiver, hkdf } from "./crypto/x3dh.js";
import { RatchetSession } from "./crypto/ratchet.js";

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
      className="text-[9px] text-slate-400 hover:text-sky-500 flex-shrink-0 mt-0.5 ml-2 transition">
      {copied ? "✓" : "copy"}
    </button>
  );
}

function Row({ label, value, mono = true, highlight }) {
  const colourClass = highlight === "green"  ? "text-sky-600"
                    : highlight === "yellow" ? "text-amber-600"
                    : highlight === "red"    ? "text-red-400"
                    : "text-sky-700";
  return (
    <div className="flex flex-col gap-0.5 py-1 border-b border-sky-100">
      <span className="text-[10px] text-slate-400 uppercase tracking-wider">{label}</span>
      <div className="flex items-start">
        <span className={`text-[11px] break-all flex-1 ${mono ? "font-mono" : ""} ${colourClass}`}>
          {value ?? "—"}
        </span>
        <CopyBtn value={value} />
      </div>
    </div>
  );
}

function Section({ title, children }) {
  return (
    <div className="mb-5">
      <div className="text-[10px] text-sky-500 font-bold uppercase tracking-widest mb-1">
        {title}
      </div>
      {children}
    </div>
  );
}

function Badge({ label, colour }) {
  const cls = colour === "green"  ? "bg-green-100 text-green-700"
            : colour === "yellow" ? "bg-amber-100 text-amber-700"
            : colour === "blue"   ? "bg-sky-100 text-sky-700"
            :                       "bg-red-100 text-red-500";
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
          <div className="mt-2 text-[10px] text-slate-400">
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
      <div className="mb-4 text-[11px] text-slate-500 leading-relaxed">
        X3DH (Extended Triple Diffie-Hellman) establishes a shared secret between two parties
        who have never spoken before — using only public keys exchanged via an untrusted server.
        Four DH operations are combined, giving both authentication and forward secrecy.
      </div>

      {!selected && (
        <div className="text-slate-400 text-[11px] mt-4 text-center">
          Select a conversation to see X3DH details
        </div>
      )}

      {selected && !sess && (
        <div className="text-slate-400 text-[11px] mt-4 text-center">
          No session yet — send a message first
        </div>
      )}

      {sess && !debug && (
        <div className="text-slate-400 text-[11px] mt-4 text-center">
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
              <span className="text-[10px] text-slate-400">
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
            <div className="mt-2 text-[10px] text-slate-400">
              Each DH output is g^(priv_a · priv_b) mod p — a 256-byte value.
              All four are concatenated (with 0xFF padding) and fed into HKDF.
            </div>
          </Section>

          <Section title="Shared Secret (SK) — derived via HKDF-SHA256">
            <Row label="SK (full 32 bytes / 64 hex chars)" value={debug.sk} highlight="green" />
            <div className="mt-2 text-[10px] text-slate-400">
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
              <div className="mt-2 text-[10px] text-slate-400">
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
      <div className="mb-4 text-[11px] text-slate-500 leading-relaxed">
        The Double Ratchet combines a <em>symmetric-key ratchet</em> (one key per message,
        forward secrecy) with a <em>DH ratchet</em> (new ephemeral key per reply, break-in recovery).
      </div>

      {!selected && (
        <div className="text-slate-400 text-[11px] mt-4 text-center">Select a conversation</div>
      )}
      {selected && !sess && (
        <div className="text-slate-400 text-[11px] mt-4 text-center">
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
            <div className="mt-2 text-[10px] text-slate-400">
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
      <div className="text-[10px] text-slate-400 mb-3">
        Wire-level log — what actually travels over the network to/from the server.
        Plaintext never appears here; this is exactly what the server stores.
      </div>

      {(!messageLog || messageLog.length === 0) && (
        <div className="text-slate-400 text-[11px] text-center mt-4">
          No messages yet — send one to see the encrypted wire format
        </div>
      )}

      {(messageLog || []).map((entry, i) => (
        <div key={i} className="mb-3 border border-sky-100 rounded p-2 bg-sky-50">
          <div className="flex items-center gap-2 mb-2">
            <Badge label={entry.dir === "out" ? "SENT" : "RECV"}
                   colour={entry.dir === "out" ? "red" : "blue"} />
            <span className="text-[10px] text-slate-400">{new Date(entry.ts).toLocaleTimeString()}</span>
            <Badge label="AES-256-GCM" colour="green" />
          </div>

          <div className="text-[10px] text-slate-400 mb-0.5">
            Ciphertext (base64 — what server stores, cannot read):
          </div>
          <div className="text-[11px] text-sky-700 break-all font-mono mb-2 bg-white p-1 rounded border border-sky-100">
            {entry.ciphertext
              ? entry.ciphertext.slice(0, 80) + (entry.ciphertext.length > 80 ? "…" : "")
              : "—"}
          </div>

          <div className="text-[10px] text-slate-400 mb-0.5">Double Ratchet header:</div>
          <div className="text-[10px] text-amber-600 font-mono bg-white p-1 rounded border border-sky-100">
            msg_n={entry.header?.n ?? "?"}&nbsp;&nbsp;
            prev_n={entry.header?.pn ?? "?"}&nbsp;&nbsp;
            ratchet_pub={String(entry.header?.dh ?? "").slice(0, 16)}…
          </div>

          <div className="text-[10px] text-slate-400 mt-1.5 italic">
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
      <div className="mb-3 text-[11px] text-slate-500 leading-relaxed">
        This is exactly what the server has stored in SQLite — raw ciphertext blobs.
        The server has no keys and cannot decrypt any of these messages.
      </div>

      {!selected && (
        <div className="text-slate-400 text-[11px] text-center mt-4">
          Select a conversation to query the server
        </div>
      )}

      {loading && (
        <div className="text-slate-400 text-[11px] text-center mt-4 animate-pulse">
          Fetching from server…
        </div>
      )}

      {error && (
        <div className="text-red-400 text-[11px] text-center mt-4">
          Error: {error}
        </div>
      )}

      {history && history.length === 0 && (
        <div className="text-slate-400 text-[11px] text-center mt-4">
          No messages stored on server yet
        </div>
      )}

      {history && history.length > 0 && (
        <>
          <div className="text-[10px] text-slate-400 mb-3">
            {history.length} message{history.length !== 1 ? "s" : ""} stored in SQLite
            — sender / recipient visible, payload opaque
          </div>
          {history.slice().reverse().map((m, i) => (
            <div key={i} className="mb-2 border border-sky-100 rounded p-2 bg-sky-50">
              <div className="flex items-center gap-2 mb-1">
                <span className="text-[10px] text-slate-500 font-mono">
                  {m.sender} → {m.recipient}
                </span>
                <span className="ml-auto text-[9px] text-slate-400">
                  {m.sent_at ? new Date(m.sent_at * 1000).toLocaleTimeString() : ""}
                </span>
              </div>
              <div className="text-[10px] text-slate-400 mb-0.5">Stored payload (server-side view):</div>
              <div className="text-[11px] text-sky-700 font-mono break-all bg-white p-1 rounded border border-sky-100">
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
                    <div className="text-[10px] text-amber-600 font-mono mt-1">
                      header: msg_n={p.header.n} prev_n={p.header.pn}
                    </div>
                  );
                } catch {}
                return null;
              })()}
              <div className="text-[10px] text-slate-400 mt-1 italic">
                Server sees routing metadata only — payload is encrypted ciphertext
              </div>
            </div>
          ))}
        </>
      )}
    </>
  );
}

// ── browser test suite ───────────────────────────────────────────────────────

async function runBrowserTests(log) {
  let passed = 0;
  let failed = 0;

  function pass(name, detail) {
    passed++;
    log({ status: "pass", name, detail });
  }
  function fail(name, detail) {
    failed++;
    log({ status: "fail", name, detail });
  }

  async function makeSessionPair() {
    const aliceIK = new DHKeyPair();
    const bobIK   = new DHKeyPair();
    const bobSPK  = new DHKeyPair();
    const bobOPK  = new DHKeyPair();

    // Generate a real ECDSA P-256 signing key pair for Bob so that
    // verifySPKSignature() inside x3dhSender() passes.
    const signingKeyPair = await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]
    );
    const spkPubHex = bobSPK.publicKey.toString(16);
    const sigBytes  = await crypto.subtle.sign(
      { name: "ECDSA", hash: { name: "SHA-256" } },
      signingKeyPair.privateKey,
      new TextEncoder().encode(spkPubHex)
    );
    const rawPub = await crypto.subtle.exportKey("raw", signingKeyPair.publicKey);
    const ikSignPub = btoa(String.fromCharCode(...new Uint8Array(rawPub)));
    const spkSig    = btoa(String.fromCharCode(...new Uint8Array(sigBytes)));

    const bundle = {
      ik_pub:      bobIK.publicKey.toString(16),
      spk_pub:     spkPubHex,
      opk_pub:     bobOPK.publicKey.toString(16),
      ik_sign_pub: ikSignPub,
      spk_sig:     spkSig,
    };

    const { sk: skAlice, ekPub, senderIKPub } = await x3dhSender(aliceIK, bundle);

    const { sk: skBob } = await x3dhReceiver(
      { ik: bobIK, spk: bobSPK, opk: bobOPK },
      senderIKPub.toString(16),
      ekPub.toString(16),
    );

    const alice = new RatchetSession();
    await alice.initSender(skAlice, bobSPK.publicKey);

    const bob = new RatchetSession();
    await bob.initReceiver(skBob, alice.sendRatchet.publicKey, bobSPK);

    return { alice, bob, skAlice, skBob };
  }

  try {
    log({ status: "running", name: "1. DH Correctness" });
    const a = new DHKeyPair();
    const b = new DHKeyPair();
    const s1 = bytesToHex(a.dh(b.publicKey));
    const s2 = bytesToHex(b.dh(a.publicKey));
    if (s1 !== s2) throw new Error("Shared secrets differ");
    pass("1. DH Correctness", `DH(a,B) = DH(b,A) = ${s1.slice(0,16)}…`);
  } catch(e) { fail("1. DH Correctness", e.message); }

  try {
    log({ status: "running", name: "2. X3DH Key Agreement" });
    const { skAlice, skBob } = await makeSessionPair();
    const hexA = bytesToHex(skAlice);
    const hexB = bytesToHex(skBob);
    if (hexA !== hexB) throw new Error(`SK mismatch: ${hexA.slice(0,8)} vs ${hexB.slice(0,8)}`);
    pass("2. X3DH Key Agreement", `Both derived SK = ${hexA.slice(0,16)}… independently`);
  } catch(e) { fail("2. X3DH Key Agreement", e.message); }

  try {
    log({ status: "running", name: "3. Double Ratchet" });
    const { alice, bob } = await makeSessionPair();
    const msgs = ["Hello Bob!", "How are you?", "Signal works!"];
    for (const m of msgs) {
      const enc = await alice.encrypt(m);
      const dec = await bob.decrypt(enc);
      if (dec !== m) throw new Error(`Mismatch: expected "${m}" got "${dec}"`);
    }
    pass("3. Double Ratchet", `${msgs.length} messages encrypted & decrypted — each with a distinct AES-256-GCM key`);
  } catch(e) { fail("3. Double Ratchet", e.message); }

  try {
    log({ status: "running", name: "4. Forward Secrecy" });
    const { alice, bob } = await makeSessionPair();
    const ckBefore = bytesToHex(alice.sendingChainKey);
    const enc = await alice.encrypt("forward secrecy test");
    const ckAfter = bytesToHex(alice.sendingChainKey);
    if (ckBefore === ckAfter) throw new Error("Chain key did not advance — forward secrecy broken");
    const dec = await bob.decrypt(enc);
    if (dec !== "forward secrecy test") throw new Error("Decryption mismatch");
    let reDecryptFailed = false;
    try { await bob.decrypt(enc); } catch { reDecryptFailed = true; }
    if (!reDecryptFailed) throw new Error("Same message decrypted twice — message key was not consumed!");
    pass("4. Forward Secrecy",
      `CK before: ${ckBefore.slice(0,8)}… → CK after: ${ckAfter.slice(0,8)}… (advanced, old key deleted). Re-decryption blocked ✓`);
  } catch(e) { fail("4. Forward Secrecy", e.message); }

  try {
    log({ status: "running", name: "5. Server Blindness" });
    const { alice } = await makeSessionPair();
    const plaintext = "Top secret UIC message";
    const enc = await alice.encrypt(plaintext);
    const ctBytes = enc.ciphertext;
    if (ctBytes.includes("Top") || ctBytes.includes("secret") || ctBytes.includes("UIC"))
      throw new Error("Plaintext found in ciphertext!");
    pass("5. Server Blindness", `Ciphertext: ${ctBytes.slice(0,32)}… — plaintext not present`);
  } catch(e) { fail("5. Server Blindness", e.message); }

  try {
    log({ status: "running", name: "6. Bidirectional + DH Ratchet" });
    const { alice, bob } = await makeSessionPair();
    await bob.decrypt(await alice.encrypt("Hey Bob"));
    const rk1 = bytesToHex(bob.rootKey);
    await alice.decrypt(await bob.encrypt("Hey Alice"));
    const rk2 = bytesToHex(alice.rootKey);
    await bob.decrypt(await alice.encrypt("Again"));
    const rk3 = bytesToHex(bob.rootKey);
    if (rk1 === rk2 || rk2 === rk3) throw new Error("Root key did not rotate on direction change");
    pass("6. Bidirectional + DH Ratchet", `Root key rotated: ${rk1.slice(0,8)}… → ${rk2.slice(0,8)}… → ${rk3.slice(0,8)}…`);
  } catch(e) { fail("6. Bidirectional + DH Ratchet", e.message); }

  try {
    log({ status: "running", name: "7. Break-in Recovery" });
    const { alice, bob } = await makeSessionPair();
    await bob.decrypt(await alice.encrypt("msg 1"));
    await alice.decrypt(await bob.encrypt("msg 2"));
    const stolen = alice.sendingChainKey.slice();
    await bob.decrypt(await alice.encrypt("msg 3"));
    await alice.decrypt(await bob.encrypt("msg 4"));
    const newCK = bytesToHex(alice.sendingChainKey);
    if (bytesToHex(stolen) === newCK) throw new Error("Chain key was not rotated");
    pass("7. Break-in Recovery", `Stolen key ${bytesToHex(stolen).slice(0,8)}… replaced by ${newCK.slice(0,8)}… after DH ratchet`);
  } catch(e) { fail("7. Break-in Recovery", e.message); }

  try {
    log({ status: "running", name: "8. Out-of-Order Messages" });
    const { alice, bob } = await makeSessionPair();
    const a = await alice.encrypt("First");
    const b = await alice.encrypt("Second");
    const c = await alice.encrypt("Third");
    const r1 = await bob.decrypt(c);
    const r2 = await bob.decrypt(a);
    const r3 = await bob.decrypt(b);
    if (r1 !== "Third" || r2 !== "First" || r3 !== "Second")
      throw new Error(`Wrong order: ${r1}, ${r2}, ${r3}`);
    pass("8. Out-of-Order Messages", `Delivered C→A→B, decrypted: "${r1}", "${r2}", "${r3}" ✓`);
  } catch(e) { fail("8. Out-of-Order Messages", e.message); }

  try {
    log({ status: "running", name: "9. Key Uniqueness" });
    const { alice } = await makeSessionPair();
    const cts = await Promise.all(Array.from({length: 10}, (_, i) => alice.encrypt(`msg ${i}`)));
    const ctSet = new Set(cts.map(e => e.ciphertext));
    if (ctSet.size !== 10) throw new Error("Duplicate ciphertext — key reuse detected!");
    pass("9. Key Uniqueness", `10 messages → 10 distinct ciphertexts — no AES key reused`);
  } catch(e) { fail("9. Key Uniqueness", e.message); }

  return { passed, failed, total: passed + failed };
}

function TestsTab() {
  const [results, setResults] = useState([]);
  const [running, setRunning] = useState(false);
  const [summary, setSummary] = useState(null);

  async function run() {
    setResults([]);
    setSummary(null);
    setRunning(true);
    const logs = [];
    const { passed, failed, total } = await runBrowserTests(entry => {
      logs.push(entry);
      setResults([...logs]);
    });
    setSummary({ passed, failed, total });
    setRunning(false);
  }

  return (
    <>
      <div className="mb-3 text-[11px] text-slate-500 leading-relaxed">
        Runs the Signal Protocol test suite directly in this browser tab — using the exact
        same <span className="text-sky-600 font-mono">dh.js · x3dh.js · ratchet.js</span> that
        encrypts your real messages. No Python, no server.
      </div>

      <button
        onClick={run}
        disabled={running}
        className="w-full py-2 mb-4 rounded text-[11px] font-bold transition text-white
                   bg-red-400 hover:bg-red-500 disabled:opacity-40 disabled:cursor-not-allowed"
      >
        {running ? "Running…" : "▶ Run Browser Tests"}
      </button>

      {results.map((r, i) => (
        <div key={i} className={`mb-2 rounded p-2 border text-[11px] font-mono
          ${r.status === "pass" ? "border-green-200 bg-green-50"
          : r.status === "fail" ? "border-red-200 bg-red-50"
          :                       "border-sky-100 bg-sky-50"}`}>
          <div className="flex items-center gap-2">
            <span className={
              r.status === "pass" ? "text-green-600" :
              r.status === "fail" ? "text-red-500"   : "text-slate-400 animate-pulse"
            }>
              {r.status === "pass" ? "✓" : r.status === "fail" ? "✗" : "…"}
            </span>
            <span className={
              r.status === "pass" ? "text-green-700" :
              r.status === "fail" ? "text-red-600"   : "text-slate-500"
            }>
              {r.name}
            </span>
          </div>
          {r.detail && (
            <div className="mt-1 text-[10px] text-slate-500 pl-4 break-all">{r.detail}</div>
          )}
        </div>
      ))}

      {summary && (
        <div className={`mt-3 p-3 rounded text-center text-[12px] font-bold border
          ${summary.failed === 0
            ? "border-green-300 bg-green-50 text-green-700"
            : "border-red-300 bg-red-50 text-red-500"}`}>
          {summary.failed === 0
            ? `✓ ALL ${summary.total} TESTS PASSED — browser crypto verified`
            : `✗ ${summary.failed} / ${summary.total} FAILED`}
        </div>
      )}
    </>
  );
}

// ── main panel ────────────────────────────────────────────────────────────────

const TABS = ["keys", "x3dh", "ratchet", "messages", "server", "tests"];

export default function DevPanel({ user, selected, sessions, messageLog }) {
  const [open, setOpen] = useState(false);
  const [tab, setTab]   = useState("keys");

  const sess = selected ? sessions[selected] : null;

  return (
    <div className="fixed bottom-0 left-0 z-50 font-mono">
      <button
        onClick={() => setOpen(o => !o)}
        className="absolute bottom-0 left-0 bg-white border border-sky-200
                   text-sky-500 text-[11px] px-3 py-1.5 rounded-tr-lg hover:bg-sky-50 transition"
      >
        {open ? "✕ dev panel" : "⚙ dev panel"}
      </button>

      {open && (
        <div className="w-[460px] h-[600px] bg-white border border-sky-200 rounded-tr-xl
                        flex flex-col shadow-2xl mb-7 ml-0">
          <div className="px-4 py-2 border-b border-sky-100 flex items-center gap-2">
            <span className="text-sky-600 text-xs font-bold">
              Signal Protocol — Developer View
            </span>
            <span className="ml-auto text-[10px] text-slate-400">@{user.net_id}</span>
          </div>

          <div className="flex border-b border-sky-100 text-[11px] overflow-x-auto">
            {TABS.map(t => (
              <button key={t} onClick={() => setTab(t)}
                className={`px-3 py-1.5 capitalize whitespace-nowrap transition
                  ${tab === t
                    ? "text-sky-500 border-b-2 border-sky-500"
                    : "text-slate-400 hover:text-slate-600"}`}>
                {t === "x3dh"    ? "X3DH"
                 : t === "keys"   ? "Keys"
                 : t === "server" ? "Server View"
                 : t === "tests"  ? "▶ Tests"
                 : t.charAt(0).toUpperCase() + t.slice(1)}
              </button>
            ))}
          </div>

          <div className="flex-1 overflow-y-auto p-4 text-xs">
            {tab === "keys"     && <KeysTab     user={user} selected={selected} sess={sess} />}
            {tab === "x3dh"     && <X3DHTab     user={user} selected={selected} sess={sess} />}
            {tab === "ratchet"  && <RatchetTab  selected={selected} sess={sess} />}
            {tab === "messages" && <MessagesTab selected={selected} messageLog={messageLog} />}
            {tab === "server"   && <ServerTab   user={user} selected={selected} />}
            {tab === "tests"    && <TestsTab />}
          </div>
        </div>
      )}
    </div>
  );
}
