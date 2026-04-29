import { useState, useEffect, useRef, useCallback } from "react";
import socket from "./socket";
import { loadKeys, findOpk } from "./App";
import { DHKeyPair, hexToBigInt } from "./crypto/dh.js";
import { x3dhSender, x3dhReceiver } from "./crypto/x3dh.js";
import { RatchetSession } from "./crypto/ratchet.js";
import DevPanel from "./DevPanel.jsx";

const API = "http://localhost:5001";

// ── localStorage helpers ──────────────────────────────────────────

function saveSession(myId, peerId, sess) {
  localStorage.setItem(`ratchet_${myId}_${peerId}`, sess.serialize());
}

function loadSession(myId, peerId) {
  const raw = localStorage.getItem(`ratchet_${myId}_${peerId}`);
  return raw ? RatchetSession.deserialize(raw) : null;
}

function saveMessages(myId, peerId, msgs) {
  localStorage.setItem(`messages_${myId}_${peerId}`, JSON.stringify(msgs));
}

function loadMessages(myId, peerId) {
  const raw = localStorage.getItem(`messages_${myId}_${peerId}`);
  return raw ? JSON.parse(raw) : [];
}

function markInitSent(myId, peerId) {
  localStorage.setItem(`init_sent_${myId}_${peerId}`, "1");
}

function wasInitSent(myId, peerId) {
  return !!localStorage.getItem(`init_sent_${myId}_${peerId}`);
}

// ── Sky background (pixel art) ────────────────────────────────────

function SkyBackground() {
  return (
    <>
      <style>{`
        @keyframes birdFly {
          from { transform: translateX(-60px); }
          to   { transform: translateX(calc(100vw + 60px)); }
        }
        @keyframes cloudDrift1 {
          0%, 100% { transform: translateX(0px); }
          50%      { transform: translateX(20px); }
        }
        @keyframes cloudDrift2 {
          0%, 100% { transform: translateX(0px); }
          50%      { transform: translateX(-14px); }
        }
      `}</style>

      <div
        className="fixed inset-0"
        style={{
          zIndex: 0,
          background: "linear-gradient(to bottom, #0284c7 0%, #0ea5e9 20%, #38bdf8 48%, #7dd3fc 72%, #bae6fd 100%)",
        }}
      >
        {/* Cloud 1 — large, left (pixel art stacked rects, P=8) */}
        <div style={{ position:"absolute", top:"7%", left:"5%", animation:"cloudDrift1 14s ease-in-out infinite" }}>
          <svg width="112" height="40" viewBox="0 0 112 40" shapeRendering="crispEdges">
            <rect x="24" y="0"  width="64" height="8" fill="white" opacity="0.96"/>
            <rect x="16" y="8"  width="80" height="8" fill="white" opacity="0.96"/>
            <rect x="8"  y="16" width="96" height="8" fill="white" opacity="0.96"/>
            <rect x="0"  y="24" width="112" height="8" fill="white" opacity="0.96"/>
            <rect x="0"  y="32" width="112" height="8" fill="white" opacity="0.96"/>
          </svg>
        </div>

        {/* Cloud 2 — medium, right (P=7) */}
        <div style={{ position:"absolute", top:"16%", right:"9%", animation:"cloudDrift2 19s ease-in-out infinite 3s" }}>
          <svg width="84" height="28" viewBox="0 0 84 28" shapeRendering="crispEdges">
            <rect x="14" y="0"  width="56" height="7" fill="white" opacity="0.90"/>
            <rect x="7"  y="7"  width="70" height="7" fill="white" opacity="0.90"/>
            <rect x="0"  y="14" width="84" height="7" fill="white" opacity="0.90"/>
            <rect x="0"  y="21" width="84" height="7" fill="white" opacity="0.90"/>
          </svg>
        </div>

        {/* Cloud 3 — small, top-center (P=5) */}
        <div style={{ position:"absolute", top:"4%", left:"42%", animation:"cloudDrift1 24s ease-in-out infinite 7s" }}>
          <svg width="60" height="20" viewBox="0 0 60 20" shapeRendering="crispEdges">
            <rect x="10" y="0"  width="40" height="5" fill="white" opacity="0.84"/>
            <rect x="5"  y="5"  width="50" height="5" fill="white" opacity="0.84"/>
            <rect x="0"  y="10" width="60" height="5" fill="white" opacity="0.84"/>
            <rect x="0"  y="15" width="60" height="5" fill="white" opacity="0.84"/>
          </svg>
        </div>

        {/* Cloud 4 — medium, mid-screen left (P=6) */}
        <div style={{ position:"absolute", top:"38%", left:"2%", animation:"cloudDrift2 17s ease-in-out infinite 4s" }}>
          <svg width="96" height="30" viewBox="0 0 96 30" shapeRendering="crispEdges">
            <rect x="18" y="0"  width="60" height="6" fill="white" opacity="0.88"/>
            <rect x="12" y="6"  width="72" height="6" fill="white" opacity="0.88"/>
            <rect x="6"  y="12" width="84" height="6" fill="white" opacity="0.88"/>
            <rect x="0"  y="18" width="96" height="6" fill="white" opacity="0.88"/>
            <rect x="0"  y="24" width="96" height="6" fill="white" opacity="0.88"/>
          </svg>
        </div>

        {/* Cloud 5 — tiny wisp, mid-right (P=4) */}
        <div style={{ position:"absolute", top:"32%", right:"18%", animation:"cloudDrift1 20s ease-in-out infinite 1s" }}>
          <svg width="44" height="16" viewBox="0 0 44 16" shapeRendering="crispEdges">
            <rect x="8"  y="0"  width="28" height="4" fill="white" opacity="0.78"/>
            <rect x="4"  y="4"  width="36" height="4" fill="white" opacity="0.78"/>
            <rect x="0"  y="8"  width="44" height="4" fill="white" opacity="0.78"/>
            <rect x="0"  y="12" width="44" height="4" fill="white" opacity="0.78"/>
          </svg>
        </div>

        {/* Cloud 6 — large, lower-center (P=9) */}
        <div style={{ position:"absolute", top:"55%", left:"28%", animation:"cloudDrift2 22s ease-in-out infinite 5s" }}>
          <svg width="126" height="45" viewBox="0 0 126 45" shapeRendering="crispEdges">
            <rect x="27" y="0"  width="72" height="9" fill="white" opacity="0.82"/>
            <rect x="18" y="9"  width="90" height="9" fill="white" opacity="0.82"/>
            <rect x="9"  y="18" width="108" height="9" fill="white" opacity="0.82"/>
            <rect x="0"  y="27" width="126" height="9" fill="white" opacity="0.82"/>
            <rect x="0"  y="36" width="126" height="9" fill="white" opacity="0.82"/>
          </svg>
        </div>

        {/* Cloud 7 — small, lower-right (P=5) */}
        <div style={{ position:"absolute", top:"62%", right:"5%", animation:"cloudDrift1 16s ease-in-out infinite 9s" }}>
          <svg width="60" height="20" viewBox="0 0 60 20" shapeRendering="crispEdges">
            <rect x="10" y="0"  width="40" height="5" fill="white" opacity="0.80"/>
            <rect x="5"  y="5"  width="50" height="5" fill="white" opacity="0.80"/>
            <rect x="0"  y="10" width="60" height="5" fill="white" opacity="0.80"/>
            <rect x="0"  y="15" width="60" height="5" fill="white" opacity="0.80"/>
          </svg>
        </div>

        {/* Bird — smooth SVG path (same as original) */}
        <div style={{ position:"absolute", top:"21%", left:0, animation:"birdFly 34s linear infinite 1s" }}>
          <svg width="50" height="28" viewBox="0 0 50 28">
            <ellipse cx="25" cy="16" rx="5" ry="3" fill="#0c2340"/>
            <circle cx="22" cy="12" r="3.5" fill="#0c2340"/>
            <path d="M19,12 L15,13" stroke="#0c2340" strokeWidth="1.8" strokeLinecap="round" fill="none"/>
            <path d="M20,16 Q12,6 3,10" stroke="#0c2340" strokeWidth="3" fill="none" strokeLinecap="round"/>
            <path d="M30,16 Q38,6 47,10" stroke="#0c2340" strokeWidth="3" fill="none" strokeLinecap="round"/>
            <path d="M30,17 Q35,21 38,17 Q35,23 30,19" fill="#0c2340"/>
          </svg>
        </div>
      </div>
    </>
  );
}

// ── Chat ──────────────────────────────────────────────────────────

export default function Chat({ user, onLogout }) {
  const [users, setUsers]           = useState([]);
  const [onlineUsers, setOnlineUsers] = useState([]);
  const [selected, setSelected]     = useState(null);
  const [messages, setMessages]     = useState({});   // peer -> [{from,text,ts}]
  const [input, setInput]           = useState("");
  const [fingerprint, setFingerprint] = useState(user.fingerprint || "");
  const [sessionFPs, setSessionFPs] = useState({});   // peer -> fingerprint string
  const [connected, setConnected]   = useState(false);
  const [devSessions, setDevSessions] = useState({});  // peer -> session snapshot for DevPanel
  const [messageLog, setMessageLog]   = useState([]);  // [{dir,plaintext,ciphertext,header,ts}]
  const bottomRef = useRef(null);

  // Always-current sessions map for socket handler
  const sessionsRef = useRef({});

  // ── Helpers ────────────────────────────────────────────────────

  const appendMessage = useCallback((peer, msg) => {
    // Always read from localStorage before writing — React state is empty on
    // fresh login so offline messages would otherwise overwrite saved history.
    const existing = loadMessages(user.net_id, peer);
    const isDupe = existing.some(m => m.id === msg.id);
    if (!isDupe) {
      saveMessages(user.net_id, peer, [...existing, msg].sort((a, b) => a.ts - b.ts));
    }
    setMessages(prev => {
      const inState = prev[peer] || [];
      if (inState.some(m => m.id === msg.id)) return prev;
      return { ...prev, [peer]: [...inState, msg].sort((a, b) => a.ts - b.ts) };
    });
  }, [user.net_id]);

  // Build and persist a ratchet session as Alice (sender)
  async function buildSenderSession(peer) {
    const myKeys = loadKeys(user.net_id);
    if (!myKeys) throw new Error("No local keys — re-register");

    const res = await fetch(`${API}/bundle/${peer}`);
    const bundle = await res.json();
    if (!bundle.ik_pub) throw new Error("No bundle for peer");

    const { sk, ekPub, senderIKPub, opkPubUsed, debug: x3dhDebug } = await x3dhSender(myKeys.ik, bundle);

    const sess = new RatchetSession();
    await sess.initSender(sk, hexToBigInt(bundle.spk_pub));

    // Store what Bob needs to recreate SK on his side
    sess._initHeader = {
      ek_pub:        ekPub.toString(16),
      sender_ik_pub: senderIKPub.toString(16),
      opk_pub_used:  opkPubUsed,   // so Bob can find the right OPK private key
    };
    sess._peerBundle = bundle;
    sess._x3dhDebug  = x3dhDebug;

    // Clear init_sent so the new session_init header is always sent with first message
    localStorage.removeItem(`init_sent_${user.net_id}_${peer}`);

    saveSession(user.net_id, peer, sess);
    sessionsRef.current[peer] = sess;

    setSessionFPs(prev => ({ ...prev, [peer]: bundle.fingerprint }));
    return sess;
  }

  // Build and persist a ratchet session as Bob (receiver)
  async function buildReceiverSession(peer, sessionInit, ratchetPubHex) {
    const myKeys = loadKeys(user.net_id);
    if (!myKeys) throw new Error("No local keys — re-register");

    // Find the exact OPK private key Alice used — identified by opk_pub_used in the header
    const opkKey = sessionInit.opk_pub_used
      ? (findOpk(user.net_id, sessionInit.opk_pub_used) ?? myKeys.opk)
      : myKeys.opk;

    const receiverKeys = { ik: myKeys.ik, spk: myKeys.spk, opk: opkKey };

    const { sk, debug: x3dhDebug } = await x3dhReceiver(
      receiverKeys,
      sessionInit.sender_ik_pub,
      sessionInit.ek_pub,
    );

    const sess = new RatchetSession();
    await sess.initReceiver(sk, hexToBigInt(ratchetPubHex), myKeys.spk);
    sess._x3dhDebug = x3dhDebug;

    saveSession(user.net_id, peer, sess);
    sessionsRef.current[peer] = sess;
    return sess;
  }

  async function getSession(peer) {
    if (sessionsRef.current[peer]) return sessionsRef.current[peer];
    const stored = loadSession(user.net_id, peer);
    if (stored) {
      sessionsRef.current[peer] = stored;
      return stored;
    }
    // No session in memory or storage — build as sender (first contact)
    // This path is only hit when WE initiate; if they initiated we already
    // have a session from buildReceiverSession triggered on message receive.
    return await buildSenderSession(peer);
  }

  // ── Socket ────────────────────────────────────────────────────

  useEffect(() => {
    socket.on("connect",       () => { setConnected(true); socket.emit("authenticate", { net_id: user.net_id }); });
    socket.on("disconnect",    () => setConnected(false));
    socket.on("online_update", setOnlineUsers);
    socket.connect();
    socket.on("authenticated", d => setFingerprint(d.fingerprint));

    socket.on("message", async (msg) => {
      const { id: msgId, sender, payload, ts: msgTs } = msg;
      let plaintext;
      try {
        let sess = sessionsRef.current[sender];

        if (payload.session_init) {
          // session_init present means sender started a fresh X3DH session —
          // always rebuild, even if a stale session exists in memory/localStorage
          sess = await buildReceiverSession(
            sender,
            payload.session_init,
            payload.header.dh,
          );
        } else if (!sess) {
          const stored = loadSession(user.net_id, sender);
          if (stored) {
            sess = stored;
            sessionsRef.current[sender] = sess;
          } else {
            plaintext = "[no session — send a message first]";
          }
        }

        if (sess && plaintext === undefined) {
          plaintext = await sess.decrypt(payload);
          saveSession(user.net_id, sender, sess);
        }
      } catch (err) {
        console.error("Decrypt error:", err);
        plaintext = "[decryption failed]";
      }
      logMessage("in", payload);
      snapSession(sender);
      appendMessage(sender, { id: msgId, from: sender, text: plaintext, ts: msgTs ?? Date.now() });
    });

    return () => {
      socket.off("connect");
      socket.off("disconnect");
      socket.off("online_update");
      socket.off("authenticated");
      socket.off("message");
      socket.disconnect();
    };
  }, [user.net_id]);

  // ── User list + online poll ───────────────────────────────────

  useEffect(() => {
    const load = () => {
      fetch(`${API}/users?me=${user.net_id}`).then(r => r.json()).then(setUsers);
      fetch(`${API}/online`).then(r => r.json()).then(setOnlineUsers);
    };
    load();
    const t = setInterval(load, 3000);
    return () => clearInterval(t);
  }, [user]);

  function snapSession(peer) {
    const sess = sessionsRef.current[peer];
    if (sess) setDevSessions(prev => ({ ...prev, [peer]: sess }));
  }

  function logMessage(dir, encrypted) {
    setMessageLog(prev => [{
      dir,
      ciphertext: encrypted?.ciphertext,
      header:     encrypted?.header,
      ts: Date.now(),
    }, ...prev].slice(0, 50));
  }

  // ── Select conversation — load history synchronously ─────────

  function selectPeer(peer) {
    setSelected(peer);
    // Load persisted messages immediately, not in an effect, to avoid
    // race conditions with incoming socket messages overwriting state.
    const cached = loadMessages(user.net_id, peer);
    setMessages(prev => {
      // Merge: keep any messages already in state (from socket) that
      // aren't in the cached list yet (e.g. arrived this session).
      const inState = prev[peer] || [];
      const cachedIds = new Set(cached.map(m => m.id));
      const extra = inState.filter(m => !cachedIds.has(m.id));
      return { ...prev, [peer]: [...cached, ...extra].sort((a, b) => a.ts - b.ts) };
    });
    // Restore session fingerprint from stored session
    const sess = loadSession(user.net_id, peer);
    if (sess) sessionsRef.current[peer] = sess;
  }

  // ── Auto-scroll ───────────────────────────────────────────────

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, selected]);

  // ── Send ──────────────────────────────────────────────────────

  async function sendMessage(e) {
    e.preventDefault();
    if (!input.trim() || !selected) return;

    try {
      const sess = await getSession(selected);
      const isFirst = !wasInitSent(user.net_id, selected);

      const payload = await sess.encrypt(input.trim());

      // First message carries the X3DH init header so receiver can derive SK
      if (isFirst && sess._initHeader) {
        payload.session_init = sess._initHeader;
        markInitSent(user.net_id, selected);
      }

      saveSession(user.net_id, selected, sess);

      const msgId = crypto.randomUUID();
      const ts = Date.now();
      socket.emit("send_message", {
        sender:    user.net_id,
        recipient: selected,
        payload,
        ts,
      });

      // Sender records their own message with the same ID structure
      logMessage("out", payload);
      snapSession(selected);
      appendMessage(selected, { id: msgId, from: user.net_id, text: input.trim(), ts });
      setInput("");
    } catch (err) {
      console.error("Encrypt error:", err);
    }
  }

  const msgs = messages[selected] || [];

  // ── Render ────────────────────────────────────────────────────

  return (
    <>
    <SkyBackground />

    <div className="flex h-screen text-black font-mono" style={{ position: "relative", zIndex: 1 }}>
      {/* Sidebar */}
      <aside className="w-64 border-r border-sky-200 flex flex-col" style={{ background: "rgba(255,255,255,0.92)" }}>
        <div className="p-4 border-b border-sky-100">
          <div className="flex items-center gap-2">
            <div className="text-sky-600 font-bold text-lg">UIC Signal</div>
            <span className={`w-2 h-2 rounded-full ${connected ? "bg-green-400" : "bg-red-400"}`}
                  title={connected ? "Connected" : "Disconnected — reconnecting…"} />
          </div>
          <div className="text-xs text-slate-500 mt-1 truncate">@{user.net_id}</div>
          <div className="text-[10px] text-slate-400 mt-1 break-all">FP: {fingerprint}</div>
          <button
            onClick={onLogout}
            className="mt-2 text-xs text-slate-400 hover:text-red-400 transition"
          >
            logout
          </button>
        </div>
        <div className="flex-1 overflow-y-auto">
          {users.length === 0 && (
            <div className="p-4 text-xs text-slate-400">No other users yet</div>
          )}
          {users.map(u => {
            const isOnline = onlineUsers.includes(u);
            return (
              <button
                key={u}
                onClick={() => selectPeer(u)}
                className={`w-full text-left px-4 py-3 text-sm border-b border-sky-50 transition
                  ${selected === u ? "bg-sky-100 text-sky-700" : "hover:bg-sky-50/80 text-slate-600"}`}
              >
                <span className="inline-flex items-center gap-2 w-full">
                  <span className={`w-2 h-2 rounded-full flex-shrink-0 ${isOnline ? "bg-green-400" : "bg-slate-300"}`} />
                  <span className="truncate">{u}</span>
                  {isOnline && <span className="ml-auto text-[10px] text-green-500">online</span>}
                </span>
              </button>
            );
          })}
        </div>
      </aside>

      {/* Chat area — transparent so the sky shows through */}
      <main className="flex-1 flex flex-col">
        {!selected ? (
          <div className="flex-1 flex items-center justify-center text-white/80 text-sm drop-shadow">
            Select a conversation
          </div>
        ) : (
          <>
            <header className="px-6 py-3 border-b border-sky-200 flex items-center gap-3"
                    style={{ background: "rgba(255,255,255,0.90)" }}>
              <span className="text-sky-700 font-bold">@{selected}</span>
              {sessionFPs[selected] && (
                <span className="text-[10px] text-slate-400">
                  🔑 {sessionFPs[selected]}
                </span>
              )}
              <span className="ml-auto text-[10px] text-green-600">AES-256-GCM</span>
            </header>

            <div className="flex-1 overflow-y-auto p-6 space-y-3">
              {msgs.map((m, i) => (
                <div key={i} className={`flex ${m.from === user.net_id ? "justify-end" : "justify-start"}`}>
                  <div className={`max-w-[70%] px-4 py-2 rounded-xl text-sm shadow-sm
                    ${m.from === user.net_id
                      ? "bg-sky-500 text-white"
                      : "bg-white/90 text-black border border-sky-100"}`}>
                    {m.text}
                    <div className="text-[10px] mt-1 opacity-50 text-right">
                      {new Date(m.ts).toLocaleTimeString()}
                    </div>
                  </div>
                </div>
              ))}
              <div ref={bottomRef} />
            </div>

            <form onSubmit={sendMessage} className="p-4 border-t border-sky-200 flex gap-2"
                  style={{ background: "rgba(255,255,255,0.90)" }}>
              <input
                value={input}
                onChange={e => setInput(e.target.value)}
                placeholder="Type a message…"
                className="flex-1 bg-sky-50 border border-sky-200 rounded-lg px-4 py-2 text-sm
                           text-black placeholder-slate-400 focus:outline-none focus:border-sky-400"
              />
              <button
                type="submit"
                className="bg-red-400 hover:bg-red-500 px-4 py-2 rounded-lg text-sm font-bold text-white transition shadow-sm"
              >
                Send
              </button>
            </form>
          </>
        )}
      </main>
    </div>

    <DevPanel
      user={user}
      selected={selected}
      sessions={devSessions}
      messageLog={messageLog}
    />
    </>
  );
}
