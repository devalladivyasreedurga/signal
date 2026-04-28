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
    socket.on("connect",    () => { setConnected(true); socket.emit("authenticate", { net_id: user.net_id }); });
    socket.on("disconnect", () => setConnected(false));
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
    <div className="flex h-screen bg-[#0a1628] text-white font-mono">
      {/* Sidebar */}
      <aside className="w-64 border-r border-[#cc0000]/30 flex flex-col">
        <div className="p-4 border-b border-[#cc0000]/30">
          <div className="flex items-center gap-2">
            <div className="text-[#cc0000] font-bold text-lg">UIC Signal</div>
            <span className={`w-2 h-2 rounded-full ${connected ? "bg-green-400" : "bg-red-500"}`}
                  title={connected ? "Connected" : "Disconnected — reconnecting…"} />
          </div>
          <div className="text-xs text-gray-400 mt-1 truncate">@{user.net_id}</div>
          <div className="text-[10px] text-gray-500 mt-1 break-all">FP: {fingerprint}</div>
          <button
            onClick={onLogout}
            className="mt-2 text-xs text-gray-500 hover:text-[#cc0000] transition"
          >
            logout
          </button>
        </div>
        <div className="flex-1 overflow-y-auto">
          {users.length === 0 && (
            <div className="p-4 text-xs text-gray-500">No other users yet</div>
          )}
          {users.map(u => {
            const isOnline = onlineUsers.includes(u);
            return (
              <button
                key={u}
                onClick={() => selectPeer(u)}
                className={`w-full text-left px-4 py-3 text-sm border-b border-[#cc0000]/10 transition
                  ${selected === u ? "bg-[#cc0000]/20 text-white" : "hover:bg-white/5 text-gray-300"}`}
              >
                <span className="inline-flex items-center gap-2 w-full">
                  <span className={`w-2 h-2 rounded-full flex-shrink-0 ${isOnline ? "bg-green-400" : "bg-gray-600"}`} />
                  <span className="truncate">{u}</span>
                  {isOnline && <span className="ml-auto text-[10px] text-green-400">online</span>}
                </span>
              </button>
            );
          })}
        </div>
      </aside>

      {/* Chat area */}
      <main className="flex-1 flex flex-col">
        {!selected ? (
          <div className="flex-1 flex items-center justify-center text-gray-500 text-sm">
            Select a conversation
          </div>
        ) : (
          <>
            <header className="px-6 py-3 border-b border-[#cc0000]/30 flex items-center gap-3">
              <span className="text-[#cc0000] font-bold">@{selected}</span>
              {sessionFPs[selected] && (
                <span className="text-[10px] text-gray-400">
                  🔑 {sessionFPs[selected]}
                </span>
              )}
              <span className="ml-auto text-[10px] text-green-500">AES-256-GCM</span>
            </header>

            <div className="flex-1 overflow-y-auto p-6 space-y-3">
              {msgs.map((m, i) => (
                <div key={i} className={`flex ${m.from === user.net_id ? "justify-end" : "justify-start"}`}>
                  <div className={`max-w-[70%] px-4 py-2 rounded-lg text-sm
                    ${m.from === user.net_id ? "bg-[#cc0000] text-white" : "bg-[#1a2a4a] text-gray-100"}`}>
                    <span className="mr-1">🔒</span>{m.text}
                    <div className="text-[10px] mt-1 opacity-50 text-right">
                      {new Date(m.ts).toLocaleTimeString()}
                    </div>
                  </div>
                </div>
              ))}
              <div ref={bottomRef} />
            </div>

            <form onSubmit={sendMessage} className="p-4 border-t border-[#cc0000]/30 flex gap-2">
              <input
                value={input}
                onChange={e => setInput(e.target.value)}
                placeholder="Type a message…"
                className="flex-1 bg-[#1a2a4a] border border-[#cc0000]/30 rounded px-4 py-2 text-sm
                           text-white placeholder-gray-500 focus:outline-none focus:border-[#cc0000]"
              />
              <button
                type="submit"
                className="bg-[#cc0000] hover:bg-[#aa0000] px-4 py-2 rounded text-sm font-bold transition"
              >
                Send
              </button>
            </form>
          </>
        )}
      </main>
    </div>  {/* end flex h-screen */}

    <DevPanel
      user={user}
      selected={selected}
      sessions={devSessions}
      messageLog={messageLog}
    />
    </>
  );
}
