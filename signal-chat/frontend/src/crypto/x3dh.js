// X3DH (Extended Triple Diffie-Hellman) — browser side.
// Mirrors crypto/x3dh.py exactly. All DH ops use dh.js (BigInt).
// Only HKDF comes from WebCrypto (same rule as Python: only AES-GCM + HKDF allowed).

import { DHKeyPair, hexToBigInt, bigIntToBytes } from "./dh.js";

const X3DH_INFO = new TextEncoder().encode("UIC-Signal-X3DH-v1");
const F = new Uint8Array(32).fill(0xff);  // same padding as Python

function concat(...arrays) {
  const total = arrays.reduce((s, a) => s + a.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const a of arrays) { out.set(a, offset); offset += a.length; }
  return out;
}

export async function hkdf(ikm, salt = new Uint8Array(32), info = X3DH_INFO, length = 32) {
  const key = await crypto.subtle.importKey("raw", ikm, { name: "HKDF" }, false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt, info },
    key, length * 8
  );
  return new Uint8Array(bits);
}

// Sender-side X3DH (Alice's browser)
// senderIK      — DHKeyPair (Alice's identity key, private in localStorage)
// recipientBundle — { ik_pub, spk_pub, opk_pub } hex strings from server
// Returns { sk, ekPub (BigInt), senderIKPub (BigInt) }
export async function x3dhSender(senderIK, recipientBundle) {
  const ek = new DHKeyPair();  // ephemeral key, generated fresh each session

  const rik  = hexToBigInt(recipientBundle.ik_pub);
  const rspk = hexToBigInt(recipientBundle.spk_pub);

  if (!recipientBundle.opk_pub) throw new Error(`No one-time prekey available for this user`);
  const ropk = hexToBigInt(recipientBundle.opk_pub);

  const dh1 = senderIK.dh(rspk);   // DH(sender_IK,   recipient_SPK)
  const dh2 = ek.dh(rik);           // DH(sender_EK,   recipient_IK)
  const dh3 = ek.dh(rspk);          // DH(sender_EK,   recipient_SPK)
  const dh4 = ek.dh(ropk);          // DH(sender_EK,   recipient_OPK)

  const km = concat(F, dh1, dh2, dh3, dh4);
  const sk = await hkdf(km);

  return { sk, ekPub: ek.publicKey, senderIKPub: senderIK.publicKey };
}

// Receiver-side X3DH (Bob's browser)
// receiverKeys  — { ik, spk, opk } DHKeyPairs loaded from localStorage
// senderIKPub   — hex string from session_init header
// ekPub         — hex string from session_init header
// Returns sk (Uint8Array, 32 bytes)
export async function x3dhReceiver(receiverKeys, senderIKPubHex, ekPubHex) {
  const sik = hexToBigInt(senderIKPubHex);
  const ek  = hexToBigInt(ekPubHex);

  const dh1 = receiverKeys.spk.dh(sik);   // DH(recipient_SPK, sender_IK)
  const dh2 = receiverKeys.ik.dh(ek);      // DH(recipient_IK,  sender_EK)
  const dh3 = receiverKeys.spk.dh(ek);     // DH(recipient_SPK, sender_EK)
  const dh4 = receiverKeys.opk.dh(ek);     // DH(recipient_OPK, sender_EK)

  const km = concat(F, dh1, dh2, dh3, dh4);
  return await hkdf(km);
}
