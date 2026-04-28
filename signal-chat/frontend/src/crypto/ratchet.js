// Double Ratchet — browser side.
// Mirrors crypto/ratchet.py exactly.
// DH ratchet uses dh.js (BigInt). AES-256-GCM + HKDF use WebCrypto API.

import { DHKeyPair, bigIntToHex, hexToBigInt, bytesToHex, hexToBytes } from "./dh.js";
import { hkdf } from "./x3dh.js";

const RK_INFO = new TextEncoder().encode("UIC-Signal-RatchetRoot-v1");
const CK_INFO = new TextEncoder().encode("UIC-Signal-RatchetChain-v1");
const MAX_SKIP = 100;

async function kdfRK(rootKey, dhOut) {
  const key = await crypto.subtle.importKey("raw", dhOut, { name: "HKDF" }, false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: rootKey, info: RK_INFO },
    key, 64 * 8
  );
  const out = new Uint8Array(bits);
  return [out.slice(0, 32), out.slice(32)];  // [newRootKey, chainKey]
}

async function kdfCK(chainKey) {
  const key = await crypto.subtle.importKey("raw", chainKey, { name: "HKDF" }, false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(32), info: CK_INFO },
    key, 64 * 8
  );
  const out = new Uint8Array(bits);
  return [out.slice(0, 32), out.slice(32)];  // [newChainKey, messageKey]
}

async function aesEncrypt(mk, plaintext, aad) {
  const key = await crypto.subtle.importKey("raw", mk, { name: "AES-GCM" }, false, ["encrypt"]);
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: nonce, additionalData: aad },
    key,
    new TextEncoder().encode(plaintext)
  );
  // nonce prepended, same layout as Python: nonce + ciphertext
  const out = new Uint8Array(12 + ct.byteLength);
  out.set(nonce);
  out.set(new Uint8Array(ct), 12);
  return out;
}

async function aesDecrypt(mk, ciphertext, aad) {
  const key = await crypto.subtle.importKey("raw", mk, { name: "AES-GCM" }, false, ["decrypt"]);
  const pt = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: ciphertext.slice(0, 12), additionalData: aad },
    key,
    ciphertext.slice(12)
  );
  return new TextDecoder().decode(pt);
}

export class RatchetSession {
  constructor() {
    this.rootKey         = null;
    this.sendingChainKey = null;
    this.recvChainKey    = null;
    this.sendRatchet     = new DHKeyPair();
    this.recvRatchetPub  = null;  // BigInt
    this.sendMsgNum      = 0;
    this.recvMsgNum      = 0;
    this.prevSendCount   = 0;
    this.skipped         = {};    // "pubHex:n" -> Uint8Array mk
  }

  // Alice calls this after x3dhSender
  // sharedKey: Uint8Array (32 bytes from X3DH)
  // theirRatchetPub: BigInt (Bob's SPK public key used as initial ratchet target)
  async initSender(sharedKey, theirRatchetPub) {
    this.recvRatchetPub = theirRatchetPub;
    const dhOut = this.sendRatchet.dh(theirRatchetPub);
    [this.rootKey, this.sendingChainKey] = await kdfRK(sharedKey, dhOut);
  }

  // Bob calls this after x3dhReceiver
  // sharedKey: Uint8Array (32 bytes from X3DH)
  // theirRatchetPub: BigInt (Alice's ratchet pub from message header)
  // myInitialKeypair: DHKeyPair (Bob's SPK — used to derive first recv chain)
  async initReceiver(sharedKey, theirRatchetPub, myInitialKeypair) {
    this.sendRatchet    = myInitialKeypair;
    this.recvRatchetPub = theirRatchetPub;
    const dhOut = myInitialKeypair.dh(theirRatchetPub);
    [this.rootKey, this.recvChainKey] = await kdfRK(sharedKey, dhOut);
  }

  async encrypt(plaintext) {
    if (!this.sendingChainKey) {
      // Bob's first send after receiving — derive sending chain with a fresh ratchet key.
      // Does not touch recvChainKey so Bob can still decrypt future messages from Alice.
      if (!this.recvRatchetPub) throw new Error("Sending chain not initialised");
      this.sendRatchet = new DHKeyPair();
      const dhOut = this.sendRatchet.dh(this.recvRatchetPub);
      [this.rootKey, this.sendingChainKey] = await kdfRK(this.rootKey, dhOut);
      this.sendMsgNum = 0;
      this.prevSendCount = 0;
    }
    const [newCK, mk] = await kdfCK(this.sendingChainKey);
    this.sendingChainKey = newCK;

    const header = {
      dh: bigIntToHex(this.sendRatchet.publicKey),
      pn: this.prevSendCount,
      n:  this.sendMsgNum,
    };
    this.sendMsgNum++;

    const aad = new TextEncoder().encode(JSON.stringify(header));
    const ct  = await aesEncrypt(mk, plaintext, aad);
    return { header, ciphertext: bytesToHex(ct) };
  }

  async decrypt(message) {
    const { header } = message;
    const ct = hexToBytes(message.ciphertext);
    const dhPub = hexToBigInt(header.dh);
    const n  = header.n;
    const pn = header.pn;

    // Check skipped message keys
    const skipKey = `${header.dh}:${n}`;
    if (this.skipped[skipKey]) {
      const mk = this.skipped[skipKey];
      delete this.skipped[skipKey];
      const aad = new TextEncoder().encode(JSON.stringify(header));
      return await aesDecrypt(mk, ct, aad);
    }

    const currentDHHex = this.recvRatchetPub ? bigIntToHex(this.recvRatchetPub) : null;
    if (header.dh !== currentDHHex) {
      await this._skipMessageKeys(pn);
      await this._dhRatchet(dhPub);
    }

    await this._skipMessageKeys(n);
    const [newCK, mk] = await kdfCK(this.recvChainKey);
    this.recvChainKey = newCK;
    this.recvMsgNum++;

    const aad = new TextEncoder().encode(JSON.stringify(header));
    return await aesDecrypt(mk, ct, aad);
  }

  async _skipMessageKeys(until) {
    if (this.recvMsgNum + MAX_SKIP < until) throw new Error("Too many skipped messages");
    while (this.recvChainKey && this.recvMsgNum < until) {
      const [newCK, mk] = await kdfCK(this.recvChainKey);
      this.recvChainKey = newCK;
      this.skipped[`${bigIntToHex(this.recvRatchetPub)}:${this.recvMsgNum}`] = mk;
      this.recvMsgNum++;
    }
  }

  async _dhRatchet(theirPub) {
    this.prevSendCount = this.sendMsgNum;
    this.sendMsgNum    = 0;
    this.recvMsgNum    = 0;
    this.recvRatchetPub = theirPub;
    const dh1 = this.sendRatchet.dh(theirPub);
    [this.rootKey, this.recvChainKey] = await kdfRK(this.rootKey, dh1);
    this.sendRatchet = new DHKeyPair();
    const dh2 = this.sendRatchet.dh(theirPub);
    [this.rootKey, this.sendingChainKey] = await kdfRK(this.rootKey, dh2);
  }

  // ── Persistence ───────────────────────────────────────────────

  serialize() {
    const skippedSer = {};
    for (const [k, v] of Object.entries(this.skipped))
      skippedSer[k] = bytesToHex(v);
    return JSON.stringify({
      rootKey:         this.rootKey         ? bytesToHex(this.rootKey)         : null,
      sendingChainKey: this.sendingChainKey ? bytesToHex(this.sendingChainKey) : null,
      recvChainKey:    this.recvChainKey    ? bytesToHex(this.recvChainKey)    : null,
      sendRatchet:     this.sendRatchet.toJSON(),
      recvRatchetPub:  this.recvRatchetPub  ? bigIntToHex(this.recvRatchetPub) : null,
      sendMsgNum:      this.sendMsgNum,
      recvMsgNum:      this.recvMsgNum,
      prevSendCount:   this.prevSendCount,
      skipped:         skippedSer,
    });
  }

  static deserialize(json) {
    const d = JSON.parse(json);
    const sess = new RatchetSession();
    sess.rootKey         = d.rootKey         ? hexToBytes(d.rootKey)         : null;
    sess.sendingChainKey = d.sendingChainKey ? hexToBytes(d.sendingChainKey) : null;
    sess.recvChainKey    = d.recvChainKey    ? hexToBytes(d.recvChainKey)    : null;
    sess.sendRatchet     = DHKeyPair.fromJSON(d.sendRatchet);
    sess.recvRatchetPub  = d.recvRatchetPub  ? hexToBigInt(d.recvRatchetPub) : null;
    sess.sendMsgNum      = d.sendMsgNum;
    sess.recvMsgNum      = d.recvMsgNum;
    sess.prevSendCount   = d.prevSendCount;
    const skipped = {};
    for (const [k, v] of Object.entries(d.skipped || {}))
      skipped[k] = hexToBytes(v);
    sess.skipped = skipped;
    return sess;
  }
}
