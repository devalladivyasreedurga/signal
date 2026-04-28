// Diffie-Hellman from scratch — RFC 3526 Group 14 (2048-bit MODP)
// Mirrors crypto/dh.py exactly. Uses BigInt because 2048-bit numbers
// exceed JS's Number.MAX_SAFE_INTEGER.

const P = BigInt(
  "0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
  "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
  "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
  "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
  "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
  "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
  "83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
  "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
  "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +
  "DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
  "15728E5A8AACAA68FFFFFFFFFFFFFFFF"
);
const G = 2n;

// Square-and-multiply — same algorithm as dh.py
function powMod(base, exp, mod) {
  let result = 1n;
  base = base % mod;
  while (exp > 0n) {
    if (exp & 1n) result = result * base % mod;
    base = base * base % mod;
    exp >>= 1n;
  }
  return result;
}

function generatePrivateKey() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  let n = 0n;
  for (const b of bytes) n = (n << 8n) | BigInt(b);
  return (n % (P - 2n)) + 2n;
}

function generatePublicKey(priv) {
  return powMod(G, priv, P);
}

function computeSharedSecret(theirPub, myPriv) {
  return powMod(theirPub, myPriv, P);
}

// ── Serialization helpers ─────────────────────────────────────────

export function bigIntToHex(n) {
  return n.toString(16);
}

export function hexToBigInt(h) {
  return BigInt("0x" + h);
}

// BigInt → 256-byte Uint8Array (big-endian) for use as raw key material
export function bigIntToBytes(n) {
  const hex = n.toString(16).padStart(512, "0");
  const out = new Uint8Array(256);
  for (let i = 0; i < 256; i++)
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("");
}

export function hexToBytes(hex) {
  return new Uint8Array(hex.match(/.{2}/g).map(b => parseInt(b, 16)));
}

// ── DHKeyPair ─────────────────────────────────────────────────────

export class DHKeyPair {
  constructor(priv = null) {
    this.privateKey = priv ?? generatePrivateKey();
    this.publicKey  = generatePublicKey(this.privateKey);
  }

  // Returns 256-byte Uint8Array shared secret
  dh(theirPub) {
    return bigIntToBytes(computeSharedSecret(theirPub, this.privateKey));
  }

  toJSON() {
    return {
      privateKey: bigIntToHex(this.privateKey),
      publicKey:  bigIntToHex(this.publicKey),
    };
  }

  static fromJSON(obj) {
    return new DHKeyPair(hexToBigInt(obj.privateKey));
  }
}

export { P, G, powMod, generatePrivateKey, generatePublicKey, computeSharedSecret };
