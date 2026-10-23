// Sealed notes with WebCrypto, byte-compatible with jam-privacy-service's client/notecrypt.py:
// X25519 (sender's fresh ephemeral key, receiver's key) -> HKDF-SHA256 (salt: the ephemeral
// public key, info "jam-privacy-note-v1") -> AES-256-GCM (nonce 12 zero bytes; the
// ephemeral public key as associated data). Sealed: epk (32) || ciphertext (40) || tag (16).
const c = globalThis.crypto;
const INFO = new TextEncoder().encode("jam-privacy-note-v1");
const PKCS8_X25519 = Uint8Array.from([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20]);
export const SEALED_LEN = 88;

const b64u = (s) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (ch) => ch.charCodeAt(0));

/** A key pair from a 32-byte secret: { priv: CryptoKey, pub: Uint8Array(32) }. */
export async function keyPair(secret32) {
  const pkcs8 = new Uint8Array([...PKCS8_X25519, ...secret32]);
  const priv = await c.subtle.importKey("pkcs8", pkcs8, { name: "X25519" }, true, ["deriveBits"]);
  const jwk = await c.subtle.exportKey("jwk", priv);
  return { priv, pub: b64u(jwk.x) };
}

async function aesKey(priv, peerPub, epk, usage) {
  const pub = await c.subtle.importKey("raw", peerPub, { name: "X25519" }, false, []);
  const secret = new Uint8Array(await c.subtle.deriveBits({ name: "X25519", public: pub }, priv, 256));
  const hk = await c.subtle.importKey("raw", secret, "HKDF", false, ["deriveKey"]);
  return c.subtle.deriveKey({ name: "HKDF", hash: "SHA-256", salt: epk, info: INFO }, hk, { name: "AES-GCM", length: 256 }, false, [usage]);
}

export async function seal(receiverPub, plaintext) {
  const eph = await c.subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]);
  const epk = new Uint8Array(await c.subtle.exportKey("raw", eph.publicKey));
  const key = await aesKey(eph.privateKey, receiverPub, epk, "encrypt");
  const ct = new Uint8Array(await c.subtle.encrypt({ name: "AES-GCM", iv: new Uint8Array(12), additionalData: epk, tagLength: 128 }, key, plaintext));
  return new Uint8Array([...epk, ...ct]);
}

/** The plaintext, or null if the note is not for this key (or was tampered with). */
export async function open(priv, sealed) {
  if (sealed.length < 48) return null;
  const epk = sealed.slice(0, 32);
  try {
    const key = await aesKey(priv, epk, epk, "decrypt");
    return new Uint8Array(await c.subtle.decrypt({ name: "AES-GCM", iv: new Uint8Array(12), additionalData: epk, tagLength: 128 }, key, sealed.slice(32)));
  } catch { return null; }
}

/** value (u64 LE) || blinding (32, big-endian field element). */
export function notePlaintext(value, blinding) {
  const out = new Uint8Array(40);
  let v = BigInt(value);
  for (let i = 0; i < 8; i++) { out[i] = Number(v & 0xffn); v >>= 8n; }
  let b = BigInt(blinding);
  for (let i = 39; i >= 8; i--) { out[i] = Number(b & 0xffn); b >>= 8n; }
  return out;
}

export function noteFromPlaintext(pt) {
  let v = 0n; for (let i = 7; i >= 0; i--) v = (v << 8n) | BigInt(pt[i]);
  let b = 0n; for (let i = 8; i < 40; i++) b = (b << 8n) | BigInt(pt[i]);
  return { value: v, blinding: b };
}
