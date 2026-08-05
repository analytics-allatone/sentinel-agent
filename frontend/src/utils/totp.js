/**
 * Client-side TOTP (RFC 6238) using the Web Crypto API — no external crypto lib.
 *
 * Powers a FRONTEND-ONLY OTP login: the app shows a QR code, the user scans it
 * with Google Authenticator / Microsoft Authenticator / Authy, the app produces
 * a 6-digit code, and this module verifies it in the browser.
 *
 * NOTE: real OTP must be verified on a server. Verifying in the browser is a
 * UI/demo, not a security boundary. The codes themselves are standards-correct,
 * so real authenticator apps interoperate.
 */

const B32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const DIGITS = 6;
const PERIOD = 30; // seconds per code
export const TOTP_ISSUER = "Sentinel";

// ── Base32 (RFC 4648) ─────────────────────────────────────────────────────────
function base32Encode(bytes) {
  let bits = "";
  for (const b of bytes) bits += b.toString(2).padStart(8, "0");
  let out = "";
  for (let i = 0; i + 5 <= bits.length; i += 5) {
    out += B32_ALPHABET[parseInt(bits.substr(i, 5), 2)];
  }
  const remainder = bits.length % 5;
  if (remainder !== 0) {
    const tail = bits.substr(bits.length - remainder).padEnd(5, "0");
    out += B32_ALPHABET[parseInt(tail, 2)];
  }
  return out;
}

function base32Decode(str) {
  const clean = str.replace(/=+$/, "").replace(/\s/g, "").toUpperCase();
  let bits = "";
  for (const c of clean) {
    const val = B32_ALPHABET.indexOf(c);
    if (val < 0) continue;
    bits += val.toString(2).padStart(5, "0");
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.substr(i, 8), 2));
  }
  return new Uint8Array(bytes);
}

/** Generate a fresh random Base32 secret (default 20 bytes / 160 bits). */
export function generateSecret(byteLength = 20) {
  const random = crypto.getRandomValues(new Uint8Array(byteLength));
  return base32Encode(random);
}

/** Build the otpauth:// URL encoded into the QR code the user scans. */
export function buildOtpauthUrl(secret, accountEmail) {
  const label = encodeURIComponent(`${TOTP_ISSUER}:${accountEmail}`);
  const params = new URLSearchParams({
    secret,
    issuer: TOTP_ISSUER,
    algorithm: "SHA1",
    digits: String(DIGITS),
    period: String(PERIOD),
  });
  return `otpauth://totp/${label}?${params.toString()}`;
}

// ── Pure-JS SHA-1 + HMAC-SHA1 ─────────────────────────────────────────────────
// Implemented in plain JS (not the Web Crypto API) on purpose: crypto.subtle is
// ONLY available in a "secure context" (HTTPS or localhost). On a plain-HTTP
// deployment it's undefined, which used to make OTP verification silently fail
// in production while working locally. This works everywhere.

function rotl(n, s) {
  return ((n << s) | (n >>> (32 - s))) >>> 0;
}

function sha1(msg) {
  const len = msg.length;
  const bitLen = len * 8;
  const paddedLen = (((len + 8) >> 6) + 1) << 6; // multiple of 64
  const buf = new Uint8Array(paddedLen);
  buf.set(msg);
  buf[len] = 0x80;
  const dv = new DataView(buf.buffer);
  dv.setUint32(paddedLen - 4, bitLen >>> 0);
  dv.setUint32(paddedLen - 8, Math.floor(bitLen / 0x100000000));

  let h0 = 0x67452301,
    h1 = 0xefcdab89,
    h2 = 0x98badcfe,
    h3 = 0x10325476,
    h4 = 0xc3d2e1f0;
  const w = new Uint32Array(80);

  for (let i = 0; i < paddedLen; i += 64) {
    for (let t = 0; t < 16; t++) w[t] = dv.getUint32(i + t * 4);
    for (let t = 16; t < 80; t++)
      w[t] = rotl(w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16], 1);

    let a = h0,
      b = h1,
      c = h2,
      d = h3,
      e = h4;
    for (let t = 0; t < 80; t++) {
      let f, k;
      if (t < 20) {
        f = (b & c) | (~b & d);
        k = 0x5a827999;
      } else if (t < 40) {
        f = b ^ c ^ d;
        k = 0x6ed9eba1;
      } else if (t < 60) {
        f = (b & c) | (b & d) | (c & d);
        k = 0x8f1bbcdc;
      } else {
        f = b ^ c ^ d;
        k = 0xca62c1d6;
      }
      const tmp = (rotl(a, 5) + f + e + k + w[t]) >>> 0;
      e = d;
      d = c;
      c = rotl(b, 30);
      b = a;
      a = tmp;
    }
    h0 = (h0 + a) >>> 0;
    h1 = (h1 + b) >>> 0;
    h2 = (h2 + c) >>> 0;
    h3 = (h3 + d) >>> 0;
    h4 = (h4 + e) >>> 0;
  }

  const out = new Uint8Array(20);
  const odv = new DataView(out.buffer);
  odv.setUint32(0, h0);
  odv.setUint32(4, h1);
  odv.setUint32(8, h2);
  odv.setUint32(12, h3);
  odv.setUint32(16, h4);
  return out;
}

function concatBytes(a, b) {
  const out = new Uint8Array(a.length + b.length);
  out.set(a);
  out.set(b, a.length);
  return out;
}

function hmacSha1(key, msg) {
  const BLOCK = 64;
  let k = key;
  if (k.length > BLOCK) k = sha1(k);
  if (k.length < BLOCK) {
    const padded = new Uint8Array(BLOCK);
    padded.set(k);
    k = padded;
  }
  const oKeyPad = new Uint8Array(BLOCK);
  const iKeyPad = new Uint8Array(BLOCK);
  for (let i = 0; i < BLOCK; i++) {
    oKeyPad[i] = k[i] ^ 0x5c;
    iKeyPad[i] = k[i] ^ 0x36;
  }
  return sha1(concatBytes(oKeyPad, sha1(concatBytes(iKeyPad, msg))));
}

// ── HOTP / TOTP core ──────────────────────────────────────────────────────────
function hotp(secretBytes, counter) {
  const buffer = new Uint8Array(8); // 8-byte big-endian counter
  const view = new DataView(buffer.buffer);
  view.setUint32(0, Math.floor(counter / 2 ** 32));
  view.setUint32(4, counter >>> 0);

  const sig = hmacSha1(secretBytes, buffer);

  const offset = sig[sig.length - 1] & 0x0f; // dynamic truncation (RFC 4226)
  const binary =
    ((sig[offset] & 0x7f) << 24) |
    ((sig[offset + 1] & 0xff) << 16) |
    ((sig[offset + 2] & 0xff) << 8) |
    (sig[offset + 3] & 0xff);
  return (binary % 10 ** DIGITS).toString().padStart(DIGITS, "0");
}

/** Current TOTP code for a Base32 secret. */
export function generateTotp(secret, nowSeconds = Date.now() / 1000) {
  const counter = Math.floor(nowSeconds / PERIOD);
  return hotp(base32Decode(secret), counter);
}

/**
 * Verify a submitted code, tolerating +/- `window` time-steps of clock drift
 * (default 1 => ~90s tolerance).
 */
export function verifyTotp(secret, code, window = 1) {
  if (!secret || !code) return false;
  const cleaned = code.trim().replace(/\s/g, "");
  if (!/^\d{6}$/.test(cleaned)) return false;

  const counter = Math.floor(Date.now() / 1000 / PERIOD);
  const bytes = base32Decode(secret);
  for (let w = -window; w <= window; w++) {
    if (hotp(bytes, counter + w) === cleaned) return true;
  }
  return false;
}

/**
 * Return the persisted TOTP secret for an email, generating and storing one on
 * first use so the same authenticator entry keeps working across logins.
 */
export function getOrCreateSecret(email) {
  const key = `otp-secret:${(email || "").trim().toLowerCase()}`;
  let secret = localStorage.getItem(key);
  if (!secret) {
    secret = generateSecret();
    localStorage.setItem(key, secret);
  }
  return secret;
}
