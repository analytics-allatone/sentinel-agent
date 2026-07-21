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

// ── HOTP / TOTP core ──────────────────────────────────────────────────────────
async function hotp(secretBytes, counter) {
  const buffer = new ArrayBuffer(8); // 8-byte big-endian counter
  const view = new DataView(buffer);
  view.setUint32(0, Math.floor(counter / 2 ** 32));
  view.setUint32(4, counter >>> 0);

  const key = await crypto.subtle.importKey(
    "raw",
    secretBytes,
    { name: "HMAC", hash: "SHA-1" },
    false,
    ["sign"],
  );
  const sig = new Uint8Array(await crypto.subtle.sign("HMAC", key, buffer));

  const offset = sig[sig.length - 1] & 0x0f; // dynamic truncation (RFC 4226)
  const binary =
    ((sig[offset] & 0x7f) << 24) |
    ((sig[offset + 1] & 0xff) << 16) |
    ((sig[offset + 2] & 0xff) << 8) |
    (sig[offset + 3] & 0xff);
  return (binary % 10 ** DIGITS).toString().padStart(DIGITS, "0");
}

/** Current TOTP code for a Base32 secret. */
export async function generateTotp(secret, nowSeconds = Date.now() / 1000) {
  const counter = Math.floor(nowSeconds / PERIOD);
  return hotp(base32Decode(secret), counter);
}

/**
 * Verify a submitted code, tolerating +/- `window` time-steps of clock drift
 * (default 1 => ~90s tolerance).
 */
export async function verifyTotp(secret, code, window = 1) {
  if (!secret || !code) return false;
  const cleaned = code.trim().replace(/\s/g, "");
  if (!/^\d{6}$/.test(cleaned)) return false;

  const counter = Math.floor(Date.now() / 1000 / PERIOD);
  const bytes = base32Decode(secret);
  for (let w = -window; w <= window; w++) {
    if ((await hotp(bytes, counter + w)) === cleaned) return true;
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
