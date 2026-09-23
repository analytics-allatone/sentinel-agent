/**
 * Two-step verification API calls.
 *
 * ── Where the contract came from ────────────────────────────────────────────
 * The backend's 2FA landed in commit db66374 ("2fa added", src/api/v1/auth_api.py),
 * and it is the authority here — it differs from the written spec in four ways
 * that matter, so this file follows the code:
 *
 *   spec                          backend
 *   tempToken                     challenge_token   (issued only when 2FA is on)
 *   twoFactorEnabled              two_fa_enabled
 *   POST /2fa/verify   + bearer   POST /login/2fa, challenge_token in the BODY
 *   qrCode (a data URL)           qr_code_png_base64 (bare base64, no prefix)
 *   POST /2fa/disable  { code }   { password, code }
 *
 * And three endpoints in the spec do not exist yet: /2fa/skip, /2fa/status and
 * both /2fa/email-otp/* calls. Their paths stay declared below so the pages
 * built for them start working the moment the backend ships them.
 *
 * Setup and enable require a REAL session (Depends(verify_token)), not the
 * challenge token — which is why turning 2FA on happens from the sidebar switch
 * inside the app rather than during sign-in.
 *
 * Responses are still read tolerantly (either spelling, enveloped or bare): the
 * project's own envelope is { status, message, data }, and the field names above
 * may yet be renamed.
 */
import api from "./api";

/** Paths, relative to the API base (…/api/v1). Change here if the API differs. */
export const TWO_FACTOR_PATHS = {
  login: "/login",
  // Signed in: the sidebar switch.
  setup: "/2fa/setup",
  enable: "/2fa/enable",
  disable: "/2fa/disable",
  // Signing in: the challenge step.
  verify: "/login/2fa",
  // Not deployed yet — the pages that use them are unreachable until they are.
  skip: "/2fa/skip",
  emailOtpSend: "/2fa/email-otp/send",
  emailOtpVerify: "/2fa/email-otp/verify",
};

/** The envelope's payload, or the body itself when there is no envelope. */
function body(res) {
  const data = (res && res.data) || {};
  return data && typeof data === "object" && "data" in data ? data.data || {} : data;
}

/** First key that is actually present, so either spelling works. */
function pick(source, ...names) {
  for (const name of names) {
    if (source && source[name] !== undefined && source[name] !== null) return source[name];
  }
  return undefined;
}

/** The short-lived challenge token: held in memory only, never persisted. */
export function readTempToken(res) {
  const d = body(res);
  return pick(
    d,
    "challenge_token",
    "challengeToken",
    "tempToken",
    "temp_token",
    "preAuthToken",
    "pre_auth_token"
  );
}

/** The real session token, issued once the flow completes. */
export function readAccessToken(res) {
  const d = body(res);
  return pick(d, "accessToken", "access_token");
}

export function readRefreshToken(res) {
  const d = body(res);
  return pick(d, "refreshToken", "refresh_token");
}

/**
 * The QR image, ready to put in an <img src>.
 *
 * The backend answers with `qr_code_png_base64`: the PNG's bytes in base64 and
 * nothing else. A browser will not draw that — it needs the media type in front
 * of it — which is why the picture came out blank. A value that already carries
 * its own prefix, or is a plain URL, is passed through untouched.
 */
export function readQrCode(res) {
  const d = body(res);
  const value = pick(
    d,
    "qr_code_png_base64",
    "qrCodePngBase64",
    "qrCode",
    "qr_code",
    "qrCodeUrl",
    "qr_code_url",
    "qrDataUrl"
  );

  if (!value || typeof value !== "string") return "";
  if (/^data:image\//i.test(value)) return value;
  if (/^https?:\/\//i.test(value)) return value;
  // An otpauth:// URI is the secret in text form, not a picture: readSetupKey
  // hands that to the user to type in instead.
  if (/^otpauth:\/\//i.test(value)) return "";

  return `data:image/png;base64,${value}`;
}

/**
 * The same secret in text, for someone who cannot scan the picture — most
 * authenticator apps take it typed. Shown alongside the QR, never stored.
 */
export function readSetupKey(res) {
  const d = body(res);
  return pick(d, "secret", "two_fa_secret", "manual_entry_key") || "";
}

/**
 * The otpauth:// URI the QR encodes. On a phone it opens the authenticator app
 * directly, which beats typing 32 characters.
 */
export function readSetupUri(res) {
  const d = body(res);
  return pick(d, "otpauth_uri", "otpauthUri", "otpauth_url") || "";
}

/** The key in groups of four — the way it is read aloud, and typed. */
export function formatSetupKey(secret) {
  const clean = String(secret || "").replace(/\s+/g, "").toUpperCase();
  const groups = clean.match(/.{1,4}/g);
  return groups ? groups.join(" ") : "";
}

/** Booleans arrive as real booleans, but a string "false" must not read as true. */
function readFlag(source, ...names) {
  const value = pick(source, ...names);
  if (typeof value === "string") return value.toLowerCase() === "true";
  return Boolean(value);
}

export function readTwoFactorState(res) {
  const d = body(res);
  return {
    twoFactorEnabled: readFlag(
      d,
      "two_fa_enabled",
      "twoFaEnabled",
      "twoFactorEnabled",
      "two_factor_enabled"
    ),
    twoFactorSkipped: readFlag(d, "twoFactorSkipped", "two_factor_skipped"),
  };
}

/**
 * A challenge-step request carries the challenge token, not a session token.
 *
 * `skipAuthToken` tells the shared request interceptor to leave the header
 * alone — otherwise a stale session cookie would be sent instead.
 */
function withTempToken(tempToken, config = {}) {
  return {
    ...config,
    headers: { ...(config.headers || {}), Authorization: `Bearer ${tempToken}` },
    skipAuthToken: true,
    skipGlobalLoader: true,
  };
}

/** Step 1 — email + password. Answers with tokens, or with a challenge. */
export function login(email, password) {
  return api.post(
    TWO_FACTOR_PATHS.login,
    { email, password },
    { skipGlobalLoader: true }
  );
}

/**
 * Step 2 — the code from the authenticator app at sign-in.
 *
 * The challenge token goes in the body, where the endpoint reads it, and also
 * as the bearer so the request carries an Authorization header either way:
 *
 *   signing in   Bearer <challenge_token>, the credential this step owns
 *   scanning a   no challenge exists, so the header is left to the shared
 *   new secret   interceptor, which attaches the session token
 */
export function verifyTwoFactor(challengeToken, code) {
  const config = challengeToken
    ? withTempToken(challengeToken)
    : { skipGlobalLoader: true };

  return api.post(
    TWO_FACTOR_PATHS.verify,
    { challenge_token: challengeToken, code },
    config
  );
}

/* ── From inside the app, with a real session ──────────────────────────────
 *
 * The switch in the sidebar belongs to someone who is already signed in, so
 * these calls carry the session token the shared interceptor attaches. The
 * backend requires exactly that (Depends(verify_token)).
 */
const asSignedInUser = { skipGlobalLoader: true };

/** A fresh secret, its QR image and its text key. */
export function startTwoFactorSetup() {
  return api.post(TWO_FACTOR_PATHS.setup, {}, asSignedInUser);
}

/** Confirm the scanned secret as a signed-in user: POST /2fa/enable { code }. */
export function confirmTwoFactorEnabled(code) {
  return api.post(TWO_FACTOR_PATHS.enable, { code }, asSignedInUser);
}

/**
 * Turn 2FA off: POST /2fa/disable { password, code }.
 *
 * The backend asks for the password as well as a current code, on purpose: a
 * stolen session alone must not be able to remove the second factor.
 */
export function disableTwoFactor(password, code) {
  return api.post(TWO_FACTOR_PATHS.disable, { password, code }, asSignedInUser);
}

/* ── Not deployed yet ──────────────────────────────────────────────────────
 * The sign-in flow has no "skip" step (login either returns tokens or a
 * challenge) and no email fallback. These stay for the pages already built
 * against the spec; they will 404 until the endpoints exist.
 */

/** "Skip for now" during sign-in. */
export function skipTwoFactor(tempToken) {
  return api.post(TWO_FACTOR_PATHS.skip, {}, withTempToken(tempToken));
}

/** Setup from the sign-in flow. The deployed backend wants a real session. */
export function setupTwoFactor(tempToken) {
  return api.post(TWO_FACTOR_PATHS.setup, {}, withTempToken(tempToken));
}

/** Enable from the sign-in flow. The deployed backend wants a real session. */
export function enableTwoFactor(tempToken, code) {
  return api.post(TWO_FACTOR_PATHS.enable, { code }, withTempToken(tempToken));
}

/** Email a one-time code to the account's address. */
export function sendEmailOtp(tempToken) {
  return api.post(TWO_FACTOR_PATHS.emailOtpSend, {}, withTempToken(tempToken));
}

/** The emailed code. Success lets the user set up a new secret. */
export function verifyEmailOtp(tempToken, otp) {
  return api.post(TWO_FACTOR_PATHS.emailOtpVerify, { otp }, withTempToken(tempToken));
}

/**
 * What to show the user when a call fails.
 *
 * Nothing about the code is echoed back — a wrong code always reads the same,
 * so the message cannot be used to tell "wrong" from "expired".
 */
export function errorMessage(error, fallback = "Invalid code, please try again.") {
  const data = error && error.response && error.response.data;
  return (
    (data && (data.detail || data.message)) ||
    (typeof data === "string" ? data : "") ||
    fallback
  );
}

/**
 * A token that has expired, or was never valid — as opposed to a code the user
 * simply got wrong.
 *
 * The two are worth separating because the backend answers 401 to both:
 *
 *   "Invalid code" / "Invalid password"   the user mistyped — stay on the page
 *   "Token expired" / "Invalid challenge" the credential is gone — start again
 *
 * Sending someone back to the login screen over one mistyped digit is the worse
 * failure of the two, so a 401 that names the code or the password is treated as
 * a rejected attempt; anything else about a 401 is treated as expired.
 */
const REJECTED_INPUT = /\b(code|password|otp)\b/i;

export function isSessionExpired(error) {
  const status = error && error.response && error.response.status;
  if (status !== 401 && status !== 403) return false;

  return !REJECTED_INPUT.test(errorMessage(error, ""));
}
