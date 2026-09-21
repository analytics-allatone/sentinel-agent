/**
 * Whether this account has two-step verification turned on.
 *
 * The API has no endpoint that reports it outside of sign-in, so the answer
 * from the login response is remembered here and the sidebar switch starts from
 * it. It is refreshed from the server whenever `/2fa/status` answers.
 *
 * Only this flag is stored. The pre-auth token, the QR code and every code the
 * user types stay in memory, exactly as before — knowing that 2FA is on is not
 * a secret, and the switch would otherwise flash the wrong state on every load.
 */
export const TWO_FACTOR_ENABLED_KEY = "two_factor_enabled";

export function rememberTwoFactorEnabled(enabled) {
  try {
    localStorage.setItem(TWO_FACTOR_ENABLED_KEY, enabled ? "true" : "false");
  } catch (err) {
    // Private browsing can refuse storage; the switch still works for this tab.
  }
}

export function readRememberedTwoFactorEnabled() {
  try {
    return localStorage.getItem(TWO_FACTOR_ENABLED_KEY) === "true";
  } catch (err) {
    return false;
  }
}

export function forgetTwoFactorEnabled() {
  try {
    localStorage.removeItem(TWO_FACTOR_ENABLED_KEY);
  } catch (err) {
    // nothing to clean up
  }
}
