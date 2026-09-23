import React, { useCallback, useEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { LuShieldCheck } from "react-icons/lu";

import OtpInput, { OTP_LENGTH } from "../components/OtpInput/OtpInput";
import PasswordField from "../components/PasswordField/PasswordField";
import {
  confirmTwoFactorEnabled,
  disableTwoFactor,
  errorMessage,
  formatSetupKey,
  readQrCode,
  readSetupKey,
  readSetupUri,
  startTwoFactorSetup,
} from "../api/twoFactor";
import {
  readRememberedTwoFactorEnabled,
  rememberTwoFactorEnabled,
} from "./twoFactorPreference";
import "./TwoFactor.css";
import "./TwoFactorToggle.css";

/**
 * The two-step verification switch that lives in the sidebar.
 *
 * Turning it on runs on a real session, which is what /2fa/setup and
 * /2fa/enable both require — the two calls this switch makes, along with
 * /2fa/disable on the way back down.
 *
 * Neither direction is a single request, and that is deliberate:
 *
 *   off to on   a new secret is created, its QR shown, and the switch only
 *               moves once the user proves the authenticator app has it.
 *               Flipping it without that locks the account out at next sign-in.
 *   on to off   the backend asks for the password AND a current code, so a
 *               stolen session alone cannot remove the second factor.
 *
 * Nothing is written down along the way: the QR, the setup key, the password
 * and the typed codes live in this component's state and go with it. Only
 * "2FA is on" is remembered, so the switch does not start in the wrong
 * position on the next page load.
 */
export default function TwoFactorToggle() {
  const [enabled, setEnabled] = useState(readRememberedTwoFactorEnabled);
  const [dialog, setDialog] = useState(null); // null | "enable" | "disable"
  const [qrCode, setQrCode] = useState("");
  const [setupKey, setSetupKey] = useState("");
  const [setupUri, setSetupUri] = useState("");
  const [loadingQr, setLoadingQr] = useState(false);
  const [code, setCode] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  const noticeTimer = useRef(null);
  const dialogRef = useRef(null);

  useEffect(() => () => clearTimeout(noticeTimer.current), []);

  const reset = useCallback(() => {
    setCode("");
    setPassword("");
    setQrCode("");
    setSetupKey("");
    setSetupUri("");
    setError("");
  }, []);

  const closeDialog = useCallback(() => {
    if (busy) return; // a request is in flight; let it finish
    setDialog(null);
    reset();
  }, [busy, reset]);

  // Put the cursor where the typing is meant to land — the password box, or the
  // first code box — rather than on the dialog itself, which would look open and
  // ready while quietly swallowing everything typed into it. It runs again when
  // the boxes stop being disabled, because the QR arrives after the dialog does.
  useEffect(() => {
    if (!dialog) return undefined;

    const root = dialogRef.current;
    if (root) {
      const active = document.activeElement;
      const alreadyTyping =
        active && root.contains(active) && active.tagName === "INPUT";

      if (!alreadyTyping) {
        const firstField = root.querySelector("input:not([disabled])");
        (firstField || root).focus();
      }
    }

    const onKeyDown = (e) => {
      if (e.key === "Escape") closeDialog();
    };
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, [dialog, loadingQr, busy, closeDialog]);

  const settle = (nowEnabled, message) => {
    setEnabled(nowEnabled);
    rememberTwoFactorEnabled(nowEnabled);
    setBusy(false);
    setDialog(null);
    reset();
    setNotice(message);
    clearTimeout(noticeTimer.current);
    noticeTimer.current = setTimeout(() => setNotice(""), 6000);
  };

  const openEnable = async () => {
    setDialog("enable");
    reset();
    setNotice("");
    setLoadingQr(true);

    try {
      const res = await startTwoFactorSetup();
      const image = readQrCode(res);
      if (!image) setError("The QR code did not arrive. Try again in a moment.");
      setQrCode(image || "");
      setSetupKey(readSetupKey(res));
      setSetupUri(readSetupUri(res));
    } catch (err) {
      setError(errorMessage(err, "Could not start setup. Please try again."));
    } finally {
      setLoadingQr(false);
    }
  };

  const openDisable = () => {
    setDialog("disable");
    reset();
    setNotice("");
  };

  const submit = async (submitted) => {
    const value = submitted || code;
    if (value.length !== OTP_LENGTH || busy) return;

    const turningOff = dialog === "disable";
    if (turningOff && !password) {
      setError("Enter your password to confirm.");
      return;
    }

    setBusy(true);
    setError("");

    try {
      if (turningOff) {
        await disableTwoFactor(password, value);
        settle(false, "Two-step verification is off.");
      } else {
        // POST /2fa/enable { code } — the only call that turns 2FA on.
        await confirmTwoFactorEnabled(value);
        settle(true, "Two-step verification is on.");
      }
    } catch (err) {
      // A rejected attempt leaves the switch exactly where it was, and clears
      // the code so the next try starts from a fresh one — the old one has
      // expired by now anyway.
      setError(errorMessage(err));
      setCode("");
      setBusy(false);
    }
  };

  const turningOn = dialog === "enable";

  return (
    <div className="tf-switch-block">
      <div className="tf-switch-row">
        <span className="tf-switch-icon" aria-hidden="true">
          <LuShieldCheck />
        </span>

        <span className="tf-switch-text">
          <span className="tf-switch-label">Two-step verification</span>
          <span className="tf-switch-state">{enabled ? "On" : "Off"}</span>
        </span>

        <button
          type="button"
          role="switch"
          aria-checked={enabled}
          aria-label="Two-step verification"
          className={`tf-switch ${enabled ? "tf-switch-on" : ""}`}
          onClick={enabled ? openDisable : openEnable}
          disabled={Boolean(dialog)}
          title={
            enabled
              ? "Turn off two-step verification"
              : "Turn on two-step verification"
          }
        >
          <span className="tf-switch-knob" aria-hidden="true" />
        </button>
      </div>

      {notice && (
        <p className="tf-switch-notice" role="status">
          {notice}
        </p>
      )}

      {dialog &&
        createPortal(
          <div
            className="tf-modal-overlay"
            onMouseDown={(e) => {
              if (e.target === e.currentTarget) closeDialog();
            }}
          >
            <div
              className="tf-modal"
              role="dialog"
              aria-modal="true"
              aria-labelledby="tf-modal-title"
              ref={dialogRef}
              tabIndex={-1}
            >
              <h2 id="tf-modal-title" className="tf-modal-title">
                {turningOn
                  ? "Turn on two-step verification"
                  : "Turn off two-step verification"}
              </h2>

              <p className="tf-modal-lead">
                {turningOn
                  ? "Scan this QR code with your authenticator app, then enter the 6-digit code it shows."
                  : "Confirm with your password and the current 6-digit code. After this, your password alone will sign you in."}
              </p>

              {turningOn && (
                <>
                  <div className={`tf-qr ${loadingQr ? "tf-qr-loading" : ""}`}>
                    {loadingQr ? (
                      <>
                        <span className="tf-qr-spinner" aria-hidden="true" />
                        <span>Creating your code…</span>
                      </>
                    ) : qrCode ? (
                      <img
                        src={qrCode}
                        alt="Scan with your authenticator app"
                        width={220}
                      />
                    ) : (
                      <button type="button" className="tf-link" onClick={openEnable}>
                        Try again
                      </button>
                    )}
                  </div>

                  {/* Not every phone camera cooperates; the key types in too. */}
                  {setupKey && (
                    <p className="tf-setup-key">
                      Can't scan? Enter this key manually:
                      <code>{formatSetupKey(setupKey)}</code>
                      {setupUri && (
                        <a className="tf-setup-link" href={setupUri}>
                          Open in your authenticator app
                        </a>
                      )}
                    </p>
                  )}
                </>
              )}

              {error && (
                <div className="tf-error" role="alert">
                  {error}
                </div>
              )}

              <form
                className="tf-form"
                onSubmit={(e) => {
                  e.preventDefault();
                  submit();
                }}
              >
                {!turningOn && (
                  <div className="tf-field">
                    <label htmlFor="tf-disable-password">Password</label>
                    <PasswordField
                      id="tf-disable-password"
                      name="password"
                      placeholder="Your account password"
                      autoComplete="current-password"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      disabled={busy}
                    />
                  </div>
                )}

                <OtpInput
                  value={code}
                  onChange={setCode}
                  onComplete={submit}
                  disabled={busy || loadingQr}
                  autoFocus={turningOn}
                  invalid={Boolean(error) && code.length === 0}
                  label={
                    turningOn
                      ? "6-digit code from your authenticator app"
                      : "6-digit code to confirm"
                  }
                />

                <div className="tf-actions">
                  <button
                    type="submit"
                    className={`tf-btn ${turningOn ? "tf-btn-primary" : "tf-btn-danger"}`}
                    disabled={code.length !== OTP_LENGTH || busy || loadingQr}
                  >
                    {busy ? (
                      <>
                        <span className="tf-spinner" aria-hidden="true" />
                        {turningOn ? "Turning on…" : "Turning off…"}
                      </>
                    ) : turningOn ? (
                      "Verify and turn on"
                    ) : (
                      "Turn off"
                    )}
                  </button>

                  <button
                    type="button"
                    className="tf-btn tf-btn-secondary"
                    onClick={closeDialog}
                    disabled={busy}
                  >
                    Cancel
                  </button>
                </div>
              </form>
            </div>
          </div>,
          document.body
        )}
    </div>
  );
}
