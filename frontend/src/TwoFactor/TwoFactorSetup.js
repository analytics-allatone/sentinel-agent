import React, { useCallback, useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";

import OtpInput, { OTP_LENGTH } from "../components/OtpInput/OtpInput";
import {
  confirmTwoFactorEnabled,
  errorMessage,
  formatSetupKey,
  isSessionExpired,
  readQrCode,
  readSetupKey,
  readSetupUri,
  startTwoFactorSetup,
} from "../api/twoFactor";
import TwoFactorLayout from "./TwoFactorLayout";
import { rememberTwoFactorEnabled } from "./twoFactorPreference";
import { useAbandonToLogin } from "./TwoFactorContext";

/**
 * Turning two-step verification on, right after signing up.
 *
 * The session already exists at this point — signup issued one — which is what
 * /2fa/setup requires. The QR is requested on arrival, held in state for as
 * long as the page is open, and never written anywhere: the image is the
 * secret.
 *
 * The code typed back goes to POST /2fa/enable { code }, which is what
 * actually switches the second factor on. Leaving this page early leaves 2FA
 * off rather than half-on.
 */
export default function TwoFactorSetup() {
  const navigate = useNavigate();
  const abandon = useAbandonToLogin();

  const [qrCode, setQrCode] = useState("");
  const [setupKey, setSetupKey] = useState("");
  const [setupUri, setSetupUri] = useState("");
  const [loadingQr, setLoadingQr] = useState(true);
  const [code, setCode] = useState("");
  const [verifying, setVerifying] = useState(false);
  const [error, setError] = useState("");

  const loadQr = useCallback(async () => {
    setLoadingQr(true);
    setError("");

    try {
      const res = await startTwoFactorSetup();
      const image = readQrCode(res);
      if (!image) {
        setError("The QR code did not arrive. Try again in a moment.");
      }
      setQrCode(image || "");
      setSetupKey(readSetupKey(res));
      setSetupUri(readSetupUri(res));
    } catch (err) {
      if (isSessionExpired(err)) {
        abandon();
        return;
      }
      setError(errorMessage(err, "Could not create a QR code. Please try again."));
    } finally {
      setLoadingQr(false);
    }
  }, [abandon]);

  useEffect(() => {
    loadQr();
  }, [loadQr]);

  const handleVerify = async (submitted) => {
    const value = submitted || code;
    if (value.length !== OTP_LENGTH || verifying) return;

    setVerifying(true);
    setError("");

    try {
      // POST /2fa/enable { code } — the only call that turns 2FA on.
      await confirmTwoFactorEnabled(value);
      rememberTwoFactorEnabled(true);
      navigate("/app/dashboard", { replace: true });
    } catch (err) {
      if (isSessionExpired(err)) {
        abandon();
        return;
      }
      // A rejected code is cleared, not left in place: the next attempt starts
      // from an empty field with the cursor already in it.
      setError(errorMessage(err));
      setCode("");
      setVerifying(false);
    }
  };

  const later = () => {
    rememberTwoFactorEnabled(false);
    navigate("/app/dashboard", { replace: true });
  };

  return (
    <TwoFactorLayout
      title="Two-Step Verification"
      lead="Scan the QR code with your authenticator app, then enter the 6-digit code it shows."
      error={error}
    >
      <div className={`tf-qr ${loadingQr ? "tf-qr-loading" : ""}`}>
        {loadingQr ? (
          <>
            <span className="tf-qr-spinner" aria-hidden="true" />
            <span>Creating your code…</span>
          </>
        ) : qrCode ? (
          <img src={qrCode} alt="Scan with your authenticator app" width={220} />
        ) : (
          <button type="button" className="tf-link" onClick={loadQr}>
            Try again
          </button>
        )}
      </div>

      {/* Not every phone camera cooperates; the key types in too, in fours. */}
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

      <form
        className="tf-form"
        onSubmit={(e) => {
          e.preventDefault();
          handleVerify();
        }}
      >
        <OtpInput
          value={code}
          onChange={setCode}
          onComplete={handleVerify}
          disabled={verifying || loadingQr}
          invalid={Boolean(error) && code.length === 0}
          label="6-digit code from your authenticator app"
        />

        <div className="tf-actions">
          <button
            type="submit"
            className="tf-btn tf-btn-primary"
            disabled={code.length !== OTP_LENGTH || verifying || loadingQr}
          >
            {verifying ? (
              <>
                <span className="tf-spinner" aria-hidden="true" />
                Verifying…
              </>
            ) : (
              "Verify and turn on"
            )}
          </button>

          <button
            type="button"
            className="tf-btn tf-btn-secondary"
            onClick={later}
            disabled={verifying}
          >
            Skip for now
          </button>
        </div>
      </form>
    </TwoFactorLayout>
  );
}
