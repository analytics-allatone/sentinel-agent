import React, { useEffect, useRef, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";

import OtpInput, { OTP_LENGTH } from "../components/OtpInput/OtpInput";
import {
  errorMessage,
  isSessionExpired,
  sendEmailOtp,
  verifyEmailOtp,
} from "../api/twoFactor";
import TwoFactorLayout from "./TwoFactorLayout";
import { useAbandonToLogin, useTwoFactor } from "./TwoFactorContext";

/**
 * The way back in when the authenticator app is gone.
 *
 * A correct emailed code does NOT sign the user in — it only earns the right to
 * set up a new secret, so the page hands over to setup. Signing in here would
 * make email a second password and undo the point of the second factor.
 */
const RESEND_SECONDS = 60;

export default function EmailOtpVerify() {
  const navigate = useNavigate();
  const location = useLocation();
  const { tempToken } = useTwoFactor();
  const abandon = useAbandonToLogin();

  const [otp, setOtp] = useState("");
  const [verifying, setVerifying] = useState(false);
  const [resending, setResending] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  // The countdown continues from the send that brought the user here, so it
  // reflects the server's rate limit rather than restarting on arrival.
  const sentAt = (location.state && location.state.sentAt) || Date.now();
  const [secondsLeft, setSecondsLeft] = useState(() =>
    Math.max(0, RESEND_SECONDS - Math.floor((Date.now() - sentAt) / 1000))
  );
  const timerRef = useRef(null);

  useEffect(() => {
    if (secondsLeft <= 0) return undefined;
    timerRef.current = setTimeout(() => setSecondsLeft((s) => s - 1), 1000);
    return () => clearTimeout(timerRef.current);
  }, [secondsLeft]);

  const handleVerify = async (submitted) => {
    const value = submitted || otp;
    if (value.length !== OTP_LENGTH || verifying) return;

    setVerifying(true);
    setError("");
    setNotice("");

    try {
      await verifyEmailOtp(tempToken, value);
      // Straight on to a new QR code — the same pre-auth token carries over,
      // now at the stage that allows a fresh secret.
      navigate("/app/2fa/setup", { replace: true });
    } catch (err) {
      if (isSessionExpired(err)) {
        abandon();
        return;
      }
      setError(errorMessage(err));
      setOtp("");
      setVerifying(false);
    }
  };

  const handleResend = async () => {
    if (secondsLeft > 0 || resending) return;
    setResending(true);
    setError("");
    setNotice("");

    try {
      await sendEmailOtp(tempToken);
      setSecondsLeft(RESEND_SECONDS);
      setNotice("We sent another code.");
    } catch (err) {
      if (isSessionExpired(err)) {
        abandon();
        return;
      }
      setError(errorMessage(err, "Could not send another code. Please try again."));
    } finally {
      setResending(false);
    }
  };

  return (
    <TwoFactorLayout
      title="Check your email"
      lead="We've sent a 6-digit code to your email"
      error={error}
      footer={
        <>
          <button
            type="button"
            className="tf-link"
            onClick={handleResend}
            disabled={secondsLeft > 0 || resending || verifying}
          >
            {resending
              ? "Sending…"
              : secondsLeft > 0
                ? `Resend code in ${secondsLeft}s`
                : "Resend code"}
          </button>
          <p className="tf-note">
            Once the code is confirmed you'll set up your authenticator app again.
          </p>
        </>
      }
    >
      {notice && (
        <p className="tf-note" role="status">
          {notice}
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
          value={otp}
          onChange={setOtp}
          onComplete={handleVerify}
          disabled={verifying}
          invalid={Boolean(error) && otp.length === 0}
          label="6-digit code from your email"
        />

        <div className="tf-actions">
          <button
            type="submit"
            className="tf-btn tf-btn-primary"
            disabled={otp.length !== OTP_LENGTH || verifying}
          >
            {verifying ? (
              <>
                <span className="tf-spinner" aria-hidden="true" />
                Verifying…
              </>
            ) : (
              "Verify"
            )}
          </button>
        </div>
      </form>
    </TwoFactorLayout>
  );
}
