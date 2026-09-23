import React, { useState } from "react";
import { useNavigate } from "react-router-dom";

import OtpInput, { OTP_LENGTH } from "../components/OtpInput/OtpInput";
import {
  errorMessage,
  isSessionExpired,
  readAccessToken,
  readRefreshToken,
  sendEmailOtp,
  verifyTwoFactor,
} from "../api/twoFactor";
import TwoFactorLayout from "./TwoFactorLayout";
import {
  useAbandonToLogin,
  useCompleteSignIn,
  useTwoFactor,
} from "./TwoFactorContext";

/**
 * The step every sign-in goes through once two-step verification is on.
 *
 * There is deliberately no QR code here. A page that can show a fresh secret to
 * whoever holds a password is a way around the second factor, not a convenience
 * — resetting has to go through the emailed code first.
 */
export default function TwoFactorVerify() {
  const navigate = useNavigate();
  const { tempToken } = useTwoFactor();
  const completeSignIn = useCompleteSignIn();
  const abandon = useAbandonToLogin();

  const [code, setCode] = useState("");
  const [verifying, setVerifying] = useState(false);
  const [sendingEmail, setSendingEmail] = useState(false);
  const [error, setError] = useState("");

  const handleVerify = async (submitted) => {
    const value = submitted || code;
    if (value.length !== OTP_LENGTH || verifying) return;

    setVerifying(true);
    setError("");

    try {
      const res = await verifyTwoFactor(tempToken, value);
      completeSignIn(readAccessToken(res), readRefreshToken(res), {
        twoFactorEnabled: true,
      });
    } catch (err) {
      if (isSessionExpired(err)) {
        abandon();
        return;
      }
      setError(errorMessage(err));
      setCode("");
      setVerifying(false);
    }
  };

  const handleEmailInstead = async () => {
    if (sendingEmail || verifying) return;
    setSendingEmail(true);
    setError("");

    try {
      await sendEmailOtp(tempToken);
      // The next page starts its own 60-second countdown from this send.
      navigate("/app/2fa/email-otp", { state: { sentAt: Date.now() } });
    } catch (err) {
      if (isSessionExpired(err)) {
        abandon();
        return;
      }
      setError(errorMessage(err, "Could not send the email. Please try again."));
      setSendingEmail(false);
    }
  };

  return (
    <TwoFactorLayout
      title="Two-Step Verification"
      lead="Enter the 6-digit code from your authenticator app"
      error={error}
      footer={
        <button
          type="button"
          className="tf-link"
          onClick={handleEmailInstead}
          disabled={sendingEmail || verifying}
        >
          {sendingEmail
            ? "Sending a code to your email…"
            : "Don't have your code? Get a code by email"}
        </button>
      }
    >
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
          disabled={verifying}
          invalid={Boolean(error) && code.length === 0}
          label="6-digit code from your authenticator app"
        />

        <div className="tf-actions">
          <button
            type="submit"
            className="tf-btn tf-btn-primary"
            disabled={code.length !== OTP_LENGTH || verifying}
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
