import React from "react";
import { useNavigate } from "react-router-dom";
import { LuShieldCheck } from "react-icons/lu";

import TwoFactorLayout from "./TwoFactorLayout";
import { rememberTwoFactorEnabled } from "./twoFactorPreference";

/**
 * The choice offered straight after signing up: turn two-step verification on
 * now, or go in without it.
 *
 * Signup already returned a real session, so there is nothing to ask the API
 * here — and no "skip" endpoint to call. Skipping is simply walking to the
 * dashboard, and turning it on is the ordinary /2fa/setup flow the sidebar
 * switch uses, which is why this page makes no request of its own.
 */
export default function EnableTwoFactorPrompt() {
  const navigate = useNavigate();

  const skip = () => {
    rememberTwoFactorEnabled(false);
    navigate("/app/dashboard", { replace: true });
  };

  return (
    <TwoFactorLayout
      title="Secure your account"
      lead="Two-step verification asks for a code from your phone as well as your password, so a stolen password is not enough to get in."
      footer={
        <p className="tf-note">
          You can turn this on at any time from the sidebar.
        </p>
      }
    >
      <div className="tf-shield" aria-hidden="true">
        <LuShieldCheck size={28} strokeWidth={1.5} />
      </div>

      <ul className="tf-points">
        <li>Works with Google Authenticator, Microsoft Authenticator or Authy.</li>
        <li>Takes about a minute to set up — scan one QR code.</li>
        <li>Your password alone will no longer be enough to sign in.</li>
      </ul>

      <div className="tf-actions">
        <button
          type="button"
          className="tf-btn tf-btn-primary"
          onClick={() => navigate("/app/2fa/setup")}
        >
          Enable two-step verification
        </button>

        <button type="button" className="tf-btn tf-btn-secondary" onClick={skip}>
          Skip for now
        </button>
      </div>
    </TwoFactorLayout>
  );
}
