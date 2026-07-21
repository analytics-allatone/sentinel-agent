import { useState, useRef, useEffect, useMemo } from "react";
import { useNavigate, useLocation, Navigate } from "react-router-dom";
import { QRCodeCanvas } from "qrcode.react";
import { setCookie } from "../api/api";
import { getOrCreateSecret, buildOtpauthUrl, verifyTotp } from "../utils/totp";
import "./VerifyOtp.css";

const OTP_LENGTH = 6;

/**
 * VerifyOtp — second step of login.
 *
 *   1. We show a QR code (an otpauth:// URL built from a per-user TOTP secret).
 *   2. The user scans it with Google Authenticator / Microsoft Authenticator /
 *      Authy, which then generates a rotating 6-digit OTP.
 *   3. The user types that OTP here; we verify it in the browser and sign in.
 *
 * Frontend-only: the secret lives in localStorage and verification happens in
 * the browser, so this is a working demo of the flow, not a security boundary.
 */
function VerifyOtp() {
  const navigate = useNavigate();
  const location = useLocation();

  const email = location.state?.email || "";
  const pendingAccessToken = location.state?.pendingAccessToken;
  const pendingRefreshToken = location.state?.pendingRefreshToken;

  const [digits, setDigits] = useState(Array(OTP_LENGTH).fill(""));
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [loading, setLoading] = useState(false);

  const inputsRef = useRef([]);

  // A stable secret + its QR URL for this user (persisted so the same
  // authenticator entry keeps working on future logins).
  const secret = useMemo(() => (email ? getOrCreateSecret(email) : ""), [email]);
  const otpauthUrl = useMemo(
    () => (secret ? buildOtpauthUrl(secret, email) : ""),
    [secret, email],
  );

  useEffect(() => {
    inputsRef.current[0]?.focus();
  }, []);

  // Guard: reached without coming through the login step.
  if (!email) {
    return <Navigate to="/login" replace />;
  }

  const focusInput = (i) => inputsRef.current[i]?.focus();

  const handleChange = (index, value) => {
    const digit = value.replace(/\D/g, "").slice(-1);
    const next = [...digits];
    next[index] = digit;
    setDigits(next);
    setError("");
    if (digit && index < OTP_LENGTH - 1) focusInput(index + 1);
  };

  const handleKeyDown = (index, e) => {
    if (e.key === "Backspace") {
      if (digits[index]) {
        const next = [...digits];
        next[index] = "";
        setDigits(next);
      } else if (index > 0) {
        focusInput(index - 1);
      }
    } else if (e.key === "ArrowLeft" && index > 0) {
      focusInput(index - 1);
    } else if (e.key === "ArrowRight" && index < OTP_LENGTH - 1) {
      focusInput(index + 1);
    }
  };

  const handlePaste = (e) => {
    e.preventDefault();
    const pasted = e.clipboardData.getData("text").replace(/\D/g, "").slice(0, OTP_LENGTH);
    if (!pasted) return;
    const next = Array(OTP_LENGTH).fill("");
    pasted.split("").forEach((d, i) => (next[i] = d));
    setDigits(next);
    setError("");
    focusInput(Math.min(pasted.length, OTP_LENGTH - 1));
  };

  const finishLogin = () => {
    if (pendingAccessToken) setCookie("token", pendingAccessToken, 7);
    if (pendingRefreshToken) setCookie("refresh_token", pendingRefreshToken, 30);
    localStorage.setItem("auth_email", email);
    navigate("/dashboard");
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");
    setSuccess("");

    const code = digits.join("");
    if (code.length !== OTP_LENGTH) {
      setError(`Please enter the full ${OTP_LENGTH}-digit code`);
      return;
    }

    setLoading(true);
    try {
      const ok = await verifyTotp(secret, code);
      if (ok) {
        setSuccess("Verified! Signing you in...");
        setTimeout(finishLogin, 800);
        return;
      }
      setError("Invalid or expired code. Check your authenticator app.");
      setDigits(Array(OTP_LENGTH).fill(""));
      focusInput(0);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="votp-page">
      <div className="votp-container">
        <div className="card">
          <div className="card-header">
            <div className="votp-icon">🔐</div>
            <h1>Two-Step Verification</h1>
            <p>
              Scan the QR code with your authenticator app, then enter the
              6-digit code it shows.
            </p>
          </div>

          {error && <div className="error-message">{error}</div>}
          {success && <div className="success-message">{success}</div>}

          {/* Step 1: QR to scan */}
          <div className="qr-panel">
            <div className="qr-box">
              <QRCodeCanvas value={otpauthUrl} size={168} includeMargin />
            </div>
            <ol className="qr-steps">
              <li>
                Open <strong>Google Authenticator</strong>, Microsoft
                Authenticator, or Authy.
              </li>
              <li>Scan this QR (or add the key below manually).</li>
              <li>Enter the 6-digit code it generates.</li>
            </ol>
          </div>

          <details className="manual-key">
            <summary>Can't scan? Enter this key manually</summary>
            <code>{secret}</code>
          </details>

          {/* Step 2: enter OTP */}
          <form onSubmit={handleSubmit}>
            <div className="otp-inputs" onPaste={handlePaste}>
              {digits.map((digit, index) => (
                <input
                  key={index}
                  ref={(el) => (inputsRef.current[index] = el)}
                  type="text"
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  maxLength="1"
                  className={`otp-box ${digit ? "filled" : ""}`}
                  value={digit}
                  onChange={(e) => handleChange(index, e.target.value)}
                  onKeyDown={(e) => handleKeyDown(index, e)}
                  disabled={loading}
                />
              ))}
            </div>

            <button
              type="submit"
              className={`verify-btn ${loading ? "loading" : ""}`}
              disabled={loading}
            >
              {loading ? "Verifying..." : "Verify & Login"}
            </button>
          </form>

          <p className="votp-signin-as">
            Signing in as <strong>{email}</strong>
          </p>
          <div className="login-link">
            <a href="/login">Back to Sign in</a>
          </div>
        </div>
      </div>
    </div>
  );
}

export default VerifyOtp;
