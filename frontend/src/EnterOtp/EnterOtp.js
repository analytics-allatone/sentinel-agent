import { useState, useRef, useEffect } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import api from "../api/api";
import "./EnterOtp.css";

const OTP_LENGTH = 6;
const RESEND_SECONDS = 30;

function EnterOtp() {
  const [digits, setDigits] = useState(Array(OTP_LENGTH).fill(""));
  const [loading, setLoading] = useState(false);
  const [resending, setResending] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [timer, setTimer] = useState(RESEND_SECONDS);

  const inputsRef = useRef([]);
  const navigate = useNavigate();
  const location = useLocation();

  // The email is usually passed in from the previous step (e.g. login/register).
  const email = location.state?.email || "";

  useEffect(() => {
    inputsRef.current[0]?.focus();
  }, []);

  // Countdown for the resend button.
  useEffect(() => {
    if (timer <= 0) return;
    const id = setInterval(() => setTimer((t) => t - 1), 1000);
    return () => clearInterval(id);
  }, [timer]);

  const focusInput = (index) => {
    inputsRef.current[index]?.focus();
  };

  const handleChange = (index, value) => {
    const digit = value.replace(/\D/g, "").slice(-1); // keep last typed digit
    const next = [...digits];
    next[index] = digit;
    setDigits(next);
    setError("");

    if (digit && index < OTP_LENGTH - 1) {
      focusInput(index + 1);
    }
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
    const pasted = e.clipboardData
      .getData("text")
      .replace(/\D/g, "")
      .slice(0, OTP_LENGTH);
    if (!pasted) return;

    const next = Array(OTP_LENGTH).fill("");
    pasted.split("").forEach((d, i) => {
      next[i] = d;
    });
    setDigits(next);
    setError("");
    focusInput(Math.min(pasted.length, OTP_LENGTH - 1));
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
      await api.post("/api/v1/verify-otp", { email, otp: code });
      setSuccess("Verified successfully! Redirecting...");
      setTimeout(() => navigate("/dashboard"), 1500);
    } catch (err) {
      setError(err.response?.data?.message || "Invalid or expired OTP");
      setDigits(Array(OTP_LENGTH).fill(""));
      focusInput(0);
    } finally {
      setLoading(false);
    }
  };

  const handleResend = async () => {
    if (timer > 0 || resending) return;
    setError("");
    setSuccess("");
    setResending(true);
    try {
      await api.post("/api/v1/resend-otp", { email });
      setSuccess("A new code has been sent to your email");
      setTimer(RESEND_SECONDS);
    } catch (err) {
      setError(err.response?.data?.message || "Failed to resend code");
    } finally {
      setResending(false);
    }
  };

  return (
    <div className="otp-page">
      <div className="otp-container">
        <div className="card">
          <div className="card-header">
            <div className="otp-icon">🔒</div>
            <h1>Enter OTP</h1>
            <p>
              We've sent a {OTP_LENGTH}-digit verification code
              {email ? (
                <>
                  {" "}to <strong>{email}</strong>
                </>
              ) : (
                " to your email"
              )}
            </p>
          </div>

          <form onSubmit={handleSubmit}>
            {error && <div className="error-message">{error}</div>}
            {success && <div className="success-message">{success}</div>}

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
              {loading ? "Verifying..." : "Verify"}
            </button>
          </form>

          <div className="resend-row">
            {timer > 0 ? (
              <span className="resend-timer">
                Resend code in <strong>{timer}s</strong>
              </span>
            ) : (
              <button
                type="button"
                className="resend-btn"
                onClick={handleResend}
                disabled={resending}
              >
                {resending ? "Sending..." : "Resend Code"}
              </button>
            )}
          </div>

          <div className="login-link">
            <a href="/login">Back to Sign in</a>
          </div>
        </div>
      </div>
    </div>
  );
}

export default EnterOtp;
