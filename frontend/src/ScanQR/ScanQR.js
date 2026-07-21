import { useEffect, useRef, useState } from "react";
import { useNavigate, useLocation, Navigate } from "react-router-dom";
import { Html5QrcodeScanner } from "html5-qrcode";
import { setCookie } from "../api/api";
import "./ScanQR.css";

const READER_ID = "qr-reader";

/**
 * ScanQR — second step of login. After email + password succeed, the user must:
 *   1. Scan a QR code with their device camera (or upload a QR image), then
 *   2. Enter a password to finish signing in.
 *
 * Frontend-only: the tokens issued at the email/password step are held in
 * navigation state and only committed (as cookies) once both the scan and the
 * password step are completed here. There is no server enforcing this gate, so
 * it is a UX/demo flow rather than a real security boundary.
 */
function ScanQR() {
  const navigate = useNavigate();
  const location = useLocation();

  // Passed from the Login page. Without an email we weren't sent here by login.
  const email = location.state?.email || "";
  const pendingAccessToken = location.state?.pendingAccessToken;
  const pendingRefreshToken = location.state?.pendingRefreshToken;

  const [scannedValue, setScannedValue] = useState(null); // set once a QR decodes
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [loading, setLoading] = useState(false);

  const scannerRef = useRef(null);

  // Mount the camera scanner while we're on the scan step. Tear it down on
  // unmount or once a code is captured.
  useEffect(() => {
    if (scannedValue) return undefined; // scan step done -> no scanner needed
    if (!email) return undefined; // guard-redirect will handle it

    const scanner = new Html5QrcodeScanner(
      READER_ID,
      { fps: 10, qrbox: { width: 240, height: 240 }, rememberLastUsedCamera: true },
      /* verbose */ false,
    );
    scannerRef.current = scanner;

    const onSuccess = (decodedText) => {
      setScannedValue(decodedText);
      setError("");
      // Stop the camera as soon as we have a code.
      scanner.clear().catch(() => {});
      scannerRef.current = null;
    };
    // Per-frame decode failures are normal (no QR in view) — ignore them.
    const onError = () => {};

    scanner.render(onSuccess, onError);

    return () => {
      // Html5QrcodeScanner.clear() rejects if already cleared; swallow it.
      if (scannerRef.current) {
        scannerRef.current.clear().catch(() => {});
        scannerRef.current = null;
      }
    };
  }, [scannedValue, email]);

  // Guard: reached without coming through the login step.
  if (!email) {
    return <Navigate to="/login" replace />;
  }

  const finishLogin = () => {
    if (pendingAccessToken) setCookie("token", pendingAccessToken, 7);
    if (pendingRefreshToken) setCookie("refresh_token", pendingRefreshToken, 30);
    localStorage.setItem("auth_email", email);
    navigate("/dashboard");
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    setError("");
    if (!scannedValue) {
      setError("Please scan your QR code first");
      return;
    }
    if (!password) {
      setError("Please enter your password");
      return;
    }
    setLoading(true);
    setSuccess("Verified! Signing you in...");
    setTimeout(finishLogin, 800);
  };

  const rescan = () => {
    setScannedValue(null);
    setPassword("");
    setError("");
    setSuccess("");
  };

  return (
    <div className="scan-page">
      <div className="scan-container">
        <div className="card">
          <div className="card-header">
            <div className="scan-icon">{scannedValue ? "🔑" : "📷"}</div>
            <h1>{scannedValue ? "Enter Password" : "Scan QR Code"}</h1>
            <p>
              {scannedValue
                ? "Enter your password to finish signing in."
                : "Point your camera at your QR code, or upload an image of it."}
            </p>
          </div>

          {error && <div className="error-message">{error}</div>}
          {success && <div className="success-message">{success}</div>}

          {/* Step 1: scan */}
          {!scannedValue && (
            <div className="scan-body">
              <div id={READER_ID} className="qr-reader" />
              <p className="scan-hint">
                Signing in as <strong>{email}</strong>
              </p>
            </div>
          )}

          {/* Step 2: password */}
          {scannedValue && (
            <form onSubmit={handleSubmit}>
              <div className="scanned-chip" title={scannedValue}>
                <span className="scanned-check">✓</span> QR code scanned
              </div>

              <div className="input-group">
                <label htmlFor="scan-password">Password</label>
                <input
                  id="scan-password"
                  type="password"
                  placeholder="Enter your password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  disabled={loading}
                  autoFocus
                />
              </div>

              <button
                type="submit"
                className={`verify-btn ${loading ? "loading" : ""}`}
                disabled={loading}
              >
                {loading ? "Signing in..." : "Verify & Login"}
              </button>

              <button
                type="button"
                className="rescan-btn"
                onClick={rescan}
                disabled={loading}
              >
                Scan a different code
              </button>
            </form>
          )}

          <div className="login-link">
            <a href="/login">Back to Sign in</a>
          </div>
        </div>
      </div>
    </div>
  );
}

export default ScanQR;
