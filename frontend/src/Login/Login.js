import { useEffect, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { setCookie } from "../api/api";
import {
  errorMessage,
  login as loginRequest,
  readAccessToken,
  readRefreshToken,
  readTempToken,
  readTwoFactorState,
} from "../api/twoFactor";
import { useTwoFactor } from "../TwoFactor/TwoFactorContext";
import { rememberTwoFactorEnabled } from "../TwoFactor/twoFactorPreference";
import Header from "../Header/Header";
import PasswordField from "../components/PasswordField/PasswordField";
import "./Login.css";

function Login() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const navigate = useNavigate();
  const location = useLocation();
  const { begin } = useTwoFactor();

  // A pre-auth token that ran out mid-flow sends the user back here with a
  // reason, rather than to a login page that looks like nothing happened.
  useEffect(() => {
    if (location.state && location.state.notice) setNotice(location.state.notice);
  }, [location.state]);

  const login = async (e) => {
    e.preventDefault();
    setError("");

    if (!email || !password) {
      setError("Please fill in all fields");
      return;
    }

    setLoading(true);
    setNotice("");
    try {
      const address = email.trim().toLowerCase();
      const response = await loginRequest(address, password);

      const challengeToken = readTempToken(response);
      const { twoFactorEnabled } = readTwoFactorState(response);

      // two_fa_enabled decides the path: an account with it on gets no session
      // here, only the short-lived challenge token, kept in memory for the
      // code page. Turning 2FA on is not offered at sign-in — that needs a
      // real session, so it lives after signup and on the sidebar switch.
      if (twoFactorEnabled || challengeToken) {
        if (!challengeToken) {
          setError("Two-step verification could not start. Please try again.");
          return;
        }
        begin(challengeToken, address);
        navigate("/app/2fa/verify");
        return;
      }

      // two_fa_enabled false: the API signed the user straight in, and the
      // tokens in this same answer are the session.
      const accessToken = readAccessToken(response);
      if (!accessToken) {
        setError("Sign-in did not complete. Please try again.");
        return;
      }

      setCookie("token", accessToken, 7);
      const refreshToken = readRefreshToken(response);
      if (refreshToken) setCookie("refresh_token", refreshToken, 30);
      localStorage.setItem("auth_email", address);
      rememberTwoFactorEnabled(twoFactorEnabled);
      navigate("/app/dashboard", { replace: true });
    } catch (err) {
      setError(errorMessage(err, "Login failed. Please try again."));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="login-page">
      <Header />
      {/* <header className="page-header">
        <div className="header-content">
          <div className="logo">
            <img src="https://via.placeholder.com/150x40?text=Guardlynx" alt="Guardlynx Logo" className="logo-img" />
          </div>
          <div className="header-info">
            <h2>Guardlynx</h2>
            <p>Security Management System</p>
          </div>
          <nav className="header-nav">
            <a href="/app/register" className="nav-link">Sign Up</a>
          </nav>
        </div>
      </header> */}

      <div className="login-container">
        <div className="card">
          <div className="card-header">
            <h1>Welcome Back</h1>
            <p>Sign in to your account</p>
          </div>

          <form onSubmit={login}>
            {notice && (
              <div className="notice-message" role="status">
                {notice}
              </div>
            )}
            {error && <div className="error-message">{error}</div>}

            <div className="input-group">
              <label htmlFor="email">Email</label>
              <input
                id="email"
                type="email"
                placeholder="Enter your email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                disabled={loading}
              />
            </div>

            <div className="input-group">
              <label htmlFor="password">Password</label>
              <PasswordField
                id="password"
                name="password"
                placeholder="Enter your password"
                autoComplete="current-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                disabled={loading}
              />
            </div>

            <a href="/app/forgot-password" className="forgot-password">Forgot password?</a>

            <button
              type="submit"
              className={`login-btn ${loading ? "loading" : ""}`}
              disabled={loading}
            >
              {loading ? "Signing in..." : "Sign In"}
            </button>
          </form>

          <div className="signup-link">
            Don't have an account? <a href="/app/register">Sign up here</a>
          </div>
        </div>
      </div>
    </div>
  );
}

export default Login;
