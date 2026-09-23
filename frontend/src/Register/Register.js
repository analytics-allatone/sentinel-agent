import { useState } from "react";
import { useNavigate } from "react-router-dom";
import api, { setCookie } from "../api/api";
import { readAccessToken, readRefreshToken } from "../api/twoFactor";
import PasswordField from "../components/PasswordField/PasswordField";
import "./Register.css";
import Header from "../Header/Header";


function Register() {
  // Signup sends only what a person types. The role is assigned by the
  // backend, so it is neither asked for here nor put in the request body.
  const [form, setForm] = useState({
    name: "",
    email: "",
    password: "",
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const navigate = useNavigate();

  const handleChange = (e) => {
    const { name, value } = e.target;
    setForm({ ...form, [name]: value });
  };

  const validateForm = () => {
    if (!form.name.trim() || !form.email || !form.password) {
      setError("Please fill in all fields");
      return false;
    }

    if (!/^\S+@\S+\.\S+$/.test(form.email)) {
      setError("Please enter a valid email address");
      return false;
    }

    if (form.password.length < 6) {
      setError("Password must be at least 6 characters long");
      return false;
    }

    return true;
  };

  const register = async (e) => {
    e.preventDefault();
    setError("");
    setSuccess("");

    if (!validateForm()) {
      return;
    }

    setLoading(true);
    try {
      const address = form.email.trim().toLowerCase();
      const response = await api.post("/signup", {
        name: form.name.trim(),
        email: address,
        password: form.password,
      });

      // Remember the registered email so the RBAC layer can identify the
      // user (the first registered user becomes the Super Admin).
      localStorage.setItem("auth_email", address);

      // Signup hands back a real session, so the new account is already
      // signed in. That session is what lets the next page offer two-step
      // verification: /2fa/setup needs a token, not a half-signed-in state.
      const accessToken = readAccessToken(response);
      if (!accessToken) {
        setError("Account created, but sign-in did not complete. Please log in.");
        return;
      }

      setCookie("token", accessToken, 7);
      const refreshToken = readRefreshToken(response);
      if (refreshToken) setCookie("refresh_token", refreshToken, 30);

      setSuccess("Account created successfully!");
      setForm({ name: "", email: "", password: "" });
      navigate("/app/2fa/enable", { replace: true });
    } catch (err) {
      setError(
        err.response?.data?.message || "Registration failed. Please try again.",
      );
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="register-page">
      <Header />
      <div className="register-container">
        <div className="card">
          <div className="card-header">
            <h1>Create Account</h1>
            <p>Join us today</p>
          </div>

          <form onSubmit={register}>
            {error && <div className="error-message">{error}</div>}
            {success && <div className="success-message">{success}</div>}

            <div className="input-group">
              <label htmlFor="name">Name</label>
              <input
                id="name"
                type="text"
                name="name"
                placeholder="Enter your full name"
                autoComplete="name"
                value={form.name}
                onChange={handleChange}
                disabled={loading}
              />
            </div>

            <div className="input-group">
              <label htmlFor="email">Email</label>
              <input
                id="email"
                type="email"
                name="email"
                placeholder="Enter your email"
                autoComplete="email"
                value={form.email}
                onChange={handleChange}
                disabled={loading}
              />
            </div>

            <div className="input-group">
              <label htmlFor="password">Password</label>
              <PasswordField
                id="password"
                name="password"
                placeholder="Create a password"
                autoComplete="new-password"
                value={form.password}
                onChange={handleChange}
                disabled={loading}
              />
            </div>

            <button
              type="submit"
              className={`register-btn ${loading ? "loading" : ""}`}
              disabled={loading}
            >
              {loading ? "Creating Account..." : "Sign Up"}
            </button>
          </form>

          <div className="login-link">
            Already have an account? <a href="/app/login">Sign in here</a>
          </div>
        </div>
      </div>
    </div>
  );
}

export default Register;
