import React, { useState } from "react";
import Modal from "./Modal";
import { INVITE_ROLES, MIN_PASSWORD } from "../AccessContext";

function randomPassword() {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789";
  let out = "";
  for (let i = 0; i < 10; i++) out += chars[Math.floor(Math.random() * chars.length)];
  return out;
}

export default function InviteModal({ onClose, onInvite }) {
  const [email, setEmail] = useState("");
  const [name, setName] = useState("");
  const [role, setRole] = useState("view_only");
  const [password, setPassword] = useState("");
  const [showPw, setShowPw] = useState(false);
  const [error, setError] = useState("");

  const [submitting, setSubmitting] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");
    if (!password || password.length < MIN_PASSWORD) {
      setError(`Set a password of at least ${MIN_PASSWORD} characters.`);
      return;
    }
    setSubmitting(true);
    try {
      await onInvite({ email, name, role, password });
    } catch (err) {
      setError(err.message || "Could not create the user.");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <Modal
      title="Invite user"
      onClose={onClose}
      footer={
        <>
          <button className="rbac-btn" onClick={onClose} disabled={submitting}>
            Cancel
          </button>
          <button
            className="rbac-btn rbac-btn-primary"
            form="invite-form"
            type="submit"
            disabled={submitting}
          >
            {submitting ? "Creating…" : "Create user"}
          </button>
        </>
      }
    >
      <form id="invite-form" onSubmit={handleSubmit} className="rbac-form">
        <label className="rbac-field">
          <span className="rbac-label">Email address</span>
          <input
            type="email"
            className="rbac-input"
            placeholder="person@company.com"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            autoFocus
          />
        </label>

        <label className="rbac-field">
          <span className="rbac-label">Name (optional)</span>
          <input
            type="text"
            className="rbac-input"
            placeholder="Jane Doe"
            value={name}
            onChange={(e) => setName(e.target.value)}
          />
        </label>

        <label className="rbac-field">
          <span className="rbac-label">Temporary password</span>
          <div className="rbac-pw-row">
            <input
              type={showPw ? "text" : "password"}
              className="rbac-input"
              placeholder={`At least ${MIN_PASSWORD} characters`}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
            <button
              type="button"
              className="rbac-btn rbac-btn-mini"
              onClick={() => setShowPw((v) => !v)}
            >
              {showPw ? "Hide" : "Show"}
            </button>
            <button
              type="button"
              className="rbac-btn rbac-btn-mini"
              onClick={() => {
                setPassword(randomPassword());
                setShowPw(true);
              }}
            >
              Generate
            </button>
          </div>
          <p className="rbac-hint">Share this with the user — they sign in with their email + this password.</p>
        </label>

        <div className="rbac-field">
          <span className="rbac-label">Role</span>
          <div className="rbac-role-picker">
            {INVITE_ROLES.map((r) => (
              <button
                type="button"
                key={r.key}
                className={`rbac-role-option ${role === r.key ? "selected" : ""}`}
                onClick={() => setRole(r.key)}
              >
                <span className="rbac-role-option-title">{r.label}</span>
                <span className="rbac-role-option-desc">
                  {r.key === "admin"
                    ? "Can manage resources"
                    : "Can only view data"}
                </span>
              </button>
            ))}
          </div>
        </div>

        {error && <div className="rbac-error">{error}</div>}
      </form>
    </Modal>
  );
}
