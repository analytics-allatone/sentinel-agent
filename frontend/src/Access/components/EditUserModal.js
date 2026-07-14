import React, { useState } from "react";
import Modal from "./Modal";
import { INVITE_ROLES, MIN_PASSWORD } from "../AccessContext";

export default function EditUserModal({ user, onClose, onSave }) {
  const isSuper = user.role === "super_admin";
  const [name, setName] = useState(user.name || "");
  const [role, setRole] = useState(user.role);
  const [newPassword, setNewPassword] = useState("");
  const [error, setError] = useState("");
  const [saving, setSaving] = useState(false);

  const handleSave = async () => {
    setError("");
    if (!name.trim()) {
      setError("Name cannot be empty.");
      return;
    }
    if (newPassword && newPassword.length < MIN_PASSWORD) {
      setError(`Password must be at least ${MIN_PASSWORD} characters.`);
      return;
    }
    setSaving(true);
    try {
      await onSave({
        name: name.trim(),
        role,
        newPassword: newPassword || undefined,
      });
    } catch (err) {
      setError(err.message || "Could not update the user.");
    } finally {
      setSaving(false);
    }
  };

  return (
    <Modal
      title={`Edit access — ${user.email}`}
      onClose={onClose}
      footer={
        <>
          <button className="rbac-btn" onClick={onClose} disabled={saving}>
            Cancel
          </button>
          <button
            className="rbac-btn rbac-btn-primary"
            onClick={handleSave}
            disabled={isSuper || saving}
          >
            {saving ? "Saving…" : "Save changes"}
          </button>
        </>
      }
    >
      {isSuper ? (
        <p className="rbac-hint">
          Super Admin has full, non-editable access to the system.
        </p>
      ) : (
        <div className="rbac-form">
          <label className="rbac-field">
            <span className="rbac-label">Name</span>
            <input
              type="text"
              className="rbac-input"
              placeholder="Full name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              autoFocus
            />
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
                    {r.key === "admin" ? "Can manage resources" : "Can only view data"}
                  </span>
                </button>
              ))}
            </div>
          </div>

          <label className="rbac-field">
            <span className="rbac-label">Reset password (optional)</span>
            <input
              type="text"
              className="rbac-input"
              placeholder="Leave blank to keep current password"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
            />
          </label>

          {error && <div className="rbac-error">{error}</div>}
        </div>
      )}
    </Modal>
  );
}
