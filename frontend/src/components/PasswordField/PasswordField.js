import React, { useState } from "react";
import { LuEye, LuEyeOff } from "react-icons/lu";

import "./PasswordField.css";

/**
 * A password box with a show/hide control.
 *
 * The toggle is a real button so it is reachable by keyboard and announced by
 * screen readers, and it never submits the form it sits in. Revealing is local
 * to this field and resets on every render of a fresh page — nothing about the
 * choice is remembered.
 */
export default function PasswordField({
  id,
  name,
  value,
  onChange,
  placeholder,
  autoComplete = "current-password",
  disabled = false,
  required = false,
  className = "",
}) {
  const [revealed, setRevealed] = useState(false);

  return (
    <div className="pwd-field">
      <input
        id={id}
        className={`pwd-input ${className}`.trim()}
        type={revealed ? "text" : "password"}
        name={name}
        value={value}
        onChange={onChange}
        placeholder={placeholder}
        autoComplete={autoComplete}
        disabled={disabled}
        required={required}
      />

      <button
        type="button"
        className="pwd-toggle"
        onClick={() => setRevealed((shown) => !shown)}
        aria-label={revealed ? "Hide password" : "Show password"}
        aria-pressed={revealed}
        title={revealed ? "Hide password" : "Show password"}
        tabIndex={disabled ? -1 : 0}
      >
        {revealed ? <LuEyeOff size={18} strokeWidth={1.6} /> : <LuEye size={18} strokeWidth={1.6} />}
      </button>
    </div>
  );
}
