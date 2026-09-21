import React, { useEffect, useMemo, useRef } from "react";

import "./OtpInput.css";

/**
 * A six-box one-time-code field.
 *
 * The value is held by the caller as a plain string, so the boxes are only a
 * way of typing it: everything that matters — length, validity, when to submit —
 * is decided in one place rather than across six inputs.
 *
 * Behaviour the boxes have to get right, because people do all of these:
 *   typing      moves to the next box
 *   backspace   clears this box, or steps back when it is already empty
 *   arrows      move between boxes
 *   paste       a whole code fills every box, wherever it was pasted
 *   autofill    an SMS/email code arrives as one string in the first box
 */
const LENGTH = 6;
const DIGITS_ONLY = /\D/g;

export default function OtpInput({
  value = "",
  onChange,
  onComplete,
  disabled = false,
  autoFocus = true,
  label = "One-time code",
  describedBy,
  invalid = false,
}) {
  const inputsRef = useRef([]);

  const digits = useMemo(() => {
    const clean = String(value || "").replace(DIGITS_ONLY, "").slice(0, LENGTH);
    return Array.from({ length: LENGTH }, (_, i) => clean[i] || "");
  }, [value]);

  /**
   * Put the cursor in the field, and keep it useful.
   *
   * The boxes are often disabled when they first mount — the QR they belong to
   * is still on its way — and focusing a disabled input does nothing at all, so
   * this has to run again when they come alive. Without that, the page looks
   * ready while every keystroke goes nowhere.
   *
   * It stands aside while someone is typing in one of the boxes, and returns to
   * the first box whenever the code is empty: that is where the next attempt
   * starts, including after a rejected code clears the field.
   */
  useEffect(() => {
    if (!autoFocus || disabled) return;

    const boxes = inputsRef.current;
    const first = boxes[0];
    if (!first) return;

    const cursorIsHere = boxes.some((box) => box && box === document.activeElement);
    const empty = digits.every((digit) => !digit);

    if (!cursorIsHere || empty) first.focus();
  }, [autoFocus, disabled, digits]);

  const focusBox = (index) => {
    const box = inputsRef.current[Math.max(0, Math.min(LENGTH - 1, index))];
    if (box) {
      box.focus();
      box.select();
    }
  };

  const emit = (next) => {
    const code = next.join("").slice(0, LENGTH);
    onChange(code);
    if (code.length === LENGTH && onComplete) onComplete(code);
  };

  const handleChange = (index, raw) => {
    const typed = raw.replace(DIGITS_ONLY, "");
    if (!typed) return;

    // One character is a keystroke; several mean a paste or an autofilled code
    // landing in whichever box had focus.
    if (typed.length > 1) {
      const next = [...digits];
      for (let i = 0; i < typed.length && index + i < LENGTH; i += 1) {
        next[index + i] = typed[i];
      }
      emit(next);
      focusBox(index + typed.length);
      return;
    }

    const next = [...digits];
    next[index] = typed;
    emit(next);
    if (index < LENGTH - 1) focusBox(index + 1);
  };

  const handleKeyDown = (index, event) => {
    if (event.key === "Backspace") {
      event.preventDefault();
      const next = [...digits];
      if (next[index]) {
        next[index] = "";
        emit(next);
      } else if (index > 0) {
        next[index - 1] = "";
        emit(next);
        focusBox(index - 1);
      }
      return;
    }

    if (event.key === "ArrowLeft" && index > 0) {
      event.preventDefault();
      focusBox(index - 1);
    }
    if (event.key === "ArrowRight" && index < LENGTH - 1) {
      event.preventDefault();
      focusBox(index + 1);
    }
  };

  const handlePaste = (index, event) => {
    const pasted = (event.clipboardData.getData("text") || "").replace(DIGITS_ONLY, "");
    if (!pasted) return;
    event.preventDefault();

    // A full code fills from the start wherever it was dropped; a partial one
    // continues from the box that received it.
    const start = pasted.length >= LENGTH ? 0 : index;
    const next = [...digits];
    for (let i = 0; i < pasted.length && start + i < LENGTH; i += 1) {
      next[start + i] = pasted[i];
    }
    emit(next);
    focusBox(start + pasted.length);
  };

  return (
    <div
      className={`otp-input ${invalid ? "otp-input--invalid" : ""}`}
      role="group"
      aria-label={label}
      aria-describedby={describedBy}
    >
      {digits.map((digit, index) => (
        <input
          key={index}
          ref={(el) => {
            inputsRef.current[index] = el;
          }}
          className="otp-box"
          type="text"
          inputMode="numeric"
          autoComplete={index === 0 ? "one-time-code" : "off"}
          pattern="[0-9]*"
          maxLength={LENGTH}
          value={digit}
          disabled={disabled}
          aria-label={`Digit ${index + 1} of ${LENGTH}`}
          aria-invalid={invalid || undefined}
          onChange={(e) => handleChange(index, e.target.value)}
          onKeyDown={(e) => handleKeyDown(index, e)}
          onPaste={(e) => handlePaste(index, e)}
          onFocus={(e) => e.target.select()}
        />
      ))}
    </div>
  );
}

export { LENGTH as OTP_LENGTH };
