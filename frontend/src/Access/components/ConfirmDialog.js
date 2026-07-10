import React from "react";
import Modal from "./Modal";

/**
 * props:
 *  - title, message
 *  - confirmLabel (default "Confirm"), cancelLabel (default "Cancel")
 *  - danger (bool) — red confirm button
 *  - onConfirm, onCancel
 */
export default function ConfirmDialog({
  title = "Are you sure?",
  message,
  confirmLabel = "Confirm",
  cancelLabel = "Cancel",
  danger = false,
  onConfirm,
  onCancel,
}) {
  return (
    <Modal
      title={title}
      size="sm"
      onClose={onCancel}
      footer={
        <>
          <button className="rbac-btn" onClick={onCancel}>
            {cancelLabel}
          </button>
          <button
            className={`rbac-btn ${danger ? "rbac-btn-danger" : "rbac-btn-primary"}`}
            onClick={onConfirm}
          >
            {confirmLabel}
          </button>
        </>
      }
    >
      <p className="rbac-confirm-msg">{message}</p>
    </Modal>
  );
}
