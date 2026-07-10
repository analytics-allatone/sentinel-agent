import React, { useEffect } from "react";

/**
 * Accessible base modal: click-backdrop / Escape to close, centered card.
 * props: title, onClose, children, footer, size ("sm"|"md")
 */
export default function Modal({ title, onClose, children, footer, size = "md" }) {
  useEffect(() => {
    const onKey = (e) => {
      if (e.key === "Escape") onClose?.();
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [onClose]);

  return (
    <div className="rbac-modal-backdrop" onMouseDown={onClose}>
      <div
        className={`rbac-modal rbac-modal-${size}`}
        role="dialog"
        aria-modal="true"
        aria-label={title}
        onMouseDown={(e) => e.stopPropagation()}
      >
        <div className="rbac-modal-head">
          <h3 className="rbac-modal-title">{title}</h3>
          <button className="rbac-modal-close" onClick={onClose} aria-label="Close">
            ✕
          </button>
        </div>
        <div className="rbac-modal-body">{children}</div>
        {footer && <div className="rbac-modal-foot">{footer}</div>}
      </div>
    </div>
  );
}
