import React from "react";

import Header from "../Header/Header";
import "./TwoFactor.css";

/**
 * The frame every step of the second factor shares: the app header, a single
 * centred card, a title, one line of explanation, and whatever the step needs.
 *
 * Keeping it in one place is what makes the four steps feel like one flow
 * rather than four pages that happen to follow each other.
 */
export default function TwoFactorLayout({ title, lead, children, footer, error }) {
  return (
    <div className="tf-page">
      <Header />

      <main className="tf-main">
        <section className="tf-card" aria-labelledby="tf-title">
          <h1 className="tf-title" id="tf-title">
            {title}
          </h1>

          {lead && <p className="tf-lead">{lead}</p>}

          {error && (
            <p className="tf-error" role="alert">
              {error}
            </p>
          )}

          {children}

          {footer && <div className="tf-footer">{footer}</div>}
        </section>
      </main>
    </div>
  );
}
