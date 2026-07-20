import React from "react";

/**
 * Decorative blurred gradient blobs that drift slowly behind the card. Purely
 * cosmetic, so it is hidden from assistive tech and ignores pointer events;
 * the animation is disabled under prefers-reduced-motion (see the CSS).
 */
export default function FloatingShapes() {
  return (
    <div className="ua__shapes" aria-hidden="true">
      <span className="ua__shape ua__shape--1" />
      <span className="ua__shape ua__shape--2" />
      <span className="ua__shape ua__shape--3" />
      <span className="ua__shape ua__shape--4" />
    </div>
  );
}
