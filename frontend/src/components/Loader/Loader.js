import React from "react";
import "./Loader.css";

function Loader({ isVisible }) {
  if (!isVisible) return null;

  return (
    <div className="loader-overlay">
      <div className="loader-container">
        <div className="circular-loader">
          <div className="spinner"></div>
        </div>
        <p className="loader-text">Loading...</p>
      </div>
    </div>
  );
}

export default Loader;
