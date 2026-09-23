import React, { createContext, useCallback, useContext, useMemo, useState } from "react";
import { Navigate, useLocation, useNavigate } from "react-router-dom";

import { getCookie, setCookie } from "../api/api";
import { rememberTwoFactorEnabled } from "./twoFactorPreference";

/**
 * The half-authenticated state between a correct password and a finished
 * second step.
 *
 * The pre-auth token lives in memory only — never in localStorage or a cookie —
 * so closing the tab ends the attempt, and nothing that survives a reload can be
 * replayed. That is the whole point of it being short-lived.
 *
 * A consequence worth knowing: refreshing a 2FA page drops the token and sends
 * the user back to sign in. That is the correct trade, not an oversight.
 */
const TwoFactorContext = createContext(null);

export function TwoFactorProvider({ children }) {
  const [session, setSession] = useState(null); // { tempToken, email }

  const begin = useCallback((tempToken, email) => {
    setSession({ tempToken, email });
  }, []);

  const clear = useCallback(() => setSession(null), []);

  const value = useMemo(
    () => ({
      tempToken: session && session.tempToken,
      email: session && session.email,
      begin,
      clear,
    }),
    [session, begin, clear]
  );

  return <TwoFactorContext.Provider value={value}>{children}</TwoFactorContext.Provider>;
}

export function useTwoFactor() {
  const context = useContext(TwoFactorContext);
  if (!context) {
    throw new Error("useTwoFactor must be used inside a TwoFactorProvider");
  }
  return context;
}

/**
 * Finish signing in: store the session the way the rest of the app already
 * does (a `token` cookie the API client reads), drop the pre-auth token, and
 * land on the dashboard.
 */
export function useCompleteSignIn() {
  const navigate = useNavigate();
  const { email, clear } = useTwoFactor();

  return useCallback(
    (accessToken, refreshToken, options = {}) => {
      if (accessToken) setCookie("token", accessToken, 7);
      if (refreshToken) setCookie("refresh_token", refreshToken, 30);
      if (email) localStorage.setItem("auth_email", email);
      // How the sign-in ended is what the sidebar switch starts from.
      if (options.twoFactorEnabled !== undefined) {
        rememberTwoFactorEnabled(options.twoFactorEnabled);
      }
      clear();
      navigate("/app/dashboard", { replace: true });
    },
    [navigate, email, clear]
  );
}

/**
 * Sends the user back to sign in when the attempt is over — either because the
 * token expired mid-flow, or because they opened a 2FA page directly.
 */
export function useAbandonToLogin() {
  const navigate = useNavigate();
  const { clear } = useTwoFactor();

  return useCallback(
    (message = "Session expired, please log in again.") => {
      clear();
      navigate("/app/login", { replace: true, state: { notice: message } });
    },
    [navigate, clear]
  );
}

/**
 * The pages that run on a real session: the choice offered after signing up,
 * and the setup page behind it. Both call endpoints the backend protects with
 * an ordinary access token, so a visitor without one has nothing to do here.
 */
export function hasSession() {
  // The same three places the request interceptor looks for a token. Checking
  // fewer of them here is what made this page bounce to login for a visitor the
  // rest of the app considered signed in.
  try {
    return Boolean(
      getCookie("token") || getCookie("access_token") || localStorage.getItem("token")
    );
  } catch (err) {
    return Boolean(getCookie("token") || getCookie("access_token"));
  }
}

export function RequireSession({ children }) {
  const location = useLocation();

  if (!hasSession()) {
    return (
      <Navigate
        to="/app/login"
        replace
        state={{ notice: "Please log in to continue.", from: location.pathname }}
      />
    );
  }

  return children;
}

/** The challenge step is only reachable while a sign-in is in progress. */
export function RequireTempToken({ children }) {
  const { tempToken } = useTwoFactor();
  const location = useLocation();

  if (!tempToken) {
    return (
      <Navigate
        to="/app/login"
        replace
        state={{
          notice: "Session expired, please log in again.",
          from: location.pathname,
        }}
      />
    );
  }

  return children;
}
