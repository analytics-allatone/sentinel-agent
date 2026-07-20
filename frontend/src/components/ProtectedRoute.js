import React, { useEffect, useState } from "react";
import { Navigate, useLocation } from "react-router-dom";
import Layout from "./Layout";
import useAuth from "../hooks/useAuth";
import { isAuthorized } from "../utils/authz";
import "./ProtectedRoute.css";

/**
 * Route guard.
 *
 * Props
 *  - element | children : the protected UI (either works; `element` kept for
 *                         backward-compatibility with existing call sites)
 *  - roles  : string[]  allowed role keys, e.g. ["admin", "super_admin"].
 *                       Omitted/empty => any authenticated user is allowed.
 *  - perm   : string    a required permission action, e.g. "manageUsers".
 *  - withLayout : bool  wrap the element in the app chrome (default true).
 *
 * Behaviour
 *  - Not authenticated                    -> /login (remembers the attempt).
 *  - Authenticated but lacking role/perm  -> /unauthorized (passes the attempt
 *                                            and the reason for the 403 page).
 *  - Authorized                           -> renders the element.
 *
 * Direct URL access and page refresh are both covered: the guard re-evaluates
 * the cookie + RBAC state on every render, so there is no way around it by
 * typing a restricted URL, and a refresh keeps the session (cookie-backed).
 */
const CHECK_GRACE_MS = 500;

function PermissionSpinner() {
  return (
    <div className="pr-checking" role="status" aria-live="polite">
      <span className="pr-spinner" aria-hidden="true" />
      <span className="pr-checking-label">Checking permissions…</span>
    </div>
  );
}

export default function ProtectedRoute({ element, children, roles, perm, withLayout = true }) {
  const location = useLocation();
  const { isAuthenticated, role, can } = useAuth();

  const node = element !== undefined ? element : children;
  const needsAuthz = (Array.isArray(roles) && roles.length > 0) || !!perm;

  // Give AccessContext a brief moment to resolve the current user on first load
  // so a role-gated route doesn't flash a false 403 before RBAC hydrates. Plain
  // auth-only routes skip this entirely and render immediately, as before.
  const [settled, setSettled] = useState(!needsAuthz);
  useEffect(() => {
    if (!needsAuthz || role) {
      setSettled(true);
      return undefined;
    }
    const t = setTimeout(() => setSettled(true), CHECK_GRACE_MS);
    return () => clearTimeout(t);
  }, [needsAuthz, role]);

  if (!isAuthenticated) {
    return <Navigate to="/login" replace state={{ from: location }} />;
  }

  if (needsAuthz && !settled) {
    return <PermissionSpinner />;
  }

  if (needsAuthz && !isAuthorized({ userRole: role, can, roles, perm })) {
    return (
      <Navigate
        to="/unauthorized"
        replace
        state={{ from: location, requiredRoles: roles || [], requiredPerm: perm || null }}
      />
    );
  }

  return withLayout ? <Layout>{node}</Layout> : node;
}
