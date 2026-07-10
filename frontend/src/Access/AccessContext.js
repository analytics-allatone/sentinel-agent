import React, { createContext, useContext, useEffect, useMemo, useState } from "react";

/**
 * Frontend-only RBAC store.
 *
 * Roles:
 *   super_admin — full access, the only role that can manage users
 *   admin       — can manage resources (create/edit/delete), configurable
 *   view_only   — read-only, cannot create/edit/delete
 *
 * The FIRST user to sign in (when the store is empty) is bootstrapped as the
 * Super Admin. Everyone else must be invited by e-mail before they get access.
 * State is persisted to localStorage so it survives reloads.
 */

const USERS_KEY = "rbac_users_v1";
const CURRENT_KEY = "rbac_current_email_v1";

export const ROLES = {
  super_admin: { key: "super_admin", label: "Super Admin" },
  admin: { key: "admin", label: "Admin" },
  view_only: { key: "view_only", label: "View Only" },
};

// invitable roles (Super Admin is only ever assigned via bootstrap)
export const INVITE_ROLES = [ROLES.admin, ROLES.view_only];

export const ACTIONS = ["view", "create", "edit", "delete", "manageUsers"];

export function permsForRole(role) {
  switch (role) {
    case "super_admin":
      return { view: true, create: true, edit: true, delete: true, manageUsers: true };
    case "admin":
      return { view: true, create: true, edit: true, delete: true, manageUsers: false };
    case "view_only":
    default:
      return { view: true, create: false, edit: false, delete: false, manageUsers: false };
  }
}

// effective permissions: role preset, with per-user overrides for admins
export function effectivePerms(user) {
  if (!user || user.status !== "active") {
    return { view: false, create: false, edit: false, delete: false, manageUsers: false };
  }
  const base = permsForRole(user.role);
  if (user.role === "admin" && user.permissions) {
    return { ...base, ...user.permissions, view: true, manageUsers: false };
  }
  return base;
}

function loadUsers() {
  try {
    const raw = localStorage.getItem(USERS_KEY);
    return raw ? JSON.parse(raw) : [];
  } catch {
    return [];
  }
}

function saveUsers(users) {
  localStorage.setItem(USERS_KEY, JSON.stringify(users));
}

function nowIso() {
  return new Date().toISOString();
}

function makeId() {
  return `u_${Math.random().toString(36).slice(2, 9)}`;
}

// NOTE: frontend-only demo. Passwords are stored as a non-reversible hash
// (djb2) rather than plaintext. A real system must hash on a secure backend.
export function hashPassword(pw) {
  let h = 5381;
  const s = String(pw || "");
  for (let i = 0; i < s.length; i++) {
    h = (h << 5) + h + s.charCodeAt(i);
    h |= 0;
  }
  return "h" + (h >>> 0).toString(36);
}

export const MIN_PASSWORD = 6;

const AccessContext = createContext(null);

export function AccessProvider({ children }) {
  const [users, setUsers] = useState(() => loadUsers());
  const [currentEmail, setCurrentEmail] = useState(() => {
    // Prefer an explicit RBAC session; otherwise adopt the website login
    // (auth_email) if that account already exists — avoids a sign-in flash.
    const saved = localStorage.getItem(CURRENT_KEY) || "";
    if (saved) return saved;
    const authEmail = (localStorage.getItem("auth_email") || "").trim().toLowerCase();
    const existing = loadUsers().find((u) => u.email.toLowerCase() === authEmail);
    return existing && existing.status === "active" ? existing.email : "";
  });

  useEffect(() => saveUsers(users), [users]);
  useEffect(() => {
    if (currentEmail) localStorage.setItem(CURRENT_KEY, currentEmail);
  }, [currentEmail]);

  const currentUser = useMemo(
    () => users.find((u) => u.email.toLowerCase() === currentEmail.toLowerCase()) || null,
    [users, currentEmail]
  );

  const perms = useMemo(() => effectivePerms(currentUser), [currentUser]);
  const can = (action) => !!perms[action];

  /**
   * Sign in with an e-mail (simulates login/registration).
   * - store empty            => becomes Super Admin (first user rule)
   * - invited & active user  => granted their role
   * - disabled user          => rejected
   * - unknown e-mail         => rejected (must be invited first)
   * returns the signed-in user
   */
  const signInAs = (rawEmail, rawPassword, opts = {}) => {
    const email = (rawEmail || "").trim().toLowerCase();
    const trusted = !!opts.trusted; // website session — already authenticated
    if (!email) throw new Error("Enter an e-mail address.");

    const existing = users.find((u) => u.email.toLowerCase() === email);

    if (!existing) {
      if (users.length === 0) {
        // first ever user → Super Admin (sets their own password at the gate)
        if (!trusted) {
          if (!rawPassword) throw new Error("Create a password to continue.");
          if (rawPassword.length < MIN_PASSWORD)
            throw new Error(`Password must be at least ${MIN_PASSWORD} characters.`);
        }
        const admin = {
          id: makeId(),
          email,
          name: email.split("@")[0],
          role: "super_admin",
          permissions: null,
          status: "active",
          invitedAt: nowIso(),
          lastActive: nowIso(),
          password: trusted ? null : hashPassword(rawPassword),
        };
        setUsers([admin]);
        setCurrentEmail(email);
        return admin;
      }
      throw new Error("This e-mail has not been invited. Ask a Super Admin for access.");
    }

    if (existing.status !== "active") {
      throw new Error("This account is disabled. Contact your Super Admin.");
    }

    if (!trusted) {
      if (existing.password) {
        if (hashPassword(rawPassword) !== existing.password)
          throw new Error("Incorrect password.");
      } else {
        // account has no local password → managed via the main website login
        throw new Error("Use the main website login for this account.");
      }
    }

    setUsers((prev) =>
      prev.map((u) => (u.id === existing.id ? { ...u, lastActive: nowIso() } : u))
    );
    setCurrentEmail(existing.email);
    return existing;
  };

  const signOut = () => {
    setCurrentEmail("");
    localStorage.removeItem(CURRENT_KEY);
  };

  // ── management actions (guard with can('manageUsers') at call sites) ──
  const inviteUser = ({ email, name, role, permissions, password }) => {
    const clean = (email || "").trim().toLowerCase();
    if (!clean || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(clean)) {
      throw new Error("Enter a valid e-mail address.");
    }
    if (users.some((u) => u.email.toLowerCase() === clean)) {
      throw new Error("A user with this e-mail already exists.");
    }
    if (!password || password.length < MIN_PASSWORD) {
      throw new Error(`Set a password of at least ${MIN_PASSWORD} characters.`);
    }
    const user = {
      id: makeId(),
      email: clean,
      name: name?.trim() || clean.split("@")[0],
      role: role || "view_only",
      permissions: role === "admin" ? permissions || permsForRole("admin") : null,
      status: "active",
      invitedAt: nowIso(),
      lastActive: null,
      password: hashPassword(password),
    };
    setUsers((prev) => [user, ...prev]);
    return user;
  };

  const updateUser = (id, patch) => {
    setUsers((prev) =>
      prev.map((u) => {
        if (u.id !== id) return u;
        const next = { ...u, ...patch };
        // an optional password reset comes through as plaintext `newPassword`
        if (patch.newPassword) {
          next.password = hashPassword(patch.newPassword);
        }
        delete next.newPassword;
        // keep permissions consistent with role
        if (patch.role && patch.role !== "admin") next.permissions = null;
        if (patch.role === "admin" && !next.permissions) {
          next.permissions = permsForRole("admin");
        }
        return next;
      })
    );
  };

  const setUserStatus = (id, status) => updateUser(id, { status });

  const removeUser = (id) => {
    const target = users.find((u) => u.id === id);
    if (target && target.role === "super_admin") {
      const admins = users.filter((u) => u.role === "super_admin").length;
      if (admins <= 1) throw new Error("Cannot remove the last Super Admin.");
    }
    setUsers((prev) => prev.filter((u) => u.id !== id));
    if (target && target.email.toLowerCase() === currentEmail.toLowerCase()) signOut();
  };

  // Adopt the website session on mount: if the user is logged in (auth_email)
  // and not already signed into RBAC, sign them in — the first such user is
  // bootstrapped as the Super Admin.
  useEffect(() => {
    const authEmail = (localStorage.getItem("auth_email") || "").trim().toLowerCase();
    if (!authEmail) return;
    const already = users.find((u) => u.email.toLowerCase() === currentEmail.toLowerCase());
    if (already && already.status === "active") return;
    try {
      signInAs(authEmail, null, { trusted: true });
    } catch {
      /* email not invited and store not empty — fall back to the sign-in gate */
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const value = {
    users,
    currentUser,
    currentEmail,
    perms,
    can,
    signInAs,
    signOut,
    inviteUser,
    updateUser,
    setUserStatus,
    removeUser,
  };

  return <AccessContext.Provider value={value}>{children}</AccessContext.Provider>;
}

export function useAccess() {
  const ctx = useContext(AccessContext);
  if (!ctx) throw new Error("useAccess must be used within an AccessProvider");
  return ctx;
}

/**
 * Guard a subtree by permission. Renders `fallback` when the current user
 * lacks the permission. Use for both route protection and inline controls.
 */
export function RequirePermission({ perm, fallback = null, children }) {
  const { can } = useAccess();
  return can(perm) ? <>{children}</> : <>{fallback}</>;
}
