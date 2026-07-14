import React, { useMemo, useState } from "react";
import "./AccessManagement.css";
import { useAccess, ROLES } from "./AccessContext";
import UsersTable from "./components/UsersTable";
import InviteModal from "./components/InviteModal";
import EditUserModal from "./components/EditUserModal";
import ConfirmDialog from "./components/ConfirmDialog";
import RoleBadge from "./components/RoleBadge";

function ShieldIcon() {
  return (
    <svg width="22" height="22" viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <path d="M12 2 4 5v6c0 5 3.4 8.5 8 11 4.6-2.5 8-6 8-11V5l-8-3Z" fill="#4f46e5" opacity="0.15" />
      <path d="M12 2 4 5v6c0 5 3.4 8.5 8 11 4.6-2.5 8-6 8-11V5l-8-3Z" stroke="#4f46e5" strokeWidth="1.5" strokeLinejoin="round" />
      <path d="m9 12 2 2 4-4" stroke="#4f46e5" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

// ── sign-in / bootstrap gate (frontend-only identity) ──────────
function SignInGate() {
  const { users, signInAs } = useAccess();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const firstUser = users.length === 0;

  const submit = (e) => {
    e.preventDefault();
    setError("");
    try {
      signInAs(email, password);
    } catch (err) {
      setError(err.message);
    }
  };

  return (
    <div className="rbac-gate">
      <div className="rbac-gate-card">
        <div className="rbac-gate-icon">
          <ShieldIcon />
        </div>
        <h1 className="rbac-gate-title">
          {firstUser ? "Set up Access Management" : "Sign in to continue"}
        </h1>
        <p className="rbac-gate-sub">
          {firstUser
            ? "You're the first user — you'll be set up as the Super Admin with full access."
            : "Enter your invited e-mail to access the workspace."}
        </p>
        <form onSubmit={submit} className="rbac-gate-form">
          <input
            type="email"
            className="rbac-input"
            placeholder="you@company.com"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            autoFocus
          />
          <input
            type="password"
            className="rbac-input"
            placeholder={firstUser ? "Create a password" : "Password"}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
          <button className="rbac-btn rbac-btn-primary" type="submit">
            {firstUser ? "Create Super Admin" : "Sign in"}
          </button>
        </form>
        {error && <div className="rbac-error">{error}</div>}
      </div>
    </div>
  );
}

// ── main page ──────────────────────────────────────────────────
export default function AccessManagement() {
  const {
    users,
    currentUser,
    can,
    signOut,
    inviteUser,
    updateUser,
    setUserStatus,
    removeUser,
  } = useAccess();

  const [search, setSearch] = useState("");
  const [inviting, setInviting] = useState(false);
  const [editUser, setEditUser] = useState(null);
  const [confirm, setConfirm] = useState(null); // { title, message, danger, onConfirm }
  const [banner, setBanner] = useState("");

  const canManage = can("manageUsers");

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    if (!q) return users;
    return users.filter(
      (u) =>
        u.email.toLowerCase().includes(q) ||
        (u.name || "").toLowerCase().includes(q) ||
        (ROLES[u.role]?.label || "").toLowerCase().includes(q)
    );
  }, [users, search]);

  const stats = useMemo(() => {
    const s = { total: users.length, admins: 0, viewers: 0, disabled: 0 };
    users.forEach((u) => {
      if (u.role === "admin" || u.role === "super_admin") s.admins += 1;
      if (u.role === "view_only") s.viewers += 1;
      if (u.status !== "active") s.disabled += 1;
    });
    return s;
  }, [users]);

  const flash = (msg) => {
    setBanner(msg);
    window.setTimeout(() => setBanner(""), 2600);
  };

  if (!currentUser) return <SignInGate />;

  const handleInvite = async (payload) => {
    const user = await inviteUser(payload);
    setInviting(false);
    flash(`User ${user.email} created.`);
  };

  const handleSaveEdit = async (patch) => {
    await updateUser(editUser.id, patch);
    flash(`Updated access for ${editUser.email}.`);
    setEditUser(null);
  };

  const handleToggle = (u) => {
    const disabling = u.status === "active";
    setConfirm({
      title: disabling ? "Disable account?" : "Enable account?",
      message: disabling
        ? `${u.email} will immediately lose access to the application.`
        : `${u.email} will regain access with their assigned role.`,
      confirmLabel: disabling ? "Disable" : "Enable",
      danger: disabling,
      onConfirm: () => {
        setUserStatus(u.id, disabling ? "disabled" : "active");
        setConfirm(null);
        flash(`${u.email} ${disabling ? "disabled" : "enabled"}.`);
      },
    });
  };

  const handleRemove = (u) => {
    setConfirm({
      title: "Remove user access?",
      message: `This permanently removes ${u.email} from the workspace. They will need a new invite to return.`,
      confirmLabel: "Remove",
      danger: true,
      onConfirm: async () => {
        try {
          await removeUser(u.id);
          flash(`${u.email} removed.`);
        } catch (err) {
          flash(err.message);
        }
        setConfirm(null);
      },
    });
  };

  return (
    <div className="rbac-page">
      {/* header */}
      <div className="rbac-header">
        <div className="rbac-header-left">
          <ShieldIcon />
          <div>
            <h1 className="rbac-h1">Access Management</h1>
            <p className="rbac-subtitle">Manage users, roles and permissions.</p>
          </div>
        </div>
        <div className="rbac-header-right">
          <div className="rbac-whoami">
            <span className="rbac-whoami-email">{currentUser.email}</span>
            <RoleBadge role={currentUser.role} />
          </div>
          {/* <button className="rbac-btn rbac-btn-ghost" onClick={signOut}>
            Sign out
          </button> */}
        </div>
      </div>

      {banner && <div className="rbac-flash">{banner}</div>}

      {/* stat cards */}
      <div className="rbac-stats">
        <StatCard label="Total users" value={stats.total} />
        <StatCard label="Admins" value={stats.admins} tone="indigo" />
        <StatCard label="View only" value={stats.viewers} tone="slate" />
        <StatCard label="Disabled" value={stats.disabled} tone="red" />
      </div>

      {/* toolbar */}
      <div className="rbac-toolbar">
        <div className="rbac-search">
          <span className="rbac-search-icon">⌕</span>
          <input
            className="rbac-search-input"
            placeholder="Search by email, name or role…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
          {search && (
            <button className="rbac-search-clear" onClick={() => setSearch("")} aria-label="Clear">
              ✕
            </button>
          )}
        </div>
        {canManage ? (
          <button className="rbac-btn rbac-btn-primary" onClick={() => setInviting(true)}>
            + Invite user
          </button>
        ) : (
          <span className="rbac-readonly-tag">Read-only access</span>
        )}
      </div>

      {!canManage && (
        <div className="rbac-notice">
          You are signed in as <strong>{ROLES[currentUser.role]?.label}</strong>. Only a
          Super Admin can invite users or change roles.
        </div>
      )}

      {/* table */}
      <UsersTable
        users={filtered}
        currentUserId={currentUser.id}
        canManage={canManage}
        onEdit={setEditUser}
        onToggleStatus={handleToggle}
        onRemove={handleRemove}
      />

      {/* modals */}
      {inviting && <InviteModal onClose={() => setInviting(false)} onInvite={handleInvite} />}
      {editUser && (
        <EditUserModal user={editUser} onClose={() => setEditUser(null)} onSave={handleSaveEdit} />
      )}
      {confirm && (
        <ConfirmDialog
          title={confirm.title}
          message={confirm.message}
          confirmLabel={confirm.confirmLabel}
          danger={confirm.danger}
          onConfirm={confirm.onConfirm}
          onCancel={() => setConfirm(null)}
        />
      )}
    </div>
  );
}

function StatCard({ label, value, tone = "default" }) {
  return (
    <div className={`rbac-stat rbac-stat-${tone}`}>
      <span className="rbac-stat-value">{value}</span>
      <span className="rbac-stat-label">{label}</span>
    </div>
  );
}
