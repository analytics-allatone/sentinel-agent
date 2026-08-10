import React, { useEffect, useMemo, useState } from "react";
import "./ChannelsManager.css";

/**
 * Channels Manager — FRONTEND ONLY.
 *
 * Users register notification channels. They pick a service (Email, WhatsApp,
 * Slack, …); the form then shows exactly the fields that service needs; they
 * register it. Registered channels can be viewed, edited and removed. Any
 * number of channels can be added. Everything persists to localStorage.
 */

const STORE_KEY = "message_channels_v1";

// ── service catalogue: each service declares the fields it needs ──────────────
const SERVICES = [
  {
    id: "email",
    label: "Email",
    icon: "/gmail.png",
    color: "#2563eb",
    blurb: "Send notifications to an inbox",
    primary: "email",
    fields: [
      { name: "label", label: "Label", placeholder: "e.g. Work inbox" },
      { name: "email", label: "Email Address", type: "email", placeholder: "you@company.com", required: true },
    ],
  },
  {
    id: "whatsapp",
    label: "WhatsApp",
    icon: "/whatsapp.png",
    color: "#25d366",
    blurb: "Message a WhatsApp number",
    primary: "phone",
    fields: [
      { name: "label", label: "Label", placeholder: "e.g. On-call phone" },
      { name: "phone", label: "Phone Number", type: "tel", placeholder: "+91 98765 43210", required: true },
    ],
  },
  {
    id: "sms",
    label: "SMS",
    icon: "/sms.png",
    color: "#0891b2",
    blurb: "Text a mobile number",
    primary: "phone",
    fields: [
      { name: "label", label: "Label", placeholder: "e.g. Alerts phone" },
      { name: "phone", label: "Phone Number", type: "tel", placeholder: "+91 98765 43210", required: true },
    ],
  },
  {
    id: "slack",
    label: "Slack",
    icon: "/slack.png",
    color: "#611f69",
    blurb: "Post to a Slack channel",
    primary: "channel",
    fields: [
      { name: "label", label: "Label", placeholder: "e.g. Team Slack" },
      { name: "channel", label: "Channel", placeholder: "#alerts", required: true },
      { name: "webhook", label: "Incoming Webhook URL", type: "url", placeholder: "https://hooks.slack.com/services/…", required: true },
    ],
  },
  {
    id: "telegram",
    label: "Telegram",
    icon: "/telegram.png",
    color: "#229ed9",
    blurb: "Send to a Telegram chat",
    primary: "chatId",
    fields: [
      { name: "label", label: "Label", placeholder: "e.g. Ops group" },
      { name: "chatId", label: "Chat ID / @username", placeholder: "@ops_team or 123456789", required: true },
      { name: "botToken", label: "Bot Token", placeholder: "123456:ABC-DEF…", required: true },
    ],
  },
  {
    id: "discord",
    label: "Discord",
    icon: "/discord.png",
    color: "#5865f2",
    blurb: "Post to a Discord channel",
    primary: "webhook",
    fields: [
      { name: "label", label: "Label", placeholder: "e.g. Server alerts" },
      { name: "webhook", label: "Webhook URL", type: "url", placeholder: "https://discord.com/api/webhooks/…", required: true },
    ],
  },
  {
    id: "teams",
    label: "Microsoft Teams",
    icon: "/teams.png",
    color: "#5b5fc7",
    blurb: "Post to a Teams channel",
    primary: "webhook",
    fields: [
      { name: "label", label: "Label", placeholder: "e.g. IT Teams" },
      { name: "webhook", label: "Webhook URL", type: "url", placeholder: "https://outlook.office.com/webhook/…", required: true },
    ],
  },
  {
    id: "jira",
    label: "Jira",
    icon: "/jira.png",
    color: "#0052cc",
    blurb: "Create issues in a project",
    primary: "project",
    fields: [
      { name: "label", label: "Label", placeholder: "e.g. Security board" },
      { name: "baseUrl", label: "Base URL", type: "url", placeholder: "https://your-org.atlassian.net", required: true },
      { name: "project", label: "Project Key", placeholder: "SEC", required: true },
      { name: "email", label: "Account Email", type: "email", placeholder: "you@company.com", required: true },
      { name: "apiToken", label: "API Token", placeholder: "••••••••", required: true },
    ],
  },
];

const serviceById = (id) => SERVICES.find((s) => s.id === id);

// icons can be an image path (e.g. "/slack.png" in public/) or an emoji.
const isImgIcon = (icon) =>
  typeof icon === "string" && /\.(png|svg|jpe?g|webp)$/i.test(icon);

// render either an <img> (for image paths) or the emoji/text as-is.
function renderIcon(icon, alt, size = "lg") {
  if (isImgIcon(icon)) {
    return <img src={icon} alt={alt} className={`ch-icon-img ${size}`} />;
  }
  return icon;
}

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function loadChannels() {
  try {
    const raw = localStorage.getItem(STORE_KEY);
    return raw ? JSON.parse(raw) : [];
  } catch {
    return [];
  }
}

function validateField(field, value) {
  const v = (value || "").trim();
  if (field.required && !v) return `${field.label} is required`;
  if (!v) return null;
  if (field.type === "email" && !EMAIL_RE.test(v)) return "Enter a valid email address";
  if (field.type === "tel" && v.replace(/\D/g, "").length < 8) return "Enter a valid phone number";
  if (field.type === "url" && !/^https?:\/\/.+/i.test(v)) return "Enter a valid URL (https://…)";
  return null;
}

export default function ChannelsManager() {
  const [channels, setChannels] = useState(loadChannels);
  const [modalOpen, setModalOpen] = useState(false);
  const [step, setStep] = useState("choose"); // "choose" | "form"
  const [serviceId, setServiceId] = useState(null);
  const [values, setValues] = useState({});
  const [editingId, setEditingId] = useState(null);
  const [errors, setErrors] = useState({});
  const [toast, setToast] = useState(null);
  const [filter, setFilter] = useState("all");

  useEffect(() => {
    localStorage.setItem(STORE_KEY, JSON.stringify(channels));
  }, [channels]);

  useEffect(() => {
    if (!toast) return;
    const t = setTimeout(() => setToast(null), 2600);
    return () => clearTimeout(t);
  }, [toast]);

  const service = serviceId ? serviceById(serviceId) : null;

  const counts = useMemo(() => {
    const map = {};
    for (const c of channels) map[c.serviceId] = (map[c.serviceId] || 0) + 1;
    return map;
  }, [channels]);

  const visible = useMemo(
    () => (filter === "all" ? channels : channels.filter((c) => c.serviceId === filter)),
    [channels, filter],
  );

  // ── modal controls ──────────────────────────────────────────────
  const openAdd = () => {
    setEditingId(null);
    setServiceId(null);
    setValues({});
    setErrors({});
    setStep("choose");
    setModalOpen(true);
  };

  const pickService = (id) => {
    setServiceId(id);
    setValues({});
    setErrors({});
    setStep("form");
  };

  const openEdit = (channel) => {
    setEditingId(channel.id);
    setServiceId(channel.serviceId);
    setValues({ ...channel.values });
    setErrors({});
    setStep("form");
    setModalOpen(true);
  };

  const closeModal = () => {
    setModalOpen(false);
    setEditingId(null);
    setServiceId(null);
    setValues({});
    setErrors({});
  };

  const setField = (name, val) => {
    setValues((v) => ({ ...v, [name]: val }));
    setErrors((e) => ({ ...e, [name]: undefined }));
  };

  const submit = (e) => {
    e.preventDefault();
    if (!service) return;

    // validate
    const next = {};
    for (const f of service.fields) {
      const msg = validateField(f, values[f.name]);
      if (msg) next[f.name] = msg;
    }
    if (Object.keys(next).length) {
      setErrors(next);
      return;
    }

    const clean = {};
    for (const f of service.fields) clean[f.name] = (values[f.name] || "").trim();

    if (editingId) {
      setChannels((cur) =>
        cur.map((c) =>
          c.id === editingId ? { ...c, values: clean } : c,
        ),
      );
      setToast(`${service.label} channel updated`);
    } else {
      const channel = {
        id: `ch_${Date.now()}`,
        serviceId: service.id,
        values: clean,
        createdAt: new Date().toISOString(),
      };
      setChannels((cur) => [channel, ...cur]);
      setToast(`${service.label} channel registered`);
    }
    closeModal();
  };

  const removeChannel = (channel) => {
    const s = serviceById(channel.serviceId);
    const detail = channel.values[s?.primary] || s?.label;
    if (window.confirm(`Remove this ${s?.label} channel (${detail})?`)) {
      setChannels((cur) => cur.filter((c) => c.id !== channel.id));
      setToast("Channel removed");
    }
  };

  const titleFor = (channel, s) =>
    channel.values.label?.trim() || s?.label || "Channel";
  const primaryFor = (channel, s) => channel.values[s?.primary] || "—";
  const primaryLabelFor = (s) =>
    s?.fields.find((f) => f.name === s.primary)?.label || "Destination";

  return (
    <div className="ch-page">
      {/* ── header ─────────────────────────────────────────── */}
      <header className="ch-header">
        <div>
          <h1 className="ch-title">Message Channels</h1>
          <p className="ch-subtitle">
            Register where notifications are delivered — add as many as you need.
          </p>
        </div>
        <button className="ch-add-btn" onClick={openAdd}>
          <span className="ch-add-plus">+</span> Add Channel
        </button>
      </header>

      {/* ── stats strip ────────────────────────────────────── */}
      {channels.length > 0 && (
        <div className="ch-stats">
          <div className="ch-stat">
            <span className="ch-stat-num">{channels.length}</span>
            <span className="ch-stat-label">
              Channel{channels.length === 1 ? "" : "s"}
            </span>
          </div>
          <div className="ch-stat-divider" />
          <div className="ch-stat">
            <span className="ch-stat-num">{Object.keys(counts).length}</span>
            <span className="ch-stat-label">Services connected</span>
          </div>
          <div className="ch-stat-services">
            {SERVICES.filter((s) => counts[s.id]).map((s) => (
              <span
                key={s.id}
                className="ch-stat-chip"
                style={{ background: `${s.color}14` }}
                title={`${s.label}: ${counts[s.id]}`}
              >
                {renderIcon(s.icon, s.label, "xs")}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* ── filter chips ───────────────────────────────────── */}
      {channels.length > 0 && (
        <div className="ch-filters">
          <button
            className={`ch-filter ${filter === "all" ? "on" : ""}`}
            onClick={() => setFilter("all")}
          >
            All <span className="ch-filter-n">{channels.length}</span>
          </button>
          {SERVICES.filter((s) => counts[s.id]).map((s) => (
            <button
              key={s.id}
              className={`ch-filter ${filter === s.id ? "on" : ""}`}
              onClick={() => setFilter(s.id)}
            >
              {renderIcon(s.icon, s.label, "xs")}
              <span className="ch-filter-label">{s.label}</span>
              <span className="ch-filter-n">{counts[s.id]}</span>
            </button>
          ))}
        </div>
      )}

      {/* ── channel grid / empty state ─────────────────────── */}
      {channels.length === 0 ? (
        <div className="ch-empty">
          <div className="ch-empty-icon">📡</div>
          <h2>No channels yet</h2>
          <p>Add your first channel to start delivering notifications.</p>
          <button className="ch-add-btn big" onClick={openAdd}>
            <span className="ch-add-plus">+</span> Add Channel
          </button>
        </div>
      ) : (
        <div className="ch-grid">
          {visible.map((channel) => {
            const s = serviceById(channel.serviceId);
            return (
              <div className="ch-card" style={{ "--accent": s?.color }} key={channel.id}>
                <div className="ch-card-top">
                  <span className="ch-badge" style={{ background: `${s?.color}18` }}>
                    {renderIcon(s?.icon, s?.label, "lg")}
                  </span>
                  <div className="ch-card-head">
                    <div className="ch-card-name">{titleFor(channel, s)}</div>
                    <div className="ch-card-service">{s?.label}</div>
                  </div>
                  <div className="ch-card-actions">
                    <button className="ch-icon-btn" title="Edit" onClick={() => openEdit(channel)}>
                      ✏️
                    </button>
                    <button className="ch-icon-btn danger" title="Remove" onClick={() => removeChannel(channel)}>
                      🗑️
                    </button>
                  </div>
                </div>
                <div className="ch-card-field">
                  <span className="ch-card-field-label">{primaryLabelFor(s)}</span>
                  <span className="ch-card-primary">{primaryFor(channel, s)}</span>
                </div>
                <div className="ch-card-meta">
                  <span className="ch-status-pill">
                    <span className="ch-dot" /> Active
                  </span>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* ── add / edit modal ───────────────────────────────── */}
      {modalOpen && (
        <div className="ch-modal-backdrop" onClick={closeModal}>
          <div className="ch-modal" onClick={(e) => e.stopPropagation()}>
            {step === "choose" && (
              <>
                <div className="ch-modal-head">
                  <h2>Add a channel</h2>
                  <button className="ch-close" onClick={closeModal}>✕</button>
                </div>
                <p className="ch-modal-sub">Choose a service to connect</p>
                <div className="ch-service-grid">
                  {SERVICES.map((s) => (
                    <button
                      key={s.id}
                      className="ch-service-tile"
                      onClick={() => pickService(s.id)}
                    >
                      <span className="ch-tile-icon" style={{ background: `${s.color}18` }}>
                        {renderIcon(s.icon, s.label, "lg")}
                      </span>
                      <span className="ch-tile-name">{s.label}</span>
                      <span className="ch-tile-blurb">{s.blurb}</span>
                    </button>
                  ))}
                </div>
              </>
            )}

            {step === "form" && service && (
              <>
                <div className="ch-modal-head">
                  <div className="ch-modal-title">
                    {!editingId && (
                      <button className="ch-back" onClick={() => setStep("choose")} title="Back">
                        ‹
                      </button>
                    )}
                    <span className="ch-tile-icon sm" style={{ background: `${service.color}18` }}>
                      {renderIcon(service.icon, service.label, "md")}
                    </span>
                    <h2>
                      {editingId ? "Edit" : "New"} {service.label} channel
                    </h2>
                  </div>
                  <button className="ch-close" onClick={closeModal}>✕</button>
                </div>

                <form className="ch-form" onSubmit={submit}>
                  {service.fields.map((f) => (
                    <div className="ch-field" key={f.name}>
                      <label className="ch-label">
                        {f.label}
                        {f.required && <span className="ch-req">*</span>}
                      </label>
                      <input
                        className={`ch-input ${errors[f.name] ? "err" : ""}`}
                        type={f.type === "email" || f.type === "url" ? "text" : f.type || "text"}
                        placeholder={f.placeholder}
                        value={values[f.name] || ""}
                        onChange={(e) => setField(f.name, e.target.value)}
                        autoComplete="off"
                      />
                      {errors[f.name] && <span className="ch-err">{errors[f.name]}</span>}
                    </div>
                  ))}
                  <div className="ch-form-actions">
                    <button type="button" className="ch-btn ghost" onClick={closeModal}>
                      Cancel
                    </button>
                    <button type="submit" className="ch-btn primary">
                      {editingId ? "Save changes" : "Register channel"}
                    </button>
                  </div>
                </form>
              </>
            )}
          </div>
        </div>
      )}

      {toast && <div className="ch-toast">✓ {toast}</div>}
    </div>
  );
}
