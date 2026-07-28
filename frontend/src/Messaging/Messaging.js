import React, { useEffect, useMemo, useRef, useState } from "react";
import "./Messaging.css";

/**
 * Messaging / Notifications — FRONTEND ONLY.
 *
 * Two-pane chat layout:
 *   • Left column — every delivery platform (icon + name).
 *   • Right pane  — the thread for the selected platform, plus a compose
 *                   FORM whose fields change per platform
 *                   (Email → To/Subject/Message, Jira → Project/Type/… etc).
 *
 * Nothing is actually sent — sends are simulated and persisted to
 * localStorage. Wire `sendMessage()` to your backend later.
 */

const HISTORY_KEY = "messaging_outbox_v1";
const RECIPIENTS_KEY = "messaging_recipients_v1";

// ── delivery platforms ────────────────────────────────────────────
const PLATFORMS = [
  { id: "email", label: "Email", icon: "✉️", color: "#2563eb" },
  { id: "sms", label: "SMS", icon: "💬", color: "#0891b2" },
  { id: "whatsapp", label: "WhatsApp", icon: "🟢", color: "#25d366" },
  { id: "slack", label: "Slack", icon: "🔷", color: "#611f69" },
  { id: "jira", label: "Jira", icon: "🧩", color: "#0052cc" },
  { id: "teams", label: "Teams", icon: "👨‍💼", color: "#5b5fc7" },
  { id: "telegram", label: "Telegram", icon: "✈️", color: "#229ed9" },
  { id: "discord", label: "Discord", icon: "🎮", color: "#5865f2" },
];
const platformById = (id) => PLATFORMS.find((p) => p.id === id);

/**
 * EmailJS — actually sends email from the browser (frontend-only).
 *
 * SETUP (one time, ~2 min):
 *   1. Create a free account at https://www.emailjs.com
 *   2. Add an Email Service (Gmail/Outlook/etc.) → copy its Service ID.
 *   3. Create an Email Template that uses these variables:
 *        To:      {{to_email}}
 *        Cc:      {{cc}}
 *        Subject: {{subject}}
 *        Body:    {{message}}
 *      → copy its Template ID.
 *   4. Account → General → copy your Public Key.
 *   5. Paste all three below. That's it — sending goes live.
 */
const EMAILJS = {
  serviceId: "service_ap9e5pb",
  templateId: "template_ibg3rrg",
  publicKey: "p3JVzcQa3AWG9YmKQ",
};
const emailjsReady = () =>
  !!(EMAILJS.serviceId && EMAILJS.templateId && EMAILJS.publicKey);

async function sendViaEmailJS(params) {
  const res = await fetch("https://api.emailjs.com/api/v1.0/email/send", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      service_id: EMAILJS.serviceId,
      template_id: EMAILJS.templateId,
      user_id: EMAILJS.publicKey,
      template_params: params,
    }),
  });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(text || `EmailJS error ${res.status}`);
  }
}

// Open a URL (wa.me / sms: link) in a new tab reliably, without navigating
// the current site away. An anchor click counts as a user gesture, so popup
// blockers allow it.
function openLink(url) {
  const a = document.createElement("a");
  a.href = url;
  a.target = "_blank";
  a.rel = "noopener noreferrer";
  document.body.appendChild(a);
  a.click();
  a.remove();
}

/**
 * Per-platform form schema. Field types:
 *   recipients — multi-select of users (the "To")
 *   text       — single line
 *   textarea   — multi line
 *   select     — dropdown (needs `options`)
 */
const FIELDS = {
  email: [
    { name: "to", label: "To", type: "recipients", required: true },
    { name: "cc", label: "Cc", type: "text", placeholder: "comma-separated emails (optional)" },
    { name: "subject", label: "Subject", type: "text", placeholder: "Email subject", required: true },
    { name: "message", label: "Message", type: "textarea", placeholder: "Write your email…", required: true },
  ],
  sms: [
    { name: "phone", label: "Phone Number", type: "tel", placeholder: "+919876543210 (include country code)", required: true },
    { name: "message", label: "Message", type: "textarea", placeholder: "Text message…", required: true, maxLength: 160 },
  ],
  whatsapp: [
    { name: "phone", label: "Phone Number", type: "tel", placeholder: "+919876543210 (include country code)", required: true },
    { name: "message", label: "Message", type: "textarea", placeholder: "WhatsApp message…", required: true },
  ],
  slack: [
    { name: "channel", label: "Channel", type: "text", placeholder: "#channel or @user", required: true },
    { name: "message", label: "Message", type: "textarea", placeholder: "Slack message…", required: true },
  ],
  jira: [
    { name: "project", label: "Project", type: "text", placeholder: "e.g. SEC", required: true },
    { name: "issueType", label: "Issue Type", type: "select", options: ["Task", "Bug", "Incident", "Story"], required: true },
    { name: "priority", label: "Priority", type: "select", options: ["Low", "Medium", "High", "Critical"] },
    { name: "summary", label: "Summary", type: "text", placeholder: "Issue summary", required: true },
    { name: "description", label: "Description", type: "textarea", placeholder: "Describe the issue…", required: true },
  ],
  teams: [
    { name: "to", label: "Team / Channel", type: "text", placeholder: "Team › Channel", required: true },
    { name: "message", label: "Message", type: "textarea", placeholder: "Teams message…", required: true },
  ],
  telegram: [
    { name: "chat", label: "Chat", type: "text", placeholder: "@username or chat id", required: true },
    { name: "message", label: "Message", type: "textarea", placeholder: "Telegram message…", required: true },
  ],
  discord: [
    { name: "server", label: "Server", type: "text", placeholder: "Server name", required: true },
    { name: "channel", label: "Channel", type: "text", placeholder: "#channel", required: true },
    { name: "message", label: "Message", type: "textarea", placeholder: "Discord message…", required: true },
  ],
};

// recipients start empty — users add their own via the "+ Add" control
const SEED_RECIPIENTS = [];

const EMAIL_RE = /^[^\s@]+@([^\s@]+\.[^\s@]+)$/;
const isEmail = (s) => EMAIL_RE.test((s || "").trim());

/**
 * Frontend-only email verification.
 * Every email is checked against a live, keyless verification API before it
 * can be added. If it doesn't pass, it is NOT added.
 *
 *   Primary  : Disify        (https://disify.com/api/email/<email>)
 *   Fallback : Mailcheck.ai  (used only if Disify is unreachable)
 *
 * Both confirm valid syntax + a real mail domain (MX) and flag disposable
 * addresses. Note: a specific mailbox's existence still can't be proven from
 * the browser (providers block SMTP probing) — that needs a paid backend.
 */
async function verifyWithDisify(addr) {
  const res = await fetch(`https://disify.com/api/email/${encodeURIComponent(addr)}`);
  const d = await res.json();
  if (d.format === false) return { ok: false, reason: "Invalid email format" };
  if (d.dns === false)
    return { ok: false, reason: `“${d.domain}” has no mail server — not added` };
  if (d.disposable === true)
    return { ok: false, reason: "Disposable email not allowed — not added" };
  return { ok: true, reason: `${d.domain} verified — valid mail domain` };
}

async function verifyWithMailcheck(addr) {
  const res = await fetch(`https://api.mailcheck.ai/email/${encodeURIComponent(addr)}`);
  const d = await res.json();
  if (d.mx === false)
    return { ok: false, reason: `“${d.domain}” has no mail server — not added` };
  if (d.disposable === true)
    return { ok: false, reason: "Disposable email not allowed — not added" };
  return { ok: true, reason: `${d.domain} verified — valid mail domain` };
}

async function verifyEmail(email) {
  const addr = (email || "").trim();
  if (!EMAIL_RE.test(addr)) return { ok: false, reason: "Invalid email format" };

  try {
    return await verifyWithDisify(addr);
  } catch {
    // Disify unreachable — try the fallback provider
  }
  try {
    return await verifyWithMailcheck(addr);
  } catch {
    return { ok: false, reason: "Couldn't verify email right now — try again" };
  }
}

function loadJSON(key, fallback) {
  try {
    const raw = localStorage.getItem(key);
    return raw ? JSON.parse(raw) : fallback;
  } catch {
    return fallback;
  }
}

function fmtTime(iso) {
  try {
    return new Date(iso).toLocaleString([], {
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  } catch {
    return "";
  }
}

// pick a sensible title + body for a stored message, per platform
function preview(entry) {
  const f = entry.fields || {};
  if (entry.platform === "email") return { title: f.subject, body: f.message };
  if (entry.platform === "jira")
    return {
      title: `${f.project ? f.project + " · " : ""}${f.issueType || ""}${f.priority ? " · " + f.priority : ""}`,
      subtitle: f.summary,
      body: f.description,
    };
  return { title: null, body: f.message };
}

export default function Messaging() {
  const [recipients, setRecipients] = useState(() =>
    loadJSON(RECIPIENTS_KEY, SEED_RECIPIENTS),
  );
  const [history, setHistory] = useState(() => loadJSON(HISTORY_KEY, []));

  const [activePlatform, setActivePlatform] = useState("email");
  const [values, setValues] = useState({});
  const [selectedRecipients, setSelectedRecipients] = useState([]);
  const [sending, setSending] = useState(false);
  const [sendMsg, setSendMsg] = useState(null); // { ok, text }

  // add-recipient inline form
  const [newName, setNewName] = useState("");
  const [newHandle, setNewHandle] = useState("");
  const [showAdd, setShowAdd] = useState(false);
  const [verifying, setVerifying] = useState(false);
  const [verifyMsg, setVerifyMsg] = useState(null); // { ok, text }

  const feedRef = useRef(null);

  useEffect(() => {
    localStorage.setItem(HISTORY_KEY, JSON.stringify(history));
  }, [history]);
  useEffect(() => {
    localStorage.setItem(RECIPIENTS_KEY, JSON.stringify(recipients));
  }, [recipients]);

  // reset the form when switching platform
  useEffect(() => {
    setValues({});
    setShowAdd(false);
    setSendMsg(null);
  }, [activePlatform]);

  const active = platformById(activePlatform);
  const schema = FIELDS[activePlatform] || [];
  const hasRecipients = schema.some((f) => f.type === "recipients");

  const thread = useMemo(
    () => history.filter((m) => m.platform === activePlatform),
    [history, activePlatform],
  );

  const counts = useMemo(() => {
    const map = {};
    for (const m of history) map[m.platform] = (map[m.platform] || 0) + 1;
    return map;
  }, [history]);

  useEffect(() => {
    if (feedRef.current) feedRef.current.scrollTop = feedRef.current.scrollHeight;
  }, [thread]);

  const setField = (name, val) => setValues((v) => ({ ...v, [name]: val }));

  const toggleRecipient = (id) =>
    setSelectedRecipients((cur) =>
      cur.includes(id) ? cur.filter((x) => x !== id) : [...cur, id],
    );

  const addRecipient = async (e) => {
    e.preventDefault();
    const name = newName.trim();
    const handle = newHandle.trim();
    if (!name || !handle) return;

    // verify email-looking handles before adding
    let verified = false;
    if (isEmail(handle)) {
      setVerifying(true);
      setVerifyMsg(null);
      const result = await verifyEmail(handle);
      setVerifying(false);
      if (!result.ok) {
        setVerifyMsg({ ok: false, text: result.reason });
        return; // block the add on a failed check
      }
      verified = true;
    }

    const id = `u_${Date.now()}`;
    setRecipients((cur) => [...cur, { id, name, handle, verified }]);
    setSelectedRecipients((cur) => [...cur, id]);
    setNewName("");
    setNewHandle("");
    setVerifyMsg(null);
    setShowAdd(false);
  };

  const removeRecipient = (id) => {
    setRecipients((cur) => cur.filter((r) => r.id !== id));
    setSelectedRecipients((cur) => cur.filter((x) => x !== id));
  };

  // validation — every required field present
  const isValid = schema.every((f) => {
    if (!f.required) return true;
    if (f.type === "recipients") return selectedRecipients.length > 0;
    return (values[f.name] || "").trim().length > 0;
  });
  const canSend = isValid && !sending;

  const sendMessage = async () => {
    if (!canSend) return;
    setSending(true);
    setSendMsg(null);

    const chosen = recipients.filter((r) => selectedRecipients.includes(r.id));
    const fieldValues = { ...values };
    if (hasRecipients) {
      fieldValues.to = chosen.map((r) => `${r.name} (${r.handle})`).join(", ");
    }

    let status = "sent";
    try {
      if (activePlatform === "email") {
        if (!emailjsReady()) {
          throw new Error(
            "Email sending isn't configured. Add your EmailJS keys (EMAILJS) in Messaging.js — see the setup notes there.",
          );
        }
        // one real email per recipient
        for (const r of chosen) {
          await sendViaEmailJS({
            to_email: r.handle,
            to_name: r.name,
            subject: values.subject || "",
            message: values.message || "",
            cc: values.cc || "",
          });
        }
        setSendMsg({
          ok: true,
          text: `Email sent to ${chosen.length} recipient${chosen.length > 1 ? "s" : ""}.`,
        });
      } else if (activePlatform === "sms") {
        const phone = (values.phone || "").trim();
        if (!phone) throw new Error("Enter a phone number");
        const body = encodeURIComponent(values.message || "");
        openLink(`sms:${phone}?body=${body}`); // opens the device SMS app
        fieldValues.to = phone; // for the thread display
        setSendMsg({ ok: true, text: `Opened SMS app for ${phone} — press send there.` });
      } else if (activePlatform === "whatsapp") {
        const phone = (values.phone || "").trim();
        const digits = phone.replace(/\D/g, ""); // wa.me needs digits only
        if (!digits) throw new Error("Enter a valid phone number with country code");
        const text = encodeURIComponent(values.message || "");
        openLink(`https://wa.me/${digits}?text=${text}`); // opens WhatsApp
        fieldValues.to = phone; // for the thread display
        setSendMsg({ ok: true, text: `Opened WhatsApp for ${phone} — press send there.` });
      } else {
        // other platforms need a backend integration — simulated for now
        await new Promise((res) => setTimeout(res, 400));
        status = "sent (simulated)";
        setSendMsg({
          ok: true,
          text: `${active?.label} send is simulated (needs a backend integration).`,
        });
      }
    } catch (e) {
      // surface a backend error detail if present (FastAPI HTTPException)
      const detail =
        e?.response?.data?.detail ||
        e?.response?.data?.message ||
        e?.message ||
        "Failed to send.";
      setSending(false);
      setSendMsg({ ok: false, text: detail });
      return; // don't record a failed send
    }

    const entry = {
      id: `m_${Date.now()}`,
      platform: activePlatform,
      fields: fieldValues,
      recipients: chosen.map((r) => ({ id: r.id, name: r.name, handle: r.handle })),
      sentAt: new Date().toISOString(),
      status,
    };

    setHistory((cur) => [...cur, entry]);
    setValues({});
    setSending(false);
  };

  const renderField = (f) => {
    if (f.type === "recipients") {
      return (
        <div className="msg-field" key={f.name}>
          <label className="msg-flabel">
            {f.label} {f.required && <span className="msg-req">*</span>}
            <span className="msg-fhint">
              {selectedRecipients.length} selected
            </span>
          </label>
          <div className="msg-chips">
            {recipients.map((r) => {
              const on = selectedRecipients.includes(r.id);
              return (
                <div
                  key={r.id}
                  className={`msg-chip ${on ? "on" : ""}`}
                  onClick={() => toggleRecipient(r.id)}
                  title={r.handle}
                  role="button"
                >
                  <span className="msg-chip-av">{r.name.charAt(0).toUpperCase()}</span>
                  <span className="msg-chip-name">{r.name}</span>
                  {r.verified && (
                    <span className="msg-chip-verified" title="Email domain verified">
                      ✔
                    </span>
                  )}
                  {on && <span className="msg-chip-x">✓</span>}
                  <span
                    className="msg-chip-remove"
                    title={`Remove ${r.name}`}
                    onClick={(e) => {
                      e.stopPropagation();
                      removeRecipient(r.id);
                    }}
                  >
                    ✕
                  </span>
                </div>
              );
            })}
            <button
              type="button"
              className="msg-chip add"
              onClick={() => setShowAdd((s) => !s)}
            >
              + Add
            </button>
          </div>
          {showAdd && (
            <>
              <form className="msg-add" onSubmit={addRecipient}>
                <input
                  className="msg-tinput"
                  placeholder="Name"
                  value={newName}
                  onChange={(e) => setNewName(e.target.value)}
                />
                <input
                  className="msg-tinput"
                  placeholder="Email / phone / #channel"
                  value={newHandle}
                  onChange={(e) => {
                    setNewHandle(e.target.value);
                    setVerifyMsg(null);
                  }}
                />
                <button
                  className="msg-btn"
                  disabled={!newName.trim() || !newHandle.trim() || verifying}
                >
                  {verifying ? "Verifying…" : "Add"}
                </button>
              </form>
              {verifying && (
                <div className="msg-verify checking">🔍 Verifying email domain…</div>
              )}
              {verifyMsg && (
                <div className={`msg-verify ${verifyMsg.ok ? "ok" : "error"}`}>
                  {verifyMsg.ok ? "✓ " : "⚠ "}
                  {verifyMsg.text}
                </div>
              )}
              {isEmail(newHandle) && !verifying && !verifyMsg && (
                <div className="msg-verify hint">
                  Email domain will be checked — invalid domains can't be added.
                </div>
              )}
            </>
          )}
        </div>
      );
    }

    if (f.type === "select") {
      return (
        <div className="msg-field" key={f.name}>
          <label className="msg-flabel">
            {f.label} {f.required && <span className="msg-req">*</span>}
          </label>
          <select
            className="msg-select"
            value={values[f.name] || ""}
            onChange={(e) => setField(f.name, e.target.value)}
          >
            <option value="">Select…</option>
            {f.options.map((o) => (
              <option key={o} value={o}>
                {o}
              </option>
            ))}
          </select>
        </div>
      );
    }

    if (f.type === "textarea") {
      return (
        <div className="msg-field" key={f.name}>
          <label className="msg-flabel">
            {f.label} {f.required && <span className="msg-req">*</span>}
            {f.maxLength && (
              <span className="msg-fhint">
                {(values[f.name] || "").length}/{f.maxLength}
              </span>
            )}
          </label>
          <textarea
            className="msg-tarea"
            rows={4}
            maxLength={f.maxLength}
            placeholder={f.placeholder}
            value={values[f.name] || ""}
            onChange={(e) => setField(f.name, e.target.value)}
          />
        </div>
      );
    }

    // text
    return (
      <div className="msg-field" key={f.name}>
        <label className="msg-flabel">
          {f.label} {f.required && <span className="msg-req">*</span>}
        </label>
        <input
          className="msg-tinput full"
          placeholder={f.placeholder}
          value={values[f.name] || ""}
          onChange={(e) => setField(f.name, e.target.value)}
        />
      </div>
    );
  };

  return (
    <div className="msg-page">
      <div className="msg-shell">
        {/* ── LEFT: platform column ─────────────────────────── */}
        <aside className="msg-rail">
          <div className="msg-rail-head">
            <span className="msg-rail-title">Platforms</span>
          </div>
          <ul className="msg-rail-list">
            {PLATFORMS.map((p) => {
              const on = p.id === activePlatform;
              return (
                <li key={p.id}>
                  <button
                    className={`msg-rail-item ${on ? "active" : ""}`}
                    style={on ? { borderLeftColor: p.color } : undefined}
                    onClick={() => setActivePlatform(p.id)}
                  >
                    <span className="msg-rail-icon" style={{ background: `${p.color}18` }}>
                      {p.icon}
                    </span>
                    <span className="msg-rail-name">{p.label}</span>
                    {counts[p.id] > 0 && (
                      <span className="msg-rail-count">{counts[p.id]}</span>
                    )}
                  </button>
                </li>
              );
            })}
          </ul>
        </aside>

        {/* ── RIGHT: thread + platform form ─────────────────── */}
        <section className="msg-panel">
          <header className="msg-panel-head">
            <span className="msg-panel-icon" style={{ background: `${active?.color}18` }}>
              {active?.icon}
            </span>
            <div>
              <div className="msg-panel-name">{active?.label}</div>
              <div className="msg-panel-sub">
                {thread.length} message{thread.length === 1 ? "" : "s"}
              </div>
            </div>
          </header>

          {/* message thread */}
          <div className="msg-thread" ref={feedRef}>
            {thread.length === 0 ? (
              <div className="msg-empty">
                <div className="msg-empty-icon">{active?.icon || "📭"}</div>
                <p>No messages on {active?.label} yet.</p>
                <p className="msg-empty-sub">Fill the form below and hit send.</p>
              </div>
            ) : (
              thread.map((m) => {
                const p = preview(m);
                return (
                  <div key={m.id} className="msg-bubble">
                    {p.title && <div className="msg-bubble-title">{p.title}</div>}
                    {p.subtitle && <div className="msg-bubble-sub">{p.subtitle}</div>}
                    {p.body && <div className="msg-bubble-body">{p.body}</div>}
                    <div className="msg-bubble-foot">
                      {m.fields.to && <span className="msg-to">To: {m.fields.to}</span>}
                      {!m.fields.to && m.fields.channel && (
                        <span className="msg-to">#{m.fields.channel.replace(/^#/, "")}</span>
                      )}
                      <span className="msg-time">{fmtTime(m.sentAt)}</span>
                      <span className="msg-status">✓✓</span>
                    </div>
                  </div>
                );
              })
            )}
          </div>

          {/* platform-specific compose form */}
          <div className="msg-form">
            <div className="msg-form-title">
              New {active?.label} message
            </div>
            <div className="msg-form-fields">{schema.map(renderField)}</div>
            <div className="msg-form-actions">
              {activePlatform === "email" && !emailjsReady() && (
                <div className="msg-verify hint">
                  ⚙ To really send, add your EmailJS keys in{" "}
                  <code>Messaging.js</code> (see setup notes at the top).
                </div>
              )}
              {activePlatform === "sms" && (
                <div className="msg-verify hint">
                  📱 Opens your device's SMS app with the message pre-filled — just
                  press send there. Works best on mobile.
                </div>
              )}
              {activePlatform === "whatsapp" && (
                <div className="msg-verify hint">
                  🟢 Opens WhatsApp (app/web) with your message pre-filled — just
                  press send there. No API key needed.
                </div>
              )}
              <button className="msg-send-wide" disabled={!canSend} onClick={sendMessage}>
                {sending ? "Sending…" : `Send ${active?.label} ➤`}
              </button>
              {sendMsg && (
                <div className={`msg-verify ${sendMsg.ok ? "ok" : "error"}`}>
                  {sendMsg.ok ? "✓ " : "⚠ "}
                  {sendMsg.text}
                </div>
              )}
            </div>
          </div>
        </section>
      </div>
    </div>
  );
}
