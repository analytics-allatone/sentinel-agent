import React, { useEffect, useMemo, useRef, useState } from "react";

import { fetchAgents } from "../api/agents";

/**
 * Pick an agent by name, from the agents that exist.
 *
 * Typing the name of an agent from memory is how this field worked before, and
 * it still does — the text is sent whatever the list says. The list is an aid,
 * not a gate: `/get-agents` needs a session and can answer 401 or nothing at
 * all, and a filter that stops working because a second, unrelated request
 * failed would be worse than no dropdown.
 *
 * So: the field is a combobox over whatever names arrived, and a plain text
 * field when none did.
 */
export default function AgentPicker({ value, onChange, id = "al-agent" }) {
  const [agents, setAgents] = useState([]);
  const [loadFailed, setLoadFailed] = useState(false);
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(-1);

  const wrapRef = useRef(null);
  const inputRef = useRef(null);
  const listId = `${id}-listbox`;

  useEffect(() => {
    let alive = true;
    fetchAgents().then((list) => {
      if (!alive) return;
      const names = [...new Set(list.map((a) => a.name).filter(Boolean))].sort((a, b) =>
        a.localeCompare(b)
      );
      setAgents(list.filter((a) => names.includes(a.name)));
      setLoadFailed(names.length === 0);
    });
    return () => {
      alive = false;
    };
  }, []);

  /** What is typed narrows the list; an exact pick leaves it whole. */
  const matches = useMemo(() => {
    const needle = String(value || "").trim().toLowerCase();
    if (!needle) return agents;
    const exact = agents.some((a) => a.name.toLowerCase() === needle);
    if (exact) return agents;
    return agents.filter(
      (a) =>
        a.name.toLowerCase().includes(needle) ||
        (a.hostName || "").toLowerCase().includes(needle)
    );
  }, [agents, value]);

  // A click anywhere else is a decision not to pick.
  useEffect(() => {
    if (!open) return undefined;
    const away = (e) => {
      if (wrapRef.current && !wrapRef.current.contains(e.target)) setOpen(false);
    };
    document.addEventListener("mousedown", away);
    return () => document.removeEventListener("mousedown", away);
  }, [open]);

  const choose = (name) => {
    onChange(name);
    setOpen(false);
    setActive(-1);
    if (inputRef.current) inputRef.current.focus();
  };

  const onKeyDown = (e) => {
    if (e.key === "Escape") {
      setOpen(false);
      setActive(-1);
      return;
    }

    if (e.key === "ArrowDown" || e.key === "ArrowUp") {
      e.preventDefault();
      if (!open) {
        setOpen(true);
        setActive(0);
        return;
      }
      const last = matches.length - 1;
      setActive((i) => {
        if (e.key === "ArrowDown") return i >= last ? 0 : i + 1;
        return i <= 0 ? last : i - 1;
      });
      return;
    }

    if (e.key === "Enter" && open && active >= 0 && matches[active]) {
      // Enter inside an open list picks; it does not submit the filter form.
      e.preventDefault();
      choose(matches[active].name);
    }
  };

  const hasList = agents.length > 0;

  return (
    <div className="al-combo" ref={wrapRef}>
      <input
        id={id}
        ref={inputRef}
        className="al-input al-input--agent"
        type="text"
        role={hasList ? "combobox" : undefined}
        aria-expanded={hasList ? open : undefined}
        aria-controls={hasList ? listId : undefined}
        aria-autocomplete={hasList ? "list" : undefined}
        aria-activedescendant={open && active >= 0 ? `${id}-opt-${active}` : undefined}
        autoComplete="off"
        placeholder="Every agent"
        value={value}
        onChange={(e) => {
          onChange(e.target.value);
          setOpen(true);
          setActive(-1);
        }}
        /* Opened by a click, not by focus: choosing an agent returns focus to
           the field, and a focus handler that opens would pop the list it just
           closed straight back up. The keyboard opens it with ArrowDown. */
        onClick={() => hasList && setOpen(true)}
        onKeyDown={onKeyDown}
      />

      {open && hasList && (
        <ul className="al-combo-list" id={listId} role="listbox" aria-label="Agents">
          {/* Clearing is a choice in the list, not a separate control. */}
          <li
            role="option"
            aria-selected={!value}
            className={`al-combo-opt al-combo-opt--any ${!value ? "is-picked" : ""}`}
            onMouseDown={(e) => e.preventDefault()}
            onClick={() => choose("")}
          >
            Every agent
          </li>

          {matches.map((agent, i) => (
            <li
              key={agent.id}
              id={`${id}-opt-${i}`}
              role="option"
              aria-selected={agent.name === value}
              className={`al-combo-opt ${i === active ? "is-active" : ""} ${
                agent.name === value ? "is-picked" : ""
              }`}
              // mousedown would blur the input before the click lands
              onMouseDown={(e) => e.preventDefault()}
              onClick={() => choose(agent.name)}
              onMouseEnter={() => setActive(i)}
            >
              <span className="al-combo-name">{agent.name}</span>
              {agent.hostName && <span className="al-combo-host">{agent.hostName}</span>}
            </li>
          ))}

          {matches.length === 0 && (
            <li className="al-combo-empty">
              No agent matches that. It will still be sent as typed.
            </li>
          )}
        </ul>
      )}

      {/* Said once, quietly: the field works, the list is what is missing. */}
      {loadFailed && <span className="al-combo-note">type a name — the list is unavailable</span>}
    </div>
  );
}
