import React, { useEffect, useState } from "react";
import TwoFactorToggle from "../TwoFactor/TwoFactorToggle";
import "./Sidebar.css";

import {
  LuLayoutDashboard,
  LuUsers,
  LuFolderTree,
  LuMonitor,
  LuMonitorCog,
  LuBell,
  LuMessageSquare,
  LuShieldCheck,
  LuChartNoAxesColumn,
  LuClipboardList,
  LuPlug,
  LuSettings,
  LuPalette,
  LuRocket,
  LuUserRound,
  LuChevronDown,
  LuChevronsLeft,
} from "react-icons/lu";

/**
 * The menu below names every section the product will have; only some of them
 * are built. These are the ones with a route in App.js — anything else lands on
 * the 403 page instead of a blank screen. Building a page? Add its path here.
 */
const ROUTED_PATHS = new Set([
  "/dashboard",
  "/grafanaDashboard",
  "/messages",
  "/reports/soc2",
  "/access",
  "/design-system",
]);

const UNROUTED_PATH = "/*";

/** Where a menu item actually goes: its own page, or the 403 until it exists. */
function hrefFor(item) {
  return `/app${ROUTED_PATHS.has(item.href) ? item.href : UNROUTED_PATH}`;
}


/** The menu, grouped by what someone came to do. */
const NAV_SECTIONS = [
  { title: "Overview", items: ["dashboard", "agents", "groups", "endpoints"] },
  { title: "Monitoring", items: ["agent-details", "alerts", "messages", "activity"] },
  { title: "Reports", items: ["reports"] },
  { title: "Administration", items: ["policies", "integrations", "users", "design-system", "settings"] },
];

const Sidebar = ({ isOpen, onClose }) => {
  const [activeMenu, setActiveMenu] = useState("dashboard");

  // A drawer that covers the page has to be dismissable from the keyboard,
  // not only by finding the scrim with a pointer.
  useEffect(() => {
    if (!isOpen || !onClose) return undefined;

    const onKeyDown = (event) => {
      if (event.key === "Escape") onClose();
    };

    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, [isOpen, onClose]);

  const menuItems = [
    {
      id: "dashboard",
      label: "Dashboard",
      icon: LuLayoutDashboard,
      href: "/dashboard",
    },
    {
      id: "agents",
      label: "Agents",
      icon: LuUsers,
      href: "/agents",
    },
    {
      id: "agent-details",
      label: "Grafana Dashboard",
      icon: LuMonitorCog,
      href: "/grafanaDashboard",
    },
    {
      id: "groups",
      label: "Groups",
      icon: LuFolderTree,
      href: "/groups",
    },
    {
      id: "endpoints",
      label: "Endpoints",
      icon: LuMonitor,
      href: "/endpoints",
    },
    {
      id: "alerts",
      label: "Alerts",
      icon: LuBell,
      href: "/alerts",
      badge: 3,
    },
    {
      id: "messages",
      label: "Messages",
      icon: LuMessageSquare,
      href: "/messages",
    },
    {
      id: "policies",
      label: "Policies",
      icon: LuShieldCheck,
      href: "/policies",
    },
    {
      id: "reports",
      label: "SOC2Reports",
      icon: LuChartNoAxesColumn,
      href: "/reports/soc2",
    },
    {
      id: "activity",
      label: "Activity Logs",
      icon: LuClipboardList,
      href: "/activity-logs",
    },
    {
      id: "integrations",
      label: "Integrations",
      icon: LuPlug,
      href: "/integrations",
    },
    {
      id: "users",
      label: "Users",
      icon: LuUsers,
      href: "/access",
    },
    {
      id: "design-system",
      label: "Design system",
      icon: LuPalette,
      href: "/design-system",
    },
    {
      id: "settings",
      label: "Settings",
      icon: LuSettings,
      href: "/settings",
    },
  ];

  const byId = menuItems.reduce((all, item) => {
    all[item.id] = item;
    return all;
  }, {});

  const handleMenuClick = (id) => {
    setActiveMenu(id);

    // Mobile par menu click ke baad sidebar close hoga
    if (window.innerWidth <= 768 && onClose) {
      onClose();
    }
  };

  return (
    <>
      {/* Mobile overlay */}
      <div
        className={`sidebar-overlay ${isOpen ? "visible" : ""}`}
        onClick={onClose}
        role="presentation"
        aria-hidden="true"
      ></div>

      <aside className={`sidebar ${isOpen ? "open" : ""}`}>

        {/* =================================
            SIDEBAR HEADER
            ================================= */}
        <div className="sidebar-header">

  <div className="sidebar-brand">

    <div className="sidebar-brand-icon phi-wordmark-mark">
      G
    </div>

    <span className="sidebar-brand-name phi-wordmark">
      GuardLynx
    </span>

  </div>

  <button
    className="sidebar-menu-toggle"
    onClick={onClose}
    aria-label="Close sidebar"
  >
    ☰
  </button>

</div>


        {/* =================================
            NAVIGATION
            ================================= */}
        <nav className="sidebar-nav" aria-label="Main">

          {NAV_SECTIONS.map((section) => (
            <div className="nav-section" key={section.title}>
              <h2 className="nav-section-title">{section.title}</h2>

              <ul className="nav-menu">
                {section.items.map((id) => {
                  const item = byId[id];
                  if (!item) return null;
                  const Icon = item.icon;
                  const current = activeMenu === item.id;

                  return (
                    <li key={item.id}>
                      <a
                        href={hrefFor(item)}
                        className={`nav-item ${current ? "active" : ""}`}
                        aria-current={current ? "page" : undefined}
                        onClick={() => handleMenuClick(item.id)}
                      >
                        <span className="nav-icon">
                          <Icon />
                        </span>

                        <span className="nav-label">{item.label}</span>

                        {item.badge && (
                          <span className="nav-badge">{item.badge}</span>
                        )}
                      </a>
                    </li>
                  );
                })}
              </ul>
            </div>
          ))}

          {/* Not navigation — it scrolls with the menu rather than pinning
              the bottom of the column. */}
          {/* =================================
              UPGRADE CARD
              ================================= */}
          <div className="sidebar-upgrade-card">

            <div className="upgrade-icon">
              <LuRocket />
            </div>

            <h4>
              Upgrade to Pro
            </h4>

            <p>
              Unlock advanced features,
              custom alerts, insights and more.
            </p>

            <button className="upgrade-button">
              Upgrade Now →
            </button>

          </div>

        </nav>


        {/* =================================
            BOTTOM AREA
            ================================= */}
        <div className="sidebar-bottom">


          {/* =================================
              ACCOUNT SECURITY
              ================================= */}
          <TwoFactorToggle />


          {/* =================================
              USER CARD
              ================================= */}
          <div className="sidebar-user-card">

            <div className="sidebar-user-avatar">
              <LuUserRound />
            </div>

            <div className="sidebar-user-info">

              <span className="sidebar-user-name">
                Admin
              </span>

              <span className="sidebar-user-role">
                Super Administrator
              </span>

            </div>

            <span className="sidebar-user-arrow">
              <LuChevronDown />
            </span>

          </div>


          {/* =================================
              COLLAPSE
              ================================= */}
          <button
            className="sidebar-collapse"
            onClick={onClose}
          >

            <span className="collapse-icon">
              <LuChevronsLeft />
            </span>

            <span>
              Collapse
            </span>

          </button>

        </div>

      </aside>
    </>
  );
};

export default Sidebar;