import React, { useState } from "react";
import "./dashboard-Header.css";
import { logout } from "../api/api";

import {
  LuSearch,
  LuBell,
  LuUserRound,
  LuChevronDown,
} from "react-icons/lu";

const DashboardHeader = ({ onMenuToggle , sidebarOpen}) => {
  const [isProfileOpen, setIsProfileOpen] = useState(false);
  const [isNotificationOpen, setIsNotificationOpen] = useState(false);

  // const toggleProfile = () => {
  //   setIsProfileOpen((prev) => !prev);
  //   setIsNotificationOpen(false);
  // };

  const toggleNotification = () => {
    setIsNotificationOpen((prev) => !prev);
    setIsProfileOpen(false);
  };

  return (
    <header className="dashboard-header">

      {/* =================================
          HEADER LEFT
          ================================= */}
      <div className="header-left">

  {!sidebarOpen && (
    <button
      className="header-sidebar-toggle"
      onClick={onMenuToggle}
      aria-label="Open sidebar"
    >
      ☰
    </button>
  )}

  <div className="header-page-info">
    <h1>GuardLynx</h1>
    {/* <p>Overview of your network security</p> */}
  </div>

</div>


      {/* =================================
          HEADER RIGHT
          ================================= */}
      <div className="header-right">

        {/* SEARCH */}
        <div className="search-box">

          <LuSearch className="header-search-icon" />

          <input
            type="text"
            placeholder="Search anything..."
          />

          {/* <span className="search-shortcut">
            ⌘ K
          </span> */}

        </div>


        {/* NOTIFICATION */}
        <div className="notification-wrapper">

          <button
            className="notification-btn"
            onClick={toggleNotification}
            aria-label="Notifications"
          >
            <LuBell />

            <span className="notification-badge">
              3
            </span>
          </button>

          {isNotificationOpen && (
            <div className="notification-dropdown">

              <div className="notification-header">
                Notifications
              </div>

              <div className="notification-item">
                <span className="notification-dot red"></span>
                New agent connected
              </div>

              <div className="notification-item">
                <span className="notification-dot orange"></span>
                Agent disconnected
              </div>

              <div className="notification-item">
                <span className="notification-dot purple"></span>
                System update available
              </div>

            </div>
          )}

        </div>


        {/* PROFILE */}
        <div
  className="profile-section"
  onMouseEnter={() => {
    setIsProfileOpen(true);
    setIsNotificationOpen(false);
  }}
  onMouseLeave={() => {
    setIsProfileOpen(false);
  }}
>

          <button
            className="profile-btn"
            type="button"
          >

            <span className="avatar">
              <LuUserRound />
            </span>

            <span className="profile-user-info">

              <span className="user-name">
                Admin
              </span>

              <span className="user-role">
                Super Admin
              </span>

            </span>

            <span className="profile-arrow">
              <LuChevronDown />
            </span>

          </button>


          {isProfileOpen && (
            <div className="profile-dropdown">

              <div className="profile-item">
                My Profile
              </div>

              <div className="profile-item">
                Settings
              </div>

              <div className="profile-item">
                Help
              </div>

              <hr />

              <div
                className="profile-item logout"
                onClick={logout}
              >
                Logout
              </div>

            </div>
          )}

        </div>

      </div>

    </header>
  );
};

export default DashboardHeader;