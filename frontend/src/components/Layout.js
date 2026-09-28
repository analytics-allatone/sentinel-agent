// import React, { useState } from "react";
// import Header from "../DashboardHeader/dashboard-Header";
// import Sidebar from "../Sidebar/Sidebar";
// import "./Layout.css";

// const Layout = ({ children }) => {
//   const [sidebarOpen, setSidebarOpen] = useState(false);

//   return (
//     <div className="layout">
//       <Header onMenuToggle={() => setSidebarOpen(!sidebarOpen)} />
//       <Sidebar isOpen={sidebarOpen} onClose={() => setSidebarOpen(false)} />
//       <div className="layout-content">{children}</div>
//     </div>
//   );
// };

// export default Layout;

import React, { useEffect, useState } from "react";
import Header from "../DashboardHeader/dashboard-Header";
import Sidebar from "../Sidebar/Sidebar";
import "./Layout.css";

const Layout = ({ children }) => {
  /**
   * On a wide screen the sidebar is a column of the page, so it starts open;
   * below the 987px breakpoint it is a drawer, so it starts closed. It used
   * to start closed everywhere, which left the navigation invisible until
   * someone went looking for it.
   */
  const [sidebarOpen, setSidebarOpen] = useState(
    () => typeof window === "undefined" || window.innerWidth > 987
  );

  // Crossing the breakpoint changes what the sidebar *is*, so it follows.
  useEffect(() => {
    if (!window.matchMedia) return undefined;

    const wide = window.matchMedia("(min-width: 988px)");
    const onChange = (event) => setSidebarOpen(event.matches);

    if (wide.addEventListener) wide.addEventListener("change", onChange);
    else wide.addListener(onChange);

    return () => {
      if (wide.removeEventListener) wide.removeEventListener("change", onChange);
      else wide.removeListener(onChange);
    };
  }, []);

  const toggleSidebar = () => {
    setSidebarOpen((prev) => !prev);
  };

  const closeSidebar = () => {
    setSidebarOpen(false);
  };

  return (
  <div
    className={`layout ${
      sidebarOpen ? "sidebar-open" : "sidebar-closed"
    }`}
  >
    {/* The first stop for a keyboard: straight past the chrome. */}
    <a className="phi-skip" href="#main-content">
      Skip to content
    </a>

    <Header
      onMenuToggle={toggleSidebar}
      sidebarOpen={sidebarOpen}
    />

    <Sidebar
      isOpen={sidebarOpen}
      onClose={closeSidebar}
    />

    <main className="layout-main" id="main-content" tabIndex={-1}>
      <div className="layout-content">
        {children}
      </div>
    </main>
  </div>
);
};

export default Layout;
