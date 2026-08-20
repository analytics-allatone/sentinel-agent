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

import React, { useState } from "react";
import Header from "../DashboardHeader/dashboard-Header";
import Sidebar from "../Sidebar/Sidebar";
import "./Layout.css";

const Layout = ({ children }) => {
  const [sidebarOpen, setSidebarOpen] = useState(true);

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
    <Header
      onMenuToggle={toggleSidebar}
      sidebarOpen={sidebarOpen}
    />

    <Sidebar
      isOpen={sidebarOpen}
      onClose={closeSidebar}
    />

    <main className="layout-main">
      <div className="layout-content">
        {children}
      </div>
    </main>
  </div>
);
};

export default Layout;
