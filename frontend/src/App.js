import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import logo from "./logo.svg";
import "./App.css";
import Login from "./Login/Login";
import Register from "./Register/Register";
import Dashboard from "./Dashboard/Dashboard";
import ForgotPage from "./ForgotPage/forgot-page";
import EnterOtp from "./EnterOtp/EnterOtp";
import ScanQR from "./ScanQR/ScanQR";
import VerifyOtp from "./VerifyOtp/VerifyOtp";
import InstallationProcess from "./InstallationProcess/InstallationProcess";
import AgentDetails from "./Dashboard/AgentDashboard/AgentDetails";
import ProtectedRoute from "./components/ProtectedRoute";
import { LoadingProvider } from "./context/LoadingContext";
import Loader from "./components/Loader/Loader";
import { useEffect, useState } from "react";
import { registerLoaderCallbacks } from "./api/api";
import AgentCardGrid from "./Dashboard/AgentDashboard/AgentCardGrid";
import SOC2Report from "./Reports/SOC2Report";
import CapacityDashboard1 from "./Reports/CapacityDashboard1";
import { AccessProvider } from "./Access/AccessContext";
import AccessManagement from "./Access/AccessManagement";
import CapacityDashboard from "./Reports/CapacityDashboard";
import Unauthorized from "./pages/Unauthorized/Unauthorized";
import Messaging from "./Messaging/Messaging";
import ChannelsManager from "./Channels/ChannelsManager";

function AppContent() {
  const [isLoading, setIsLoading] = useState(false);

  useEffect(() => {
    // Register the loader callbacks with the API
    registerLoaderCallbacks(
      () => setIsLoading(true),
      () => setIsLoading(false),
    );
  }, []);

  return (
    <div className="App">
      <Loader isVisible={isLoading} />
      <BrowserRouter>
        <Routes>
          {/* Root → send users into the /app-prefixed app */}
          <Route path="/" element={<Navigate to="/app/login" replace />} />

          {/* Public Routes - No authentication required */}
          <Route path="/app" element={<Login />} />
          <Route path="/app/login" element={<Login />} />
          <Route path="/app/register" element={<Register />} />
          <Route path="/app/forgot-password" element={<ForgotPage />} />
          <Route path="/app/enter-otp" element={<EnterOtp />} />
          <Route path="/app/scan-qr" element={<ScanQR />} />
          <Route path="/app/verify-otp" element={<VerifyOtp />} />
          {/* 403 — full-screen, no app chrome; the guard redirects here */}
          <Route path="/app/unauthorized" element={<Unauthorized />} />

          {/* Protected Routes - Authentication required */}
          <Route
            path="/app/dashboard"
            element={<ProtectedRoute element={<Dashboard />} />}
          />
          <Route
            path="/app/installation"
            element={<ProtectedRoute element={<InstallationProcess />} />}
          />
          <Route
            path="/app/agentDetailsCard"
            element={<ProtectedRoute element={<AgentCardGrid />} />}
          />
          <Route
            path="/app/reports/soc2"
            element={<ProtectedRoute element={<SOC2Report />} />}
          />
          <Route
            path="/app/reports/capacity1"
            element={<ProtectedRoute element={<CapacityDashboard />} />}
          />
          <Route
            path="/app/reports/capacity"
            element={<ProtectedRoute element={<CapacityDashboard />} />}
          />
          {/* RBAC — self-contained, uses its own sign-in / role gate */}
          <Route path="/app/access"     element={<ProtectedRoute element={<AccessManagement />} />} />

          {/* Messaging / Notifications — frontend-only broadcast composer */}
          <Route path="/app/messages1"   element={<ProtectedRoute element={<Messaging />} />} />

          {/* Channels — register/manage notification destinations */}
          <Route path="/app/messages"   element={<ProtectedRoute element={<ChannelsManager />} />} />

          {/*
            Role-based protection examples (ProtectedRoute now accepts `roles`
            and `perm`; omit both for an auth-only route as above):

              // only Admin (super_admin) or Manager (admin) may enter:
              <Route
                path="/reports/capacity"
                element={
                  <ProtectedRoute roles={["super_admin", "admin"]} element={<CapacityDashboard />} />
                }
              />

              // require a specific permission action instead of a role:
              <Route
                path="/access"
                element={<ProtectedRoute perm="manageUsers" element={<AccessManagement />} />}
              />

            Not signed in        -> /login (the attempted route is remembered).
            Signed in, no access -> /unauthorized (the 403 page).
          */}
          <Route
            path="/app/agentDetails"
            element={
              <ProtectedRoute
                element={
                  <AgentDetails
                    agentId="agent_test_001"
                    agentName="TestAgent"
                  />
                }
              />
            }
          />
        </Routes>
      </BrowserRouter>
    </div>
  );
}

function App() {
  return (
    <LoadingProvider>
      <AccessProvider>
        <AppContent />
      </AccessProvider>
    </LoadingProvider>
  );
}

export default App;
