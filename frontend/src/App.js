import { BrowserRouter, Routes, Route } from "react-router-dom";
import logo from "./logo.svg";
import "./App.css";
import Login from "./Login/Login";
import Register from "./Register/Register";
import Dashboard from "./Dashboard/Dashboard";
import ForgotPage from "./ForgotPage/forgot-page";
import InstallationProcess from "./InstallationProcess/InstallationProcess";
import AgentDetails from "./Dashboard/AgentDashboard/AgentDetails";
import ProtectedRoute from "./components/ProtectedRoute";
import { LoadingProvider } from "./context/LoadingContext";
import Loader from "./components/Loader/Loader";
import { useEffect, useState } from "react";
import { registerLoaderCallbacks } from "./api/api";
import AgentCardGrid from "./Dashboard/AgentDashboard/AgentCardGrid";
import SOC2Report from "./Reports/SOC2Report";
import CapacityDashboard from "./Reports/CapacityDashboard";
import { AccessProvider } from "./Access/AccessContext";
import AccessManagement from "./Access/AccessManagement";
import CapacityDashboard1 from "./Reports/CapacityDashboard1";

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
          {/* Public Routes - No authentication required */}
          <Route path="/" element={<Login />} />
          <Route path="/login" element={<Login />} />
          <Route path="/register" element={<Register />} />
          <Route path="/forgot-password" element={<ForgotPage />} />

          {/* Protected Routes - Authentication required */}
          <Route
            path="/dashboard"
            element={<ProtectedRoute element={<Dashboard />} />}
          />
          <Route
            path="/installation"
            element={<ProtectedRoute element={<InstallationProcess />} />}
          />
          <Route
            path="/agentDetailsCard"
            element={<ProtectedRoute element={<AgentCardGrid />} />}
          />
          <Route
            path="/reports/soc2"
            element={<ProtectedRoute element={<SOC2Report />} />}
          />
          <Route
            path="/reports/capacity"
            element={<ProtectedRoute element={<CapacityDashboard />} />}
          />
          <Route
            path="/reports/capacity1"
            element={<ProtectedRoute element={<CapacityDashboard1 />} />}
          />
          {/* RBAC — self-contained, uses its own sign-in / role gate */}
          <Route path="/access"     element={<ProtectedRoute element={<AccessManagement />} />} />
          <Route
            path="/agentDetails"
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
