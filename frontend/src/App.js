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
      <AppContent />
    </LoadingProvider>
  );
}

export default App;
