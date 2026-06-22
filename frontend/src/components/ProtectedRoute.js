import React from "react";
import { Navigate } from "react-router-dom";
import { getCookie } from "../api/api";
import Layout from "./Layout";

const ProtectedRoute = ({ element }) => {
  const token = getCookie("token");

  // If token exists, render the element wrapped in Layout, otherwise redirect to login
  return token ? <Layout>{element}</Layout> : <Navigate to="/login" replace />;
};

export default ProtectedRoute;
