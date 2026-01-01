import { Navigate, Outlet } from "react-router-dom";
import { useAuth } from "../context/AuthContext";

const Protected = ({ allowedRoles }) => {
  const { auth, loading } = useAuth();

  if (loading) return null;

  if (!auth?.user) {
    return <Navigate to="/login" replace />;
  }

  if (
    allowedRoles &&
    !allowedRoles.includes(auth.user.role)
  ) {
    return <Navigate to="/unauthorized" replace />;
  }

  return <Outlet />;
};

export default Protected;
