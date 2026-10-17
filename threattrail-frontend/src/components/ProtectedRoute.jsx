import { Navigate, useLocation } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'

export default function ProtectedRoute({ children }) {
  const { user, loading } = useAuth()
  const location = useLocation()

  if (loading) {
    return (
      <div className="db-loading">
        <div className="db-loading-spinner" />
        <span>Authenticating session…</span>
      </div>
    )
  }

  if (!user) {
    // Preserve intended destination so user is returned after login
    return <Navigate to="/login" state={{ from: location }} replace />
  }

  return children
}
