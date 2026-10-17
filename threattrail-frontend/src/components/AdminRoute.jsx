import { Navigate, useLocation, Link } from 'react-router-dom'
import { ShieldAlert, ArrowLeft, KeyRound } from 'lucide-react'
import { useAuth } from '../context/AuthContext'

export default function AdminRoute({ children }) {
  const { user, loading, isAdmin } = useAuth()
  const location = useLocation()

  if (loading) {
    return (
      <div className="db-loading">
        <div className="db-loading-spinner" />
        <span>Verifying administrative authorization…</span>
      </div>
    )
  }

  // Not logged in at all -> redirect to admin login
  if (!user) {
    return <Navigate to="/admin/login" state={{ from: location }} replace />
  }

  // Logged in, but not an admin -> show Access Denied warning
  if (!isAdmin) {
    return (
      <div className="auth-access-denied-container">
        <div className="auth-access-denied-card">
          <div className="access-denied-icon">
            <ShieldAlert size={48} color="#ef4444" />
          </div>
          <span className="access-denied-badge">RESTRICTED CONSOLE</span>
          <h2>403 — Administrator Clearance Required</h2>
          <p>
            You are currently signed in as analyst <strong className="user-highlight">{user.username}</strong> (Role: <span className="role-tag">{user.role}</span>).
            Access to the SOC Management Console, Scenario Builder, and Log Ingest is restricted to administrator accounts only.
          </p>
          <div className="access-denied-actions">
            <Link to="/" className="btn btn-primary">
              <ArrowLeft size={14} style={{ display: 'inline', marginRight: 4, verticalAlign: 'middle' }} />
              Return to Dashboard
            </Link>
            <Link to="/admin/login" className="btn btn-secondary">
              <KeyRound size={14} style={{ display: 'inline', marginRight: 4, verticalAlign: 'middle' }} />
              Sign In as Admin
            </Link>
          </div>
        </div>
      </div>
    )
  }

  // User is admin
  return children
}
