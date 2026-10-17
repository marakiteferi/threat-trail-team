import { useState } from 'react'
import { Link, useNavigate, useLocation } from 'react-router-dom'
import {
  ShieldAlert,
  Key,
  Eye,
  EyeOff,
  AlertOctagon,
  AlertTriangle,
  ArrowRight,
  ArrowLeft,
} from 'lucide-react'
import { useAuth } from '../context/AuthContext'

export default function AdminLogin() {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [error, setError] = useState(null)
  const [loading, setLoading] = useState(false)

  const { adminLogin } = useAuth()
  const navigate = useNavigate()
  const location = useLocation()
  const from = location.state?.from?.pathname || '/admin'

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError(null)
    setLoading(true)

    try {
      await adminLogin(username, password)
      navigate(from, { replace: true })
    } catch (err) {
      const raw = err.response?.data?.detail
      let msg = 'Administrative login rejected'
      if (typeof raw === 'string') msg = raw
      else if (Array.isArray(raw)) msg = raw.map(e => e.msg || e.detail || JSON.stringify(e)).join(', ')
      else if (err.message) msg = err.message
      setError(msg)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="auth-page auth-page-admin">
      <div className="auth-card auth-card-admin">
        {/* Card Header */}
        <div className="auth-card-header">
          <div className="auth-badge auth-badge-admin">
            <span className="auth-badge-dot dot-red" />
            <ShieldAlert size={12} style={{ marginRight: 2 }} />
            Level 5 Clearance — Administrator Only
          </div>
          <h2 className="auth-title auth-title-admin">
            Command Console <span className="auth-admin-tag">ADMIN</span>
          </h2>
          <p className="auth-sub">
            Authentication portal for SOC Managers and Instructors to manage scenarios, ingest raw event artifacts, and oversee training telemetry.
          </p>
        </div>

        {/* Error Alert */}
        {error && (
          <div className="auth-error-alert auth-error-admin">
            <AlertOctagon size={16} className="auth-error-icon" />
            <span>{error}</span>
          </div>
        )}

        {/* Form */}
        <form onSubmit={handleSubmit} className="auth-form">
          <div className="auth-form-field">
            <label htmlFor="admin-username">Administrator Account</label>
            <div className="auth-input-wrapper">
              <span className="auth-input-icon">
                <ShieldAlert size={15} />
              </span>
              <input
                id="admin-username"
                type="text"
                required
                placeholder="e.g. admin"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                className="auth-input auth-input-admin"
                autoComplete="username"
              />
            </div>
          </div>

          <div className="auth-form-field">
            <label htmlFor="admin-password">Clearance Key / Password</label>
            <div className="auth-input-wrapper">
              <span className="auth-input-icon">
                <Key size={15} />
              </span>
              <input
                id="admin-password"
                type={showPassword ? 'text' : 'password'}
                required
                placeholder="Enter admin password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="auth-input auth-input-admin"
                autoComplete="current-password"
              />
              <button
                type="button"
                className="auth-toggle-pwd"
                onClick={() => setShowPassword(!showPassword)}
                tabIndex={-1}
                aria-label={showPassword ? 'Hide password' : 'Show password'}
              >
                {showPassword ? <EyeOff size={15} /> : <Eye size={15} />}
              </button>
            </div>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="auth-submit-btn auth-submit-admin"
          >
            {loading ? (
              <>
                <span className="auth-spinner" />
                <span>Verifying Administrator Credentials…</span>
              </>
            ) : (
              <>
                <span>Enter Admin Console</span>
                <ArrowRight size={15} className="auth-btn-arrow" />
              </>
            )}
          </button>
        </form>

        {/* Card Footer Links */}
        <div className="auth-card-footer">
          <div className="auth-admin-note">
            <AlertTriangle size={13} style={{ display: 'inline', marginRight: 4, verticalAlign: 'middle', color: '#f87171' }} />
            <em>Notice: Standard analyst accounts cannot authenticate here. If you are a trainee or SOC analyst, please use the analyst portal.</em>
          </div>

          <div className="auth-back-analyst-row">
            <Link to="/login" className="auth-back-link">
              <ArrowLeft size={13} style={{ display: 'inline', marginRight: 4, verticalAlign: 'middle' }} />
              Return to Analyst Portal
            </Link>
          </div>
        </div>
      </div>
    </div>
  )
}
