import { useState } from 'react'
import { Link, useNavigate, useLocation } from 'react-router-dom'
import {
  User,
  Lock,
  Eye,
  EyeOff,
  AlertTriangle,
  ArrowRight,
} from 'lucide-react'
import { useAuth } from '../context/AuthContext'

export default function Login() {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [error, setError] = useState(null)
  const [loading, setLoading] = useState(false)

  const { login, logout } = useAuth()
  const navigate = useNavigate()
  const location = useLocation()
  const from = location.state?.from?.pathname || '/'

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError(null)
    setLoading(true)

    try {
      const loggedInUser = await login(username, password)
      if (loggedInUser?.role === 'admin') {
        logout()
        setError('Administrator account detected. Please authenticate via the Admin Console at /admin/login.')
        return
      }
      navigate(from, { replace: true })
    } catch (err) {
      const raw = err.response?.data?.detail
      let msg = 'Failed to authenticate'
      if (typeof raw === 'string') msg = raw
      else if (Array.isArray(raw)) msg = raw.map(e => e.msg || e.detail || JSON.stringify(e)).join(', ')
      else if (err.message) msg = err.message
      setError(msg)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="auth-page">
      <div className="auth-card">
        {/* Card Header */}
        <div className="auth-card-header">
          <div className="auth-badge auth-badge-user">
            <span className="auth-badge-dot" />
            SOC Analyst Portal
          </div>
          <h2 className="auth-title">Analyst Authentication</h2>
          <p className="auth-sub">Sign in to access assigned attack scenarios, event telemetry, and investigation challenges.</p>
        </div>

        {/* Auth prompt banner if redirected from an investigation attempt */}
        {location.state?.from && (
          <div className="auth-notice-banner">
            <Lock size={15} className="notice-icon" />
            <span>Authentication required to investigate scenarios. Please sign in to continue.</span>
          </div>
        )}

        {/* Error Alert */}
        {error && (
          <div className="auth-error-alert">
            <AlertTriangle size={15} className="auth-error-icon" />
            <span>{error}</span>
          </div>
        )}

        {/* Form */}
        <form onSubmit={handleSubmit} className="auth-form">
          <div className="auth-form-field">
            <label htmlFor="login-username">Analyst Handle / Username</label>
            <div className="auth-input-wrapper">
              <span className="auth-input-icon">
                <User size={15} />
              </span>
              <input
                id="login-username"
                type="text"
                required
                placeholder="e.g. analyst"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                className="auth-input"
                autoComplete="username"
              />
            </div>
          </div>

          <div className="auth-form-field">
            <div className="auth-label-row">
              <label htmlFor="login-password">Password</label>
            </div>
            <div className="auth-input-wrapper">
              <span className="auth-input-icon">
                <Lock size={15} />
              </span>
              <input
                id="login-password"
                type={showPassword ? 'text' : 'password'}
                required
                placeholder="Enter password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="auth-input"
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
            className="auth-submit-btn auth-submit-user"
          >
            {loading ? (
              <>
                <span className="auth-spinner" />
                <span>Authenticating…</span>
              </>
            ) : (
              <>
                <span>Sign In as Analyst</span>
                <ArrowRight size={15} className="auth-btn-arrow" />
              </>
            )}
          </button>
        </form>

        {/* Card Footer Links */}
        <div className="auth-card-footer">
          <p className="auth-switch-text">
            New to ThreatTrail?{' '}
            <Link to="/register" className="auth-switch-link">
              Register analyst account →
            </Link>
          </p>
        </div>
      </div>
    </div>
  )
}
