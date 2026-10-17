import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import {
  User,
  Lock,
  KeyRound,
  Eye,
  EyeOff,
  AlertTriangle,
  ArrowRight,
  Check,
  X,
} from 'lucide-react'
import { useAuth } from '../context/AuthContext'

export default function Register() {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [error, setError] = useState(null)
  const [loading, setLoading] = useState(false)

  const { register } = useAuth()
  const navigate = useNavigate()

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError(null)

    if (username.trim().length < 3) {
      setError('Username must be at least 3 characters long')
      return
    }

    if (password.length < 8) {
      setError('Password must be at least 8 characters long')
      return
    }

    if (!/[A-Za-z]/.test(password) || !/[0-9!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]/.test(password)) {
      setError('Password must contain at least one letter and one number or special character')
      return
    }

    if (password !== confirmPassword) {
      setError('Passwords do not match')
      return
    }

    setLoading(true)
    try {
      await register(username.trim(), password)
      navigate('/', { replace: true })
    } catch (err) {
      const rawDetail = err.response?.data?.detail
      let msg = 'Registration failed'
      if (typeof rawDetail === 'string') {
        msg = rawDetail
      } else if (Array.isArray(rawDetail)) {
        msg = rawDetail
          .map((d) => (typeof d === 'string' ? d : d.msg || d.detail || JSON.stringify(d)))
          .join(', ')
      } else if (rawDetail && typeof rawDetail === 'object') {
        msg = rawDetail.msg || rawDetail.detail || JSON.stringify(rawDetail)
      } else if (err.message) {
        msg = err.message
      }
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
          <div className="auth-badge auth-badge-green">
            <span className="auth-badge-dot dot-green" />
            New Analyst Onboarding
          </div>
          <h2 className="auth-title">Create Analyst Account</h2>
          <p className="auth-sub">Enroll as a security investigator to train on live attack forensic artifacts.</p>
        </div>

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
            <label htmlFor="reg-username">Analyst Handle / Username</label>
            <div className="auth-input-wrapper">
              <span className="auth-input-icon">
                <User size={15} />
              </span>
              <input
                id="reg-username"
                type="text"
                required
                placeholder="Choose a username (min 3 chars)"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                className="auth-input"
                autoComplete="username"
              />
            </div>
            <span className="auth-field-hint">Letters, numbers, underscores, or hyphens</span>
          </div>

          <div className="auth-form-field">
            <label htmlFor="reg-password">Password</label>
            <div className="auth-input-wrapper">
              <span className="auth-input-icon">
                <Lock size={15} />
              </span>
              <input
                id="reg-password"
                type={showPassword ? 'text' : 'password'}
                required
                placeholder="Enter password (min 8 chars)"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="auth-input"
                autoComplete="new-password"
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
            <span className="auth-field-hint">Min 8 characters (letters + numbers or symbols)</span>
          </div>

          <div className="auth-form-field">
            <label htmlFor="reg-confirm-password">Confirm Password</label>
            <div className="auth-input-wrapper">
              <span className="auth-input-icon">
                <KeyRound size={15} />
              </span>
              <input
                id="reg-confirm-password"
                type={showPassword ? 'text' : 'password'}
                required
                placeholder="Repeat your password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                className="auth-input"
                autoComplete="new-password"
              />
            </div>
            {password && confirmPassword && (
              <span className={`auth-field-hint ${password === confirmPassword ? 'hint-success' : 'hint-error'}`}>
                {password === confirmPassword ? (
                  <><Check size={12} style={{ display: 'inline', marginRight: 4, verticalAlign: 'middle' }} /> Passwords match</>
                ) : (
                  <><X size={12} style={{ display: 'inline', marginRight: 4, verticalAlign: 'middle' }} /> Passwords do not match</>
                )}
              </span>
            )}
          </div>

          <button
            type="submit"
            disabled={loading}
            className="auth-submit-btn auth-submit-register"
          >
            {loading ? (
              <>
                <span className="auth-spinner" />
                <span>Creating Account…</span>
              </>
            ) : (
              <>
                <span>Complete Registration</span>
                <ArrowRight size={15} className="auth-btn-arrow" />
              </>
            )}
          </button>
        </form>

        {/* Card Footer Links */}
        <div className="auth-card-footer">
          <p className="auth-switch-text">
            Already have an analyst account?{' '}
            <Link to="/login" className="auth-switch-link">
              Sign In here →
            </Link>
          </p>
        </div>
      </div>
    </div>
  )
}
