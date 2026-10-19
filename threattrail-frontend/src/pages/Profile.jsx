import { useState, useEffect, useCallback } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import {
  User, Mail, Lock, Palette, Save, ArrowLeft,
  CheckCircle2, AlertTriangle, Shield, Trophy,
  Target, Zap, BookOpen, Star, TrendingUp, Clock,
  PlayCircle,
} from 'lucide-react'
import api from '../api'
import { useAuth } from '../context/AuthContext'

// Preset avatar colors
const AVATAR_COLORS = [
  '#3b82f6', '#8b5cf6', '#ec4899', '#f59e0b',
  '#10b981', '#ef4444', '#06b6d4', '#f97316',
  '#6366f1', '#84cc16', '#14b8a6', '#a855f7',
]

function AvatarCircle({ username, color, size = 64 }) {
  const initial = (username || '?').charAt(0).toUpperCase()
  return (
    <div
      style={{
        width: size,
        height: size,
        borderRadius: '50%',
        background: `linear-gradient(135deg, ${color || '#3b82f6'}, ${color ? color + 'cc' : '#8b5cf6'})`,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        fontSize: size * 0.42,
        fontWeight: 800,
        color: '#fff',
        boxShadow: `0 0 20px ${color || '#3b82f6'}55`,
        flexShrink: 0,
        letterSpacing: '-0.02em',
        border: `2px solid ${color || '#3b82f6'}66`,
      }}
    >
      {initial}
    </div>
  )
}

export default function Profile() {
  const navigate = useNavigate()
  const { user, logout } = useAuth()

  const [activeTab, setActiveTab] = useState('profile')

  // Profile fields
  const [username, setUsername] = useState(user?.username || '')
  const [email, setEmail] = useState(user?.email || '')
  const [avatarColor, setAvatarColor] = useState(user?.avatar_color || '#3b82f6')
  const [currentPassword, setCurrentPassword] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')

  // UI states
  const [saving, setSaving] = useState(false)
  const [msg, setMsg] = useState(null) // { type: 'success' | 'error', text: string }
  const [stats, setStats] = useState(null)
  const [activity, setActivity] = useState(null)
  const [loadingStats, setLoadingStats] = useState(false)

  const showMsg = (type, text) => {
    setMsg({ type, text })
    setTimeout(() => setMsg(null), 5000)
  }

  const loadStats = useCallback(async () => {
    setLoadingStats(true)
    try {
      const [statsRes, activityRes] = await Promise.all([
        api.get('/auth/profile/stats').catch(() => ({ data: null })),
        api.get('/profile/activity').catch(() => ({ data: null })),
      ])
      setStats(statsRes?.data || null)
      setActivity(activityRes?.data || null)
    } catch {
      // stats not critical
    } finally {
      setLoadingStats(false)
    }
  }, [])

  useEffect(() => {
    if (activeTab === 'activity') loadStats()
  }, [activeTab, loadStats])

  const handleSaveProfile = async (e) => {
    e.preventDefault()
    setSaving(true)
    setMsg(null)
    try {
      const payload = {}
      if (username.trim() !== (user?.username || '')) payload.username = username.trim()
      if (email.trim() !== (user?.email || '')) payload.email = email.trim()
      if (avatarColor !== (user?.avatar_color || '#3b82f6')) payload.avatar_color = avatarColor

      if (newPassword) {
        if (newPassword !== confirmPassword) {
          showMsg('error', 'New passwords do not match.')
          setSaving(false)
          return
        }
        if (newPassword.length < 4) {
          showMsg('error', 'New password must be at least 4 characters.')
          setSaving(false)
          return
        }
        payload.new_password = newPassword
        payload.current_password = currentPassword
      }

      if (Object.keys(payload).length === 0) {
        showMsg('error', 'No changes to save.')
        setSaving(false)
        return
      }

      const res = await api.patch('/auth/profile', payload)

      // Update localStorage user
      const stored = JSON.parse(localStorage.getItem('threattrail_user') || '{}')
      const updated = { ...stored, ...res.data }
      localStorage.setItem('threattrail_user', JSON.stringify(updated))

      setCurrentPassword('')
      setNewPassword('')
      setConfirmPassword('')
      showMsg('success', 'Profile updated successfully! You may need to sign back in if you changed your username.')
    } catch (err) {
      showMsg('error', err.response?.data?.detail || 'Failed to update profile.')
    } finally {
      setSaving(false)
    }
  }

  const rankStatus = (pts) => {
    if (pts >= 200) return { label: 'Principal SOC Lead', badge: '🏆', color: '#f3c25b' }
    if (pts >= 120) return { label: 'Senior Threat Hunter', badge: '🛡️', color: '#60a5fa' }
    if (pts >= 50) return { label: 'Incident Responder', badge: '🔍', color: '#34d399' }
    return { label: 'Junior Analyst', badge: '🔰', color: '#94a3b8' }
  }

  const rank = rankStatus(stats?.total_points || 0)

  return (
    <div className="profile-page">
      {/* ── Back Button ── */}
      <button
        className="back-btn"
        onClick={() => navigate(-1)}
        title="Go back to previous page"
      >
        <ArrowLeft size={16} />
        <span>Back</span>
      </button>

      {/* ── Profile Header ── */}
      <div className="profile-hero">
        <div className="profile-hero-avatar">
          <AvatarCircle username={username || user?.username} color={avatarColor} size={80} />
          <div className="profile-hero-info">
            <h2 className="profile-hero-name">{user?.username}</h2>
            <span className={`profile-role-tag ${user?.role === 'admin' ? 'role-admin' : 'role-analyst'}`}>
              {user?.role === 'admin' ? '🛡️ Administrator' : '🔍 SOC Analyst'}
            </span>
            {user?.email && (
              <span className="profile-hero-email">{user.email}</span>
            )}
          </div>
        </div>

        {stats && (
          <div className="profile-hero-stats">
            <div className="profile-stat-pill">
              <Trophy size={14} />
              <span>{stats.total_points} pts</span>
            </div>
            <div className="profile-stat-pill">
              <Target size={14} />
              <span>{stats.scenarios_completed} scenarios</span>
            </div>
            <div className="profile-stat-pill">
              <TrendingUp size={14} />
              <span>{stats.average_score}% avg</span>
            </div>
          </div>
        )}
      </div>

      {/* ── Tabs ── */}
      <div className="profile-tabs">
        {[
          { id: 'profile', label: 'Edit Profile', icon: <User size={14} /> },
          { id: 'security', label: 'Password', icon: <Lock size={14} /> },
          { id: 'appearance', label: 'Appearance', icon: <Palette size={14} /> },
          { id: 'activity', label: 'My Activity', icon: <BookOpen size={14} /> },
        ].map(tab => (
          <button
            key={tab.id}
            className={`profile-tab ${activeTab === tab.id ? 'profile-tab-active' : ''}`}
            onClick={() => setActiveTab(tab.id)}
          >
            {tab.icon}
            <span>{tab.label}</span>
          </button>
        ))}
      </div>

      {/* ── Message Banner ── */}
      {msg && (
        <div className={`profile-msg-banner ${msg.type === 'success' ? 'msg-success-banner' : 'msg-error-banner'}`}>
          {msg.type === 'success' ? <CheckCircle2 size={15} /> : <AlertTriangle size={15} />}
          <span>{msg.text}</span>
        </div>
      )}

      {/* ── Tab: Edit Profile ── */}
      {activeTab === 'profile' && (
        <form className="profile-card" onSubmit={handleSaveProfile}>
          <h3 className="profile-card-title">
            <User size={16} />
            Personal Information
          </h3>
          <p className="profile-card-desc">Update your display name and email address.</p>

          <div className="profile-field-group">
            <label className="profile-label">Username</label>
            <div className="profile-input-wrap">
              <User size={14} className="profile-input-icon" />
              <input
                type="text"
                className="profile-input"
                value={username}
                onChange={e => setUsername(e.target.value)}
                placeholder="Your username"
                minLength={3}
              />
            </div>
            <span className="profile-hint">Min 3 characters. Letters, numbers, hyphens, dots only.</span>
          </div>

          <div className="profile-field-group">
            <label className="profile-label">Email Address</label>
            <div className="profile-input-wrap">
              <Mail size={14} className="profile-input-icon" />
              <input
                type="email"
                className="profile-input"
                value={email}
                onChange={e => setEmail(e.target.value)}
                placeholder="your@email.com (optional)"
              />
            </div>
            <span className="profile-hint">Used for account identification only. Not shared publicly.</span>
          </div>

          <div className="profile-actions-row">
            <button type="submit" className="btn-profile-save" disabled={saving}>
              {saving ? (
                <><span className="inv-spinner" style={{ width: 14, height: 14 }} />Saving...</>
              ) : (
                <><Save size={14} />Save Profile</>
              )}
            </button>
          </div>
        </form>
      )}

      {/* ── Tab: Password / Security ── */}
      {activeTab === 'security' && (
        <form className="profile-card" onSubmit={handleSaveProfile}>
          <h3 className="profile-card-title">
            <Lock size={16} />
            Change Password
          </h3>
          <p className="profile-card-desc">Set a new password. You'll need to enter your current one to confirm.</p>

          <div className="profile-field-group">
            <label className="profile-label">Current Password</label>
            <div className="profile-input-wrap">
              <Lock size={14} className="profile-input-icon" />
              <input
                type="password"
                className="profile-input"
                value={currentPassword}
                onChange={e => setCurrentPassword(e.target.value)}
                placeholder="Enter current password"
              />
            </div>
          </div>

          <div className="profile-field-group">
            <label className="profile-label">New Password</label>
            <div className="profile-input-wrap">
              <Lock size={14} className="profile-input-icon" />
              <input
                type="password"
                className="profile-input"
                value={newPassword}
                onChange={e => setNewPassword(e.target.value)}
                placeholder="New password (min 4 characters)"
                minLength={4}
              />
            </div>
          </div>

          <div className="profile-field-group">
            <label className="profile-label">Confirm New Password</label>
            <div className="profile-input-wrap">
              <Lock size={14} className="profile-input-icon" />
              <input
                type="password"
                className="profile-input"
                value={confirmPassword}
                onChange={e => setConfirmPassword(e.target.value)}
                placeholder="Repeat new password"
              />
            </div>
            {newPassword && confirmPassword && newPassword !== confirmPassword && (
              <span className="profile-hint profile-hint-error">Passwords do not match.</span>
            )}
          </div>

          <div className="profile-actions-row">
            <button
              type="submit"
              className="btn-profile-save"
              disabled={saving || !currentPassword || !newPassword || newPassword !== confirmPassword}
            >
              {saving ? (
                <><span className="inv-spinner" style={{ width: 14, height: 14 }} />Saving...</>
              ) : (
                <><Save size={14} />Update Password</>
              )}
            </button>
          </div>
        </form>
      )}

      {/* ── Tab: Appearance (Avatar Color) ── */}
      {activeTab === 'appearance' && (
        <form className="profile-card" onSubmit={handleSaveProfile}>
          <h3 className="profile-card-title">
            <Palette size={16} />
            Avatar Appearance
          </h3>
          <p className="profile-card-desc">Pick an accent color for your profile avatar displayed across the platform.</p>

          {/* Live Preview */}
          <div className="avatar-preview-row">
            <AvatarCircle username={username || user?.username} color={avatarColor} size={72} />
            <div>
              <div className="avatar-preview-name">{username || user?.username}</div>
              <div className="avatar-preview-sub">Preview of your avatar</div>
              <div className="avatar-color-hex">{avatarColor}</div>
            </div>
          </div>

          {/* Color Grid */}
          <div className="avatar-color-grid">
            {AVATAR_COLORS.map(c => (
              <button
                key={c}
                type="button"
                className={`avatar-color-swatch ${avatarColor === c ? 'swatch-selected' : ''}`}
                style={{ background: c, boxShadow: avatarColor === c ? `0 0 0 3px #fff, 0 0 0 5px ${c}` : 'none' }}
                onClick={() => setAvatarColor(c)}
                title={c}
              />
            ))}
          </div>

          {/* Custom hex input */}
          <div className="profile-field-group" style={{ marginTop: '16px' }}>
            <label className="profile-label">Custom Hex Color</label>
            <div className="profile-input-wrap">
              <div style={{ width: 14, height: 14, borderRadius: 3, background: avatarColor, flexShrink: 0 }} />
              <input
                type="text"
                className="profile-input"
                value={avatarColor}
                onChange={e => {
                  const v = e.target.value
                  if (/^#[0-9A-Fa-f]{0,6}$/.test(v)) setAvatarColor(v)
                }}
                placeholder="#3b82f6"
                maxLength={7}
              />
            </div>
          </div>

          <div className="profile-actions-row">
            <button type="submit" className="btn-profile-save" disabled={saving}>
              {saving ? (
                <><span className="inv-spinner" style={{ width: 14, height: 14 }} />Saving...</>
              ) : (
                <><Save size={14} />Save Appearance</>
              )}
            </button>
          </div>
        </form>
      )}

      {/* ── Tab: Activity Stats ── */}
      {activeTab === 'activity' && (
        <div className="profile-card">
          <h3 className="profile-card-title">
            <Star size={16} />
            Investigation History & Stats
          </h3>

          {loadingStats ? (
            <div className="db-loading" style={{ minHeight: '20vh' }}>
              <div className="db-loading-spinner" />
              <span>Loading your stats...</span>
            </div>
          ) : stats ? (
            <>
              {/* Rank Banner */}
              <div className="profile-rank-banner" style={{ borderColor: `${rank.color}55`, background: `${rank.color}0e` }}>
                <span style={{ fontSize: '2rem' }}>{rank.badge}</span>
                <div>
                  <div className="profile-rank-label" style={{ color: rank.color }}>
                    {rank.label} {stats.rank ? `• Leaderboard Rank #${stats.rank}` : ''}
                  </div>
                  <div className="profile-rank-sub">{stats.total_points} total points earned</div>
                </div>
              </div>

              {/* Stats Grid */}
              <div className="profile-stats-grid">
                {[
                  {
                    label: 'Total Attempts',
                    value: stats.total_attempts ?? ((stats.total_trials || 0) + (activity?.active_wrong_guesses || 0)),
                    icon: <BookOpen size={15} />,
                    color: '#60a5fa',
                  },
                  {
                    label: 'Scenarios Done',
                    value: stats.scenarios_completed,
                    icon: <Target size={15} />,
                    color: '#34d399',
                  },
                  {
                    label: 'Leaderboard Rank',
                    value: stats.rank ? `#${stats.rank}` : 'Unranked',
                    icon: <Trophy size={15} />,
                    color: '#f3c25b',
                  },
                  {
                    label: 'Total Points',
                    value: stats.total_points,
                    icon: <Star size={15} />,
                    color: '#f59e0b',
                  },
                  {
                    label: 'Average Score',
                    value: `${stats.average_score}%`,
                    icon: <TrendingUp size={15} />,
                    color: '#a78bfa',
                  },
                  {
                    label: 'Hints Used',
                    value: stats.hints_used,
                    icon: <Zap size={15} />,
                    color: '#fb923c',
                  },
                ].map((s, i) => (
                  <div key={i} className="profile-stat-card" style={{ borderColor: `${s.color}33` }}>
                    <div className="profile-stat-icon" style={{ color: s.color }}>{s.icon}</div>
                    <div className="profile-stat-value" style={{ color: s.color }}>{s.value}</div>
                    <div className="profile-stat-label">{s.label}</div>
                  </div>
                ))}
              </div>

              {/* Active In-Progress Investigations */}
              {activity?.in_progress && activity.in_progress.length > 0 && (
                <div className="profile-recent-section" style={{ marginBottom: 20 }}>
                  <h4 className="profile-recent-title" style={{ color: '#f59e0b' }}>
                    <Zap size={14} />
                    Active In-Progress Investigations ({activity.in_progress.length})
                  </h4>
                  <div className="profile-recent-list">
                    {activity.in_progress.map((item, idx) => (
                      <div key={idx} className="profile-recent-item" style={{ borderColor: 'rgba(245, 158, 11, 0.35)', background: 'rgba(245, 158, 11, 0.04)' }}>
                        <div className="profile-recent-left">
                          <Shield size={14} style={{ color: '#f59e0b' }} />
                          <div>
                            <span className="profile-recent-name">{item.scenario_name}</span>
                            <div style={{ fontSize: '0.75rem', color: '#94a3b8', marginTop: 2 }}>
                              {item.wrong_attempts > 0 ? `${item.wrong_attempts} verification attempts • ` : ''}
                              {item.hints_used > 0 ? `${item.hints_used} hint(s) unlocked • ` : ''}
                              {item.solved_questions > 0 ? `${item.solved_questions}/${item.total_questions} solved` : 'Active session'}
                            </div>
                          </div>
                        </div>
                        <div className="profile-recent-right">
                          <Link to={`/investigate/${item.scenario_id}`} className="btn-sm btn-primary" style={{ display: 'inline-flex', alignItems: 'center', gap: 6, textDecoration: 'none' }}>
                            <PlayCircle size={13} />
                            Resume Investigation →
                          </Link>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Recent Activity & Trial History */}
              {(activity?.history?.length > 0 || stats.recent_activity?.length > 0) && (
                <div className="profile-recent-section">
                  <h4 className="profile-recent-title">
                    <Clock size={14} />
                    Investigation Activity & Trial History
                  </h4>
                  <div className="profile-recent-list">
                    {(activity?.history || stats.recent_activity).map((r, i) => (
                      <div key={i} className="profile-recent-item">
                        <div className="profile-recent-left">
                          <Shield size={13} style={{ color: '#60a5fa' }} />
                          <div>
                            <span className="profile-recent-name">{r.scenario_name}</span>
                            {r.trial_number && (
                              <span style={{ marginLeft: 8, fontSize: '0.72rem', background: '#334155', color: '#94a3b8', padding: '1px 6px', borderRadius: 4 }}>
                                Trial #{r.trial_number}
                              </span>
                            )}
                          </div>
                        </div>
                        <div className="profile-recent-right">
                          <span className={`profile-score-pill ${r.score >= 80 ? 'score-great' : r.score >= 60 ? 'score-ok' : 'score-low'}`}>
                            {r.score}%
                          </span>
                          <span className="profile-pts-tag">+{r.points_earned} pts</span>
                          <Link to={`/investigate/${r.scenario_id}`} className="profile-retry-link">
                            Re-try →
                          </Link>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {stats.total_investigations === 0 && (!activity?.in_progress || activity.in_progress.length === 0) && (
                <div style={{ textAlign: 'center', padding: '40px 0', color: 'var(--text-dim)' }}>
                  <Target size={36} style={{ marginBottom: 12, opacity: 0.4 }} />
                  <div>No investigations completed yet. Start your first scenario!</div>
                  <Link to="/" className="btn btn-primary" style={{ marginTop: 16, display: 'inline-block' }}>
                    Browse Scenarios →
                  </Link>
                </div>
              )}
            </>
          ) : (
            <p style={{ color: 'var(--text-dim)', textAlign: 'center', padding: '40px 0' }}>
              Unable to load stats. Please try again.
            </p>
          )}
        </div>
      )}
    </div>
  )
}
