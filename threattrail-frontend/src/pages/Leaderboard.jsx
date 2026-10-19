import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import {
  Trophy,
  Medal,
  Award,
  Search,
  Shield,
  ShieldCheck,
  User,
  Zap,
  HelpCircle,
  Activity,
  ArrowLeft,
  ChevronRight,
  TrendingUp,
} from 'lucide-react'
import api from '../api'
import { useAuth } from '../context/AuthContext'

export default function Leaderboard() {
  const [leaderboard, setLeaderboard] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [searchTerm, setSearchTerm] = useState('')
  const { user } = useAuth()

  useEffect(() => {
    const fetchLeaderboard = async () => {
      try {
        setLoading(true)
        const res = await api.get('/leaderboard')
        setLeaderboard(res.data)
      } catch (err) {
        setError(err.response?.data?.detail || err.message || 'Failed to load leaderboard')
      } finally {
        setLoading(false)
      }
    }
    fetchLeaderboard()
  }, [])

  const filtered = leaderboard.filter(u =>
    u.username.toLowerCase().includes(searchTerm.toLowerCase()) ||
    u.status.toLowerCase().includes(searchTerm.toLowerCase())
  )

  const topThree = leaderboard.slice(0, 3)
  const currentUserRank = leaderboard.find(u => u.username === user?.username)

  const getRankBadge = (rank) => {
    if (rank === 1) return <span className="podium-rank-badge gold">🥇 1st</span>
    if (rank === 2) return <span className="podium-rank-badge silver">🥈 2nd</span>
    if (rank === 3) return <span className="podium-rank-badge bronze">🥉 3rd</span>
    return <span className="podium-rank-badge standard">#{rank}</span>
  }

  return (
    <div className="leaderboard-page">
      {/* Header */}
      <div className="lb-header">
        <div className="lb-header-left">
          <Link to="/" className="lb-back-link">
            <ArrowLeft size={16} />
            <span>Dashboard</span>
          </Link>
          <div className="lb-title-wrap">
            <div className="lb-tag">
              <Trophy size={14} />
              <span>SOC Investigation Standings</span>
            </div>
            <h1>Analyst Leaderboard & Rankings</h1>
            <p className="lb-subtitle">
              Rankings based on total forensic investigation points, scenarios completed, and hint efficiency.
            </p>
          </div>
        </div>

        {currentUserRank && (
          <div className="lb-user-summary-card">
            <div className="user-summary-top">
              <span className="summary-label">Your Current Standing</span>
              <span className="summary-status-badge">{currentUserRank.badge} {currentUserRank.status}</span>
            </div>
            <div className="user-summary-stats">
              <div className="summary-stat">
                <span className="stat-label">Rank</span>
                <span className="stat-value">#{currentUserRank.rank}</span>
              </div>
              <div className="summary-stat">
                <span className="stat-label">Points</span>
                <span className="stat-value highlight">{currentUserRank.total_points}</span>
              </div>
              <div className="summary-stat">
                <span className="stat-label">Solved</span>
                <span className="stat-value">{currentUserRank.scenarios_completed}</span>
              </div>
            </div>
          </div>
        )}
      </div>

      {loading ? (
        <div className="db-loading">
          <div className="db-loading-spinner" />
          <span>Loading analyst leaderboard...</span>
        </div>
      ) : error ? (
        <div className="error">
          <p>{error}</p>
        </div>
      ) : (
        <>
          {/* Top 3 Podium */}
          {topThree.length > 0 && (
            <div className="lb-podium-strip">
              {/* 2nd Place */}
              {topThree[1] && (
                <div className="podium-card podium-silver">
                  <div className="podium-medal">🥈</div>
                  <div className="podium-rank-tag">2nd Place</div>
                  <h3 className="podium-username">{topThree[1].username}</h3>
                  <span className="podium-status">{topThree[1].badge} {topThree[1].status}</span>
                  <div className="podium-points">{topThree[1].total_points} <small>PTS</small></div>
                  <div className="podium-meta">
                    <span>{topThree[1].scenarios_completed} Solved</span>
                    <span>•</span>
                    <span>{topThree[1].average_score}% Avg</span>
                  </div>
                </div>
              )}

              {/* 1st Place */}
              {topThree[0] && (
                <div className="podium-card podium-gold">
                  <div className="podium-crown">👑</div>
                  <div className="podium-medal">🥇</div>
                  <div className="podium-rank-tag">Leader & Champion</div>
                  <h3 className="podium-username">{topThree[0].username}</h3>
                  <span className="podium-status">{topThree[0].badge} {topThree[0].status}</span>
                  <div className="podium-points">{topThree[0].total_points} <small>PTS</small></div>
                  <div className="podium-meta">
                    <span>{topThree[0].scenarios_completed} Solved</span>
                    <span>•</span>
                    <span>{topThree[0].average_score}% Avg</span>
                  </div>
                </div>
              )}

              {/* 3rd Place */}
              {topThree[2] && (
                <div className="podium-card podium-bronze">
                  <div className="podium-medal">🥉</div>
                  <div className="podium-rank-tag">3rd Place</div>
                  <h3 className="podium-username">{topThree[2].username}</h3>
                  <span className="podium-status">{topThree[2].badge} {topThree[2].status}</span>
                  <div className="podium-points">{topThree[2].total_points} <small>PTS</small></div>
                  <div className="podium-meta">
                    <span>{topThree[2].scenarios_completed} Solved</span>
                    <span>•</span>
                    <span>{topThree[2].average_score}% Avg</span>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Search bar & Table */}
          <div className="lb-table-card">
            <div className="lb-table-toolbar">
              <div className="lb-search-wrap">
                <Search size={15} className="lb-search-icon" />
                <input
                  type="text"
                  placeholder="Filter by analyst name or status title..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="lb-search-input"
                />
                {searchTerm && (
                  <button type="button" className="lb-search-clear" onClick={() => setSearchTerm('')}>×</button>
                )}
              </div>
              <div className="lb-count-tag">
                Showing {filtered.length} analysts
              </div>
            </div>

            <div className="lb-table-wrap">
              <table className="lb-table">
                <thead>
                  <tr>
                    <th style={{ width: '80px' }}>Rank</th>
                    <th>Analyst</th>
                    <th>Status Title</th>
                    <th>Points</th>
                    <th>Solved</th>
                    <th>Accuracy</th>
                    <th>Total Trials</th>
                    <th>Hints Used</th>
                  </tr>
                </thead>
                <tbody>
                  {filtered.length === 0 ? (
                    <tr>
                      <td colSpan="8" className="empty">
                        No analysts found matching "{searchTerm}".
                      </td>
                    </tr>
                  ) : (
                    filtered.map((entry) => {
                      const isCurrentUser = user && user.username === entry.username
                      return (
                        <tr
                          key={entry.user_id}
                          className={`lb-row ${isCurrentUser ? 'current-user-row' : ''}`}
                        >
                          <td>
                            {getRankBadge(entry.rank)}
                          </td>
                          <td>
                            <div className="analyst-cell">
                              <span className="analyst-avatar">
                                {entry.role === 'admin' ? <ShieldCheck size={14} color="#60a5fa" /> : <User size={14} />}
                              </span>
                              <span className="analyst-name">{entry.username}</span>
                              {isCurrentUser && <span className="you-pill">You</span>}
                            </div>
                          </td>
                          <td>
                            <span className="status-title-pill">
                              <span className="status-badge-icon">{entry.badge}</span>
                              <span>{entry.status}</span>
                            </span>
                          </td>
                          <td>
                            <strong className="pts-highlight">{entry.total_points}</strong> pts
                          </td>
                          <td>
                            <span className="scenarios-count">{entry.scenarios_completed}</span>
                          </td>
                          <td>
                            <span className={`score-pill ${entry.average_score >= 80 ? 'high' : entry.average_score >= 50 ? 'mid' : 'low'}`}>
                              {entry.average_score}%
                            </span>
                          </td>
                          <td>
                            <span className="trials-pill">{entry.total_trials}</span>
                          </td>
                          <td>
                            {entry.hints_used_count > 0 ? (
                              <span className="hints-used-pill">
                                💡 {entry.hints_used_count} (-{entry.hints_used_count * 15} pts)
                              </span>
                            ) : (
                              <span className="hints-none-pill">0</span>
                            )}
                          </td>
                        </tr>
                      )
                    })
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </>
      )}
    </div>
  )
}
