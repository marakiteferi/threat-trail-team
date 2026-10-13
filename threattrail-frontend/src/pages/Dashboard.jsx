import { useEffect, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import {
  Key,
  UserCheck,
  Brain,
  Zap,
  Monitor,
  Activity,
  RefreshCw,
  FileText,
  HelpCircle,
  AlertTriangle,
  ArrowRight,
  Lock,
  Inbox,
  Shield,
  Crosshair,
  Info,
  ChevronDown,
  ChevronUp,
  Terminal,
  BookOpen,
} from 'lucide-react'
import api from '../api'
import { useAuth } from '../context/AuthContext'

const SEVERITY_META = {
  Critical: { color: '#bc8cff', bg: 'rgba(188,140,255,0.12)', border: 'rgba(188,140,255,0.35)' },
  High:     { color: '#f85149', bg: 'rgba(248,81,73,0.12)',   border: 'rgba(248,81,73,0.35)'   },
  Medium:   { color: '#d29922', bg: 'rgba(210,153,34,0.12)',  border: 'rgba(210,153,34,0.35)'  },
  Low:      { color: '#3fb950', bg: 'rgba(63,185,80,0.12)',   border: 'rgba(63,185,80,0.35)'   },
}

function AttackIcon({ mitre, size = 18 }) {
  if (!mitre) return <Shield size={size} />
  const prefix = mitre.toUpperCase().slice(0, 5)

  switch (prefix) {
    case 'T1110': return <Key size={size} />
    case 'T1078': return <UserCheck size={size} />
    case 'T1003': return <Brain size={size} />
    case 'T1059': return <Zap size={size} />
    case 'T1021': return <Monitor size={size} />
    case 'T1055': return <Activity size={size} />
    case 'T1547': return <RefreshCw size={size} />
    case 'T1566': return <Crosshair size={size} />
    default:      return <Shield size={size} />
  }
}

function ScenarioCard({ scenario, index, isAuthenticated }) {
  const sev = scenario.severity || scenario.alert_severity || 'High'
  const meta = SEVERITY_META[sev] || SEVERITY_META.High
  const navigate = useNavigate()

  const handleCardClick = (e) => {
    if (e.target.closest('a') || e.target.closest('button')) return
    if (isAuthenticated) {
      navigate(`/investigate/${scenario.id}`)
    } else {
      navigate('/login', { state: { from: { pathname: `/investigate/${scenario.id}` } } })
    }
  }

  return (
    <div
      className="db-scenario-card"
      style={{ animationDelay: `${index * 70}ms`, cursor: 'pointer' }}
      onClick={handleCardClick}
    >
      <div className="db-card-glow" style={{ background: `radial-gradient(circle at top right, ${meta.color}18 0%, transparent 65%)` }} />

      <div className="db-card-top">
        <div className="db-card-icon" style={{ background: meta.bg, border: `1px solid ${meta.border}`, color: meta.color }}>
          <AttackIcon mitre={scenario.mitre_technique} size={20} />
        </div>
        <div className="db-card-badges">
          {scenario.in_progress && (
            <span className="db-mitre-badge" style={{ background: 'rgba(245, 158, 11, 0.15)', color: '#f59e0b', border: '1px solid rgba(245, 158, 11, 0.4)' }}>
              In Progress
            </span>
          )}
          {scenario.trials_count > 0 && (
            <span className="db-mitre-badge" style={{ background: 'rgba(59, 130, 246, 0.15)', color: '#60a5fa', border: '1px solid rgba(59, 130, 246, 0.4)' }}>
              {scenario.trials_count} {scenario.trials_count === 1 ? 'Trial' : 'Trials'} ({scenario.best_score ?? 0}%)
            </span>
          )}
          <span className="db-sev-badge" style={{ background: meta.bg, border: `1px solid ${meta.border}`, color: meta.color }}>
            <span className="db-sev-dot" style={{ background: meta.color }} />
            {sev}
          </span>
          <span className="db-mitre-badge">{scenario.mitre_technique || 'N/A'}</span>
        </div>
      </div>

      <h3 className="db-card-title">{scenario.name}</h3>
      <p className="db-card-desc">{scenario.description || 'Investigate this attack scenario and identify the threat actor\'s TTPs.'}</p>

      {scenario.alert_title && (
        <div className="db-alert-preview" style={{ borderColor: meta.border }}>
          <span className="db-alert-label">
            <AlertTriangle size={12} className="alert-label-svg" />
            Active Alert
          </span>
          <span className="db-alert-text">{scenario.alert_title}</span>
        </div>
      )}

      <div className="db-card-footer">
        <div className="db-card-meta">
          <span className="db-meta-chip">
            <FileText size={12} className="meta-icon-svg" />
            {scenario.log_count ?? '—'} events
          </span>
          <span className="db-meta-chip">
            <HelpCircle size={12} className="meta-icon-svg" />
            {scenario.question_count ?? '—'} questions
          </span>
        </div>

        {isAuthenticated ? (
          <Link to={`/investigate/${scenario.id}`} className="db-start-btn">
            <span>{scenario.in_progress ? 'Resume' : scenario.trials_count > 0 ? 'Retake' : 'Investigate'}</span>
            <ArrowRight size={14} className="db-btn-arrow" />
          </Link>
        ) : (
          <Link
            to="/login"
            state={{ from: { pathname: `/investigate/${scenario.id}` } }}
            className="db-start-btn db-start-btn-locked"
            title="Sign in required to access this scenario"
          >
            <Lock size={12} />
            <span>Sign in to Investigate</span>
          </Link>
        )}
      </div>
    </div>
  )
}

function PlatformGuide() {
  const [showFaq, setShowFaq] = useState(false)

  return (
    <div className="db-guide-box">
      <div className="db-guide-top">
        <div className="db-guide-badge">
          <Info size={14} />
          <span>How ThreatTrail Works</span>
        </div>
        <button
          type="button"
          className="db-guide-toggle-btn"
          onClick={() => setShowFaq(v => !v)}
          title="Toggle Event ID and log explanation"
        >
          <span>{showFaq ? 'Hide Log Guide' : 'What are Event IDs?'}</span>
          {showFaq ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
        </button>
      </div>

      <div className="db-guide-intro">
        <h2 className="db-guide-title">Hands-On Active Directory SOC Investigation Platform</h2>
        <p className="db-guide-desc">
          ThreatTrail simulates the daily workflow of a Security Operations Center (SOC) analyst.
          Instead of multiple-choice theory quizzes, you investigate authentic recorded <strong>Windows Event Logs</strong> and <strong>Sysmon telemetry</strong> from real Active Directory cyberattacks.
        </p>
      </div>

      <div className="db-guide-steps">
        <div className="db-guide-step">
          <div className="db-guide-step-badge">Step 1</div>
          <div className="db-guide-step-body">
            <h4>Select an Attack Scenario</h4>
            <p>Choose an incident from the dashboard below to review the triggered alert, severity level, and Active Directory environment details.</p>
          </div>
        </div>

        <div className="db-guide-step">
          <div className="db-guide-step-badge">Step 2</div>
          <div className="db-guide-step-body">
            <h4>Analyze Event Logs</h4>
            <p>Filter and inspect recorded Windows security logs. Correlate timestamps, usernames, and source IPs to trace the threat actor's activity.</p>
          </div>
        </div>

        <div className="db-guide-step">
          <div className="db-guide-step-badge">Step 3</div>
          <div className="db-guide-step-body">
            <h4>Solve & Submit Answers</h4>
            <p>Identify the attacker's IP, compromised accounts, and MITRE ATT&CK techniques. Submit your forensic findings to get your score!</p>
          </div>
        </div>
      </div>

      {showFaq && (
        <div className="db-guide-faq">
          <div className="db-faq-card">
            <div className="db-faq-header">
              <HelpCircle size={16} className="faq-icon-blue" />
              <strong>Why are some Event IDs the same in the log viewer?</strong>
            </div>
            <p>
              In Windows Security logging, an <strong>Event ID is a standardized category code</strong> (like an HTTP status code), not a unique row ID.
              For example, <code>Event 4625</code> indicates a Failed Logon. If an attacker runs a password spray against 15 accounts, Windows logs 15 separate <code>4625</code> events.
              To differentiate them, look at the <strong>Timestamp</strong>, <strong>Username</strong>, <strong>Source IP</strong>, and <strong>Failure Reason (SubStatus)</strong>.
            </p>
          </div>

          <div className="db-faq-card">
            <div className="db-faq-header">
              <Terminal size={16} className="faq-icon-green" />
              <strong>Common Event IDs you will encounter:</strong>
            </div>
            <div className="db-faq-tags">
              <span className="faq-tag"><code>4625</code> Failed Logon</span>
              <span className="faq-tag"><code>4624</code> Successful Logon</span>
              <span className="faq-tag"><code>4768</code> Kerberos TGT</span>
              <span className="faq-tag"><code>4769</code> Kerberos TGS (RC4 / Kerberoast)</span>
              <span className="faq-tag"><code>4662</code> AD Object Access (DCSync)</span>
              <span className="faq-tag"><code>4688</code> Process Creation</span>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

export default function Dashboard() {
  const [scenarios, setScenarios] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const { isAuthenticated } = useAuth()

  useEffect(() => {
    api.get('/scenarios')
      .then(res => setScenarios(res.data))
      .catch(err => setError(err.message))
      .finally(() => setLoading(false))
  }, [])

  const critCount  = scenarios.filter(s => String(s.severity || s.alert_severity || '').toLowerCase() === 'critical').length
  const highCount  = scenarios.filter(s => String(s.severity || s.alert_severity || '').toLowerCase() === 'high').length
  const totalCount = scenarios.length

  if (loading) return (
    <div className="db-loading">
      <div className="db-loading-spinner" />
      <span>Loading scenarios…</span>
    </div>
  )
  if (error) return (
    <div className="error">
      <AlertTriangle size={16} />
      <span>{error}</span>
    </div>
  )

  return (
    <div className="dashboard-v2">

      {/* Hero */}
      <div className="db-hero">
        <div className="db-hero-scan-line" />
        <div className="db-hero-content">
          <div className="db-hero-tag">SOC Investigation Platform</div>
          <h1 className="db-hero-title">
            Active <span className="db-hero-accent">Threat</span> Scenarios
          </h1>
          <p className="db-hero-sub">
            Select a scenario to begin your investigation. Analyze Windows Event Logs,
            identify attack patterns, and answer forensic questions.
          </p>
        </div>

        <div className="db-stat-strip">
          <div className="db-stat-item">
            <span className="db-stat-num">{totalCount}</span>
            <span className="db-stat-label">Scenarios</span>
          </div>
          <div className="db-stat-divider" />
          <div className="db-stat-item">
            <span className="db-stat-num" style={{ color: '#f85149' }}>{highCount}</span>
            <span className="db-stat-label">High Severity</span>
          </div>
          <div className="db-stat-divider" />
          <div className="db-stat-item">
            <span className="db-stat-num" style={{ color: '#bc8cff' }}>{critCount}</span>
            <span className="db-stat-label">Critical</span>
          </div>
        </div>
      </div>

      {/* Platform Explainer Guide */}
      <PlatformGuide />

      {/* Scenario Grid */}
      {scenarios.length === 0 ? (
        <div className="db-empty">
          <div className="db-empty-icon">
            <Inbox size={42} />
          </div>
          <h3>No Scenarios Available</h3>
          <p>Run the seed script or use the Admin panel to create scenarios.</p>
        </div>
      ) : (
        <div className="db-scenario-grid">
          {scenarios.map((s, i) => (
            <ScenarioCard
              key={s.id}
              scenario={s}
              index={i}
              isAuthenticated={isAuthenticated}
            />
          ))}
        </div>
      )}
    </div>
  )
}
