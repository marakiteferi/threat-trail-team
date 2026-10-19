import { useLocation, useParams, Link, useNavigate } from 'react-router-dom'
import {
  Target,
  CheckCircle2,
  AlertTriangle,
  Shield,
  Activity,
  Zap,
} from 'lucide-react'

export default function Report() {
  const { scenarioId } = useParams()
  const location = useLocation()
  const navigate = useNavigate()

  const stored = sessionStorage.getItem(`report_${scenarioId}`)
  const report = location.state?.report || (stored ? JSON.parse(stored) : null)

  if (!report) {
    return (
      <div className="report-v2">
        <div className="rpt-no-data">
          <div className="rpt-no-data-icon">📋</div>
          <h2>No Investigation Report Found</h2>
          <p>Complete and submit the scenario investigation to view your graded debrief.</p>
          <Link to={`/investigate/${scenarioId}`} className="btn btn-primary">
            Go to Investigation →
          </Link>
        </div>
      </div>
    )
  }

  const pct =
    report.score_percent !== undefined
      ? report.score_percent
      : report.score !== undefined
      ? report.score
      : report.total_points > 0
      ? Math.round(((report.points_earned || 0) / report.total_points) * 100)
      : 0

  const correctCount =
    report.correct_count !== undefined
      ? report.correct_count
      : report.results
      ? report.results.filter((r) => r.is_correct).length
      : 0

  const totalQuestions =
    report.total_questions !== undefined
      ? report.total_questions
      : report.results
      ? report.results.length
      : 0

  const radius = 50
  const circumference = 2 * Math.PI * radius
  const strokeDashoffset = circumference - (pct / 100) * circumference

  let tierLabel = 'Needs Review'
  let tierClass = 'tier-fail'
  let ringColor = '#ef4444'

  if (pct === 100) {
    tierLabel = '🏆 Senior SOC Analyst — Perfect Triage'
    tierClass = 'tier-perfect'
    ringColor = '#f3c25b'
  } else if (pct >= 80) {
    tierLabel = '✅ Tier-2 Incident Responder'
    tierClass = 'tier-great'
    ringColor = '#22c55e'
  } else if (pct >= 60) {
    tierLabel = '🛡️ Junior Analyst — Passing Grade'
    tierClass = 'tier-pass'
    ringColor = '#3b82f6'
  } else if (pct >= 40) {
    tierLabel = '⚠️ Partial Triage — Key IOCs Missed'
    tierClass = 'tier-warn'
    ringColor = '#f59e0b'
  }

  const pinnedIds = report.pinned_log_ids || []
  const keyEvidenceIds = report.key_evidence_log_ids || []
  const matchedPins = pinnedIds.filter((id) => keyEvidenceIds.includes(id))
  const falsePositivePins = pinnedIds.filter((id) => !keyEvidenceIds.includes(id))

  const precisionPct =
    pinnedIds.length > 0
      ? Math.round((matchedPins.length / pinnedIds.length) * 100)
      : 0

  const coveragePct =
    keyEvidenceIds.length > 0
      ? Math.round((matchedPins.length / keyEvidenceIds.length) * 100)
      : 0

  return (
    <div className="report-v2">
      <div className="rpt-hero">
        <div className="rpt-hero-bg" />
        <div className="rpt-hero-content">
          <div className="rpt-ring-wrap">
            <svg className="rpt-ring-svg" viewBox="0 0 120 120">
              <circle className="rpt-ring-track" cx="60" cy="60" r={radius} />
              <circle
                className="rpt-ring-fill"
                cx="60"
                cy="60"
                r={radius}
                stroke={ringColor}
                strokeDasharray={circumference}
                strokeDashoffset={strokeDashoffset}
              />
            </svg>
            <div className="rpt-ring-center">
              <span className="rpt-pct" style={{ color: ringColor }}>
                {pct}%
              </span>
            </div>
          </div>

          <div className="rpt-hero-text">
            <h2 className="rpt-title">Incident Debrief & Evaluation</h2>
            <div className={`rpt-tier ${tierClass}`}>{tierLabel}</div>
            <div className="rpt-pts-row">
              <span className="rpt-pts-earned">{report.points_earned}</span>
              <span className="rpt-pts-sep">/</span>
              <span className="rpt-pts-total">{report.total_points} points earned</span>
            </div>
            <p className="rpt-summary">
              You answered <strong>{correctCount}</strong> of{' '}
              <strong>{totalQuestions}</strong> investigation questions correctly
              {keyEvidenceIds.length > 0 && (
                <>
                  {' '}and pinned <strong>{matchedPins.length}/{keyEvidenceIds.length}</strong> key evidence logs
                  {pinnedIds.length > 0 && (
                    <>
                      {' '}(<strong>{precisionPct}%</strong> timeline precision
                      {falsePositivePins.length > 0 && (
                        <>, <span style={{ color: '#f87171' }}>{falsePositivePins.length} false positive{falsePositivePins.length > 1 ? 's' : ''}</span></>
                      )}).
                    </>
                  )}
                </>
              )}
            </p>
          </div>
        </div>
      </div>

      {/* ─── Forensic Timeline & Evidence Triage Evaluation Card ─── */}
      <div className="rpt-triage-card">
        <div className="rpt-triage-header">
          <div className="rpt-triage-header-left">
            <Target size={20} className="rpt-triage-icon" />
            <div>
              <h3 className="rpt-triage-title">Forensic Timeline & Evidence Triage Evaluation</h3>
              <p className="rpt-triage-subtitle">
                Signal-to-noise ratio and false-positive evaluation of pinned timeline evidence
              </p>
            </div>
          </div>
          <div className="rpt-triage-badge-wrap">
            <span
              className={`rpt-precision-badge ${
                pinnedIds.length === 0
                  ? 'badge-empty'
                  : falsePositivePins.length === 0
                  ? 'badge-clean'
                  : 'badge-noisy'
              }`}
            >
              {pinnedIds.length === 0
                ? 'No Evidence Pinned'
                : `${precisionPct}% Timeline Precision`}
            </span>
          </div>
        </div>

        <div className="rpt-triage-grid">
          {/* True Attack Logs */}
          <div className="rpt-triage-stat-box">
            <div className="rpt-triage-stat-label">
              <CheckCircle2 size={14} style={{ color: '#10b981' }} />
              <span>True Attack Logs Pinned</span>
            </div>
            <div className="rpt-triage-stat-val text-success">
              {matchedPins.length} <span className="stat-sep">/</span> {keyEvidenceIds.length}
            </div>
            <div className="rpt-triage-bar-track">
              <div
                className="rpt-triage-bar-fill fill-success"
                style={{ width: `${coveragePct}%` }}
              />
            </div>
            <span className="rpt-triage-subtext">
              {keyEvidenceIds.length === 0
                ? 'No key evidence designated'
                : coveragePct === 100
                ? '100% of critical attack IOCs captured'
                : `${coveragePct}% of key attack logs pinned`}
            </span>
          </div>

          {/* False Positive Noise Pins */}
          <div className="rpt-triage-stat-box">
            <div className="rpt-triage-stat-label">
              {falsePositivePins.length === 0 ? (
                <Shield size={14} style={{ color: '#38bdf8' }} />
              ) : (
                <AlertTriangle size={14} style={{ color: '#f59e0b' }} />
              )}
              <span>Benign Noise (False Positives)</span>
            </div>
            <div
              className={`rpt-triage-stat-val ${
                falsePositivePins.length === 0 ? 'text-clean' : 'text-warning'
              }`}
            >
              {falsePositivePins.length}
            </div>
            <div className="rpt-triage-bar-track">
              <div
                className="rpt-triage-bar-fill fill-warning"
                style={{
                  width: `${
                    pinnedIds.length > 0
                      ? Math.min(100, Math.round((falsePositivePins.length / pinnedIds.length) * 100))
                      : 0
                  }%`,
                }}
              />
            </div>
            <span className="rpt-triage-subtext">
              {falsePositivePins.length === 0
                ? '0 benign noise logs pinned — clean chain of custody'
                : `${falsePositivePins.length} uncorroborated event(s) pinned`}
            </span>
          </div>

          {/* Timeline Efficiency / Signal-to-Noise */}
          <div className="rpt-triage-stat-box">
            <div className="rpt-triage-stat-label">
              <Activity size={14} style={{ color: '#a855f7' }} />
              <span>Timeline Signal Ratio</span>
            </div>
            <div className="rpt-triage-stat-val text-purple">
              {pinnedIds.length === 0 ? '—' : `${precisionPct}%`}
            </div>
            <div className="rpt-triage-bar-track">
              <div
                className="rpt-triage-bar-fill fill-purple"
                style={{ width: `${precisionPct}%` }}
              />
            </div>
            <span className="rpt-triage-subtext">
              {pinnedIds.length} total event(s) submitted to timeline
            </span>
          </div>
        </div>

        {/* SOC Coaching Callout */}
        <div
          className={`rpt-coaching-box ${
            pinnedIds.length === 0
              ? 'coaching-neutral'
              : falsePositivePins.length === 0 && matchedPins.length === keyEvidenceIds.length
              ? 'coaching-clean'
              : falsePositivePins.length > 0
              ? 'coaching-warning'
              : 'coaching-neutral'
          }`}
        >
          <div className="coaching-header">
            <Zap size={14} className="coaching-icon" />
            <strong>SOC Lead Forensic Coaching:</strong>
          </div>
          <p className="coaching-text">
            {pinnedIds.length === 0 ? (
              <>
                ⚠️ <strong>Zero Pinned Evidence:</strong> You did not pin any event logs to your attack timeline. In real-world incident response, submitting an incident report without pinning corroborating artifacts prevents escalation and legal chain-of-custody verification.
              </>
            ) : falsePositivePins.length === 0 && matchedPins.length === keyEvidenceIds.length ? (
              <>
                🌟 <strong>Flawless Evidence Triage:</strong> Your pinned timeline contains 100% true attack telemetry with zero benign background noise. This high-signal timeline allows Tier-3 incident responders and forensic leads to immediately reconstruct the attacker&apos;s actions without sorting through false leads.
              </>
            ) : falsePositivePins.length > 0 ? (
              <>
                ⚠️ <strong>High Noise Detected ({falsePositivePins.length} False Positive{falsePositivePins.length > 1 ? 's' : ''}):</strong> You pinned benign background events that were not part of the active threat vector. Keeping your forensic timeline high-signal is crucial—cluttering an incident timeline with benign noise slows down incident mitigation and confuses escalation teams.
                {matchedPins.length < keyEvidenceIds.length && (
                  <> Additionally, you missed {keyEvidenceIds.length - matchedPins.length} critical attack log(s).</>
                )}
              </>
            ) : (
              <>
                🔍 <strong>Incomplete Evidence Coverage:</strong> You pinned {matchedPins.length} of {keyEvidenceIds.length} primary attack logs with zero false positives. Review the unpinned artifacts (such as logon failures, Kerberos ticket requests, or process accesses) to capture the complete kill chain.
              </>
            )}
          </p>
        </div>
      </div>

      {report.containment_eval && report.containment_eval.enabled && (
        <div className="rpt-results-section">
          <h3 className="rpt-section-title">🛡️ Incident Containment Playbook Evaluation</h3>
          <div
            className={`rpt-result-card ${
              report.containment_eval.host_correct !== false && report.containment_eval.user_correct !== false
                ? 'rpt-correct'
                : 'rpt-incorrect'
            }`}
            style={{ padding: '16px 20px', flexDirection: 'column', gap: '8px' }}
          >
            <div><strong>Automated Quarantine Verdict:</strong> {report.containment_eval.feedback}</div>
            <div style={{ display: 'flex', gap: '24px', flexWrap: 'wrap', fontSize: '0.85rem', color: 'var(--text-dim)' }}>
              {report.containment_eval.expected_host && (
                <span>
                  Isolated Host: <strong style={{ color: 'var(--text)' }}>{report.containment_eval.selected_host || '(None)'}</strong>{' '}
                  (Expected: <code>{report.containment_eval.expected_host}</code>)
                </span>
              )}
              {report.containment_eval.expected_user && (
                <span>
                  Disabled Account: <strong style={{ color: 'var(--text)' }}>{report.containment_eval.selected_user || '(None)'}</strong>{' '}
                  (Expected: <code>{report.containment_eval.expected_user}</code>)
                </span>
              )}
            </div>
          </div>
        </div>
      )}

      <div className="rpt-results-section">
        <h3 className="rpt-section-title">Question-by-Question Debrief</h3>
        <div className="rpt-results-list">
          {report.results.map((r) => (
            <div
              key={r.question_id}
              className={`rpt-result-card ${r.is_correct ? 'rpt-correct' : 'rpt-incorrect'}`}
            >
              <div className="rpt-card-left">
                <div className={`rpt-verdict-icon ${r.is_correct ? 'rpt-v-correct' : 'rpt-v-wrong'}`}>
                  {r.is_correct ? '✓' : '✗'}
                </div>
              </div>
              <div className="rpt-card-body">
                <div className="rpt-card-top-row">
                  <span className="rpt-q-text">{r.question_text}</span>
                  <span className={`rpt-pts-pill ${r.is_correct ? 'rpt-pill-correct' : 'rpt-pill-wrong'}`}>
                    {r.points_awarded} / {r.points_possible} pts
                  </span>
                </div>

                <div className="rpt-answers">
                  <div className="rpt-answer-row">
                    <span className="rpt-answer-label">Your Answer:</span>
                    <span className={`rpt-answer-val ${r.is_correct ? 'rpt-ans-correct' : 'rpt-ans-wrong'}`}>
                      {r.user_answer || '(blank)'}
                    </span>
                  </div>
                  {!r.is_correct && (
                    <div className="rpt-answer-row">
                      <span className="rpt-answer-label">Expected IOC:</span>
                      <span className="rpt-answer-val rpt-ans-correct">{r.correct_answer}</span>
                    </div>
                  )}
                  {r.explanation && (
                    <div className="rpt-explanation-box">
                      <strong>💡 Analyst Explanation:</strong> {r.explanation}
                    </div>
                  )}
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      <div className="rpt-actions">
        <button
          className="rpt-btn-back"
          onClick={() => navigate(-1)}
          title="Go back to previous page"
        >
          ← Back
        </button>
        <Link to={`/investigate/${scenarioId}`} className="rpt-btn-retry">
          ↻ Re-Investigate Scenario
        </Link>
        <Link to="/" className="rpt-btn-back" style={{ marginLeft: 'auto' }}>
          Dashboard
        </Link>
      </div>
    </div>
  )
}
