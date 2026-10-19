import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import api from '../api'
import { useAuth } from '../context/AuthContext'
import {
  ShieldCheck,
  Layers,
  PlusCircle,
  FileText,
  HelpCircle,
  Edit3,
  Trash2,
  CheckCircle2,
  ArrowRight,
  Target,
  FolderOpen,
  AlertTriangle,
  X,
  Save,
  Activity,
  RefreshCw,
  Eye,
  Lightbulb,
  User,
  Users,
  UserPlus,
  Key,
  Calendar,
  ShieldAlert,
  Clock,
  Search,
  Shield,
} from 'lucide-react'

export default function Admin() {
  const [activeTab, setActiveTab] = useState('manage')
  const [scenarios, setScenarios] = useState([])
  const [stats, setStats] = useState(null)
  const [loadingScenarios, setLoadingScenarios] = useState(true)
  const [filterStatus, setFilterStatus] = useState('all')
  const [searchTerm, setSearchTerm] = useState('')
  const [toast, setToast] = useState(null)

  // Analyst Submissions, Trials & Guesses state
  const [submissions, setSubmissions] = useState([])
  const [loadingSubmissions, setLoadingSubmissions] = useState(false)
  const [selectedSubmission, setSelectedSubmission] = useState(null)
  const [submissionsSearch, setSubmissionsSearch] = useState('')

  // Creation form state
  const [createName, setCreateName] = useState('')
  const [createDesc, setCreateDesc] = useState('')
  const [createMitre, setCreateMitre] = useState('')
  const [createStatus, setCreateStatus] = useState('Published')
  const [createAlertTitle, setCreateAlertTitle] = useState('')
  const [createAlertSeverity, setCreateAlertSeverity] = useState('High')
  const [createSigmaRule, setCreateSigmaRule] = useState('')
  const [createContainmentHost, setCreateContainmentHost] = useState('')
  const [createContainmentUser, setCreateContainmentUser] = useState('')
  const [createQuestions, setCreateQuestions] = useState([
    { q: '', a: '', acceptable_answers: '', free_hint: '', hint: '', explanation: '', points: 10 }
  ])
  const [createFile, setCreateFile] = useState(null)
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [submitStep, setSubmitStep] = useState('')
  const [createSuccessData, setCreateSuccessData] = useState(null)
  const [createError, setCreateError] = useState('')

  // Edit Modal state
  const [editingScenario, setEditingScenario] = useState(null)
  const [editName, setEditName] = useState('')
  const [editDesc, setEditDesc] = useState('')
  const [editMitre, setEditMitre] = useState('')
  const [editStatus, setEditStatus] = useState('Draft')
  const [editAlertTitle, setEditAlertTitle] = useState('')
  const [editAlertSeverity, setEditAlertSeverity] = useState('High')
  const [editSigmaRule, setEditSigmaRule] = useState('')
  const [editContainmentHost, setEditContainmentHost] = useState('')
  const [editContainmentUser, setEditContainmentUser] = useState('')
  const [createAdContext, setCreateAdContext] = useState('{}')
  const [isAnalyzingZip, setIsAnalyzingZip] = useState(false)
  const [zipAnalysisReport, setZipAnalysisReport] = useState(null)
  const [editAdContext, setEditAdContext] = useState('{}')
  const [editQuestions, setEditQuestions] = useState([])
  const [editFile, setEditFile] = useState(null)
  const [isSavingEdit, setIsSavingEdit] = useState(false)
  const [editError, setEditError] = useState('')

  // Delete confirmation modal state
  const [deletingScenario, setDeletingScenario] = useState(null)
  const [isDeleting, setIsDeleting] = useState(false)

  // Current logged in admin
  const { user: currentAdmin } = useAuth()

  // User Management state
  const [users, setUsers] = useState([])
  const [loadingUsers, setLoadingUsers] = useState(false)
  const [usersSearch, setUsersSearch] = useState('')
  const [userRoleFilter, setUserRoleFilter] = useState('all') // 'all' | 'admin' | 'user'

  // Add User Modal state
  const [showAddUserModal, setShowAddUserModal] = useState(false)
  const [newUsername, setNewUsername] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [newRole, setNewRole] = useState('user')
  const [isAddingUser, setIsAddingUser] = useState(false)
  const [addUserError, setAddUserError] = useState('')

  // Delete User Confirmation state
  const [userToDelete, setUserToDelete] = useState(null)
  const [isDeletingUser, setIsDeletingUser] = useState(false)

  // Toggle User Role Confirmation state
  const [userToToggleRole, setUserToToggleRole] = useState(null)
  const [isTogglingRole, setIsTogglingRole] = useState(false)

  // Reset User Password state
  const [userToResetPassword, setUserToResetPassword] = useState(null)
  const [resetNewPassword, setResetNewPassword] = useState('')
  const [isResettingPassword, setIsResettingPassword] = useState(false)
  const [resetPasswordError, setResetPasswordError] = useState('')

  const showToast = (message, type = 'success') => {
    setToast({ message, type })
    setTimeout(() => setToast(null), 4500)
  }

  const loadSubmissions = async () => {
    setLoadingSubmissions(true)
    try {
      const res = await api.get('/admin/submissions')
      setSubmissions(res.data)
    } catch (err) {
      console.error('Failed to load submissions:', err)
    } finally {
      setLoadingSubmissions(false)
    }
  }

  const loadUsers = async () => {
    setLoadingUsers(true)
    try {
      const res = await api.get('/admin/users')
      setUsers(res.data)
    } catch (err) {
      console.error('Failed to load users:', err)
      showToast('Failed to load users', 'error')
    } finally {
      setLoadingUsers(false)
    }
  }

  // Fetch scenarios, stats, submissions, and users
  const loadAdminData = async () => {
    setLoadingScenarios(true)
    try {
      const [scenariosRes, statsRes, submissionsRes, usersRes] = await Promise.all([
        api.get('/admin/scenarios'),
        api.get('/admin/stats'),
        api.get('/admin/submissions').catch(() => ({ data: [] })),
        api.get('/admin/users').catch(() => ({ data: [] })),
      ])
      setScenarios(scenariosRes.data)
      setStats(statsRes.data)
      setSubmissions(submissionsRes.data || [])
      setUsers(usersRes.data || [])
    } catch (err) {
      showToast(`Failed to load data: ${err.message}`, 'error')
    } finally {
      setLoadingScenarios(false)
    }
  }

  useEffect(() => {
    loadAdminData()
  }, [])

  // ── User Management Handlers ───────────────────────────────────────────────
  const handleCreateUser = async (e) => {
    e.preventDefault()
    setIsAddingUser(true)
    setAddUserError('')
    try {
      const res = await api.post('/admin/users', {
        username: newUsername.trim(),
        password: newPassword,
        role: newRole,
      })
      setUsers(prev => [...prev, res.data])
      setShowAddUserModal(false)
      setNewUsername('')
      setNewPassword('')
      setNewRole('user')
      showToast(`User '${res.data.username}' registered successfully!`)
      if (stats) {
        setStats(prev => ({
          ...prev,
          total_users: (prev.total_users || 0) + 1,
          total_admins: res.data.role === 'admin' ? (prev.total_admins || 0) + 1 : prev.total_admins,
          total_trainees: res.data.role === 'user' ? (prev.total_trainees || 0) + 1 : prev.total_trainees,
        }))
      }
    } catch (err) {
      const raw = err.response?.data?.detail
      let msg = 'Failed to register user'
      if (typeof raw === 'string') msg = raw
      else if (Array.isArray(raw)) msg = raw.map(e => e.msg || e.detail || JSON.stringify(e)).join(', ')
      else if (raw && typeof raw === 'object') msg = raw.msg || raw.detail || JSON.stringify(raw)
      else if (err.message) msg = err.message
      setAddUserError(msg)
    } finally {
      setIsAddingUser(false)
    }
  }

  const handleDeleteUser = async () => {
    if (!userToDelete) return
    setIsDeletingUser(true)
    try {
      await api.delete(`/admin/users/${userToDelete.id}`)
      setUsers(prev => prev.filter(u => u.id !== userToDelete.id))
      showToast(`User '${userToDelete.username}' deleted successfully.`)
      if (stats) {
        setStats(prev => ({
          ...prev,
          total_users: Math.max(0, (prev.total_users || 1) - 1),
          total_admins: userToDelete.role === 'admin' ? Math.max(0, (prev.total_admins || 1) - 1) : prev.total_admins,
          total_trainees: userToDelete.role === 'user' ? Math.max(0, (prev.total_trainees || 1) - 1) : prev.total_trainees,
        }))
      }
      setUserToDelete(null)
    } catch (err) {
      showToast(err.response?.data?.detail || 'Failed to delete user', 'error')
    } finally {
      setIsDeletingUser(false)
    }
  }

  const handleToggleUserRole = (targetUser) => {
    if (currentAdmin && (targetUser.id === currentAdmin.id || targetUser.username === currentAdmin.username)) {
      showToast("You cannot change the role of your own logged-in administrator account.", "error")
      return
    }
    setUserToToggleRole(targetUser)
  }

  const confirmToggleUserRole = async () => {
    if (!userToToggleRole) return
    setIsTogglingRole(true)
    const targetUser = userToToggleRole
    const nextRole = targetUser.role === 'admin' ? 'user' : 'admin'

    try {
      await api.patch(`/admin/users/${targetUser.id}/role`, { role: nextRole })
      setUsers(prev => prev.map(u => (u.id === targetUser.id ? { ...u, role: nextRole } : u)))
      showToast(`User '${targetUser.username}' role changed to ${nextRole === 'admin' ? 'Admin' : 'Trainee'}`)
      if (stats) {
        setStats(prev => ({
          ...prev,
          total_admins: nextRole === 'admin' ? (prev.total_admins || 0) + 1 : Math.max(0, (prev.total_admins || 1) - 1),
          total_trainees: nextRole === 'user' ? (prev.total_trainees || 0) + 1 : Math.max(0, (prev.total_trainees || 1) - 1),
        }))
      }
      setUserToToggleRole(null)
    } catch (err) {
      showToast(err.response?.data?.detail || 'Failed to update user role', 'error')
    } finally {
      setIsTogglingRole(false)
    }
  }

  const handleResetPassword = async (e) => {
    e.preventDefault()
    if (!userToResetPassword) return
    setIsResettingPassword(true)
    setResetPasswordError('')
    try {
      await api.patch(`/admin/users/${userToResetPassword.id}/password`, {
        password: resetNewPassword,
      })
      showToast(`Password successfully reset for '${userToResetPassword.username}'`)
      setUserToResetPassword(null)
      setResetNewPassword('')
    } catch (err) {
      setResetPasswordError(err.response?.data?.detail || 'Failed to reset password')
    } finally {
      setIsResettingPassword(false)
    }
  }


  // ── Toggle Scenario Status (Publish / Draft) ───────────────────────────────
  const handleToggleStatus = async (scenario) => {
    const newStatus = scenario.status === 'Published' ? 'Draft' : 'Published'
    try {
      await api.patch(`/admin/scenarios/${scenario.id}/status`, { status: newStatus })
      setScenarios((prev) =>
        prev.map((s) => (s.id === scenario.id ? { ...s, status: newStatus } : s))
      )
      loadAdminData()
      showToast(`Scenario marked as ${newStatus}!`)
    } catch (err) {
      showToast(`Failed to update status: ${err.message}`, 'error')
    }
  }

  const handleAddCreateQuestion = () => {
    setCreateQuestions([
      ...createQuestions,
      { q: '', a: '', acceptable_answers: '', free_hint: '', hint: '', explanation: '', points: 10 }
    ])
  }

  const handleCreateQuestionChange = (i, field, val) => {
    const updated = [...createQuestions]
    updated[i][field] = val
    setCreateQuestions(updated)
  }

  const handleRemoveCreateQuestion = (i) => {
    if (createQuestions.length > 1) {
      setCreateQuestions(createQuestions.filter((_, idx) => idx !== i))
    }
  }

  const handleAnalyzeZipFile = async (selectedFile) => {
    const fileToAnalyze = selectedFile || createFile
    if (!fileToAnalyze) {
      showToast('Please select a .zip log archive first.', 'error')
      return
    }
    setIsAnalyzingZip(true)
    setCreateError('')
    try {
      const formData = new FormData()
      formData.append('file', fileToAnalyze)
      const res = await api.post('/admin/analyze-zip', formData, {
        headers: { 'Content-Type': 'multipart/form-data' },
      })
      const data = res.data
      const draft = data.draft

      setZipAnalysisReport(data)
      setCreateName(draft.name || '')
      setCreateDesc(draft.description || '')
      setCreateMitre(draft.mitre_technique || '')
      setCreateStatus(draft.status || 'Draft')
      setCreateAlertTitle(draft.alert_title || '')
      setCreateAlertSeverity(draft.alert_severity || 'High')
      setCreateSigmaRule(draft.sigma_rule || '')

      const adCtx = draft.ad_context || {}
      const targets = adCtx.containment_targets || {}
      setCreateContainmentHost(targets.isolate_host || '')
      setCreateContainmentUser(targets.disable_user || '')
      setCreateAdContext(JSON.stringify(adCtx, null, 2))

      if (draft.questions && draft.questions.length > 0) {
        setCreateQuestions(
          draft.questions.map((q) => ({
            q: q.question_text || '',
            a: q.correct_answer || '',
            acceptable_answers: Array.isArray(q.acceptable_answers) ? q.acceptable_answers.join(', ') : '',
            free_hint: q.free_hint || '',
            hint: q.hint || '',
            explanation: q.explanation || '',
            points: q.points || 10,
          }))
        )
      }
      showToast(
        `Analyzed ${data.total_events_in_archive.toLocaleString()} events! Review the draft below before saving.`
      )
    } catch (err) {
      setCreateError(err.response?.data?.detail || 'Failed to analyze ZIP archive')
      showToast(err.response?.data?.detail || 'ZIP analysis failed', 'error')
    } finally {
      setIsAnalyzingZip(false)
    }
  }

  // ATOMIC SCENARIO CREATION
  const handleCreateSubmit = async (e) => {
    e.preventDefault()
    setIsSubmitting(true)
    setCreateError('')
    setCreateSuccessData(null)

    try {
      setSubmitStep('Step 1/2: Atomically creating scenario, alert, Sigma rule, and questions...')
      let parsedAdContext = {}
      try {
        parsedAdContext = createAdContext.trim() ? JSON.parse(createAdContext) : {}
      } catch {
        throw new Error('Observed AD Environment JSON is not valid JSON.')
      }

      if (createContainmentHost.trim() || createContainmentUser.trim()) {
        parsedAdContext.containment_targets = {
          isolate_host: createContainmentHost.trim(),
          disable_user: createContainmentUser.trim(),
        }
      }

      const validQuestions = createQuestions
        .filter((q) => q.q.trim() && q.a.trim())
        .map((q) => ({
          question_text: q.q.trim(),
          correct_answer: q.a.trim(),
          acceptable_answers: typeof q.acceptable_answers === 'string'
            ? q.acceptable_answers.split(',').map((s) => s.trim()).filter(Boolean)
            : (q.acceptable_answers || []),
          free_hint: q.free_hint?.trim() || null,
          hint: q.hint?.trim() || null,
          explanation: q.explanation?.trim() || null,
          points: parseInt(q.points) || 10,
        }))

      const fullRes = await api.post('/admin/scenarios/full', {
        name: createName,
        description: createDesc,
        mitre_technique: createMitre,
        status: createStatus,
        alert_title: createAlertTitle || `Detection Alert: ${createName}`,
        alert_severity: createAlertSeverity,
        sigma_rule: createSigmaRule.trim() || null,
        ad_context: parsedAdContext,
        questions: validQuestions,
      })

      const scId = fullRes.data.id
      const totalPts = validQuestions.reduce((acc, q) => acc + q.points, 0)

      let logsInserted = 0
      if (createFile) {
        setSubmitStep('Step 2/2: Uploading and ingesting Windows Event logs archive...')
        const formData = new FormData()
        formData.append('file', createFile)
        const uploadRes = await api.post(`/admin/scenarios/${scId}/upload-logs`, formData, {
          headers: { 'Content-Type': 'multipart/form-data' },
        })
        logsInserted = uploadRes.data?.logs_inserted || 0
      }

      setCreateSuccessData({
        id: scId,
        name: createName,
        status: createStatus,
        mitre: createMitre,
        alertTitle: createAlertTitle,
        questionsCount: validQuestions.length,
        totalPoints: totalPts,
        logsCount: logsInserted,
      })

      showToast(`Scenario "${createName}" (${totalPts} pts) created atomically!`)

      setCreateName('')
      setCreateDesc('')
      setCreateMitre('')
      setCreateAlertTitle('')
      setCreateAlertSeverity('High')
      setCreateSigmaRule('')
      setCreateContainmentHost('')
      setCreateContainmentUser('')
      setCreateAdContext('{}')
      setZipAnalysisReport(null)
      setCreateQuestions([{ q: '', a: '', acceptable_answers: '', free_hint: '', hint: '', explanation: '', points: 10 }])
      setCreateFile(null)

      loadAdminData()
    } catch (err) {
      setCreateError(err.response?.data?.detail || err.message)
      showToast(`Creation failed: ${err.message}`, 'error')
    } finally {
      setIsSubmitting(false)
      setSubmitStep('')
    }
  }

  const openEditModal = async (scenario) => {
    setEditError('')
    setEditFile(null)
    setIsSavingEdit(false)
    try {
      const res = await api.get(`/admin/scenarios/${scenario.id}`)
      const detail = res.data
      setEditingScenario(detail)
      setEditName(detail.name)
      setEditDesc(detail.description)
      setEditMitre(detail.mitre_technique)
      setEditStatus(detail.status || 'Draft')
      setEditAlertTitle(detail.alert ? detail.alert.title : '')
      setEditAlertSeverity(detail.alert ? detail.alert.severity : 'High')
      setEditSigmaRule(detail.alert?.sigma_rule || '')

      const adCtx = detail.ad_context || {}
      const targets = adCtx.containment_targets || {}
      setEditContainmentHost(targets.isolate_host || '')
      setEditContainmentUser(targets.disable_user || '')
      setEditAdContext(JSON.stringify(adCtx, null, 2))

      setEditQuestions(
        detail.questions && detail.questions.length > 0
          ? detail.questions.map((q) => ({
              question_text: q.question_text || '',
              correct_answer: q.correct_answer || '',
              acceptable_answers: Array.isArray(q.acceptable_answers) ? q.acceptable_answers.join(', ') : (q.acceptable_answers || ''),
              free_hint: q.free_hint || '',
              hint: q.hint || '',
              explanation: q.explanation || '',
              points: q.points ?? 10,
            }))
          : [{ question_text: '', correct_answer: '', acceptable_answers: '', free_hint: '', hint: '', explanation: '', points: 10 }]
      )
    } catch (err) {
      showToast(`Failed to load scenario details: ${err.message}`, 'error')
    }
  }

  const handleSaveEdit = async (e) => {
    e.preventDefault()
    if (!editingScenario) return
    setIsSavingEdit(true)
    setEditError('')

    try {
      let parsedEditAdContext = {}
      try {
        parsedEditAdContext = editAdContext.trim() ? JSON.parse(editAdContext) : {}
      } catch {
        throw new Error('Observed AD Environment JSON is not valid JSON.')
      }

      if (editContainmentHost.trim() || editContainmentUser.trim()) {
        parsedEditAdContext.containment_targets = {
          isolate_host: editContainmentHost.trim(),
          disable_user: editContainmentUser.trim(),
        }
      }

      const payload = {
        name: editName,
        description: editDesc,
        mitre_technique: editMitre,
        status: editStatus,
        alert_title: editAlertTitle,
        alert_severity: editAlertSeverity,
        sigma_rule: editSigmaRule.trim() || null,
        ad_context: parsedEditAdContext,
        questions: editQuestions
          .filter((q) => q.question_text.trim() && q.correct_answer.trim())
          .map((q) => ({
            question_text: q.question_text.trim(),
            correct_answer: q.correct_answer.trim(),
            acceptable_answers: typeof q.acceptable_answers === 'string'
              ? q.acceptable_answers.split(',').map((s) => s.trim()).filter(Boolean)
              : (q.acceptable_answers || []),
            free_hint: q.free_hint?.trim() || null,
            hint: q.hint?.trim() || null,
            explanation: q.explanation?.trim() || null,
            points: parseInt(q.points) || 10,
          })),
      }
      await api.put(`/admin/scenarios/${editingScenario.id}/full`, payload)

      if (editFile) {
        const formData = new FormData()
        formData.append('file', editFile)
        await api.post(`/admin/scenarios/${editingScenario.id}/upload-logs`, formData, {
          headers: { 'Content-Type': 'multipart/form-data' },
        })
      }

      showToast(`Scenario "${editName}" updated successfully!`)
      setEditingScenario(null)
      loadAdminData()
    } catch (err) {
      setEditError(err.response?.data?.detail || err.message)
      showToast(`Failed to save: ${err.message}`, 'error')
    } finally {
      setIsSavingEdit(false)
    }
  }

  const handleDeleteScenario = async () => {
    if (!deletingScenario) return
    setIsDeleting(true)
    try {
      await api.delete(`/admin/scenarios/${deletingScenario.id}`)
      showToast(`Scenario "${deletingScenario.name}" was deleted!`)
      setDeletingScenario(null)
      loadAdminData()
    } catch (err) {
      showToast(`Failed to delete: ${err.message}`, 'error')
    } finally {
      setIsDeleting(false)
    }
  }

  const filteredScenarios = scenarios.filter((s) => {
    if (filterStatus === 'published' && s.status !== 'Published') return false
    if (filterStatus === 'draft' && s.status !== 'Draft') return false
    if (searchTerm) {
      const term = searchTerm.toLowerCase()
      const matchName = s.name.toLowerCase().includes(term)
      const matchMitre = s.mitre_technique.toLowerCase().includes(term)
      const matchDesc = s.description.toLowerCase().includes(term)
      if (!matchName && !matchMitre && !matchDesc) return false
    }
    return true
  })

  // Filtered submissions for trials tab
  const filteredSubmissions = submissions.filter(s => {
    if (!submissionsSearch) return true
    const term = submissionsSearch.toLowerCase()
    return (
      (s.username || '').toLowerCase().includes(term) ||
      (s.scenario_name || '').toLowerCase().includes(term) ||
      (s.mitre_technique || '').toLowerCase().includes(term)
    )
  })

  // Filtered users for user management tab
  const filteredUsers = users.filter(u => {
    if (userRoleFilter !== 'all' && u.role !== userRoleFilter) return false
    if (!usersSearch.trim()) return true
    const term = usersSearch.toLowerCase()
    return (
      (u.username || '').toLowerCase().includes(term) ||
      (u.role || '').toLowerCase().includes(term) ||
      String(u.id).includes(term)
    )
  })

  return (
    <div className="admin-page-container">
      {toast && (
        <div className={`admin-toast toast-${toast.type}`}>
          <span>{toast.message}</span>
          <button className="toast-close" onClick={() => setToast(null)}>×</button>
        </div>
      )}

      <div className="admin-header-strip">
        <div>
          <h2>
            <ShieldCheck size={22} style={{ verticalAlign: 'middle', marginRight: '8px' }} color="#00ffcc" />
            SOC Admin & Scenario Management
          </h2>
          <p className="admin-subtitle">
            Manage investigation training scenarios, ingest Windows Event logs, publish scenarios, manage Sigma rules, and manage trainee accounts.
          </p>
        </div>
        <div className="admin-nav-tabs">
          <button
            className={`admin-nav-btn ${activeTab === 'manage' ? 'active' : ''}`}
            onClick={() => setActiveTab('manage')}
          >
            <Layers size={16} style={{ verticalAlign: 'middle', marginRight: '6px' }} />
            Manage Scenarios ({scenarios.length})
          </button>
          <button
            className={`admin-nav-btn ${activeTab === 'create' ? 'active' : ''}`}
            onClick={() => {
              setActiveTab('create')
              setCreateSuccessData(null)
            }}
          >
            <PlusCircle size={16} style={{ verticalAlign: 'middle', marginRight: '6px' }} />
            Create New Scenario
          </button>
          <button
            className={`admin-nav-btn ${activeTab === 'trials' ? 'active' : ''}`}
            onClick={() => {
              setActiveTab('trials')
              loadSubmissions()
            }}
          >
            <Activity size={16} style={{ verticalAlign: 'middle', marginRight: '6px' }} />
            Analyst Trials & Guesses ({submissions.length})
          </button>
          <button
            className={`admin-nav-btn ${activeTab === 'users' ? 'active' : ''}`}
            onClick={() => {
              setActiveTab('users')
              loadUsers()
            }}
          >
            <Users size={16} style={{ verticalAlign: 'middle', marginRight: '6px' }} />
            User Management ({users.length})
          </button>
        </div>
      </div>

      {stats && (
        <div className="admin-stats-grid">
          <div className="stat-card">
            <span className="stat-label">Total Scenarios</span>
            <span className="stat-number">{stats.total_scenarios}</span>
          </div>
          <div className="stat-card stat-success">
            <span className="stat-label">Published (Live)</span>
            <span className="stat-number">{stats.published_scenarios}</span>
          </div>
          <div className="stat-card stat-warning">
            <span className="stat-label">Drafts</span>
            <span className="stat-number">{stats.draft_scenarios}</span>
          </div>
          <div className="stat-card stat-info">
            <span className="stat-label">Total Log Events</span>
            <span className="stat-number">{stats.total_logs.toLocaleString()}</span>
          </div>
          <div
            className="stat-card stat-users"
            onClick={() => {
              setActiveTab('users')
              loadUsers()
            }}
            style={{ cursor: 'pointer' }}
            title="Click to view all registered users"
          >
            <span className="stat-label">Registered Users</span>
            <span className="stat-number">
              {stats.total_users !== undefined ? stats.total_users : users.length}
            </span>
          </div>
        </div>
      )}

      {activeTab === 'manage' && (
        <div className="admin-manage-section">
          <div className="manage-controls-bar">
            <div className="filter-group">
              <button
                className={`filter-btn ${filterStatus === 'all' ? 'active' : ''}`}
                onClick={() => setFilterStatus('all')}
              >
                All ({scenarios.length})
              </button>
              <button
                className={`filter-btn ${filterStatus === 'published' ? 'active' : ''}`}
                onClick={() => setFilterStatus('published')}
              >
                Published ({scenarios.filter((s) => s.status === 'Published').length})
              </button>
              <button
                className={`filter-btn ${filterStatus === 'draft' ? 'active' : ''}`}
                onClick={() => setFilterStatus('draft')}
              >
                Drafts ({scenarios.filter((s) => s.status === 'Draft').length})
              </button>
            </div>
            <div className="search-wrap">
              <input
                type="text"
                placeholder="Search scenarios or MITRE ID..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="admin-search-input"
              />
            </div>
          </div>

          {loadingScenarios ? (
            <div className="loading">Loading scenarios...</div>
          ) : filteredScenarios.length === 0 ? (
            <div className="empty-scenarios-card">
              <p>No scenarios found matching your criteria.</p>
              <button className="btn btn-primary" onClick={() => setActiveTab('create')}>
                + Create a Scenario Now
              </button>
            </div>
          ) : (
            <div className="scenario-admin-grid">
              {filteredScenarios.map((sc) => (
                <div key={sc.id} className="scenario-admin-card">
                  <div className="sc-card-top">
                    <div className="sc-header-row">
                      <div className="sc-title-block">
                        <span className="sc-id-badge">#{sc.id}</span>
                        <h3>{sc.name}</h3>
                      </div>
                      <span className={`status-pill ${sc.status === 'Published' ? 'status-published' : 'status-draft'}`}>
                        {sc.status}
                      </span>
                    </div>
                    <div className="sc-badges-row">
                      <span className="mitre-badge">{sc.mitre_technique}</span>
                      {sc.alert && (
                        <span className={`severity-badge-sm severity-${sc.alert.severity?.toLowerCase()}`}>
                          {sc.alert.severity} Severity
                        </span>
                      )}
                      <span className="metric-chip">
                        <FileText size={13} style={{ verticalAlign: 'middle', marginRight: '4px' }} />
                        {sc.logs_count} Logs
                      </span>
                      <span className="metric-chip">
                        <HelpCircle size={13} style={{ verticalAlign: 'middle', marginRight: '4px' }} />
                        {sc.questions_count} Questions
                      </span>
                    </div>
                    <p className="sc-card-desc">{sc.description}</p>
                    {sc.alert && (
                      <div className="sc-alert-preview">
                        <strong>Alert:</strong> {sc.alert.title}
                      </div>
                    )}
                  </div>
                  <div className="sc-card-actions">
                    <button
                      className={`btn-action ${sc.status === 'Published' ? 'btn-unpublish' : 'btn-publish'}`}
                      onClick={() => handleToggleStatus(sc)}
                    >
                      {sc.status === 'Published' ? 'Set as Draft' : 'Publish Scenario'}
                    </button>
                    <button className="btn-action btn-edit" onClick={() => openEditModal(sc)}>
                      <Edit3 size={13} style={{ verticalAlign: 'middle', marginRight: '4px' }} />
                      Edit
                    </button>
                    <Link to={`/investigate/${sc.id}`} className="btn-action btn-preview">
                      Preview
                    </Link>
                    <button className="btn-action btn-delete" onClick={() => setDeletingScenario(sc)}>
                      <Trash2 size={13} style={{ verticalAlign: 'middle', marginRight: '4px' }} />
                      Delete
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {activeTab === 'create' && (
        <div className="admin-form-panel">
          {createSuccessData && (
            <div className="scenario-creation-success-box">
              <div className="success-banner-header">
                <CheckCircle2 size={32} color="#4ade80" />
                <div>
                  <h3>Scenario "{createSuccessData.name}" Created Atomically!</h3>
                  <p>
                    {createSuccessData.questionsCount} questions ({createSuccessData.totalPoints} pts) •{' '}
                    {createSuccessData.logsCount} events ingested.
                  </p>
                </div>
              </div>
              <div className="success-actions-row">
                <Link to={`/investigate/${createSuccessData.id}`} className="btn btn-primary">
                  Launch Scenario →
                </Link>
                <button className="btn btn-secondary" onClick={() => setActiveTab('manage')}>
                  Back to Scenario Manager
                </button>
              </div>
            </div>
          )}

          {createError && <div className="admin-error-box">{createError}</div>}
          {isSubmitting && (
            <div className="submission-progress-box">
              <div className="spinner" />
              <span>{submitStep}</span>
            </div>
          )}

          <form onSubmit={handleCreateSubmit}>
            {/* STEP 0: EVIDENCE-DRIVEN ZIP AUTO-ANALYZER */}
            <div className="form-section-card" style={{ borderColor: 'rgba(0, 255, 204, 0.35)' }}>
              <div className="section-title">
                <span className="step-num" style={{ background: '#00ffcc', color: '#0f172a' }}>⚡</span>
                <div>
                  <h4>Evidence-Driven .ZIP Log Analyzer & Draft Generator</h4>
                  <p style={{ fontSize: '0.82rem', color: 'var(--text-dim)', margin: 0 }}>
                    Upload a Windows Event / Sysmon .zip archive to scan 100% of events, extract observed Active Directory telemetry, and auto-populate an evidence-backed scenario draft for your review.
                  </p>
                </div>
              </div>

              <div style={{ display: 'flex', gap: 12, alignItems: 'center', flexWrap: 'wrap', marginTop: 10 }}>
                <input
                  type="file"
                  accept=".zip"
                  onChange={(e) => {
                    const f = e.target.files[0] || null
                    setCreateFile(f)
                    setZipAnalysisReport(null)
                    if (f) handleAnalyzeZipFile(f)
                  }}
                />
                <button
                  type="button"
                  className="btn btn-primary btn-sm"
                  disabled={!createFile || isAnalyzingZip}
                  onClick={() => handleAnalyzeZipFile(createFile)}
                >
                  {isAnalyzingZip ? 'Scanning Entire Archive...' : '⚡ Analyze .ZIP & Populate Draft'}
                </button>
              </div>

              {zipAnalysisReport && (
                <div style={{ marginTop: 14, padding: 14, background: 'rgba(15, 23, 42, 0.75)', borderRadius: 8, border: '1px solid rgba(56, 189, 248, 0.3)' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', flexWrap: 'wrap', gap: 8, marginBottom: 8 }}>
                    <strong style={{ color: '#38bdf8' }}>
                      📊 Telemetry Report: {zipAnalysisReport.total_events_in_archive.toLocaleString()} total events analyzed → {zipAnalysisReport.curated_events_count} curated ({zipAnalysisReport.key_evidence_count} key evidence)
                    </strong>
                    <span className="status-pill status-published" style={{ fontSize: '0.75rem' }}>
                      {zipAnalysisReport.confidence}
                    </span>
                  </div>
                  <ul style={{ margin: '6px 0', paddingLeft: 18, fontSize: '0.83rem', color: '#e2e8f0' }}>
                    {zipAnalysisReport.evidence_summary.map((item, i) => (
                      <li key={i}>{item}</li>
                    ))}
                  </ul>
                  {zipAnalysisReport.caveats?.length > 0 && (
                    <div style={{ marginTop: 8, fontSize: '0.8rem', color: '#fbbf24' }}>
                      <strong>⚠️ Analyst Review Note:</strong> {zipAnalysisReport.caveats.join(' ')}
                    </div>
                  )}
                </div>
              )}
            </div>

            <div className="form-section-card">
              <div className="section-title">
                <span className="step-num">1</span>
                <h4>Scenario Metadata & MITRE Mapping</h4>
              </div>
              <div className="form-row">
                <div className="form-field flex-2">
                  <label>Scenario Name</label>
                  <input
                    className="admin-input"
                    value={createName}
                    onChange={(e) => setCreateName(e.target.value)}
                    placeholder="e.g., Golden Ticket Forgery"
                    required
                  />
                </div>
                <div className="form-field flex-1">
                  <label>MITRE Technique ID</label>
                  <input
                    className="admin-input"
                    value={createMitre}
                    onChange={(e) => setCreateMitre(e.target.value)}
                    placeholder="e.g., T1558.001"
                    required
                  />
                </div>
                <div className="form-field flex-1">
                  <label>Visibility Status</label>
                  <select
                    className="admin-input"
                    value={createStatus}
                    onChange={(e) => setCreateStatus(e.target.value)}
                  >
                    <option value="Published">Published</option>
                    <option value="Draft">Draft</option>
                  </select>
                </div>
              </div>
              <div className="form-field">
                <label>Briefing Description</label>
                <textarea
                  className="admin-input"
                  rows={3}
                  value={createDesc}
                  onChange={(e) => setCreateDesc(e.target.value)}
                  required
                />
              </div>
            </div>

            <div className="form-section-card">
              <div className="section-title">
                <span className="step-num">2</span>
                <h4>Triggered SIEM Alert & Static Sigma Detection Rule</h4>
              </div>
              <div className="form-row">
                <div className="form-field flex-3">
                  <label>Alert Title</label>
                  <input
                    className="admin-input"
                    value={createAlertTitle}
                    onChange={(e) => setCreateAlertTitle(e.target.value)}
                    placeholder="High Severity: Suspicious Kerberos Ticket Lifetime"
                    required
                  />
                </div>
                <div className="form-field flex-1">
                  <label>Severity</label>
                  <select
                    className="admin-input"
                    value={createAlertSeverity}
                    onChange={(e) => setCreateAlertSeverity(e.target.value)}
                  >
                    <option value="Low">Low</option>
                    <option value="Medium">Medium</option>
                    <option value="High">High</option>
                    <option value="Critical">Critical</option>
                  </select>
                </div>
              </div>
              <div className="form-field">
                <label>Sigma Detection Rule YAML (Optional — shown to trainees in workbench)</label>
                <textarea
                  className="admin-input"
                  rows={5}
                  style={{ fontFamily: 'monospace', fontSize: '0.82rem' }}
                  value={createSigmaRule}
                  onChange={(e) => setCreateSigmaRule(e.target.value)}
                  placeholder="title: Suspicious Activity&#10;detection:&#10;  selection:&#10;    EventID: 4624"
                />
              </div>
              <div className="form-field" style={{ marginTop: 12 }}>
                <label>Observed Active Directory & Telemetry Context JSON (Auto-extracted from logs — editable)</label>
                <textarea
                  className="admin-input"
                  rows={6}
                  style={{ fontFamily: 'monospace', fontSize: '0.8rem' }}
                  value={createAdContext}
                  onChange={(e) => setCreateAdContext(e.target.value)}
                />
              </div>

              {/* Containment Targets Control */}
              <div className="form-row" style={{ marginTop: 12, padding: 12, background: 'rgba(245, 158, 11, 0.06)', border: '1px solid rgba(245, 158, 11, 0.25)', borderRadius: 8 }}>
                <div style={{ width: '100%', marginBottom: 4 }}>
                  <strong style={{ color: '#fbbf24', fontSize: '0.86rem' }}>
                    🛡️ Incident Containment Playbook Targets (Controls Analyst Containment Box)
                  </strong>
                  <p style={{ fontSize: '0.78rem', color: 'var(--text-dim)', margin: 0 }}>
                    Specify which compromised host and user account the analyst should quarantine at the end of the investigation (auto-filled when analyzing a .zip, or leave blank to disable containment grading).
                  </p>
                </div>
                <div className="form-field flex-1" style={{ marginBottom: 0 }}>
                  <label>Expected Host to Isolate (e.g. MORDORDC.theshire.local)</label>
                  <input
                    className="admin-input"
                    value={createContainmentHost}
                    onChange={(e) => setCreateContainmentHost(e.target.value)}
                    placeholder="Optional: Hostname to isolate"
                  />
                </div>
                <div className="form-field flex-1" style={{ marginBottom: 0 }}>
                  <label>Expected Compromised Account to Disable (e.g. pgustavo)</label>
                  <input
                    className="admin-input"
                    value={createContainmentUser}
                    onChange={(e) => setCreateContainmentUser(e.target.value)}
                    placeholder="Optional: Username to disable"
                  />
                </div>
              </div>
            </div>

            <div className="form-section-card">
              <div className="section-title">
                <span className="step-num">3</span>
                <h4>Investigation Questions, Hints & Acceptable Aliases</h4>
              </div>
              {createQuestions.map((q, idx) => (
                <div key={idx} style={{ marginBottom: 16, padding: 14, background: 'rgba(255,255,255,0.02)', borderRadius: 8, border: '1px solid var(--border)' }}>
                  <div className="question-input-row">
                    <span className="q-index-pill">Q{idx + 1}</span>
                    <input
                      className="admin-input flex-2"
                      placeholder="Question prompt..."
                      value={q.q}
                      onChange={(e) => handleCreateQuestionChange(idx, 'q', e.target.value)}
                      required
                    />
                    <input
                      className="admin-input flex-1"
                      placeholder="Canonical Answer..."
                      value={q.a}
                      onChange={(e) => handleCreateQuestionChange(idx, 'a', e.target.value)}
                      required
                    />
                    <input
                      type="number"
                      className="admin-input"
                      style={{ width: 80 }}
                      title="Question Points"
                      value={q.points}
                      onChange={(e) => handleCreateQuestionChange(idx, 'points', e.target.value)}
                    />
                    <button
                      type="button"
                      className="btn-remove-q"
                      onClick={() => handleRemoveCreateQuestion(idx)}
                    >
                      ×
                    </button>
                  </div>

                  <div className="form-row" style={{ marginTop: 8, marginBottom: 8 }}>
                    <div className="form-field flex-1" style={{ marginBottom: 0 }}>
                      <label style={{ fontSize: '0.76rem', color: '#94a3b8' }}>Acceptable Answer Aliases (comma-separated)</label>
                      <input
                        className="admin-input"
                        placeholder="e.g., corp\svc_backup, svc_backup@corp.local"
                        value={q.acceptable_answers || ''}
                        onChange={(e) => handleCreateQuestionChange(idx, 'acceptable_answers', e.target.value)}
                      />
                    </div>
                    <div className="form-field flex-1" style={{ marginBottom: 0 }}>
                      <label style={{ fontSize: '0.76rem', color: '#34d399' }}>🎁 Free Starter Hint (0 pts penalty)</label>
                      <input
                        className="admin-input"
                        placeholder="Starter pointer shown when trainee clicks Free Hint..."
                        value={q.free_hint || ''}
                        onChange={(e) => handleCreateQuestionChange(idx, 'free_hint', e.target.value)}
                      />
                    </div>
                  </div>

                  <div className="form-row" style={{ marginBottom: 0 }}>
                    <div className="form-field flex-1" style={{ marginBottom: 0 }}>
                      <label style={{ fontSize: '0.76rem', color: '#fbbf24' }}>💡 Paid Forensic Hint (-15 pts penalty, unlocks after 2 wrong tries)</label>
                      <input
                        className="admin-input"
                        placeholder="Detailed forensic walkthrough hint..."
                        value={q.hint || ''}
                        onChange={(e) => handleCreateQuestionChange(idx, 'hint', e.target.value)}
                      />
                    </div>
                    <div className="form-field flex-1" style={{ marginBottom: 0 }}>
                      <label style={{ fontSize: '0.76rem', color: '#60a5fa' }}>📋 Post-Submission Debrief Explanation</label>
                      <input
                        className="admin-input"
                        placeholder="Shown on Report page after grading..."
                        value={q.explanation || ''}
                        onChange={(e) => handleCreateQuestionChange(idx, 'explanation', e.target.value)}
                      />
                    </div>
                  </div>
                </div>
              ))}
              <button type="button" className="btn btn-secondary btn-sm" onClick={handleAddCreateQuestion}>
                + Add Question
              </button>
            </div>

            <div className="form-section-card">
              <div className="section-title">
                <span className="step-num">4</span>
                <h4>Windows Event Log Dataset (.zip)</h4>
              </div>
              <div className="file-upload-zone">
                <input
                  type="file"
                  accept=".zip"
                  onChange={(e) => setCreateFile(e.target.files[0] || null)}
                />
                {createFile && <div className="selected-file-info">Selected: {createFile.name}</div>}
              </div>
            </div>

            <div className="form-actions-bar">
              <button type="submit" className="btn btn-primary btn-lg" disabled={isSubmitting}>
                {isSubmitting ? 'Creating Scenario...' : 'Create Scenario Atomically'}
              </button>
            </div>
          </form>
        </div>
      )}

      {/* ── TAB 3: ANALYST TRIALS & GUESSES ───────────────────────────────── */}
      {activeTab === 'trials' && (
        <div className="admin-manage-section">
          <div className="manage-controls-bar">
            <div className="search-wrap" style={{ flex: 1 }}>
              <input
                type="text"
                placeholder="Search trainee username, scenario, or MITRE technique..."
                value={submissionsSearch}
                onChange={e => setSubmissionsSearch(e.target.value)}
                className="admin-search-input"
              />
            </div>
            <button
              className="btn btn-secondary btn-sm"
              onClick={loadSubmissions}
              disabled={loadingSubmissions}
            >
              <RefreshCw size={14} style={{ verticalAlign: 'middle', marginRight: '6px' }} />
              Refresh Submissions
            </button>
          </div>

          {loadingSubmissions ? (
            <div className="loading">Loading analyst trial records...</div>
          ) : filteredSubmissions.length === 0 ? (
            <div className="empty-scenarios-card">
              <p>No analyst submissions recorded yet.</p>
            </div>
          ) : (
            <div className="admin-submissions-table-wrap">
              <table className="admin-submissions-table">
                <thead>
                  <tr>
                    <th>Trainee</th>
                    <th>Scenario</th>
                    <th>MITRE ID</th>
                    <th>Score</th>
                    <th>Points</th>
                    <th>Trials</th>
                    <th>Hints Used</th>
                    <th>Submitted At</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredSubmissions.map((sub) => (
                    <tr key={sub.id}>
                      <td>
                        <div className="analyst-cell">
                          <span className="analyst-avatar">
                            {sub.user_role === 'admin' ? <ShieldCheck size={14} color="#60a5fa" /> : <User size={14} />}
                          </span>
                          <strong>{sub.username}</strong>
                        </div>
                      </td>
                      <td>
                        <span className="scenario-name-cell">{sub.scenario_name}</span>
                      </td>
                      <td>
                        <span className="db-mitre-badge">{sub.mitre_technique}</span>
                      </td>
                      <td>
                        {sub.status === 'In Progress' ? (
                          <span className="score-badge medium" style={{ background: 'rgba(245, 158, 11, 0.15)', color: '#f59e0b', border: '1px solid rgba(245, 158, 11, 0.4)' }}>
                            In Progress
                          </span>
                        ) : (
                          <span className={`score-badge ${sub.score >= 80 ? 'high' : sub.score >= 50 ? 'medium' : 'low'}`}>
                            {sub.score}%
                          </span>
                        )}
                      </td>
                      <td>
                        {sub.status === 'In Progress' ? (
                          <span style={{ color: '#94a3b8' }}>Active Session</span>
                        ) : (
                          <><strong>{sub.points_earned}</strong> / {sub.total_points} pts</>
                        )}
                      </td>
                      <td>
                        <span className="trials-count-badge">
                          <Activity size={12} />
                          {sub.trials_count} attempt{sub.trials_count !== 1 ? 's' : ''}
                        </span>
                      </td>
                      <td>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '3px' }}>
                          {sub.hints_used && sub.hints_used.length > 0 ? (
                            <span className="hint-used-tag">
                              <Lightbulb size={12} />
                              {sub.hints_used.length} paid (-{sub.hint_penalty} pts)
                            </span>
                          ) : (
                            <span className="hint-none-tag">0 paid hints</span>
                          )}
                          {sub.free_hint_id && (
                            <span style={{ fontSize: '0.72rem', color: '#34d399', display: 'inline-flex', alignItems: 'center', gap: '3px' }}>
                              🎁 Free Hint Q#{sub.free_hint_id}
                            </span>
                          )}
                        </div>
                      </td>
                      <td>
                        <span className="date-sub-text">
                          {sub.status === 'In Progress' ? (
                            <span style={{ color: '#f59e0b', fontWeight: 600 }}>Active Now</span>
                          ) : sub.submitted_at ? (
                            new Date(sub.submitted_at).toLocaleString()
                          ) : (
                            'Recent'
                          )}
                        </span>
                      </td>
                      <td>
                        <button
                          type="button"
                          className="btn-inspect-guesses"
                          onClick={() => setSelectedSubmission(sub)}
                          title="Inspect trainee guesses and forensic thought process"
                        >
                          <Eye size={13} style={{ verticalAlign: 'middle', marginRight: 4 }} />
                          Inspect Guesses
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* ── MODAL: INSPECT FORENSIC GUESSES & TRIALS ───────────────────────── */}
      {selectedSubmission && (
        <div className="modal-backdrop">
          <div className="modal-card modal-lg">
            <div className="modal-header">
              <h3>
                <Search size={18} color="#60a5fa" style={{ verticalAlign: 'middle', marginRight: '8px' }} />
                Analyst Guesses & Trial History: {selectedSubmission.username}
              </h3>
              <button
                className="modal-close-btn"
                onClick={() => setSelectedSubmission(null)}
              >
                <X size={18} />
              </button>
            </div>

            <div className="modal-body">
              <div className="submission-summary-bar">
                <div>Scenario: <strong>{selectedSubmission.scenario_name}</strong></div>
                <div>Status: <strong style={{ color: selectedSubmission.status === 'In Progress' ? '#f59e0b' : '#34d399' }}>{selectedSubmission.status || 'Completed'}</strong></div>
                {selectedSubmission.status !== 'In Progress' && (
                  <div>Score: <strong>{selectedSubmission.score}% ({selectedSubmission.points_earned}/{selectedSubmission.total_points} pts)</strong></div>
                )}
                <div>Total Attempts: <strong>{selectedSubmission.trials_count}</strong></div>
                <div>Hints Used: <strong>{selectedSubmission.hints_used?.length || 0} (-{selectedSubmission.hint_penalty || 0} pts)</strong></div>
              </div>

              <div className="guesses-list-section">
                <h4>Forensic Trials & Guesses Breakdown</h4>
                {selectedSubmission.user_guesses && Object.keys(selectedSubmission.user_guesses).length > 0 ? (
                  Object.entries(selectedSubmission.user_guesses).map(([qKey, guesses], idx) => (
                    <div key={idx} className="guess-item-card">
                      <div className="guess-item-header">
                        <span className="guess-q-tag">Question #{qKey}</span>
                        <span className="guess-attempts-count">{guesses.length} attempt{guesses.length > 1 ? 's' : ''}</span>
                      </div>
                      <div className="guess-attempts-trail">
                        {guesses.map((g, gIdx) => (
                          <div key={gIdx} className="guess-pill-row">
                            <span className="attempt-step-num">Trial {gIdx + 1}:</span>
                            <code className="guess-code-text">{g || '(Empty submission)'}</code>
                          </div>
                        ))}
                      </div>
                    </div>
                  ))
                ) : (
                  <p className="empty-guesses-text">
                    This submission was finalized in a single direct report trial without per-question check history.
                  </p>
                )}
              </div>
            </div>

            <div className="modal-footer">
              <button
                type="button"
                className="btn btn-secondary"
                onClick={() => setSelectedSubmission(null)}
              >
                Close Inspector
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ── TAB 4: USER MANAGEMENT ────────────────────────────────────────── */}
      {activeTab === 'users' && (
        <div className="admin-manage-section">
          {/* User Metrics Summary Cards */}
          <div className="user-metrics-strip">
            <div className="user-metric-card">
              <div className="user-metric-icon">
                <Users size={20} color="#38bdf8" />
              </div>
              <div className="user-metric-content">
                <span className="user-metric-num">{users.length}</span>
                <span className="user-metric-lbl">Total Registered Users</span>
              </div>
            </div>

            <div className="user-metric-card">
              <div className="user-metric-icon" style={{ background: 'rgba(56, 189, 248, 0.1)' }}>
                <User size={20} color="#38bdf8" />
              </div>
              <div className="user-metric-content">
                <span className="user-metric-num">{users.filter(u => u.role === 'user').length}</span>
                <span className="user-metric-lbl">SOC Trainees / Analysts</span>
              </div>
            </div>

            <div className="user-metric-card">
              <div className="user-metric-icon" style={{ background: 'rgba(168, 85, 247, 0.1)' }}>
                <ShieldAlert size={20} color="#c084fc" />
              </div>
              <div className="user-metric-content">
                <span className="user-metric-num">{users.filter(u => u.role === 'admin').length}</span>
                <span className="user-metric-lbl">System Administrators</span>
              </div>
            </div>

            <div className="user-metric-card">
              <div className="user-metric-icon" style={{ background: 'rgba(16, 185, 129, 0.1)' }}>
                <Activity size={20} color="#10b981" />
              </div>
              <div className="user-metric-content">
                <span className="user-metric-num">{users.filter(u => (u.submissions_count || 0) > 0).length}</span>
                <span className="user-metric-lbl">Active Investigators</span>
              </div>
            </div>
          </div>

          {/* Controls Bar */}
          <div className="manage-controls-bar">
            <div className="filter-group">
              <button
                className={`filter-btn ${userRoleFilter === 'all' ? 'active' : ''}`}
                onClick={() => setUserRoleFilter('all')}
              >
                All Users ({users.length})
              </button>
              <button
                className={`filter-btn ${userRoleFilter === 'user' ? 'active' : ''}`}
                onClick={() => setUserRoleFilter('user')}
              >
                Trainees ({users.filter(u => u.role === 'user').length})
              </button>
              <button
                className={`filter-btn ${userRoleFilter === 'admin' ? 'active' : ''}`}
                onClick={() => setUserRoleFilter('admin')}
              >
                Admins ({users.filter(u => u.role === 'admin').length})
              </button>
            </div>

            <div className="search-wrap" style={{ flex: 1, minWidth: '220px' }}>
              <input
                type="text"
                placeholder="Search username, role, or user ID..."
                value={usersSearch}
                onChange={e => setUsersSearch(e.target.value)}
                className="admin-search-input"
              />
            </div>

            <button
              className="btn btn-secondary btn-sm"
              onClick={loadUsers}
              disabled={loadingUsers}
              title="Refresh users list"
            >
              <RefreshCw size={14} style={{ verticalAlign: 'middle', marginRight: '6px' }} />
              Refresh
            </button>

            <button
              className="btn btn-primary btn-sm btn-add-user"
              onClick={() => {
                setShowAddUserModal(true)
                setAddUserError('')
                setNewUsername('')
                setNewPassword('')
                setNewRole('user')
              }}
            >
              <UserPlus size={15} style={{ verticalAlign: 'middle', marginRight: '6px' }} />
              Add New User
            </button>
          </div>

          {/* Users Table */}
          {loadingUsers ? (
            <div className="loading">Loading registered users...</div>
          ) : filteredUsers.length === 0 ? (
            <div className="empty-scenarios-card">
              <p>No registered users found matching your search.</p>
              <button
                className="btn btn-primary"
                onClick={() => setShowAddUserModal(true)}
              >
                + Register First User
              </button>
            </div>
          ) : (
            <div className="admin-submissions-table-wrap">
              <table className="admin-submissions-table users-table">
                <thead>
                  <tr>
                    <th>User ID</th>
                    <th>Username</th>
                    <th>Role</th>
                    <th>Registered Date</th>
                    <th>Investigations</th>
                    <th>Points Earned</th>
                    <th>Avg Score</th>
                    <th>Admin Controls</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredUsers.map((u) => {
                    const isSelf = currentAdmin && (currentAdmin.id === u.id || currentAdmin.username === u.username)
                    const regDateStr = u.created_at
                      ? new Date(u.created_at).toLocaleString(undefined, {
                          year: 'numeric',
                          month: 'short',
                          day: 'numeric',
                          hour: '2-digit',
                          minute: '2-digit',
                        })
                      : 'Initial Setup'

                    return (
                      <tr key={u.id} className={isSelf ? 'user-row-self' : ''}>
                        <td>
                          <span className="user-id-chip">#{u.id}</span>
                        </td>
                        <td>
                          <div className="analyst-cell">
                            <span className={`analyst-avatar ${u.role === 'admin' ? 'avatar-admin' : 'avatar-trainee'}`}>
                              {u.role === 'admin' ? <ShieldCheck size={14} color="#a855f7" /> : <User size={14} color="#38bdf8" />}
                            </span>
                            <div className="user-name-box">
                              <strong>{u.username}</strong>
                              {isSelf && <span className="self-badge">You (Active)</span>}
                            </div>
                          </div>
                        </td>
                        <td>
                          <span className={`user-role-badge ${u.role === 'admin' ? 'role-admin' : 'role-user'}`}>
                            {u.role === 'admin' ? 'Administrator' : 'SOC Trainee'}
                          </span>
                        </td>
                        <td>
                          <div className="reg-date-cell">
                            <Calendar size={13} style={{ verticalAlign: 'middle', marginRight: '6px', color: '#94a3b8' }} />
                            <span>{regDateStr}</span>
                          </div>
                        </td>
                        <td>
                          <span className="investigations-count-badge">
                            {u.submissions_count || 0} completed
                          </span>
                        </td>
                        <td>
                          <strong className="user-pts-text">{u.total_points || 0} pts</strong>
                        </td>
                        <td>
                          <span className={`score-badge ${(u.average_score || 0) >= 80 ? 'high' : (u.average_score || 0) >= 50 ? 'medium' : 'low'}`}>
                            {u.average_score || 0}%
                          </span>
                        </td>
                        <td>
                          <div className="user-actions-cluster">
                            <button
                              type="button"
                              className="btn btn-secondary btn-xs"
                              onClick={() => handleToggleUserRole(u)}
                              disabled={isSelf}
                              title={isSelf ? "Cannot change your own role" : `Switch to ${u.role === 'admin' ? 'Trainee' : 'Admin'}`}
                            >
                              <ShieldCheck size={12} style={{ marginRight: '4px' }} />
                              {u.role === 'admin' ? 'Demote' : 'Promote'}
                            </button>

                            <button
                              type="button"
                              className="btn btn-secondary btn-xs"
                              onClick={() => {
                                setUserToResetPassword(u)
                                setResetNewPassword('')
                                setResetPasswordError('')
                              }}
                              title="Reset user password"
                            >
                              <Key size={12} style={{ marginRight: '4px' }} />
                              Reset PW
                            </button>

                            <button
                              type="button"
                              className="btn btn-danger btn-xs"
                              onClick={() => setUserToDelete(u)}
                              disabled={isSelf}
                              title={isSelf ? "Cannot delete your own active account" : "Delete user"}
                            >
                              <Trash2 size={12} />
                            </button>
                          </div>
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* ── MODAL: EDIT SCENARIO ────────────────────────────────────────────── */}
      {editingScenario && (
        <div className="modal-backdrop">
          <div className="modal-card">
            <div className="modal-header">
              <h3>Edit Scenario #{editingScenario.id}</h3>
              <button className="modal-close-btn" onClick={() => setEditingScenario(null)}>×</button>
            </div>
            <form onSubmit={handleSaveEdit} className="modal-form">
              <div className="modal-scroll-area">
                {editError && <div className="admin-error-box">{editError}</div>}
                <div className="form-field">
                  <label>Scenario Name</label>
                  <input className="admin-input" value={editName} onChange={(e) => setEditName(e.target.value)} required />
                </div>
                <div className="form-row">
                  <div className="form-field flex-1">
                    <label>MITRE ID</label>
                    <input className="admin-input" value={editMitre} onChange={(e) => setEditMitre(e.target.value)} required />
                  </div>
                  <div className="form-field flex-1">
                    <label>Status</label>
                    <select className="admin-input" value={editStatus} onChange={(e) => setEditStatus(e.target.value)}>
                      <option value="Published">Published</option>
                      <option value="Draft">Draft</option>
                    </select>
                  </div>
                </div>
                <div className="form-field">
                  <label>Description</label>
                  <textarea className="admin-input" rows={3} value={editDesc} onChange={(e) => setEditDesc(e.target.value)} required />
                </div>
                <div className="form-row">
                  <div className="form-field flex-2">
                    <label>Alert Title</label>
                    <input className="admin-input" value={editAlertTitle} onChange={(e) => setEditAlertTitle(e.target.value)} />
                  </div>
                  <div className="form-field flex-1">
                    <label>Severity</label>
                    <select className="admin-input" value={editAlertSeverity} onChange={(e) => setEditAlertSeverity(e.target.value)}>
                      <option value="Low">Low</option>
                      <option value="Medium">Medium</option>
                      <option value="High">High</option>
                      <option value="Critical">Critical</option>
                    </select>
                  </div>
                </div>
                <div className="form-field">
                  <label>Sigma Rule (YAML)</label>
                  <textarea
                    className="admin-input"
                    rows={4}
                    style={{ fontFamily: 'monospace', fontSize: '0.8rem' }}
                    value={editSigmaRule}
                    onChange={(e) => setEditSigmaRule(e.target.value)}
                  />
                </div>
                <div className="form-field" style={{ marginTop: 12 }}>
                  <label>Observed Active Directory & Telemetry Context JSON (editable)</label>
                  <textarea
                    className="admin-input"
                    rows={6}
                    style={{ fontFamily: 'monospace', fontSize: '0.8rem' }}
                    value={editAdContext}
                    onChange={(e) => setEditAdContext(e.target.value)}
                  />
                </div>

                {/* Edit Containment Targets Control */}
                <div className="form-row" style={{ marginTop: 12, padding: 12, background: 'rgba(245, 158, 11, 0.06)', border: '1px solid rgba(245, 158, 11, 0.25)', borderRadius: 8 }}>
                  <div style={{ width: '100%', marginBottom: 4 }}>
                    <strong style={{ color: '#fbbf24', fontSize: '0.86rem' }}>
                      🛡️ Incident Containment Playbook Targets (Controls Analyst Containment Box)
                    </strong>
                    <p style={{ fontSize: '0.78rem', color: 'var(--text-dim)', margin: 0 }}>
                      Specify which compromised host and user account the analyst should quarantine at the end of the investigation (or leave blank to disable containment grading).
                    </p>
                  </div>
                  <div className="form-field flex-1" style={{ marginBottom: 0 }}>
                    <label>Expected Host to Isolate (e.g. MORDORDC.theshire.local)</label>
                    <input
                      className="admin-input"
                      value={editContainmentHost}
                      onChange={(e) => setEditContainmentHost(e.target.value)}
                      placeholder="Optional: Hostname to isolate"
                    />
                  </div>
                  <div className="form-field flex-1" style={{ marginBottom: 0 }}>
                    <label>Expected Compromised Account to Disable (e.g. pgustavo)</label>
                    <input
                      className="admin-input"
                      value={editContainmentUser}
                      onChange={(e) => setEditContainmentUser(e.target.value)}
                      placeholder="Optional: Username to disable"
                    />
                  </div>
                </div>

                {/* ── Edit Questions ─────────────────────────────── */}
                <div className="form-section-card" style={{ marginTop: 16 }}>
                  <div className="section-title">
                    <span className="step-num">Q</span>
                    <h4>Investigation Questions, Hints & Acceptable Aliases</h4>
                  </div>
                  {editQuestions.map((q, i) => (
                    <div key={i} className="question-block" style={{ marginBottom: 14, padding: '14px', background: 'rgba(255,255,255,0.04)', borderRadius: 8, border: '1px solid rgba(255,255,255,0.08)' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
                        <span style={{ fontSize: '0.78rem', color: '#94a3b8', fontWeight: 600 }}>Question {i + 1}</span>
                        <button
                          type="button"
                          className="btn btn-danger btn-xs"
                          onClick={() => setEditQuestions(editQuestions.filter((_, idx) => idx !== i))}
                          disabled={editQuestions.length <= 1}
                          title="Remove this question"
                        >
                          <X size={12} />
                        </button>
                      </div>
                      <div className="form-field" style={{ marginBottom: 8 }}>
                        <label style={{ fontSize: '0.78rem' }}>Question Text</label>
                        <input
                          className="admin-input"
                          value={q.question_text}
                          onChange={e => {
                            const updated = [...editQuestions]
                            updated[i] = { ...updated[i], question_text: e.target.value }
                            setEditQuestions(updated)
                          }}
                          placeholder="What is the attacker's source IP?"
                          required
                        />
                      </div>
                      <div className="form-row">
                        <div className="form-field flex-2" style={{ marginBottom: 0 }}>
                          <label style={{ fontSize: '0.78rem' }}>Canonical Answer</label>
                          <input
                            className="admin-input"
                            value={q.correct_answer}
                            onChange={e => {
                              const updated = [...editQuestions]
                              updated[i] = { ...updated[i], correct_answer: e.target.value }
                              setEditQuestions(updated)
                            }}
                            placeholder="e.g. T1003.006"
                            required
                          />
                        </div>
                        <div className="form-field flex-1" style={{ marginBottom: 0 }}>
                          <label style={{ fontSize: '0.78rem' }}>Points</label>
                          <input
                            type="number"
                            className="admin-input"
                            value={q.points}
                            min={1}
                            max={100}
                            onChange={e => {
                              const updated = [...editQuestions]
                              updated[i] = { ...updated[i], points: parseInt(e.target.value) || 10 }
                              setEditQuestions(updated)
                            }}
                          />
                        </div>
                      </div>

                      <div className="form-row" style={{ marginTop: 8, marginBottom: 8 }}>
                        <div className="form-field flex-1" style={{ marginBottom: 0 }}>
                          <label style={{ fontSize: '0.76rem', color: '#94a3b8' }}>Acceptable Answer Aliases (comma-separated)</label>
                          <input
                            className="admin-input"
                            placeholder="e.g., corp\svc_backup, svc_backup@corp.local"
                            value={q.acceptable_answers || ''}
                            onChange={e => {
                              const updated = [...editQuestions]
                              updated[i] = { ...updated[i], acceptable_answers: e.target.value }
                              setEditQuestions(updated)
                            }}
                          />
                        </div>
                        <div className="form-field flex-1" style={{ marginBottom: 0 }}>
                          <label style={{ fontSize: '0.76rem', color: '#34d399' }}>🎁 Free Starter Hint (0 pts penalty)</label>
                          <input
                            className="admin-input"
                            placeholder="Starter pointer shown when trainee clicks Free Hint..."
                            value={q.free_hint || ''}
                            onChange={e => {
                              const updated = [...editQuestions]
                              updated[i] = { ...updated[i], free_hint: e.target.value }
                              setEditQuestions(updated)
                            }}
                          />
                        </div>
                      </div>

                      <div className="form-row" style={{ marginBottom: 0 }}>
                        <div className="form-field flex-1" style={{ marginBottom: 0 }}>
                          <label style={{ fontSize: '0.76rem', color: '#fbbf24' }}>💡 Paid Forensic Hint (-15 pts penalty, unlocks after 2 wrong tries)</label>
                          <input
                            className="admin-input"
                            placeholder="Detailed forensic walkthrough hint..."
                            value={q.hint || ''}
                            onChange={e => {
                              const updated = [...editQuestions]
                              updated[i] = { ...updated[i], hint: e.target.value }
                              setEditQuestions(updated)
                            }}
                          />
                        </div>
                        <div className="form-field flex-1" style={{ marginBottom: 0 }}>
                          <label style={{ fontSize: '0.76rem', color: '#60a5fa' }}>📋 Post-Submission Debrief Explanation</label>
                          <input
                            className="admin-input"
                            placeholder="Shown on Report page after grading..."
                            value={q.explanation || ''}
                            onChange={e => {
                              const updated = [...editQuestions]
                              updated[i] = { ...updated[i], explanation: e.target.value }
                              setEditQuestions(updated)
                            }}
                          />
                        </div>
                      </div>
                    </div>
                  ))}
                  <button
                    type="button"
                    className="btn btn-secondary"
                    style={{ marginTop: 4, fontSize: '0.82rem', padding: '6px 14px' }}
                    onClick={() => setEditQuestions([...editQuestions, { question_text: '', correct_answer: '', acceptable_answers: '', free_hint: '', hint: '', explanation: '', points: 10 }])}
                  >
                    + Add Question
                  </button>
                </div>

                {/* ── Re-upload Logs ZIP ─────────────────────────── */}
                <div className="form-field" style={{ marginTop: 16 }}>
                  <label>Replace Log Events Archive (optional .zip)</label>
                  <input
                    type="file"
                    accept=".zip"
                    className="admin-input"
                    onChange={e => setEditFile(e.target.files[0] || null)}
                    style={{ paddingTop: '8px' }}
                  />
                  {editFile && (
                    <span className="field-hint" style={{ color: '#4ade80' }}>
                      ✓ {editFile.name} — will replace all existing logs on save
                    </span>
                  )}
                  {!editFile && editingScenario && (
                    <span className="field-hint">Leave empty to keep existing logs ({editingScenario.logs_count ?? 0} events)</span>
                  )}
                </div>

              </div>
              <div className="modal-footer">
                <button type="button" className="btn btn-secondary" onClick={() => setEditingScenario(null)}>
                  Cancel
                </button>
                <button type="submit" className="btn btn-primary" disabled={isSavingEdit}>
                  {isSavingEdit ? 'Saving...' : 'Save Changes'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Delete Confirmation Modal */}
      {deletingScenario && (
        <div className="modal-backdrop">
          <div className="modal-card modal-sm">
            <div className="modal-header">
              <h3>Confirm Deletion</h3>
              <button className="modal-close-btn" onClick={() => setDeletingScenario(null)}>×</button>
            </div>
            <div className="modal-body-padding">
              <p>Are you sure you want to permanently delete <strong>{deletingScenario.name}</strong> and all its logs?</p>
            </div>
            <div className="modal-footer">
              <button className="btn btn-secondary" onClick={() => setDeletingScenario(null)}>Cancel</button>
              <button className="btn btn-danger" onClick={handleDeleteScenario} disabled={isDeleting}>
                {isDeleting ? 'Deleting...' : 'Delete Permanently'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ── MODAL: ADD NEW USER ───────────────────────────────────────────── */}
      {showAddUserModal && (
        <div className="modal-backdrop">
          <div className="modal-card modal-sm">
            <div className="modal-header">
              <h3>
                <UserPlus size={18} color="#00ffcc" style={{ verticalAlign: 'middle', marginRight: '8px' }} />
                Register New User Account
              </h3>
              <button
                className="modal-close-btn"
                onClick={() => setShowAddUserModal(false)}
              >
                <X size={18} />
              </button>
            </div>

            {addUserError && (
              <div className="admin-error-box" style={{ margin: '16px 24px 0' }}>
                {addUserError}
              </div>
            )}

            <form onSubmit={handleCreateUser} className="modal-form">
              <div className="modal-body-padding">
                <div className="form-field" style={{ marginBottom: 16 }}>
                  <label>Username</label>
                  <input
                    type="text"
                    className="admin-input"
                    placeholder="e.g. jsmith or analyst_bob"
                    value={newUsername}
                    onChange={e => setNewUsername(e.target.value)}
                    required
                    minLength={3}
                  />
                  <span className="field-hint">Alphanumeric characters, underscores, and hyphens (min 3 chars)</span>
                </div>

                <div className="form-field" style={{ marginBottom: 16 }}>
                  <label>Initial / Temporary Password</label>
                  <input
                    type="password"
                    className="admin-input"
                    placeholder="Min 4 characters"
                    value={newPassword}
                    onChange={e => setNewPassword(e.target.value)}
                    required
                    minLength={4}
                  />
                </div>

                <div className="form-field">
                  <label>Account Role</label>
                  <select
                    className="admin-input"
                    value={newRole}
                    onChange={e => setNewRole(e.target.value)}
                  >
                    <option value="user">SOC Trainee / Analyst (Standard User)</option>
                    <option value="admin">System Administrator (Full Admin Access)</option>
                  </select>
                </div>
              </div>

              <div className="modal-footer">
                <button
                  type="button"
                  className="btn btn-secondary"
                  onClick={() => setShowAddUserModal(false)}
                  disabled={isAddingUser}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="btn btn-primary"
                  disabled={isAddingUser}
                >
                  {isAddingUser ? 'Creating Account...' : 'Create User Account'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* ── MODAL: DELETE USER CONFIRMATION ───────────────────────────────── */}
      {userToDelete && (
        <div className="modal-backdrop">
          <div className="modal-card modal-sm">
            <div className="modal-header">
              <h3>
                <AlertTriangle size={20} color="#ef4444" style={{ verticalAlign: 'middle', marginRight: '8px' }} />
                Delete User Account
              </h3>
              <button
                className="modal-close-btn"
                onClick={() => setUserToDelete(null)}
              >
                <X size={18} />
              </button>
            </div>
            <div className="modal-body-padding">
              <p>
                Are you sure you want to permanently delete user{' '}
                <strong>"{userToDelete.username}"</strong> ({userToDelete.role === 'admin' ? 'Administrator' : 'SOC Trainee'})?
              </p>
              <p className="text-dim" style={{ marginTop: '10px', fontSize: '0.88rem', lineHeight: '1.4' }}>
                ⚠️ This will permanently remove this user account, their scenario submission records, trial guesses, and earned leaderboard points.
              </p>
            </div>
            <div className="modal-footer">
              <button
                type="button"
                className="btn btn-secondary"
                onClick={() => setUserToDelete(null)}
                disabled={isDeletingUser}
              >
                Cancel
              </button>
              <button
                type="button"
                className="btn btn-danger"
                onClick={handleDeleteUser}
                disabled={isDeletingUser}
              >
                {isDeletingUser ? 'Deleting User...' : 'Yes, Delete User'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ── MODAL: ROLE CHANGE CONFIRMATION ─────────────────────────────────── */}
      {userToToggleRole && (
        <div className="modal-backdrop">
          <div className="modal-card modal-sm">
            <div className="modal-header">
              <h3>
                <Shield size={20} color={userToToggleRole.role === 'admin' ? '#f59e0b' : '#3b82f6'} style={{ verticalAlign: 'middle', marginRight: '8px' }} />
                {userToToggleRole.role === 'admin' ? 'Demote User Account' : 'Promote to Administrator'}
              </h3>
              <button
                className="modal-close-btn"
                onClick={() => setUserToToggleRole(null)}
              >
                <X size={18} />
              </button>
            </div>
            <div className="modal-body-padding">
              <p>
                {userToToggleRole.role === 'admin' ? (
                  <>
                    Are you sure you want to demote <strong>"{userToToggleRole.username}"</strong> from <strong>Administrator</strong> to regular <strong>SOC Trainee</strong>?
                  </>
                ) : (
                  <>
                    Are you sure you want to promote <strong>"{userToToggleRole.username}"</strong> to <strong>System Administrator</strong>?
                  </>
                )}
              </p>
              <p className="text-dim" style={{ marginTop: '10px', fontSize: '0.88rem', lineHeight: '1.4' }}>
                {userToToggleRole.role === 'admin'
                  ? 'They will lose administrative access to scenario authoring, log uploads, and user administration.'
                  : 'They will be granted full administrative rights, including creating scenarios, uploading logs, and managing users.'}
              </p>
            </div>
            <div className="modal-footer">
              <button
                type="button"
                className="btn btn-secondary"
                onClick={() => setUserToToggleRole(null)}
                disabled={isTogglingRole}
              >
                Cancel
              </button>
              <button
                type="button"
                className={userToToggleRole.role === 'admin' ? 'btn btn-warning' : 'btn btn-primary'}
                onClick={confirmToggleUserRole}
                disabled={isTogglingRole}
              >
                {isTogglingRole ? 'Updating...' : userToToggleRole.role === 'admin' ? 'Confirm Demotion' : 'Confirm Promotion'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ── MODAL: RESET PASSWORD ─────────────────────────────────────────── */}
      {userToResetPassword && (
        <div className="modal-backdrop">
          <div className="modal-card modal-sm">
            <div className="modal-header">
              <h3>
                <Key size={18} color="#f59e0b" style={{ verticalAlign: 'middle', marginRight: '8px' }} />
                Reset Password for "{userToResetPassword.username}"
              </h3>
              <button
                className="modal-close-btn"
                onClick={() => setUserToResetPassword(null)}
              >
                <X size={18} />
              </button>
            </div>

            {resetPasswordError && (
              <div className="admin-error-box" style={{ margin: '16px 24px 0' }}>
                {resetPasswordError}
              </div>
            )}

            <form onSubmit={handleResetPassword} className="modal-form">
              <div className="modal-body-padding">
                <p className="text-dim" style={{ marginBottom: 14, fontSize: '0.9rem' }}>
                  Set a new password for <strong>{userToResetPassword.username}</strong> ({userToResetPassword.role}). The user can immediately log in with this new password.
                </p>
                <div className="form-field">
                  <label>New Password</label>
                  <input
                    type="password"
                    className="admin-input"
                    placeholder="Enter new password (min 4 chars)"
                    value={resetNewPassword}
                    onChange={e => setResetNewPassword(e.target.value)}
                    required
                    minLength={4}
                  />
                </div>
              </div>
              <div className="modal-footer">
                <button
                  type="button"
                  className="btn btn-secondary"
                  onClick={() => setUserToResetPassword(null)}
                  disabled={isResettingPassword}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="btn btn-primary"
                  disabled={isResettingPassword}
                >
                  {isResettingPassword ? 'Updating Password...' : 'Save New Password'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  )
}
