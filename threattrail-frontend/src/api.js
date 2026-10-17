import axios from 'axios'

const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL || 'http://localhost:5050/api',
  timeout: 10000,
  headers: {
    'Content-Type': 'application/json',
  },
})

// Built-in fallback data so live demos survive backend/network interruptions
const OFFLINE_DEMO_SCENARIO = {
  id: 1,
  name: 'Password Spraying',
  description:
    'Detect and investigate a coordinated Active Directory password spraying attack targeting domain accounts from a single internal host.',
  mitre_technique: 'T1110.003',
  status: 'published',
  alert: {
    id: 1,
    scenario_id: 1,
    title: 'High Severity: Possible Password Spraying',
    severity: 'High',
  },
  logs: [
    ...Array.from({ length: 15 }, (_, i) => ({
      id: i + 1,
      scenario_id: 1,
      event_id: 4625,
      timestamp: `2026-10-23T08:15:${String(10 + i).padStart(2, '0')}Z`,
      source_ip: '192.168.1.200',
      username: `user${i + 1}`,
      target_host: 'DC01.corp.local',
      raw_event_data: {
        EventID: 4625,
        Status: '0xC000006D',
        SubStatus: '0xC000006A',
        LogonType: 3,
        IpAddress: '192.168.1.200',
        TargetUserName: `user${i + 1}`,
        WorkstationName: 'WKSTN-ATK01',
        Message: 'An account failed to log on. Failure Reason: Unknown user name or bad password.',
      },
    })),
    {
      id: 16,
      scenario_id: 1,
      event_id: 4624,
      timestamp: '2026-10-23T08:15:30Z',
      source_ip: '192.168.1.200',
      username: 'jdoe',
      target_host: 'DC01.corp.local',
      raw_event_data: {
        EventID: 4624,
        LogonType: 3,
        IpAddress: '192.168.1.200',
        TargetUserName: 'jdoe',
        WorkstationName: 'WKSTN-ATK01',
        Message: 'An account was successfully logged on.',
      },
    },
  ],
  questions: [
    { id: 1, scenario_id: 1, question_text: 'What is the source IP?', points: 10 },
    { id: 2, scenario_id: 1, question_text: 'Which account was successfully compromised?', points: 10 },
    { id: 3, scenario_id: 1, question_text: 'What is the MITRE technique ID?', points: 10 },
  ],
}

// Attach Bearer token to all outgoing requests if authenticated
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('threattrail_token')
    if (token && typeof token === 'string' && token.length < 4096) {
      config.headers.Authorization = `Bearer ${token.trim()}`
    }
    return config
  },
  (error) => Promise.reject(error)
)

// Automatically handle expired/invalid tokens (401) and network fallbacks
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response && error.response.status === 401) {
      const path = window.location.pathname
      const isAuthRoute =
        path === '/login' || path === '/register' || path === '/admin/login'
      if (!isAuthRoute) {
        localStorage.removeItem('threattrail_token')
        localStorage.removeItem('threattrail_user')
        window.dispatchEvent(new Event('threattrail:unauthorized'))
      }
      return Promise.reject(error)
    }

    // Graceful offline demo fallback if backend is unreachable and demo mode is enabled
    const isNetworkError = !error.response || error.code === 'ECONNABORTED'
    const offlineEnabled =
      localStorage.getItem('threattrail_offline_demo') === 'true' ||
      import.meta.env.VITE_OFFLINE_FALLBACK === 'true'

    if (isNetworkError && offlineEnabled && error.config) {
      const url = error.config.url || ''
      if (url.endsWith('/scenarios')) {
        return Promise.resolve({ data: [OFFLINE_DEMO_SCENARIO] })
      }
      if (url.includes('/scenarios/1/alert')) {
        return Promise.resolve({ data: OFFLINE_DEMO_SCENARIO.alert })
      }
      if (url.includes('/scenarios/1/logs')) {
        return Promise.resolve({ data: OFFLINE_DEMO_SCENARIO.logs })
      }
      if (url.includes('/scenarios/1/questions')) {
        return Promise.resolve({ data: OFFLINE_DEMO_SCENARIO.questions })
      }
    }

    return Promise.reject(error)
  }
)

export default api
