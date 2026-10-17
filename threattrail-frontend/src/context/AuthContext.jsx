import { createContext, useContext, useState, useEffect } from 'react'
import api from '../api'

const AuthContext = createContext(null)

export function AuthProvider({ children }) {
  const [user, setUser] = useState(() => {
    try {
      const stored = localStorage.getItem('threattrail_user')
      return stored ? JSON.parse(stored) : null
    } catch {
      return null
    }
  })
  const [token, setToken] = useState(() => localStorage.getItem('threattrail_token') || null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    // If token exists, verify with backend /auth/me
    if (token) {
      api.get('/auth/me')
        .then(res => {
          setUser(res.data)
          localStorage.setItem('threattrail_user', JSON.stringify(res.data))
        })
        .catch(() => {
          // Token is expired or invalid
          logout()
        })
        .finally(() => setLoading(false))
    } else {
      setLoading(false)
    }
  }, [token])

  const login = async (username, password) => {
    const res = await api.post('/auth/login', { username, password })
    const { token: newToken, user: newUser } = res.data
    localStorage.setItem('threattrail_token', newToken)
    localStorage.setItem('threattrail_user', JSON.stringify(newUser))
    setToken(newToken)
    setUser(newUser)
    return newUser
  }

  const adminLogin = async (username, password) => {
    const res = await api.post('/auth/admin-login', { username, password })
    const { token: newToken, user: newUser } = res.data
    localStorage.setItem('threattrail_token', newToken)
    localStorage.setItem('threattrail_user', JSON.stringify(newUser))
    setToken(newToken)
    setUser(newUser)
    return newUser
  }

  const register = async (username, password) => {
    const res = await api.post('/auth/register', { username, password })
    const { token: newToken, user: newUser } = res.data
    localStorage.setItem('threattrail_token', newToken)
    localStorage.setItem('threattrail_user', JSON.stringify(newUser))
    setToken(newToken)
    setUser(newUser)
    return newUser
  }

  const logout = () => {
    localStorage.removeItem('threattrail_token')
    localStorage.removeItem('threattrail_user')
    setToken(null)
    setUser(null)
  }

  const value = {
    user,
    token,
    loading,
    isAdmin: user?.role === 'admin',
    isAuthenticated: Boolean(user),
    login,
    adminLogin,
    register,
    logout,
  }

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth() {
  const context = useContext(AuthContext)
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider')
  }
  return context
}
