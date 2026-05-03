import { createContext, useContext, useEffect, useState } from 'react'
import { api, tokenStore } from '../api/client.js'

const AuthContext = createContext(null)

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null)
  const [loading, setLoading] = useState(true)

  // Restore session on load.
  useEffect(() => {
    const token = tokenStore.getAccess() || tokenStore.getRefresh()
    if (!token) {
      setLoading(false)
      return
    }
    api.me()
      .then(setUser)
      .catch(() => tokenStore.clear())
      .finally(() => setLoading(false))
  }, [])

  const login = async (username, password) => {
    const tokens = await api.login(username, password)
    tokenStore.set(tokens.access_token, tokens.refresh_token)
    const me = await api.me()
    setUser(me)
    return me
  }

  const logout = async () => {
    const rt = tokenStore.getRefresh()
    try {
      if (rt) await api.logout(rt)
    } catch {
      // ignore
    }
    tokenStore.clear()
    setUser(null)
  }

  return (
    <AuthContext.Provider value={{ user, setUser, loading, login, logout }}>
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth() {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used inside AuthProvider')
  return ctx
}
