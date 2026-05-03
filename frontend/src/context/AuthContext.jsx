import { createContext, useContext, useEffect, useState, useCallback } from 'react'
import { api, tokenStore } from '../api/client.js'

/**
 * @typedef {Object} AuthContextValue
 * @property {Object|null} user          - The authenticated user, or null if logged out.
 * @property {boolean}     isAuthenticated - True when a user session is active.
 * @property {boolean}     loading       - True while the session is being restored.
 * @property {Function}    login         - (username, password) => Promise<user>
 * @property {Function}    logout        - () => Promise<void>
 * @property {Function}    refreshUser   - Re-fetches the current user from the API.
 * @property {Function}    setUser       - Directly overwrite the user state.
 */

const AuthContext = createContext(/** @type {AuthContextValue|null} */ (null))

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null)
  const [loading, setLoading] = useState(true)

  // Restore session on mount.
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

  /** Re-fetches the authenticated user and updates state. */
  const refreshUser = useCallback(async () => {
    const me = await api.me()
    setUser(me)
    return me
  }, [])

  const login = useCallback(async (username, password) => {
    const tokens = await api.login(username, password)
    tokenStore.set(tokens.access_token, tokens.refresh_token)
    try {
      const me = await api.me()
      setUser(me)
      return me
    } catch (err) {
      // Roll back stored tokens if we can't confirm the session.
      tokenStore.clear()
      throw err
    }
  }, [])

  const logout = useCallback(async () => {
    const rt = tokenStore.getRefresh()
    try {
      if (rt) await api.logout(rt)
    } catch {
      // Ignore server-side logout errors; always clear locally.
    } finally {
      tokenStore.clear()
      setUser(null)
    }
  }, [])

  const value = {
    user,
    setUser,
    isAuthenticated: !!user,
    loading,
    login,
    logout,
    refreshUser,
  }

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth() {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used inside <AuthProvider>')
  return ctx
}