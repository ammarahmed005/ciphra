// Minimal API client with automatic access-token refresh using refresh-pair rotation.
const BASE = import.meta.env.VITE_API_URL || ''

const STORAGE_ACCESS = 'sc_access'
const STORAGE_REFRESH = 'sc_refresh'

export const tokenStore = {
  getAccess: () => localStorage.getItem(STORAGE_ACCESS),
  getRefresh: () => localStorage.getItem(STORAGE_REFRESH),
  set: (access, refresh) => {
    if (access) localStorage.setItem(STORAGE_ACCESS, access)
    if (refresh) localStorage.setItem(STORAGE_REFRESH, refresh)
  },
  clear: () => {
    localStorage.removeItem(STORAGE_ACCESS)
    localStorage.removeItem(STORAGE_REFRESH)
  },
}

let refreshPromise = null

async function doRefresh() {
  const rt = tokenStore.getRefresh()
  if (!rt) return false
  const resp = await fetch(`${BASE}/api/auth/refresh-pair`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ refresh_token: rt }),
  })
  if (!resp.ok) {
    tokenStore.clear()
    return false
  }
  const data = await resp.json()
  tokenStore.set(data.access_token, data.refresh_token)
  return true
}

export async function apiRequest(path, { method = 'GET', body, headers = {} } = {}) {
  const doFetch = async () => {
    const token = tokenStore.getAccess()
    const h = { 'Content-Type': 'application/json', ...headers }
    if (token) h['Authorization'] = `Bearer ${token}`
    return fetch(`${BASE}${path}`, {
      method,
      headers: h,
      body: body ? JSON.stringify(body) : undefined,
    })
  }

  let resp = await doFetch()

  // If we got a 401 and have a refresh token, try once to refresh.
  if (resp.status === 401 && tokenStore.getRefresh()) {
    // Coalesce concurrent refresh attempts.
    if (!refreshPromise) refreshPromise = doRefresh().finally(() => (refreshPromise = null))
    const ok = await refreshPromise
    if (ok) resp = await doFetch()
  }

  if (!resp.ok) {
    let detail = `HTTP ${resp.status}`
    try {
      const j = await resp.json()
      detail = j.detail || JSON.stringify(j)
    } catch {}
    const err = new Error(detail)
    err.status = resp.status
    throw err
  }

  // 204 no content
  if (resp.status === 204) return null
  const ct = resp.headers.get('content-type') || ''
  return ct.includes('application/json') ? resp.json() : resp.text()
}

// ---------- Typed endpoints ----------
export const api = {
  login: (username, password) =>
    fetch(`${BASE}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    }).then(async (r) => {
      if (!r.ok) throw new Error((await r.json()).detail || 'Login failed')
      return r.json()
    }),

  register: (payload) =>
    fetch(`${BASE}/api/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    }).then(async (r) => {
      if (!r.ok) throw new Error((await r.json()).detail || 'Registration failed')
      return r.json()
    }),

  me: () => apiRequest('/api/auth/me'),
  logout: (refresh_token) => apiRequest('/api/auth/logout', { method: 'POST', body: { refresh_token } }),
  chat: (message) => apiRequest('/api/chat', { method: 'POST', body: { message } }),
  listUsers: () => apiRequest('/api/admin/users'),
  createUser: (payload) => apiRequest('/api/admin/users', { method: 'POST', body: payload }),
  updateRole: (id, role) => apiRequest(`/api/admin/users/${id}/role`, { method: 'PATCH', body: { role } }),
  updateActive: (id, is_active) =>
    apiRequest(`/api/admin/users/${id}/active`, { method: 'PATCH', body: { is_active } }),
  listLogs: (params = {}) => {
    const q = new URLSearchParams(params).toString()
    return apiRequest(`/api/audit/logs${q ? `?${q}` : ''}`)
  },
  verifyChain: () => apiRequest('/api/audit/verify'),
  dashboard: () => apiRequest('/api/stats/dashboard'),
}
