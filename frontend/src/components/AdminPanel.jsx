import { useEffect, useState } from 'react'
import { api } from '../api/client.js'
import { useAuth } from '../context/AuthContext.jsx'

const ROLES = ['guest', 'employee', 'manager', 'admin']

export default function AdminPanel() {
  const { user: me } = useAuth()
  const [users, setUsers] = useState([])
  const [loading, setLoading] = useState(true)
  const [err, setErr] = useState('')
  const [busyId, setBusyId] = useState(null)
  const [showCreate, setShowCreate] = useState(false)

  const load = async () => {
    setLoading(true)
    setErr('')
    try {
      const data = await api.listUsers()
      setUsers(data)
    } catch (e) {
      setErr(e.message || 'Failed to load users')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [])

  const setRole = async (u, role) => {
    if (u.id === me.id || u.role === role) return
    setBusyId(u.id)
    try { await api.updateRole(u.id, role); await load() }
    catch (e) { setErr(e.message || 'Role update failed') }
    finally { setBusyId(null) }
  }

  const toggleActive = async (u) => {
    if (u.id === me.id) return
    setBusyId(u.id)
    try { await api.updateActive(u.id, !u.is_active); await load() }
    catch (e) { setErr(e.message || 'Update failed') }
    finally { setBusyId(null) }
  }

  return (
    <div style={{ padding: '28px 32px', maxWidth: 1400, margin: '0 auto' }}>
      <div style={{
        display: 'flex', justifyContent: 'space-between',
        alignItems: 'flex-start', marginBottom: 20, gap: 16, flexWrap: 'wrap',
      }}>
        <div>
          <h1 style={{ fontSize: 22, fontWeight: 600, marginBottom: 4 }}>
            User Management
          </h1>
          <p style={{ color: 'var(--text-muted)', fontSize: 13 }}>
            Manage user roles and account status. Role changes invalidate all
            active sessions for the affected user.
          </p>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <button className="btn" onClick={() => setShowCreate(true)}>
            + New user
          </button>
          <button className="btn btn-ghost" onClick={load} disabled={loading}>
            Refresh
          </button>
        </div>
      </div>

      {err && (
        <div className="alert alert-error" style={{ marginBottom: 16 }}>
          <span>⚠</span><span>{err}</span>
        </div>
      )}

      <div className="card" style={{ overflow: 'hidden' }}>
        <table className="table">
          <thead>
            <tr>
              <th style={{ width: 60 }}>ID</th>
              <th>Username</th>
              <th>Email</th>
              <th>Role</th>
              <th>Status</th>
              <th>Last login</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {loading && (
              <tr><td colSpan={7} style={{
                textAlign: 'center', color: 'var(--text-muted)', padding: 24,
              }}>Loading…</td></tr>
            )}
            {!loading && users.length === 0 && (
              <tr><td colSpan={7} style={{
                textAlign: 'center', color: 'var(--text-muted)', padding: 24,
              }}>No users</td></tr>
            )}
            {users.map((u) => {
              const isSelf = u.id === me.id
              const busy = busyId === u.id
              return (
                <tr key={u.id}>
                  <td className="muted mono text-xs">{String(u.id).padStart(3, '0')}</td>
                  <td>
                    <strong>{u.username}</strong>
                    {isSelf && <span className="muted text-xs"> (you)</span>}
                  </td>
                  <td className="muted text-sm">{u.email}</td>
                  <td><span className={`badge badge-role-${u.role}`}>{u.role}</span></td>
                  <td>
                    <span className={`badge badge-${u.is_active ? 'allowed' : 'denied'}`}>
                      {u.is_active ? 'active' : 'disabled'}
                    </span>
                  </td>
                  <td className="muted text-xs">
                    {u.last_login_at ? new Date(u.last_login_at).toLocaleString() : '—'}
                  </td>
                  <td>
                    <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                      <select
                        className="select"
                        style={{ padding: '4px 8px', fontSize: 12, width: 'auto' }}
                        value={u.role}
                        disabled={isSelf || busy}
                        onChange={(e) => setRole(u, e.target.value)}
                      >
                        {ROLES.map((r) => <option key={r} value={r}>{r}</option>)}
                      </select>
                      <button
                        className={`btn btn-sm ${u.is_active ? 'btn-danger' : ''}`}
                        disabled={isSelf || busy}
                        onClick={() => toggleActive(u)}
                      >
                        {u.is_active ? 'Disable' : 'Enable'}
                      </button>
                    </div>
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>

      <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 12 }}>
        {users.length} user{users.length !== 1 ? 's' : ''}
      </div>

      {showCreate && (
        <CreateUserDialog
          onClose={() => setShowCreate(false)}
          onCreated={() => { setShowCreate(false); load() }}
        />
      )}
    </div>
  )
}

function CreateUserDialog({ onClose, onCreated }) {
  const [form, setForm] = useState({
    username: '', email: '', password: '', role: 'employee',
  })
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)
  const set = (k, v) => setForm((f) => ({ ...f, [k]: v }))

  const submit = async (e) => {
    e.preventDefault()
    setErr('')
    setBusy(true)
    try {
      await api.createUser(form)
      onCreated()
    } catch (e) {
      setErr(e.message || 'Failed to create user')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div onClick={onClose} style={{
      position: 'fixed', inset: 0,
      background: 'rgba(0, 0, 0, 0.6)',
      display: 'flex', alignItems: 'center', justifyContent: 'center',
      zIndex: 100, padding: 20,
    }}>
      <div className="card fade-in" onClick={(e) => e.stopPropagation()}
        style={{ width: '100%', maxWidth: 440, boxShadow: 'var(--shadow-lg)' }}>
        <div className="card-header">
          <h3 style={{ fontSize: 16, fontWeight: 600 }}>Create user</h3>
          <p style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 2 }}>
            Provision a new account at the role of your choice.
          </p>
        </div>
        <form onSubmit={submit} className="card-body">
          <Field label="Username">
            <input className="input" value={form.username}
              onChange={(e) => set('username', e.target.value)}
              minLength={3} maxLength={64} required />
          </Field>
          <Field label="Email">
            <input className="input" type="email" value={form.email}
              onChange={(e) => set('email', e.target.value)} required />
          </Field>
          <Field label="Temporary password">
            <input className="input" type="text" value={form.password}
              onChange={(e) => set('password', e.target.value)}
              minLength={8} required
              placeholder="At least 8 characters" />
          </Field>
          <Field label="Role">
            <select className="select" value={form.role}
              onChange={(e) => set('role', e.target.value)}>
              {ROLES.map((r) => <option key={r} value={r}>{r}</option>)}
            </select>
          </Field>

          {err && (
            <div className="alert alert-error" style={{ marginBottom: 14 }}>
              <span>⚠</span><span>{err}</span>
            </div>
          )}

          <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
            <button type="button" className="btn btn-ghost" onClick={onClose}
              disabled={busy}>Cancel</button>
            <button type="submit" className="btn" disabled={busy}>
              {busy ? 'Creating…' : 'Create user'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

function Field({ label, children }) {
  return (
    <div style={{ marginBottom: 14 }}>
      <label style={{
        display: 'block', fontSize: 13, fontWeight: 500,
        marginBottom: 6,
      }}>{label}</label>
      {children}
    </div>
  )
}
