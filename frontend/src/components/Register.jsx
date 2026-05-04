import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { api } from '../api/client.js'
import Logo from './Logo.jsx'

export default function Register() {
  const nav = useNavigate()
  const [form, setForm] = useState({ username: '', email: '', password: '' })
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)
  const [ok, setOk] = useState(false)

  const set = (k, v) => setForm((f) => ({ ...f, [k]: v }))

  const submit = async (e) => {
    e.preventDefault()
    setErr('')
    setBusy(true)
    try {
      await api.register(form)
      setOk(true)
      setTimeout(() => nav('/login'), 1400)
    } catch (e) {
      // The server returns structured policy errors as a JSON object
      // in the detail field. Format them nicely.
      try {
        const parsed = JSON.parse(e.message)
        if (parsed?.password_policy) {
          setErr('Password did not meet policy:\n• ' +
            parsed.password_policy.join('\n• '))
        } else {
          setErr(e.message || 'Registration failed')
        }
      } catch {
        setErr(e.message || 'Registration failed')
      }
    } finally {
      setBusy(false)
    }
  }

  return (
    <div style={{
      minHeight: '100vh',
      display: 'flex', alignItems: 'center', justifyContent: 'center',
      padding: 20,
    }}>
      <div className="card fade-in" style={{
        width: '100%', maxWidth: 420,
        boxShadow: 'var(--shadow-lg)',
      }}>
        <div style={{ padding: '32px 32px 0', textAlign: 'center' }}>
          <div style={{ display: 'inline-block', marginBottom: 14 }}>
            <Logo size={44} />
          </div>
          <div style={{
            fontSize: 13, fontWeight: 700,
            letterSpacing: '0.16em',
            color: 'var(--primary)', marginBottom: 8,
          }}>CIPHRA</div>
          <h1 style={{ fontSize: 22, fontWeight: 600, marginBottom: 4 }}>
            Create your account
          </h1>
          <p style={{ color: 'var(--text-muted)', fontSize: 13 }}>
            Sign up to start using CIPHRA
          </p>
        </div>

        <div style={{ padding: 32 }}>
          <form onSubmit={submit}>
            <Field label="Username">
              <input
                className="input" value={form.username}
                onChange={(e) => set('username', e.target.value)}
                placeholder="3–64 characters, alphanumeric"
                minLength={3} maxLength={64}
                pattern="^[a-zA-Z0-9_.\-]+$"
                required
              />
            </Field>
            <Field label="Email">
              <input
                className="input" type="email" value={form.email}
                onChange={(e) => set('email', e.target.value)}
                placeholder="you@example.com"
                required
              />
            </Field>
            <Field label="Password">
              <input
                className="input" type="password" value={form.password}
                onChange={(e) => set('password', e.target.value)}
                placeholder="At least 10 characters with mixed types"
                minLength={10}
                required
              />
              <div style={{
                fontSize: 11, color: 'var(--text-muted)', marginTop: 6,
              }}>
                Must include letters, numbers, and symbols. Avoid common
                passwords and patterns like "12345" or "abcde".
              </div>
            </Field>

            <div className="alert alert-info" style={{ marginBottom: 16, fontSize: 12 }}>
              <span>ℹ</span>
              <span>
                New accounts are created with the <strong>Employee</strong> role.
                An administrator can grant additional permissions if needed.
              </span>
            </div>

            {err && (
              <div className="alert alert-error" style={{
                marginBottom: 16, whiteSpace: 'pre-wrap',
              }}>
                <span>⚠</span><span>{err}</span>
              </div>
            )}
            {ok && (
              <div className="alert alert-success" style={{ marginBottom: 16 }}>
                <span>✓</span><span>Account created. Redirecting to sign-in…</span>
              </div>
            )}

            <button type="submit" className="btn" disabled={busy}
              style={{ width: '100%', padding: '11px 16px' }}>
              {busy ? 'Creating account…' : 'Create account'}
            </button>
          </form>

          <div style={{
            marginTop: 20, paddingTop: 20,
            borderTop: '1px solid var(--border)',
            textAlign: 'center', fontSize: 13, color: 'var(--text-muted)',
          }}>
            Already have an account? <Link to="/login">Sign in</Link>
          </div>
        </div>
      </div>
    </div>
  )
}

function Field({ label, children }) {
  return (
    <div style={{ marginBottom: 16 }}>
      <label style={{
        display: 'block', fontSize: 13, fontWeight: 500,
        marginBottom: 6, color: 'var(--text)',
      }}>
        {label}
      </label>
      {children}
    </div>
  )
}
