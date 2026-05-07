import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { useAuth } from '../context/AuthContext.jsx'
import Logo from './Logo.jsx'

const SECURITY_FEATURES = [
  {
    title: 'Role-Based Access Control',
    desc: 'Every query is checked against your role before any data is returned.',
  },
  {
    title: 'Sensitivity Classification',
    desc: 'Messages are tagged Public · Internal · Confidential · Restricted in real time.',
  },
  {
    title: 'Tamper-Evident Audit Log',
    desc: 'All actions are recorded in a SHA-256 hash chain that detects modification.',
  },
  {
    title: 'Prompt-Injection Defense',
    desc: 'Malicious prompts attempting to override system instructions are blocked and logged.',
  },
]

export default function Login() {
  const { login } = useAuth()
  const nav = useNavigate()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)

  const submit = async (e) => {
    e.preventDefault()
    setErr('')
    setBusy(true)
    try {
      const u = await login(username.trim(), password)
      nav(u.role === 'admin' ? '/dashboard' : '/chat', { replace: true })
    } catch (e) {
      setErr(e.message || 'Sign-in failed')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div style={{
      minHeight: '100vh',
      display: 'grid',
      gridTemplateColumns: '1fr 1fr',
      background: 'var(--bg)',
    }} className="login-grid">
      {/* Left side — brand + security pitch */}
      <div style={{
        padding: '48px 56px',
        display: 'flex', flexDirection: 'column',
        justifyContent: 'space-between',
        background: 'linear-gradient(135deg, var(--bg-2) 0%, var(--bg) 100%)',
        borderRight: '1px solid var(--border)',
        position: 'relative', overflow: 'hidden',
      }} className="login-left">
        {/* faint gradient orb behind */}
        <div style={{
          position: 'absolute',
          width: 500, height: 500,
          background: 'radial-gradient(circle, var(--primary-soft), transparent 70%)',
          top: -150, right: -150,
          pointerEvents: 'none',
        }} />

        <div style={{ position: 'relative', zIndex: 1 }}>
          <div style={{
            display: 'flex', alignItems: 'center', gap: 12,
            marginBottom: 12,
          }}>
            <Logo size={40} />
            <div>
              <div style={{
                fontSize: 24, fontWeight: 700,
                letterSpacing: '0.08em',
                color: 'var(--text)',
              }}>
                CIPHRA
              </div>
              <div style={{
                fontSize: 11, color: 'var(--text-muted)',
                letterSpacing: '0.02em',
              }}>
                Classified Information Protected via Hash-chained Role Access
              </div>
            </div>
          </div>

          <h2 style={{
            fontSize: 28, fontWeight: 600,
            lineHeight: 1.2, marginTop: 36, marginBottom: 12,
            maxWidth: 420,
          }}>
            A chatbot that knows what you're allowed to ask.
          </h2>
          <p style={{
            color: 'var(--text-muted)', fontSize: 14,
            maxWidth: 420, lineHeight: 1.6,
          }}>
            CIPHRA classifies every query, enforces role-based access on the
            response, and records each interaction in a tamper-evident chain —
            so your AI assistant cannot become a data-leak channel.
          </p>
        </div>

        <div style={{ position: 'relative', zIndex: 1 }}>
          <div style={{
            display: 'grid', gap: 14,
            marginTop: 32,
          }}>
            {SECURITY_FEATURES.map((f, i) => (
              <div key={i} style={{
                display: 'flex', gap: 12, alignItems: 'flex-start',
              }}>
                <div style={{
                  flexShrink: 0,
                  width: 28, height: 28,
                  borderRadius: 6,
                  background: 'var(--primary-soft)',
                  border: '1px solid var(--primary-border)',
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  color: 'var(--primary)',
                }}>
                  <CheckIcon />
                </div>
                <div>
                  <div style={{ fontSize: 13, fontWeight: 600 }}>{f.title}</div>
                  <div style={{
                    fontSize: 12, color: 'var(--text-muted)',
                    marginTop: 1, lineHeight: 1.5,
                  }}>{f.desc}</div>
                </div>
              </div>
            ))}
          </div>

          <div style={{
            fontSize: 11, color: 'var(--text-faint)',
            marginTop: 32, paddingTop: 20,
            borderTop: '1px solid var(--border-muted)',
          }}>
            v1.0 · Pak-Austria Fachhochschule · Secure Software Design
          </div>
        </div>
      </div>

      {/* Right side — auth form */}
      <div style={{
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        padding: 32,
      }} className="login-right">
        <div className="card fade-in" style={{
          width: '100%', maxWidth: 380,
          boxShadow: 'var(--shadow-lg)',
        }}>
          <div style={{ padding: '32px 32px 0' }}>
            <h1 style={{ fontSize: 20, fontWeight: 600, marginBottom: 4 }}>
              Sign in
            </h1>
            <p style={{ color: 'var(--text-muted)', fontSize: 13 }}>
              Welcome back. Authenticate to continue.
            </p>
          </div>

          <div style={{ padding: 32 }}>
            <form onSubmit={submit}>
              <Field label="Username">
                <input
                  className="input"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder="Enter your username"
                  autoComplete="username"
                  autoFocus
                  required
                />
              </Field>
              <Field label="Password">
                <input
                  className="input"
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••"
                  autoComplete="current-password"
                  required
                />
              </Field>

              {err && (
                <div className="alert alert-error" style={{ marginBottom: 16 }}>
                  <span>⚠</span><span>{err}</span>
                </div>
              )}

              <button type="submit" className="btn" disabled={busy}
                style={{ width: '100%', padding: '11px 16px' }}>
                {busy ? 'Signing in…' : 'Sign in'}
              </button>
            </form>

            <div style={{
              marginTop: 20, paddingTop: 20,
              borderTop: '1px solid var(--border)',
              fontSize: 13, color: 'var(--text-muted)',
              textAlign: 'center',
            }}>
              <div style={{ marginBottom: 12 }}>
                Don't have an account? <Link to="/register">Create one</Link>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* responsive override - stack vertically on smaller screens */}
      <style>{`
        @media (max-width: 900px) {
          .login-grid {
            grid-template-columns: 1fr !important;
          }
          .login-left {
            padding: 32px !important;
            border-right: none !important;
            border-bottom: 1px solid var(--border);
          }
          .login-right { padding: 24px !important; }
        }
      `}</style>
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

function CheckIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none"
      stroke="currentColor" strokeWidth="3"
      strokeLinecap="round" strokeLinejoin="round">
      <polyline points="20 6 9 17 4 12" />
    </svg>
  )
}
