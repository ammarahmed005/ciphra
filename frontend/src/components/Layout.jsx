import { Link, NavLink, Outlet, useNavigate } from 'react-router-dom'
import { useAuth } from '../context/AuthContext.jsx'
import Logo from './Logo.jsx'

const NAV = [
  { to: '/dashboard', label: 'Dashboard', roles: ['admin'] },
  { to: '/chat', label: 'Chat', roles: ['guest', 'employee', 'manager', 'admin'] },
  { to: '/audit', label: 'Audit Log', roles: ['manager', 'admin'] },
  { to: '/admin', label: 'User Management', roles: ['admin'] },
]

const NavIcons = {
  '/dashboard': (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <rect x="3" y="3" width="7" height="9" rx="1" />
      <rect x="14" y="3" width="7" height="5" rx="1" />
      <rect x="14" y="12" width="7" height="9" rx="1" />
      <rect x="3" y="16" width="7" height="5" rx="1" />
    </svg>
  ),
  '/chat': (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z" />
    </svg>
  ),
  '/audit': (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
      <polyline points="14 2 14 8 20 8" />
      <line x1="9" y1="13" x2="15" y2="13" />
      <line x1="9" y1="17" x2="15" y2="17" />
    </svg>
  ),
  '/admin': (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2" />
      <circle cx="9" cy="7" r="4" />
      <path d="M23 21v-2a4 4 0 0 0-3-3.87" />
      <path d="M16 3.13a4 4 0 0 1 0 7.75" />
    </svg>
  ),
}

export default function Layout() {
  const { user, logout } = useAuth()
  const nav = useNavigate()

  const onLogout = async () => {
    await logout()
    nav('/login', { replace: true })
  }

  const visibleNav = NAV.filter((n) => n.roles.includes(user.role))

  return (
    <div style={{ display: 'flex', height: '100vh' }}>
      {/* Sidebar */}
      <aside style={{
        width: 248, flexShrink: 0,
        background: 'var(--bg-2)',
        borderRight: '1px solid var(--border)',
        display: 'flex', flexDirection: 'column',
      }}>
        {/* Brand */}
        <div style={{
          padding: '18px 20px',
          borderBottom: '1px solid var(--border)',
        }}>
          <Link to="/" style={{
            display: 'flex', alignItems: 'center', gap: 10,
            color: 'var(--text)', textDecoration: 'none',
          }}>
            <Logo size={28} />
            <div>
              <div style={{
                fontSize: 16, fontWeight: 700, lineHeight: 1.2,
                letterSpacing: '0.06em',
              }}>
                CIPHRA
              </div>
              <div style={{ fontSize: 10, color: 'var(--text-muted)', letterSpacing: 0.5 }}>
                RBAC Console
              </div>
            </div>
          </Link>
        </div>

        {/* Nav */}
        <nav style={{ padding: '16px 12px', flex: 1 }}>
          <div style={{
            fontSize: 11, color: 'var(--text-faint)',
            padding: '0 8px 8px', textTransform: 'uppercase',
            letterSpacing: 0.05, fontWeight: 500,
          }}>
            Workspace
          </div>

          {visibleNav.map((n) => (
            <NavLink
              key={n.to}
              to={n.to}
              style={({ isActive }) => ({
                display: 'flex', alignItems: 'center', gap: 10,
                padding: '8px 12px',
                color: isActive ? 'var(--text)' : 'var(--text-muted)',
                background: isActive ? 'var(--primary-soft)' : 'transparent',
                borderRadius: 6,
                textDecoration: 'none',
                marginBottom: 2,
                fontSize: 13,
                fontWeight: isActive ? 500 : 400,
                transition: 'background 0.1s ease, color 0.1s ease',
              })}
            >
              <span style={{ display: 'flex', opacity: 0.8 }}>{NavIcons[n.to]}</span>
              <span>{n.label}</span>
            </NavLink>
          ))}
        </nav>

        {/* User block */}
        <div style={{
          padding: 14, borderTop: '1px solid var(--border)',
        }}>
          <div style={{
            display: 'flex', alignItems: 'center', gap: 10,
            padding: '8px 4px', marginBottom: 8,
          }}>
            <div style={{
              width: 32, height: 32, borderRadius: '50%',
              background: 'var(--primary-soft)',
              border: '1px solid var(--primary-border)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              color: 'var(--primary)', fontSize: 13, fontWeight: 600,
              flexShrink: 0,
            }}>
              {user.username.slice(0, 1).toUpperCase()}
            </div>
            <div style={{ minWidth: 0, flex: 1 }}>
              <div style={{
                fontSize: 13, fontWeight: 500,
                whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis',
              }}>
                {user.username}
              </div>
              <div style={{ marginTop: 2 }}>
                <span className={`badge badge-role-${user.role}`}>
                  {user.role}
                </span>
              </div>
            </div>
          </div>
          <button onClick={onLogout} className="btn btn-ghost btn-sm" style={{ width: '100%' }}>
            Sign out
          </button>
        </div>
      </aside>

      {/* Main */}
      <main style={{ flex: 1, overflow: 'auto', background: 'var(--bg)' }}>
        <Outlet />
      </main>
    </div>
  )
}
