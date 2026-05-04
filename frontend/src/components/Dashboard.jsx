import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api/client.js'
import { useAuth } from '../context/AuthContext.jsx'

export default function Dashboard() {
  const { user } = useAuth()
  const [data, setData] = useState(null)
  const [err, setErr] = useState('')
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let alive = true
    const load = async () => {
      try {
        const d = await api.dashboard()
        if (alive) setData(d)
      } catch (e) {
        if (alive) setErr(e.message || 'Failed to load')
      } finally {
        if (alive) setLoading(false)
      }
    }
    load()
    const t = setInterval(load, 15000)
    return () => { alive = false; clearInterval(t) }
  }, [])

  return (
    <div style={{ padding: '28px 32px', maxWidth: 1400, margin: '0 auto' }}>
      {/* Header */}
      <div style={{
        display: 'flex', justifyContent: 'space-between',
        alignItems: 'flex-start', marginBottom: 24, gap: 16, flexWrap: 'wrap',
      }}>
        <div>
          <h1 style={{ fontSize: 22, fontWeight: 600, marginBottom: 4 }}>
            Dashboard
          </h1>
          <p style={{ color: 'var(--text-muted)', fontSize: 13 }}>
            System overview and recent security activity.
          </p>
        </div>
        <div style={{
          display: 'flex', alignItems: 'center', gap: 6,
          fontSize: 12, color: 'var(--text-muted)',
        }}>
          <span className="dot dot-on pulse" />
          Live · refreshes every 15s
        </div>
      </div>

      {err && (
        <div className="alert alert-error" style={{ marginBottom: 16 }}>
          <span>⚠</span><span>{err}</span>
        </div>
      )}

      {loading && !data && (
        <div className="muted" style={{ padding: 40, textAlign: 'center' }}>
          Loading dashboard data…
        </div>
      )}

      {data && (
        <>
          {/* Stat cards */}
          <div style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
            gap: 14, marginBottom: 24,
          }}>
            <Stat
              label="Queries (24h)"
              value={data.counters.queries_24h}
              sub={`${data.counters.total_queries.toLocaleString()} total`}
            />
            <Stat
              label="Denied requests (24h)"
              value={data.counters.denied_24h}
              sub={`${data.counters.denied_total} total`}
              tone={data.counters.denied_24h > 0 ? 'warning' : 'normal'}
            />
            <Stat
              label="Injection attempts (7d)"
              value={data.counters.injection_attempts_7d}
              sub="Prompt injection blocks"
              tone={data.counters.injection_attempts_7d > 0 ? 'danger' : 'normal'}
            />
            <Stat
              label="Failed logins (24h)"
              value={data.counters.failed_logins_24h}
              sub="Authentication failures"
              tone={
                data.counters.failed_logins_24h > 5 ? 'danger' :
                data.counters.failed_logins_24h > 0 ? 'warning' : 'normal'
              }
            />
            {data.total_users !== undefined && (
              <Stat
                label="Active users"
                value={data.active_users}
                sub={`${data.total_users} total`}
              />
            )}
            {data.chain && (
              <Stat
                label="Audit chain"
                value={data.chain.valid ? 'Intact' : 'Broken'}
                sub={`${data.chain.total} log entries`}
                tone={data.chain.valid ? 'success' : 'danger'}
                isText
              />
            )}
          </div>

          {/* Two-column layout */}
          <div style={{
            display: 'grid',
            gridTemplateColumns: 'minmax(280px, 1fr) 2fr',
            gap: 14,
          }}>
            {/* Classification breakdown */}
            <div className="card">
              <div className="card-header">
                <h3 style={{ fontSize: 14, fontWeight: 600 }}>
                  Query classifications
                </h3>
                <p style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 2 }}>
                  Past 7 days
                </p>
              </div>
              <div className="card-body">
                <ClassBars c={data.classifications} />
              </div>
            </div>

            {/* Recent activity */}
            <div className="card">
              <div className="card-header" style={{
                display: 'flex', justifyContent: 'space-between', alignItems: 'center',
              }}>
                <div>
                  <h3 style={{ fontSize: 14, fontWeight: 600 }}>Recent activity</h3>
                  <p style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 2 }}>
                    Latest events across the system
                  </p>
                </div>
                <Link to="/audit" style={{ fontSize: 13 }}>View all →</Link>
              </div>
              <div style={{ overflow: 'auto' }}>
                <table className="table">
                  <thead>
                    <tr>
                      <th>Time</th>
                      <th>User</th>
                      <th>Event</th>
                      <th>Classification</th>
                      <th>Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.recent.length === 0 && (
                      <tr><td colSpan={5} style={{
                        textAlign: 'center', color: 'var(--text-muted)',
                      }}>No events yet</td></tr>
                    )}
                    {data.recent.map((r) => (
                      <tr key={r.id}>
                        <td className="mono text-xs muted">
                          {new Date(r.timestamp).toLocaleTimeString()}
                        </td>
                        <td>{r.username || '—'}</td>
                        <td className="mono text-xs">{r.event_type}</td>
                        <td>
                          {r.classification
                            ? <span className={`badge badge-${r.classification}`}>{r.classification}</span>
                            : <span className="muted">—</span>}
                        </td>
                        <td>
                          <span className={`badge badge-${r.status === 'ALLOWED' ? 'allowed' : 'denied'}`}>
                            {r.status.toLowerCase()}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  )
}

function Stat({ label, value, sub, tone = 'normal', isText = false }) {
  const colors = {
    normal: 'var(--text)',
    success: 'var(--success)',
    warning: 'var(--warning)',
    danger: 'var(--danger)',
  }
  return (
    <div className="card" style={{ padding: 18 }}>
      <div style={{
        fontSize: 12, color: 'var(--text-muted)',
        fontWeight: 500, marginBottom: 8,
      }}>
        {label}
      </div>
      <div style={{
        fontSize: isText ? 22 : 28,
        fontWeight: 700,
        color: colors[tone],
        lineHeight: 1.2,
        marginBottom: 4,
      }}>
        {typeof value === 'number' ? value.toLocaleString() : value}
      </div>
      <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>{sub}</div>
    </div>
  )
}

function ClassBars({ c }) {
  const order = [
    ['public', 'Public', 'var(--success)'],
    ['internal', 'Internal', 'var(--info)'],
    ['confidential', 'Confidential', 'var(--warning)'],
    ['restricted', 'Restricted', 'var(--danger)'],
  ]
  const total = order.reduce((s, [k]) => s + (c[k] || 0), 0)
  const max = Math.max(1, ...order.map(([k]) => c[k] || 0))

  return (
    <div>
      {order.map(([k, label, color]) => {
        const n = c[k] || 0
        const pct = (n / max) * 100
        const share = total > 0 ? Math.round((n / total) * 100) : 0
        return (
          <div key={k} style={{ marginBottom: 14 }}>
            <div style={{
              display: 'flex', justifyContent: 'space-between',
              fontSize: 12, marginBottom: 6, alignItems: 'center',
            }}>
              <span className={`badge badge-${k}`}>{label}</span>
              <span className="muted">
                <strong style={{ color: 'var(--text)' }}>{n}</strong>
                <span className="text-xs"> · {share}%</span>
              </span>
            </div>
            <div style={{
              height: 6, background: 'var(--bg-3)',
              borderRadius: 3, overflow: 'hidden',
            }}>
              <div style={{
                width: `${pct}%`, height: '100%',
                background: color, transition: 'width 0.4s ease',
              }} />
            </div>
          </div>
        )
      })}
      {total === 0 && (
        <div style={{
          textAlign: 'center', padding: '20px 0',
          color: 'var(--text-muted)', fontSize: 12,
        }}>
          No queries yet
        </div>
      )}
    </div>
  )
}
