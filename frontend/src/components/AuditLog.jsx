import React, { useEffect, useState } from 'react'
import { api } from '../api/client.js'
import { useAuth } from '../context/AuthContext.jsx'

export default function AuditLog() {
  const { user } = useAuth()
  const [logs, setLogs] = useState([])
  const [loading, setLoading] = useState(true)
  const [err, setErr] = useState('')
  const [filters, setFilters] = useState({ event_type: '', username: '', status: '' })
  const [verify, setVerify] = useState(null)
  const [verifying, setVerifying] = useState(false)
  const [expandedId, setExpandedId] = useState(null)

  const load = async () => {
    setLoading(true)
    setErr('')
    try {
      const params = {}
      if (filters.event_type) params.event_type = filters.event_type
      if (filters.username) params.username = filters.username
      if (filters.status) params.status = filters.status
      params.limit = 200
      const data = await api.listLogs(params)
      setLogs(data)
    } catch (e) {
      setErr(e.message || 'Failed to load logs')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [])

  const runVerify = async () => {
    setVerifying(true)
    try {
      const r = await api.verifyChain()
      setVerify(r)
    } catch (e) {
      setVerify({ valid: false, message: e.message, total: 0 })
    } finally {
      setVerifying(false)
    }
  }

  const isAdmin = user.role === 'admin'

  return (
    <div style={{ padding: '28px 32px', maxWidth: 1400, margin: '0 auto' }}>
      <div style={{
        display: 'flex', justifyContent: 'space-between',
        alignItems: 'flex-start', marginBottom: 20, gap: 16, flexWrap: 'wrap',
      }}>
        <div>
          <h1 style={{ fontSize: 22, fontWeight: 600, marginBottom: 4 }}>
            Audit Log
          </h1>
          <p style={{ color: 'var(--text-muted)', fontSize: 13 }}>
            Every authentication, query, and admin action is recorded in a
            tamper-evident hash chain.
          </p>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          {isAdmin && (
            <button className="btn" onClick={runVerify} disabled={verifying}>
              {verifying ? 'Verifying…' : 'Verify chain'}
            </button>
          )}
          <button className="btn btn-ghost" onClick={load} disabled={loading}>
            Refresh
          </button>
        </div>
      </div>

      {verify && (
        <div className={`alert alert-${verify.valid ? 'success' : 'error'}`}
          style={{ marginBottom: 16 }}>
          <span>{verify.valid ? '✓' : '⚠'}</span>
          <div>
            <div style={{ fontWeight: 500 }}>
              {verify.valid ? 'Chain verified' : 'Chain integrity broken'}
            </div>
            <div style={{ fontSize: 12, opacity: 0.85, marginTop: 2 }}>
              {verify.message}
            </div>
          </div>
        </div>
      )}

      {/* Filters */}
      <div className="card" style={{
        padding: 14, marginBottom: 14,
        display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center',
      }}>
        <input
          className="input" style={{ width: 180 }}
          placeholder="Event type"
          value={filters.event_type}
          onChange={(e) => setFilters((f) => ({ ...f, event_type: e.target.value }))}
        />
        <input
          className="input" style={{ width: 180 }}
          placeholder="Username"
          value={filters.username}
          onChange={(e) => setFilters((f) => ({ ...f, username: e.target.value }))}
        />
        <select
          className="select" style={{ width: 160 }}
          value={filters.status}
          onChange={(e) => setFilters((f) => ({ ...f, status: e.target.value }))}
        >
          <option value="">Any status</option>
          <option value="ALLOWED">Allowed</option>
          <option value="DENIED">Denied</option>
          <option value="ERROR">Error</option>
        </select>
        <button className="btn btn-sm" onClick={load}>Apply</button>
        <button className="btn btn-ghost btn-sm" onClick={() => {
          setFilters({ event_type: '', username: '', status: '' })
          setTimeout(load, 0)
        }}>Clear</button>
      </div>

      {err && (
        <div className="alert alert-error" style={{ marginBottom: 14 }}>
          <span>⚠</span><span>{err}</span>
        </div>
      )}

      <div className="card" style={{ overflow: 'hidden' }}>
        <table className="table">
          <thead>
            <tr>
              <th style={{ width: 60 }}>ID</th>
              <th>Timestamp</th>
              <th>User</th>
              <th>Role</th>
              <th>Event</th>
              <th>Status</th>
              <th>Classification</th>
              <th>IP</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {loading && (
              <tr><td colSpan={9} style={{
                textAlign: 'center', color: 'var(--text-muted)', padding: 24,
              }}>Loading…</td></tr>
            )}
            {!loading && logs.length === 0 && (
              <tr><td colSpan={9} style={{
                textAlign: 'center', color: 'var(--text-muted)', padding: 24,
              }}>No log entries</td></tr>
            )}
            {logs.map((l) => {
              const expanded = expandedId === l.id
              return (
                <React.Fragment key={l.id}>
                  <tr style={{ cursor: 'pointer' }}
                    onClick={() => setExpandedId(expanded ? null : l.id)}>
                    <td className="muted mono text-xs">{String(l.id).padStart(4, '0')}</td>
                    <td className="muted text-xs">
                      {new Date(l.timestamp).toLocaleString()}
                    </td>
                    <td>{l.username || <span className="muted">—</span>}</td>
                    <td>{l.role
                      ? <span className={`badge badge-role-${l.role}`}>{l.role}</span>
                      : <span className="muted">—</span>}</td>
                    <td className="mono text-xs">{l.event_type}</td>
                    <td>
                      <span className={`badge badge-${l.status === 'ALLOWED' ? 'allowed' : 'denied'}`}>
                        {l.status.toLowerCase()}
                      </span>
                    </td>
                    <td>{l.classification
                      ? <span className={`badge badge-${l.classification}`}>{l.classification}</span>
                      : <span className="muted">—</span>}</td>
                    <td className="muted mono text-xs">{l.ip_address || '—'}</td>
                    <td className="muted" style={{ textAlign: 'right' }}>
                      {expanded ? '▴' : '▾'}
                    </td>
                  </tr>
                  {expanded && (
                    <tr style={{ background: 'var(--bg)' }}>
                      <td colSpan={9} style={{ padding: 16 }}>
                        <div style={{
                          display: 'grid',
                          gridTemplateColumns: '1fr 1fr',
                          gap: 14,
                        }}>
                          <Detail label="Query">
                            {l.query_text || <span className="muted">—</span>}
                          </Detail>
                          <Detail label="Response">
                            {l.response_text || <span className="muted">—</span>}
                          </Detail>
                          <Detail label="Previous hash" mono>{l.prev_hash}</Detail>
                          <Detail label="Current hash" mono>{l.current_hash}</Detail>
                        </div>
                      </td>
                    </tr>
                  )}
                </React.Fragment>
              )
            })}
          </tbody>
        </table>
      </div>

      <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 12 }}>
        {logs.length} entr{logs.length !== 1 ? 'ies' : 'y'}
      </div>
    </div>
  )
}

function Detail({ label, children, mono }) {
  return (
    <div>
      <div style={{
        fontSize: 11, color: 'var(--text-muted)',
        textTransform: 'uppercase', letterSpacing: 0.05,
        fontWeight: 500, marginBottom: 4,
      }}>
        {label}
      </div>
      <div className={mono ? 'hash' : ''} style={{
        fontSize: mono ? 11 : 13,
        wordBreak: 'break-all',
      }}>
        {children}
      </div>
    </div>
  )
}
