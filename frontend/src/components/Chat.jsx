import { useEffect, useRef, useState } from 'react'
import { api } from '../api/client.js'
import { useAuth } from '../context/AuthContext.jsx'

const SUGGESTIONS = [
  'What can you help me with?',
  'Explain the information access policy',
  'Where can I find the employee handbook?',
  'Summarize the leave request process',
  'What is the sprint planning process?',
  ]

export default function Chat() {
  const { user } = useAuth()
  const [messages, setMessages] = useState([])
  const [input, setInput] = useState('')
  const [busy, setBusy] = useState(false)
  const scrollRef = useRef(null)

  useEffect(() => {
    scrollRef.current?.scrollTo({
      top: scrollRef.current.scrollHeight,
      behavior: 'smooth',
    })
  }, [messages])

  const send = async (text) => {
    const msg = (text ?? input).trim()
    if (!msg || busy) return
    setInput('')
    setMessages((m) => [...m, { from: 'user', text: msg, ts: new Date() }])
    setBusy(true)
    try {
      const res = await api.chat(msg)
      setMessages((m) => [...m, {
        from: 'bot',
        text: res.reply,
        status: res.status,
        classification: res.classification,
        reason: res.reason,
        ts: new Date(),
      }])
    } catch (e) {
      setMessages((m) => [...m, {
        from: 'bot', text: e.message || 'Error', status: 'error', ts: new Date(),
      }])
    } finally {
      setBusy(false)
    }
  }

  const onKey = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      send()
    }
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100vh' }}>
      {/* Header */}
      <div style={{
        padding: '16px 24px',
        borderBottom: '1px solid var(--border)',
        background: 'var(--bg-2)',
      }}>
        <h1 style={{ fontSize: 16, fontWeight: 600 }}>Chat</h1>
        <p style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 2 }}>
          Queries are classified and checked against your role policy before a response is returned.
        </p>
      </div>

      {/* Messages area */}
      <div ref={scrollRef} style={{
        flex: 1, overflowY: 'auto',
        padding: 24,
        display: 'flex', flexDirection: 'column', gap: 14,
      }}>
        {messages.length === 0 && <Welcome onPick={send} username={user.username} />}
        {messages.map((m, i) => <Message key={i} m={m} />)}
        {busy && (
          <div style={{
            display: 'flex', alignItems: 'center', gap: 8,
            color: 'var(--text-muted)', fontSize: 13,
            padding: '8px 4px',
          }}>
            <Spinner /> CIPHRA is thinking…
          </div>
        )}
      </div>

      {/* Composer */}
      <div style={{
        padding: 16, borderTop: '1px solid var(--border)',
        background: 'var(--bg-2)',
      }}>
        <div style={{
          maxWidth: 1100, margin: '0 auto',
          display: 'flex', gap: 8, alignItems: 'flex-end',
        }}>
          <textarea
            className="textarea"
            style={{ resize: 'none', minHeight: 44, maxHeight: 160 }}
            rows={1}
            placeholder="Ask anything…"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={onKey}
            disabled={busy}
          />
          <button
            onClick={() => send()}
            className="btn"
            disabled={busy || !input.trim()}
            style={{ height: 42 }}
          >
            Send
          </button>
        </div>
        <div style={{
          textAlign: 'center', fontSize: 11,
          color: 'var(--text-faint)', marginTop: 6,
        }}>
          Press Enter to send, Shift+Enter for newline
        </div>
      </div>
    </div>
  )
}

function Welcome({ onPick, username }) {
  return (
    <div style={{
      maxWidth: 640, margin: '32px auto', textAlign: 'center',
    }} className="fade-in">
      <h2 style={{ fontSize: 24, fontWeight: 600, marginBottom: 8 }}>
        Hi {username} 👋
      </h2>
      <p style={{ color: 'var(--text-muted)', marginBottom: 28 }}>
        Ask anything below. Try one of these to get started:
      </p>
      <div style={{ display: 'grid', gap: 8, textAlign: 'left' }}>
        {SUGGESTIONS.map((q) => (
          <button
            key={q}
            onClick={() => onPick(q)}
            className="btn-ghost"
            style={{
              padding: '12px 16px',
              border: '1px solid var(--border)',
              borderRadius: 8,
              background: 'var(--bg-2)',
              color: 'var(--text)',
              fontSize: 13,
              cursor: 'pointer',
              transition: 'all 0.15s',
              textAlign: 'left',
            }}
          >
            {q}
          </button>
        ))}
      </div>
    </div>
  )
}

function Message({ m }) {
  const isUser = m.from === 'user'
  const ts = m.ts ? new Date(m.ts).toLocaleTimeString([], {
    hour: '2-digit', minute: '2-digit',
  }) : ''

  return (
    <div className="fade-in" style={{
      display: 'flex', justifyContent: isUser ? 'flex-end' : 'flex-start',
    }}>
      <div style={{ maxWidth: '78%' }}>
        <div style={{
          fontSize: 11, color: 'var(--text-faint)',
          marginBottom: 4,
          textAlign: isUser ? 'right' : 'left',
        }}>
          {isUser ? 'You' : 'CIPHRA'} · {ts}
        </div>

        <div style={{
          padding: '12px 16px',
          background: isUser ? 'var(--primary)' : 'var(--bg-2)',
          color: isUser ? 'white' : 'var(--text)',
          border: isUser ? 'none' : '1px solid var(--border)',
          borderRadius: 12,
          borderTopRightRadius: isUser ? 4 : 12,
          borderTopLeftRadius: isUser ? 12 : 4,
        }}>
          {!isUser && (m.classification || m.status) && (
            <div style={{
              display: 'flex', gap: 6, marginBottom: 10,
              alignItems: 'center', flexWrap: 'wrap',
            }}>
              {m.classification && (
                <span className={`badge badge-${m.classification}`}>{m.classification}</span>
              )}
              {m.status && (
                <span className={`badge badge-${m.status === 'allowed' ? 'allowed' : 'denied'}`}>
                  {m.status}
                </span>
              )}
            </div>
          )}
          <div style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-word', fontSize: 14 }}>
            {m.text}
          </div>
        </div>
      </div>
    </div>
  )
}

function Spinner() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none">
      <circle cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="3"
        strokeOpacity="0.2" />
      <path d="M12 2 a10 10 0 0 1 10 10" stroke="currentColor" strokeWidth="3"
        strokeLinecap="round">
        <animateTransform attributeName="transform" type="rotate"
          from="0 12 12" to="360 12 12" dur="1s" repeatCount="indefinite" />
      </path>
    </svg>
  )
}
