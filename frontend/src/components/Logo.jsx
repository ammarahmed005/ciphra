// CIPHRA logo
// hexagonal seal: outer boundary + four RBAC tier rings + hash-chain links
// every visual element maps to a real security property of the system

export default function Logo({ size = 32, className = '' }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 80 80"
      xmlns="http://www.w3.org/2000/svg"
      className={className}
      style={{ display: 'block' }}
      aria-label="CIPHRA"
    >
      <defs>
        <linearGradient id="ciphra-stroke" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0" stopColor="#60a5fa" />
          <stop offset="1" stopColor="#2563eb" />
        </linearGradient>
        <radialGradient id="ciphra-fill" cx="50%" cy="50%" r="50%">
          <stop offset="0" stopColor="rgba(59, 130, 246, 0.18)" />
          <stop offset="1" stopColor="rgba(59, 130, 246, 0.02)" />
        </radialGradient>
      </defs>

      {/* outer hexagon — system boundary */}
      <polygon
        points="40,4 70,22 70,58 40,76 10,58 10,22"
        fill="url(#ciphra-fill)"
        stroke="url(#ciphra-stroke)"
        strokeWidth="2.5"
        strokeLinejoin="round"
      />

      {/* four nested tier rings (guest → employee → manager → admin) */}
      <circle cx="40" cy="40" r="22" fill="none"
        stroke="#1e3a8a" strokeWidth="1" opacity="0.5" />
      <circle cx="40" cy="40" r="17" fill="none"
        stroke="#2563eb" strokeWidth="1.2" opacity="0.7" />
      <circle cx="40" cy="40" r="12" fill="none"
        stroke="#3b82f6" strokeWidth="1.5" opacity="0.85" />
      <circle cx="40" cy="40" r="7" fill="none"
        stroke="#60a5fa" strokeWidth="1.8" />

      {/* chain links left side — hash-chain audit log */}
      <ellipse cx="14" cy="38" rx="2.4" ry="3.6"
        fill="none" stroke="#60a5fa" strokeWidth="1.6" />
      <ellipse cx="14" cy="44" rx="2.4" ry="3.6"
        fill="none" stroke="#60a5fa" strokeWidth="1.6" />

      {/* chain links right side */}
      <ellipse cx="66" cy="38" rx="2.4" ry="3.6"
        fill="none" stroke="#60a5fa" strokeWidth="1.6" />
      <ellipse cx="66" cy="44" rx="2.4" ry="3.6"
        fill="none" stroke="#60a5fa" strokeWidth="1.6" />

      {/* center dot — the query being classified */}
      <circle cx="40" cy="40" r="2.2" fill="#06b6d4" />

      {/* tiny crosshair on the center dot */}
      <line x1="36" y1="40" x2="38" y2="40" stroke="#60a5fa" strokeWidth="0.8" />
      <line x1="42" y1="40" x2="44" y2="40" stroke="#60a5fa" strokeWidth="0.8" />
      <line x1="40" y1="36" x2="40" y2="38" stroke="#60a5fa" strokeWidth="0.8" />
      <line x1="40" y1="42" x2="40" y2="44" stroke="#60a5fa" strokeWidth="0.8" />
    </svg>
  )
}
