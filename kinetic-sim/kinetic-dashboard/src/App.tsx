import { useState, useEffect, useRef, useCallback } from 'react'
import './App.css'

// ─── Types ────────────────────────────────────────────────────────────────────

interface LogEntry {
  id: number
  time: string
  source: string
  message: string
  type: string
}

interface NodeInfo  { state: string }
interface HostInfo  { state: string; capacity: number; peer_id: string | null }
interface DaemonInfo { state: string; domain: string | null; host: number | null; dns_ok: boolean; lost_name?: string; lost_reason?: string; kid?: string }

interface Snapshot {
  phase: number
  phase_name: string
  nodes:   Record<string, NodeInfo>
  hosts:   Record<string, HostInfo>
  daemons: Record<string, DaemonInfo>
  logs:    Record<string, LogEntry[]>
}

// ─── Constants ────────────────────────────────────────────────────────────────

const PHASES = [
  { id: 0, label: 'Launch' },
  { id: 1, label: 'Nodes Up' },
  { id: 2, label: 'Hosts Up' },
  { id: 3, label: 'Daemons Up' },
  { id: 4, label: 'Identity' },
  { id: 5, label: 'Negotiate' },
  { id: 6, label: 'VDF + Register' },
  { id: 7, label: 'Publish' },
  { id: 8, label: 'DNS Verify' },
  { id: 9, label: 'Heartbeat' },
]



const STATE_LABELS: Record<string, string> = {
  WAITING_NODES:    'Waiting',
  BOOTING:          'Booting',
  P2P_WAIT:         'P2P...',
  CREATING_KID:     'Identity',
  NEGOTIATING_HOST: 'Negotiate',
  REGISTERING:      'VDF Proof',
  PUBLISHING:       'Publish',
  VERIFYING_DNS:    'DNS Check',
  ALIVE:            'Live ✓',
  HEARTBEATING:     'Live ✓',
  SYNCED:           'Synced',
  ROUTING:          'Routing',
  READY:            'Ready',
  FULL:             'Full',
  ERROR:            'Error',
}

// Agent avatar emojis — each role has a distinct character
const NODE_AVATARS  = ['🖥️','💾','🗄️','📡','🔌','⚙️','🏗️','🔧','📶','🌐']
const HOST_AVATARS  = ['🏢','🏗️','🌍','🔒','🌏','🚀']
const DAEMON_PERSONAS = [
  'Alice — Startup Founder',    'Bob — Privacy Advocate',     'Carol — Developer',
  'Dave — Digital Artist',      'Eve — Journalist',           'Frank — Musician',
  'Grace — Crypto Enthusiast',  'Hank — Researcher',          'Ivy — Small Business',
  'Jack — Gamer',               'Kai — Open Source Dev',      'Lena — Photographer',
  'Max — Community Org',        'Nina — Student',             'Omar — Email Provider',
  'Priya — Podcaster',          'Quinn — DAO Treasurer',      'Ray — DeFi Developer',
  'Sara — Writer',              'Tom — Data Scientist',       'Uma — SysAdmin',
  'Vic — Security Researcher',  'Wendy — DEX Developer',      'Xan — VPN Provider',
  'Yara — IoT Manufacturer',    'Zoe — Non-Profit',           'Alex — Restaurant Owner',
  'Blake — Freelancer',         'Chris — Content Creator',    'Dana — Climate Activist',
  'Eli — Game Developer',       'Fay — Healthcare Startup',   'Gil — Real Estate',
  'Hina — Robotics Startup',
]

// ─── SSE Hook — connect once, receive push updates ────────────────────────────

function useSSE(url: string): Snapshot | null {
  const [snap, setSnap] = useState<Snapshot | null>(null)
  const esRef = useRef<EventSource | null>(null)

  const connect = useCallback(() => {
    if (esRef.current) {
      esRef.current.close()
    }

    const es = new EventSource(url)
    esRef.current = es

    es.onmessage = (e) => {
      try {
        const data: Snapshot = JSON.parse(e.data)
        setSnap(data)
      } catch { /* ignore parse errors */ }
    }

    es.onerror = () => {
      es.close()
      esRef.current = null
      // Reconnect after 3s if connection dropped
      setTimeout(connect, 3000)
    }
  }, [url])

  useEffect(() => {
    connect()
    return () => {
      esRef.current?.close()
    }
  }, [connect])

  return snap
}

// ─── Phase Timeline ───────────────────────────────────────────────────────────

function PhaseTimeline({ phase }: { phase: number }) {
  return (
    <div className="phase-timeline">
      {PHASES.map((p, i) => {
        const status = p.id < phase ? 'done' : p.id === phase ? 'active' : 'pending'
        return (
          <div key={p.id} className={`phase-step ${status}`}>
            <div className="phase-dot">
              {p.id < phase ? '✓' : p.id === phase ? String(p.id) : String(p.id)}
            </div>
            <span className="phase-label">{p.label}</span>
            {i < PHASES.length - 1 && <div className="phase-connector" />}
          </div>
        )
      })}
    </div>
  )
}

// ─── Hero Counter ─────────────────────────────────────────────────────────────

function HeroCounter({ snap }: { snap: Snapshot | null }) {
  const alive   = snap ? Object.values(snap.daemons).filter(d => ['ALIVE','HEARTBEATING'].includes(d.state)).length : 0
  const dnsOk   = snap ? Object.values(snap.daemons).filter(d => d.dns_ok).length : 0
  const nodesUp = snap ? Object.values(snap.nodes).filter(n => ['SYNCED','ROUTING'].includes(n.state)).length : 0
  const hostsUp = snap ? Object.values(snap.hosts).filter(h => ['READY','FULL'].includes(h.state)).length : 0

  return (
    <div className="hero-row">
      <div className="hero-card hero-main">
        <div className="hero-number">{alive}<span className="hero-denom">/34</span></div>
        <div className="hero-label">Namespaces Live on<br /><strong>Kinetic Network</strong></div>
        {dnsOk > 0 && <div className="hero-sub">✓ {dnsOk} DNS verified</div>}
      </div>
      <div className="hero-card">
        <div className="hero-number hero-small">{nodesUp}<span className="hero-denom">/10</span></div>
        <div className="hero-label">DHT Nodes<br /><strong>Routing</strong></div>
      </div>
      <div className="hero-card">
        <div className="hero-number hero-small">{hostsUp}<span className="hero-denom">/6</span></div>
        <div className="hero-label">CDN Hosts<br /><strong>Serving</strong></div>
      </div>
    </div>
  )
}

// ─── Agent Chat Feed ──────────────────────────────────────────────────────────

function ChatMessage({ entry, avatarEmoji, roleClass }: {
  entry: LogEntry
  avatarEmoji: string
  roleClass: string
}) {
  const cleanMsg = entry.message

  return (
    <div className={`chat-msg ${roleClass}`}>
      <div className="chat-avatar" title={entry.source}>{avatarEmoji}</div>
      <div className="chat-bubble">
        <div className="chat-header">
          <span className="chat-source">{entry.source}</span>
          <span className="chat-time">{entry.time}</span>
        </div>
        <div className="chat-text">{cleanMsg}</div>
      </div>
    </div>
  )
}

function AgentFeed({ logs, avatars, roleClass, title, icon, onClick }: {
  logs: LogEntry[]
  avatars: string[]
  roleClass: string
  title: string
  icon: string
  onClick?: () => void
}) {
  const containerRef = useRef<HTMLDivElement>(null)
  const latestId = logs[0]?.id

  useEffect(() => {
    if (containerRef.current) {
      containerRef.current.scrollTop = 0
    }
  }, [latestId])

  const getAvatar = (source: string): string => {
    const match = source.match(/(\d+)$/)
    if (match) {
      const idx = (parseInt(match[1]) - 1) % avatars.length
      return avatars[idx]
    }
    return avatars[0]
  }

  return (
    <div className="agent-feed card" onClick={onClick} style={{ cursor: onClick ? 'pointer' : 'default' }}>
      <div className="feed-header">
        <span className="feed-icon">{icon}</span>
        <span className="feed-title">{title}</span>
        <span className="feed-count">{logs.length} messages</span>
      </div>
      <div className="feed-body" ref={containerRef}>
        {logs.slice(0, onClick ? 40 : 200).map(entry => (
          <ChatMessage
            key={entry.id}
            entry={entry}
            avatarEmoji={getAvatar(entry.source)}
            roleClass={roleClass}
          />
        ))}
        {logs.length === 0 && (
          <div className="feed-empty">
            <span>⏳</span> Waiting for agent activity...
          </div>
        )}
      </div>
    </div>
  )
}

// ─── Daemon Grid ──────────────────────────────────────────────────────────────

function DaemonGrid({ daemons, setSelectedDaemon }: { daemons: Record<string, DaemonInfo>, setSelectedDaemon: any }) {
  return (
    <div className="card daemon-grid-card">
      <div className="feed-header">
        <span className="feed-icon">👥</span>
        <span className="feed-title">All 34 Namespace Owners</span>
        <span className="feed-count">
          {Object.values(daemons).filter(d => ['ALIVE','HEARTBEATING'].includes(d.state)).length} live
        </span>
      </div>
      <div className="daemon-grid">
        {Object.entries(daemons).map(([id, d]) => {
          const isLive = ['ALIVE','HEARTBEATING'].includes(d.state)
          const isErr  = d.state === 'ERROR'
          
          return (
            <div 
              key={id} 
              className={`daemon-card ${isLive ? 'daemon-live' : isErr ? 'daemon-error' : ''}`}
              onClick={() => setSelectedDaemon({ id, d })}
            >
              <div className="daemon-card-top">
                <div className="daemon-dot" style={{ background: isLive ? '#10b981' : isErr ? '#ef4444' : '#f59e0b' }} />
                <span className="daemon-num">#{id}</span>
                {d.dns_ok && <span className="dns-tick">✓</span>}
              </div>
              <div className="daemon-name">{DAEMON_PERSONAS[parseInt(id) - 1]?.split(' ')[0] || `Daemon ${id}`}</div>
              <div className="daemon-domain" title={d.domain || ''}>
                {d.domain || '...'}
                {d.host && d.domain && isLive && (
                  <a 
                    className="daemon-link-icon" 
                    href={`http://localhost:5000/proxy/${d.host}/${d.domain}/index.html`} 
                    target="_blank" 
                    rel="noreferrer"
                    onClick={e => e.stopPropagation()}
                    style={{ marginLeft: '4px', textDecoration: 'none', fontSize: '14px' }}
                    title="View Website"
                  >
                    🔗
                  </a>
                )}
              </div>
              {d.lost_name && (
                <div className="daemon-lost-domain" title={d.lost_reason}>
                  {d.lost_name}
                </div>
              )}
              <div className="daemon-state" style={{ color: isLive ? '#10b981' : isErr ? '#ef4444' : '#6b7280' }}>
                {STATE_LABELS[d.state] || d.state}
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}



// ─── Connection Indicator ─────────────────────────────────────────────────────

function ConnectionDot({ connected }: { connected: boolean }) {
  return (
    <div className={`conn-dot ${connected ? 'conn-live' : 'conn-dead'}`}
         title={connected ? 'SSE connected — live updates' : 'Reconnecting...'} />
  )
}

// ─── Root App ─────────────────────────────────────────────────────────────────

export default function App() {
  const snap      = useSSE('http://localhost:5000/stream')
  const [selectedDaemon, setSelectedDaemon] = useState<{ id: string; d: any } | null>(null)
  const [selectedFeed, setSelectedFeed] = useState<string | null>(null)
  const connected = snap !== null

  const daemonLogs = snap?.logs.daemon        ?? []
  const nodeLogs   = snap?.logs.node          ?? []
  const hostLogs   = snap?.logs.host          ?? []
  const DAEMON_AVATARS = DAEMON_PERSONAS.map(p => {
    const emojis = ['👩‍💻','🧑‍🎨','👨‍💼','👩‍🔬','📰','🎵','🏦','🔭','🛒','🎮',
                    '💻','📸','🏘️','🎓','📧','🎙️','🏛️','💱','✍️','📊',
                    '🖥️','🔐','💹','🔒','🤖','🌿','🍽️','🎨','📹','🌱',
                    '🎮','🏥','🏠','🦾']
    return emojis[DAEMON_PERSONAS.indexOf(p) % emojis.length]
  })

  return (
    <div className="app">

      <header className="topbar">
        <div className="topbar-brand">
          <div className="brand-logo">⬡</div>
          <div className="brand-text">
            <div className="brand-name">Kinetic Network</div>
            <div className="brand-sub">Decentralized DNS — Live Simulation</div>
          </div>
        </div>
        <div className="topbar-center">
          {snap && <PhaseTimeline phase={snap.phase} />}
        </div>
        <div className="topbar-right">
          <ConnectionDot connected={connected} />
          <span className="conn-label">{connected ? 'Live' : 'Connecting...'}</span>
        </div>
      </header>


      <HeroCounter snap={snap} />

      <div className="main-grid">

        <div className="col-daemons">
          {snap
            ? <DaemonGrid daemons={snap.daemons} setSelectedDaemon={setSelectedDaemon} />
            : <div className="card placeholder">Connecting to orchestrator...</div>
          }
        </div>

        <div className="col-feeds">
          <AgentFeed
            logs={daemonLogs}
            avatars={DAEMON_AVATARS}
            roleClass="daemon"
            title="Namespace Owners"
            icon="👨‍💻"
            onClick={() => setSelectedFeed('daemon')}
          />
          <AgentFeed
            logs={hostLogs}
            avatars={HOST_AVATARS}
            roleClass="host"
            title="CDN Hosts"
            icon="🏢"
            onClick={() => setSelectedFeed('host')}
          />
          <AgentFeed
            logs={nodeLogs}
            avatars={NODE_AVATARS}
            roleClass="node"
            title="DHT Nodes"
            icon="🌐"
            onClick={() => setSelectedFeed('node')}
          />
        </div>

      </div>

      {selectedDaemon && (
        <div className="modal-overlay" onClick={() => setSelectedDaemon(null)}>
          <div className="modal-content" style={{ width: '500px', maxHeight: '90vh' }} onClick={e => e.stopPropagation()}>
            <button className="modal-close" onClick={() => setSelectedDaemon(null)}>×</button>
            <div className="modal-header">
              <h2>{DAEMON_PERSONAS[parseInt(selectedDaemon.id) - 1]}</h2>
              <div className={`phase-badge ${['ALIVE', 'HEARTBEATING'].includes(selectedDaemon.d.state) ? 'done' : ''}`}>
                {STATE_LABELS[selectedDaemon.d.state] || selectedDaemon.d.state}
              </div>
            </div>
            <div className="modal-body">
              <div className="modal-row">
              <span className="modal-label">Namespace:</span>
              <span className="modal-value highlight">{selectedDaemon.d.domain || 'Not assigned yet'}</span>
            </div>
              {selectedDaemon.d.lost_name && (
                <div className="modal-row error-row">
                  <span className="modal-label">Previous Conflict</span>
                  <span className="modal-value">
                    <del>{selectedDaemon.d.lost_name}</del> <span className="error-text">({selectedDaemon.d.lost_reason})</span>
                  </span>
                </div>
              )}
              <div className="modal-row">
                <span className="modal-label">Kinetic Identity (KID)</span>
                <span className="modal-value mono">{selectedDaemon.d.kid || 'Creating...'}</span>
              </div>
              <div className="modal-row">
                <span className="modal-label">Connected Host</span>
                <span className="modal-value">{selectedDaemon.d.host ? `Host #${selectedDaemon.d.host}` : 'Pending negotiation'}</span>
              </div>
              {selectedDaemon.d.host && selectedDaemon.d.domain && (
                <div className="modal-row">
                  <span className="modal-label">Website:</span>
                  <a href={`http://localhost:5000/proxy/${selectedDaemon.d.host}/${selectedDaemon.d.domain}/index.html`} target="_blank" rel="noreferrer" className="modal-value link">
                    {selectedDaemon.d.domain} 🔗
                  </a>
                </div>
              )}
              <div className="modal-row" style={{ marginTop: '12px' }}>
                <span className="modal-label" style={{ marginBottom: '8px' }}>Recent Activity</span>
                <div style={{ height: '240px', display: 'flex' }}>
                  <AgentFeed
                    logs={daemonLogs.filter(log => log.source === `UserDaemon-${selectedDaemon.id}`)}
                    avatars={DAEMON_AVATARS}
                    roleClass="daemon"
                    title={`${DAEMON_PERSONAS[parseInt(selectedDaemon.id) - 1]?.split(' ')[0]}'s Logs`}
                    icon="📜"
                  />
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {selectedFeed && (
        <div className="modal-overlay" onClick={() => setSelectedFeed(null)}>
          <div className="modal-content modal-feed-content" onClick={e => e.stopPropagation()}>
            <button className="modal-close" onClick={() => setSelectedFeed(null)}>×</button>
            {selectedFeed === 'daemon' && (
              <AgentFeed
                logs={daemonLogs}
                avatars={DAEMON_AVATARS}
                roleClass="daemon"
                title="Namespace Owners"
                icon="👨‍💻"
              />
            )}
            {selectedFeed === 'host' && (
              <AgentFeed
                logs={hostLogs}
                avatars={HOST_AVATARS}
                roleClass="host"
                title="CDN Hosts"
                icon="🏢"
              />
            )}
            {selectedFeed === 'node' && (
              <AgentFeed
                logs={nodeLogs}
                avatars={NODE_AVATARS}
                roleClass="node"
                title="DHT Nodes"
                icon="🌐"
              />
            )}
          </div>
        </div>
      )}

    </div>
  )
}
