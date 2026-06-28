import { useEffect, useState } from 'react';
import { Users, Database, Clock } from 'lucide-react';

export default function NetworkStatus() {
  const [status, setStatus] = useState<any>(null);

  useEffect(() => {
    fetch('/api/network-status')
      .then(r => r.json())
      .then(data => setStatus(data))
      .catch(console.error);
  }, []);

  return (
    <div className="content">
      <div className="header-actions">
        <h1>Network Status</h1>
        {status && <span className="status-badge active">{status.status}</span>}
      </div>
      
      <p className="subtitle">Real-time statistics of the Kinetic Decentralized Network.</p>

      {status ? (
        <div className="dashboard-grid" style={{ marginTop: '2rem' }}>
          <div className="card">
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1rem' }}>
              <Users size={20} color="#f6821f" />
              <h2 style={{ fontSize: '1.25rem', margin: 0 }}>Active Peers</h2>
            </div>
            <p style={{ fontSize: '2rem', fontWeight: 600, margin: 0 }}>{status.peers}</p>
          </div>

          <div className="card">
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1rem' }}>
              <Database size={20} color="#f6821f" />
              <h2 style={{ fontSize: '1.25rem', margin: 0 }}>DHT Size</h2>
            </div>
            <p style={{ fontSize: '2rem', fontWeight: 600, margin: 0 }}>{status.dht_size}</p>
          </div>

          <div className="card">
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1rem' }}>
              <Clock size={20} color="#f6821f" />
              <h2 style={{ fontSize: '1.25rem', margin: 0 }}>Daemon Uptime</h2>
            </div>
            <p style={{ fontSize: '2rem', fontWeight: 600, margin: 0 }}>{status.uptime}</p>
          </div>
        </div>
      ) : (
        <div className="card" style={{ marginTop: '2rem' }}>Loading network metrics...</div>
      )}
    </div>
  );
}
