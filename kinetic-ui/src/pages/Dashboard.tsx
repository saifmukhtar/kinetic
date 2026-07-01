import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { Globe, Plus, ShieldCheck } from 'lucide-react';

interface Domain {
  name: string;
  status: 'active' | 'hibernating' | 'checking';
  expires_in: string;
}

export default function Dashboard() {
  const [domains, setDomains] = useState<Domain[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch('/api/owned-names')
      .then(res => res.json())
      .then(async data => {
        const formatted = data.map((name: string) => ({
          name,
          status: 'checking',
          expires_in: 'Checking DHT network status...'
        }));
        setDomains(formatted);
        setLoading(false);

        // Verify each domain on the network
        for (const name of data) {
          try {
            const res = await fetch(`/api/resolve/${encodeURIComponent(name)}`);
            const resolveData = await res.json();
            setDomains(prev => prev.map(d => {
              if (d.name === name) {
                if (resolveData.error) {
                  return { ...d, status: 'hibernating', expires_in: 'Offline / Expired on DHT' };
                } else {
                  return { ...d, status: 'active', expires_in: 'Auto-renewing (Daemon Active)' };
                }
              }
              return d;
            }));
          } catch (e) {
            setDomains(prev => prev.map(d => d.name === name ? { ...d, status: 'hibernating', expires_in: 'Failed to verify' } : d));
          }
        }
      })
      .catch(err => {
        console.error("Failed to fetch owned domains", err);
        setLoading(false);
      });
  }, []);

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '2rem' }}>
        <div>
          <h1>Your Domains</h1>
          <p className="subtitle" style={{ marginBottom: 0 }}>Manage your Kinetic zones and DNS records.</p>
        </div>
        <Link to="/register" className="btn btn-primary">
          <Plus size={16} />
          Register Domain
        </Link>
      </div>

      <div className="grid-3">
        {loading ? (
          <div className="card" style={{ gridColumn: '1 / -1', textAlign: 'center', padding: '2rem' }}>Loading domains...</div>
        ) : domains.length > 0 ? (
          domains.map(d => (
            <Link to={`/domain/${encodeURIComponent(d.name)}`} key={d.name} style={{ color: 'inherit' }}>
              <div className="card">
                <div className="card-header">
                  <h3 className="card-title">{d.name}</h3>
                  {d.status === 'active' ? (
                    <span className="badge badge-success">Active</span>
                  ) : d.status === 'hibernating' ? (
                    <span className="badge badge-warning">Hibernating</span>
                  ) : (
                    <span className="badge" style={{ backgroundColor: 'var(--bg-secondary)', color: 'var(--text-secondary)' }}>Checking...</span>
                  )}
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: 'var(--text-secondary)', fontSize: '0.875rem' }}>
                  <ShieldCheck size={16} />
                  VDF Expires in {d.expires_in}
                </div>
              </div>
            </Link>
          ))
        ) : (
          <div className="card" style={{ gridColumn: '1 / -1', textAlign: 'center', padding: '4rem 2rem' }}>
            <Globe size={48} color="var(--text-secondary)" style={{ margin: '0 auto 1rem', opacity: 0.5 }} />
            <h3>No domains yet</h3>
            <p className="subtitle">Register your first .kin domain to get started.</p>
            <Link to="/register" className="btn btn-primary">
              <Plus size={16} />
              Register Now
            </Link>
          </div>
        )}
      </div>
    </div>
  );
}
