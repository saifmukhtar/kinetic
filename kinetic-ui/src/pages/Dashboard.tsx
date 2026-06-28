import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { Globe, Plus, ShieldCheck } from 'lucide-react';

interface Domain {
  name: string;
  status: 'active' | 'hibernating';
  expires_in: string;
}

export default function Dashboard() {
  const [domains, setDomains] = useState<Domain[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch('/api/owned-names')
      .then(res => res.json())
      .then(data => {
        // data is an array of strings e.g. ["saif.kin", "test.kin"]
        // Map it to our frontend format
        const formatted = data.map((name: string) => ({
          name,
          status: 'active',
          expires_in: 'Auto-renewing (Daemon Active)'
        }));
        setDomains(formatted);
        setLoading(false);
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
            <Link to={`/domain/${d.name}`} key={d.name} style={{ color: 'inherit' }}>
              <div className="card">
                <div className="card-header">
                  <h3 className="card-title">{d.name}</h3>
                  {d.status === 'active' ? (
                    <span className="badge badge-success">Active</span>
                  ) : (
                    <span className="badge badge-warning">Hibernating</span>
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
