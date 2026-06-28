import { Shield, Plus } from 'lucide-react';

export default function Watchtowers() {
  return (
    <div className="content">
      <div className="header-actions">
        <div>
          <h1>Watchtowers</h1>
          <p className="subtitle" style={{ marginTop: '0.25rem' }}>Deploy nodes to persist your DNS records on the DHT</p>
        </div>
        <button className="btn btn-primary" onClick={() => alert('Watchtower deployment coming soon!')}>
          <Plus size={18} />
          Deploy Watchtower
        </button>
      </div>

      <div className="card" style={{ marginTop: '2rem', textAlign: 'center', padding: '4rem 2rem' }}>
        <Shield size={48} color="#f6821f" style={{ margin: '0 auto 1rem', opacity: 0.8 }} />
        <h2>No Watchtowers Configured</h2>
        <p className="subtitle" style={{ maxWidth: '400px', margin: '0.5rem auto 1.5rem' }}>
          Watchtowers ensure your domains stay online even when your main Kinetic daemon is offline by continuously refreshing your DHT records.
        </p>
        <button className="btn btn-primary" onClick={() => alert('Coming soon!')} style={{ margin: '0 auto' }}>
          Generate Deployment Script
        </button>
      </div>
    </div>
  );
}
