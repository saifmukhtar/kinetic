import { useEffect, useState } from 'react';
import { Settings as SettingsIcon, Save, Eye, EyeOff } from 'lucide-react';

export default function Settings() {
  const [config, setConfig] = useState<any>(null);
  const [networkMode, setNetworkMode] = useState('FullNode');
  const [token, setToken] = useState(localStorage.getItem('kinetic_auth_token') || '');
  const [isSaving, setIsSaving] = useState(false);
  const [showToken, setShowToken] = useState(false);

  useEffect(() => {
    fetch('/api/config')
      .then(r => r.json())
      .then(data => {
        setConfig(data);
        if (data.mode) setNetworkMode(data.mode);
        if (data.token && !localStorage.getItem('kinetic_auth_token')) {
          setToken(data.token);
          localStorage.setItem('kinetic_auth_token', data.token);
        }
      })
      .catch(console.error);
  }, []);

  const handleSave = async () => {
    setIsSaving(true);
    localStorage.setItem('kinetic_auth_token', token);
    try {
      const res = await fetch('/api/config', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ...config, mode: networkMode })
      });
      const data = await res.json();
      alert(data.message || 'Settings saved!');
    } catch (e) {
      alert('Error saving config');
    }
    setIsSaving(false);
  };

  return (
    <div className="content">
      <div className="header-actions">
        <div>
          <h1>Daemon Settings</h1>
          <p className="subtitle" style={{ marginTop: '0.25rem' }}>Configure local proxy, network interfaces, and auth tokens</p>
        </div>
        <button className="btn btn-primary" onClick={handleSave} disabled={isSaving}>
          <Save size={18} />
          {isSaving ? 'Saving...' : 'Save Changes'}
        </button>
      </div>

      <div className="card" style={{ marginTop: '2rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1.5rem', borderBottom: '1px solid #333', paddingBottom: '1rem' }}>
          <SettingsIcon size={20} color="#f6821f" />
          <h2 style={{ fontSize: '1.25rem', margin: 0 }}>API Configuration</h2>
        </div>

        {config ? (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            <div>
              <label style={{ display: 'block', fontSize: '0.875rem', color: '#888', marginBottom: '0.5rem' }}>API Token (Bearer)</label>
              <div style={{ position: 'relative', display: 'flex', alignItems: 'center' }}>
                <input 
                  type={showToken ? 'text' : 'password'} 
                  className="input-field" 
                  value={token} 
                  onChange={e => setToken(e.target.value)}
                  style={{ width: '100%', fontFamily: 'monospace', paddingRight: '40px' }} 
                />
                <button 
                  onClick={() => setShowToken(!showToken)}
                  style={{ position: 'absolute', right: '10px', background: 'none', border: 'none', color: '#888', cursor: 'pointer', display: 'flex' }}
                  title={showToken ? "Hide Token" : "Show Token"}
                >
                  {showToken ? <EyeOff size={18} /> : <Eye size={18} />}
                </button>
              </div>
              <p style={{ fontSize: '0.75rem', color: '#666', marginTop: '0.25rem' }}>This token is required to authenticate against the local Daemon REST API. Saved locally in your browser.</p>
            </div>


          </div>
        ) : (
          <p>Loading configuration...</p>
        )}
      </div>
    </div>
  );
}
