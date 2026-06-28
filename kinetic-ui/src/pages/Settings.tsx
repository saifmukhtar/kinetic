import { useEffect, useState } from 'react';
import { Settings as SettingsIcon, Save } from 'lucide-react';

export default function Settings() {
  const [config, setConfig] = useState<any>(null);
  const [networkMode, setNetworkMode] = useState('FullNode');
  const [isSaving, setIsSaving] = useState(false);

  useEffect(() => {
    fetch('/api/config')
      .then(r => r.json())
      .then(data => {
        setConfig(data);
        if (data.mode) setNetworkMode(data.mode);
      })
      .catch(console.error);
  }, []);

  const handleSave = async () => {
    setIsSaving(true);
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
              <input 
                type="text" 
                className="input-field" 
                value={config.token || ''} 
                readOnly 
                style={{ width: '100%', fontFamily: 'monospace' }} 
              />
              <p style={{ fontSize: '0.75rem', color: '#666', marginTop: '0.25rem' }}>This token is required to authenticate against the local Daemon REST API.</p>
            </div>


          </div>
        ) : (
          <p>Loading configuration...</p>
        )}
      </div>
    </div>
  );
}
