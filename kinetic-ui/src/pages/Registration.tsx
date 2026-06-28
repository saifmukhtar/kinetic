import { useState } from 'react';
import { Terminal, Shield, Play } from 'lucide-react';

export default function Registration() {
  const [domainName, setDomainName] = useState('');
  const [isRegistering, setIsRegistering] = useState(false);
  const [progress, setProgress] = useState(0);
  const [statusMessage, setStatusMessage] = useState('Generating VDF Iterations');

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!domainName) return;
    
    setIsRegistering(true);
    setProgress(0);
    setStatusMessage('Starting registration...');

    try {
      const res = await fetch('/api/vdf/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: domainName, iterations: 100000 })
      });
      
      const data = await res.json();
      if (data.task_id) {
        pollStatus(data.task_id);
      }
    } catch (e) {
      setStatusMessage('Error starting registration');
      setIsRegistering(false);
    }
  };

  const pollStatus = (taskId: string) => {
    const interval = setInterval(async () => {
      try {
        const res = await fetch(`/api/vdf/status/${taskId}`);
        const data = await res.json();
        
        if (data.error) {
          clearInterval(interval);
          setStatusMessage('Task failed or not found.');
          setIsRegistering(false);
          return;
        }

        setProgress(data.progress);
        setStatusMessage(data.status);

        if (data.progress >= 100) {
          clearInterval(interval);
          setIsRegistering(false);
          alert('Registration Complete!');
          setDomainName('');
        } else if (data.status === 'Failed') {
          clearInterval(interval);
          setIsRegistering(false);
          alert('Registration Failed: ' + data.error);
        }
      } catch (e) {
        console.error(e);
      }
    }, 2000);
  };

  return (
    <div style={{ maxWidth: '600px', margin: '0 auto' }}>
      <h1>Register Domain</h1>
      <p className="subtitle">Reserve a new .kin domain by calculating its cryptographic VDF proof.</p>

      <div className="card">
        <form onSubmit={handleRegister}>
          <div className="form-group">
            <label className="form-label">Domain Name</label>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <input 
                type="text" 
                className="form-input" 
                placeholder="e.g. my-awesome-app"
                value={domainName}
                onChange={e => setDomainName(e.target.value)}
                disabled={isRegistering}
                style={{ flex: 1 }}
              />
              <span style={{ color: 'var(--text-secondary)', fontWeight: 600 }}>.kin</span>
            </div>
            {domainName && !isRegistering && (
              <p style={{ fontSize: '0.75rem', color: 'var(--accent-blue)', marginTop: '0.5rem' }}>
                Estimated VDF computation time: {
                  (() => {
                    const iters = Math.max(100000, Math.floor(20000000 / domainName.length));
                    const seconds = Math.floor(iters / 100000);
                    return seconds < 60 ? `~${seconds} seconds` : `~${Math.ceil(seconds / 60)} minutes`;
                  })()
                }
              </p>
            )}
          </div>

          <div style={{ marginTop: '2rem' }}>
            <button type="submit" className="btn btn-primary" style={{ width: '100%', justifyContent: 'center' }} disabled={isRegistering || !domainName}>
              {isRegistering ? (
                <>
                  <Shield size={16} /> Computing VDF Proof...
                </>
              ) : (
                <>
                  <Play size={16} /> Start Registration
                </>
              )}
            </button>
          </div>
        </form>

        {isRegistering && (
          <div style={{ marginTop: '2rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.875rem', marginBottom: '0.5rem' }}>
              <span style={{ color: 'var(--text-secondary)' }}>
                <Terminal size={14} style={{ display: 'inline', verticalAlign: 'middle', marginRight: '4px' }}/> 
                {statusMessage}
              </span>
              <span>{progress}%</span>
            </div>
            <div className="progress-container">
              <div className="progress-bar" style={{ width: `${progress}%` }}></div>
            </div>
            <p style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: '0.5rem', textAlign: 'center' }}>
              This may take a few minutes depending on your CPU. Do not close this page.
            </p>
          </div>
        )}
      </div>
    </div>
  );
}
