import { useState, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';
import { ArrowLeft, Save, Plus, Trash2, Server } from 'lucide-react';

interface DnsRecord {
  id: string;
  type: string;
  name: string;
  content: string;
  ttl: string;
}

export default function DomainView() {
  const { name } = useParams<{ name: string }>();
  const [records, setRecords] = useState<DnsRecord[]>([]);
  const [unsaved, setUnsaved] = useState(false);
  const [isSaving, setIsSaving] = useState(false);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [loadedRawData, setLoadedRawData] = useState<string>('');
  const [page, setPage] = useState(0);
  const RECORDS_PER_PAGE = 100;
  
  const totalPages = Math.ceil(records.length / RECORDS_PER_PAGE);
  const paginatedRecords = records.slice(page * RECORDS_PER_PAGE, (page + 1) * RECORDS_PER_PAGE);

  useEffect(() => {
    fetch(`/api/zone/${encodeURIComponent(name || '')}`)
      .then(res => {
        if (!res.ok) throw new Error(`API returned ${res.status}`);
        return res.json();
      })
      .then(data => {
        if (data.error) throw new Error(data.error);
        if (data.records) {
          setLoadedRawData(JSON.stringify(data.records));
          const loadedRecords: DnsRecord[] = [];
          Object.entries(data.records).forEach(([recordName, recList]: [string, any]) => {
            recList.forEach((r: any) => {
              loadedRecords.push({
                id: Math.random().toString(36).substr(2, 9),
                type: r.type,
                name: recordName,
                content: r.value,
                ttl: 'Auto'
              });
            });
          });
          setRecords(loadedRecords);
        }
        setLoading(false);
      })
      .catch(e => {
        console.error(e);
        setLoadError(e.message);
        setLoading(false);
      });
  }, [name]);

  const handleAddRecord = () => {
    setRecords([...records, { id: Math.random().toString(36).substr(2, 9), type: 'A', name: '', content: '', ttl: 'Auto' }]);
    setUnsaved(true);
  };

  const handleUpdateRecord = (id: string, field: keyof DnsRecord, value: string) => {
    setRecords(records.map(r => {
      if (r.id === id) {
        if (field === 'type' && r.type !== value) {
          return { ...r, [field]: value, content: '' };
        }
        return { ...r, [field]: value };
      }
      return r;
    }));
    setUnsaved(true);
  };

  const handleDeleteRecord = (id: string) => {
    setRecords(records.filter(r => r.id !== id));
    setUnsaved(true);
  };

  const handleSave = async () => {
    setIsSaving(true);
    // Convert back to API format
    const zoneRecords: Record<string, any[]> = {};
    records.forEach(r => {
      if (!zoneRecords[r.name]) zoneRecords[r.name] = [];
      zoneRecords[r.name].push({ type: r.type, value: r.content });
    });

    try {
      // Edge Case 61: Optimistic Concurrency Check
      if (loadedRawData) {
        const currentRes = await fetch(`/api/zone/${encodeURIComponent(name || '')}`);
        if (currentRes.ok) {
          const currentData = await currentRes.json();
          if (currentData.records && JSON.stringify(currentData.records) !== loadedRawData) {
             const confirmOverwrite = window.confirm("Warning: Another device or process has modified this zone since you loaded it. Saving will overwrite their changes! Are you sure you want to proceed?");
             if (!confirmOverwrite) {
                setIsSaving(false);
                return;
             }
          }
        }
      }

      const res = await fetch(`/api/zone/${encodeURIComponent(name || '')}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ records: zoneRecords })
      });
      const data = await res.json();
      if (data.error) {
        alert('Failed to publish records: ' + data.error);
      } else {
        setUnsaved(false);
        alert('DNS records saved and published to the network!');
      }
    } catch (e) {
      alert('Failed to save records. Check daemon connection.');
    }
    setIsSaving(false);
  };

  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', marginBottom: '2rem' }}>
        <Link to="/" className="btn btn-secondary" style={{ padding: '0.5rem' }}>
          <ArrowLeft size={16} />
        </Link>
        <div>
          <h1>{name}</h1>
          <p className="subtitle" style={{ marginBottom: 0 }}>Manage DNS records and settings for this zone.</p>
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <h2 className="card-title" style={{ margin: 0, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Server size={18} />
            DNS Records
          </h2>
          <button className="btn btn-primary" onClick={handleAddRecord}>
            <Plus size={16} /> Add Record
          </button>
        </div>

        <div className="table-container">
          {loading ? (
            <div style={{ padding: '2rem', textAlign: 'center' }}>Loading...</div>
          ) : loadError ? (
            <div style={{ padding: '2rem', textAlign: 'center', color: 'var(--danger-red)' }}>
              Error loading DNS records: {loadError}. Please check daemon connection.
            </div>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>Type</th>
                  <th>Name</th>
                  <th>Content</th>
                  <th>TTL</th>
                  <th style={{ width: '80px' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {paginatedRecords.map(record => (
                  <tr key={record.id}>
                    <td>
                      <select 
                        value={record.type} 
                        onChange={(e) => handleUpdateRecord(record.id, 'type', e.target.value)}
                        style={{ padding: '0.25rem', borderRadius: '4px', border: '1px solid var(--border-color)', background: 'var(--bg-secondary)', color: 'var(--text-primary)' }}
                      >
                        <option value="A">A</option>
                        <option value="AAAA">AAAA</option>
                        <option value="CNAME">CNAME</option>
                        <option value="TXT">TXT</option>
                        <option value="PeerId">PeerId</option>
                      </select>
                    </td>
                    <td>
                      <input 
                        type="text" 
                        value={record.name} 
                        onChange={(e) => handleUpdateRecord(record.id, 'name', e.target.value)}
                        style={{ padding: '0.25rem', borderRadius: '4px', border: '1px solid var(--border-color)', background: 'var(--bg-secondary)', color: 'var(--text-primary)', width: '100%' }}
                      />
                    </td>
                    <td>
                      <input 
                        type="text" 
                        value={record.content} 
                        onChange={(e) => handleUpdateRecord(record.id, 'content', e.target.value)}
                        style={{ padding: '0.25rem', borderRadius: '4px', border: '1px solid var(--border-color)', background: 'var(--bg-secondary)', color: 'var(--text-primary)', width: '100%', fontFamily: 'monospace' }}
                      />
                    </td>
                    <td>{record.ttl}</td>
                    <td>
                      <button className="btn" style={{ color: 'var(--danger-red)', padding: '0.25rem' }} onClick={() => handleDeleteRecord(record.id)}>
                        <Trash2 size={16} />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
        {!loading && !loadError && totalPages > 1 && (
          <div style={{ display: 'flex', justifyContent: 'center', padding: '1rem', gap: '1rem', alignItems: 'center' }}>
            <button className="btn" disabled={page === 0} onClick={() => setPage(page - 1)}>Previous</button>
            <span>Page {page + 1} of {totalPages}</span>
            <button className="btn" disabled={page >= totalPages - 1} onClick={() => setPage(page + 1)}>Next</button>
          </div>
        )}
      </div>

      {unsaved && (
        <div style={{ position: 'fixed', bottom: '2rem', left: '50%', transform: 'translateX(-50%)', backgroundColor: 'var(--bg-card)', padding: '1rem 2rem', borderRadius: '8px', border: '1px solid var(--border-color)', boxShadow: '0 10px 15px -3px rgba(0, 0, 0, 0.1)', display: 'flex', alignItems: 'center', gap: '2rem', zIndex: 100 }}>
          <div>
            <h4 style={{ margin: 0, fontSize: '0.875rem' }}>Unsaved Changes</h4>
            <p style={{ margin: 0, fontSize: '0.75rem', color: 'var(--text-secondary)' }}>You have uncommitted modifications to this zone.</p>
          </div>
          <button className="btn btn-primary" onClick={handleSave} disabled={isSaving}>
            <Save size={16} /> {isSaving ? 'Saving...' : 'Deploy & Publish'}
          </button>
        </div>
      )}
    </div>
  );
}
