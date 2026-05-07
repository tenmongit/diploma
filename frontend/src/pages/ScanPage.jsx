import { useState, useEffect, useRef } from 'react';
import client from '../api/client';

const PHASES = [
  { name: 'DNS Enumeration', icon: '🌐', pct: 20 },
  { name: 'Certificate Transparency', icon: '📜', pct: 35 },
  { name: 'Shodan Discovery', icon: '🔎', pct: 60 },
  { name: 'Censys Analysis', icon: '🔐', pct: 75 },
  { name: 'Classification', icon: '🏷️', pct: 90 },
  { name: 'Finalize', icon: '✅', pct: 100 },
];

const SUGGESTED_DOMAINS = [
  'astana.gov.kz',
  'almaty.gov.kz',
  'shymkent.gov.kz',
  'karaganda.gov.kz',
  'aktobe.gov.kz',
  'atyrau.gov.kz',
  'pavlodar.gov.kz',
  'semey.gov.kz',
  'gov.kz',
  'edu.kz',
  'mil.kz',
];

export default function ScanPage() {
  const [domain, setDomain] = useState('');
  const [activeScan, setActiveScan] = useState(null);
  const [scans, setScans] = useState([]);
  const [error, setError] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [showSuggestions, setShowSuggestions] = useState(false);
  const [scanMode, setScanMode] = useState('real');
  const pollRef = useRef(null);

  useEffect(() => {
    fetchScans();
    return () => {
      if (pollRef.current) clearInterval(pollRef.current);
    };
  }, []);

  const fetchScans = async () => {
    try {
      const res = await client.get('/api/scans');
      setScans(res.data);
      // If there's a running scan, start polling
      const running = res.data.find((s) => s.status === 'running' || s.status === 'pending');
      if (running) {
        setActiveScan(running);
        startPolling(running.id);
      }
    } catch (err) {
      console.error('Failed to fetch scans:', err);
    }
  };

  const startPolling = (scanId) => {
    if (pollRef.current) clearInterval(pollRef.current);
    pollRef.current = setInterval(async () => {
      try {
        const res = await client.get(`/api/scans/${scanId}`);
        setActiveScan(res.data);
        if (res.data.status === 'completed' || res.data.status === 'failed') {
          clearInterval(pollRef.current);
          pollRef.current = null;
          window.dispatchEvent(new CustomEvent('scan-completed', { detail: res.data }));
          fetchScans();
        }
      } catch (err) {
        console.error('Poll error:', err);
      }
    }, 2000);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!domain.trim()) return;
    setError('');
    setSubmitting(true);
    try {
      const res = await client.post('/api/scans', { target_domain: domain, scan_mode: scanMode });
      setActiveScan(res.data);
      setDomain('');
      startPolling(res.data.id);
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to create scan');
    } finally {
      setSubmitting(false);
    }
  };

  const getPhaseStatus = (phase) => {
    if (!activeScan) return '';
    if (activeScan.progress >= phase.pct) return 'completed';
    if (activeScan.progress >= phase.pct - 15) return 'active';
    return '';
  };

  const getPhaseIcon = (phase) => {
    if (!activeScan) return phase.icon;
    if (activeScan.progress >= phase.pct) return '✅';
    if (activeScan.progress >= phase.pct - 15) return '⏳';
    return phase.icon;
  };

  const getFilteredSuggestions = () => {
    if (!domain) return SUGGESTED_DOMAINS;
    return SUGGESTED_DOMAINS.filter(d => 
      d.toLowerCase().includes(domain.toLowerCase())
    );
  };

  const handleSelectDomain = (selectedDomain) => {
    setDomain(selectedDomain);
    setShowSuggestions(false);
  };

  return (
    <div className="fade-in">
      <div className="page-header">
        <h2>New Scan</h2>
        <p>Enter a domain to begin automated OSINT reconnaissance</p>
      </div>

      {/* Scan Input */}
      <div className="card">
        <form onSubmit={handleSubmit}>
          <div className="scan-mode-selector">
            <label className={`scan-mode-option ${scanMode === 'real' ? 'active' : ''}`}>
              <input
                type="radio"
                name="scanMode"
                value="real"
                checked={scanMode === 'real'}
                onChange={() => setScanMode('real')}
                disabled={submitting || (activeScan && activeScan.status === 'running')}
              />
              <span>
                <strong>Real Passive OSINT</strong>
                <small>Free public sources only</small>
              </span>
            </label>
            <label className={`scan-mode-option demo ${scanMode === 'demo' ? 'active' : ''}`}>
              <input
                type="radio"
                name="scanMode"
                value="demo"
                checked={scanMode === 'demo'}
                onChange={() => setScanMode('demo')}
                disabled={submitting || (activeScan && activeScan.status === 'running')}
              />
              <span>
                <strong>Defense Demo</strong>
                <small>Synthetic dataset, clearly marked</small>
              </span>
            </label>
          </div>

          {scanMode === 'demo' && (
            <div className="demo-notice">
              Demo mode uses synthetic OSINT-style data for academic presentation. It is not real target evidence.
            </div>
          )}

          <div className="domain-suggest-wrapper">
            <div className="scan-input-group">
              <input
                type="text"
                className="form-input"
                placeholder="Enter target domain (e.g., astana.gov.kz)"
                value={domain}
                onChange={(e) => {
                  setDomain(e.target.value);
                  setShowSuggestions(true);
                }}
                onFocus={() => setShowSuggestions(true)}
                onBlur={() => setTimeout(() => setShowSuggestions(false), 200)}
                disabled={submitting || (activeScan && activeScan.status === 'running')}
                autoComplete="off"
              />
              <button
                type="submit"
                className="btn btn-primary"
                disabled={submitting || !domain.trim() || (activeScan && activeScan.status === 'running')}
                style={{ whiteSpace: 'nowrap' }}
              >
                {submitting ? '⏳ Starting...' : '🚀 Start Scan'}
              </button>
            </div>

            {showSuggestions && getFilteredSuggestions().length > 0 && (
              <div className="domain-suggestions">
                {getFilteredSuggestions().map((suggestedDomain) => (
                  <div
                    key={suggestedDomain}
                    onClick={() => handleSelectDomain(suggestedDomain)}
                    className="domain-suggestion-item"
                  >
                    🌐 {suggestedDomain}
                  </div>
                ))}
              </div>
            )}
          </div>
        </form>

        {error && <div className="login-error">{error}</div>}

        {/* Active Scan Progress */}
        {activeScan && (activeScan.status === 'running' || activeScan.status === 'pending') && (
          <div className="scan-progress">
            <div className="progress-header">
              <span className="progress-status">
                Scanning <strong className="text-blue">{activeScan.target_domain}</strong>
                <span className={`scan-mode-badge ${activeScan.result?.scan_mode === 'demo' || scanMode === 'demo' ? 'demo' : 'real'}`}>
                  {activeScan.result?.scan_mode === 'demo' || scanMode === 'demo' ? 'DEMO' : 'REAL'}
                </span>
              </span>
              <span className="progress-pct">{activeScan.progress}%</span>
            </div>
            <div className="progress-bar" style={{ height: '12px' }}>
              <div className="progress-fill" style={{ width: `${activeScan.progress}%` }} />
            </div>

            <div className="scan-phases">
              {PHASES.map((phase) => (
                <div key={phase.name} className={`scan-phase ${getPhaseStatus(phase)}`}>
                  <span className="phase-icon">{getPhaseIcon(phase)}</span>
                  <span>{phase.name}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Completed Scan Result */}
        {activeScan && activeScan.status === 'completed' && activeScan.result && (
          <div style={{ marginTop: '24px' }}>
            <h3 className="card-title" style={{ marginBottom: '16px' }}>
              ✅ Scan Complete — {activeScan.target_domain}
              <span className={`scan-mode-badge ${activeScan.result.scan_mode === 'demo' ? 'demo' : 'real'}`}>
                {activeScan.result.scan_mode === 'demo' ? 'DEMO' : 'REAL'}
              </span>
            </h3>
            {activeScan.result.data_notice && (
              <div className={activeScan.result.scan_mode === 'demo' ? 'demo-notice' : 'real-notice'}>
                {activeScan.result.data_notice}
              </div>
            )}
            <div className="stats-grid">
              <div className="stat-card blue">
                <div className="stat-value">{activeScan.result.total_hosts || 0}</div>
                <div className="stat-label">Hosts Found</div>
              </div>
              <div className="stat-card green">
                <div className="stat-value">{activeScan.result.total_services || 0}</div>
                <div className="stat-label">Services</div>
              </div>
              <div className="stat-card red">
                <div className="stat-value">{activeScan.result.total_vulnerabilities || 0}</div>
                <div className="stat-label">Vulnerabilities</div>
              </div>
              <div className="stat-card purple">
                <div className="stat-value">{activeScan.result.subdomains_found || 0}</div>
                <div className="stat-label">Subdomains</div>
              </div>
            </div>
          </div>
        )}

        {/* Failed */}
        {activeScan && activeScan.status === 'failed' && (
          <div className="login-error" style={{ marginTop: '16px' }}>
            ❌ Scan failed: {activeScan.error_message || 'Unknown error'}
          </div>
        )}
      </div>

      {/* Previous Scans */}
      <div className="card" style={{ marginTop: '24px' }}>
        <div className="card-header">
          <h3 className="card-title">Scan History</h3>
          <button className="btn btn-secondary btn-sm" onClick={fetchScans}>🔄 Refresh</button>
        </div>
        {scans.length > 0 ? (
          <table className="data-table">
            <thead>
              <tr>
                <th>ID</th>
                <th>Target</th>
                <th>Mode</th>
                <th>Status</th>
                <th>Progress</th>
                <th>Hosts</th>
                <th>Vulns</th>
                <th>Date</th>
              </tr>
            </thead>
            <tbody>
              {scans.map((scan) => (
                <tr key={scan.id} style={{ cursor: 'pointer' }} onClick={() => setActiveScan(scan)}>
                  <td className="mono">#{scan.id}</td>
                  <td className="mono">{scan.target_domain}</td>
                  <td>
                    <span className={`scan-mode-badge ${scan.result?.scan_mode === 'demo' ? 'demo' : 'real'}`}>
                      {scan.result?.scan_mode === 'demo' ? 'DEMO' : 'REAL'}
                    </span>
                  </td>
                  <td><span className={`badge badge-${scan.status}`}>{scan.status}</span></td>
                  <td>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <div className="progress-bar" style={{ width: '80px' }}>
                        <div className="progress-fill" style={{ width: `${scan.progress}%` }} />
                      </div>
                      <span className="text-sm text-muted">{scan.progress}%</span>
                    </div>
                  </td>
                  <td>{scan.result?.total_hosts || '—'}</td>
                  <td>{scan.result?.total_vulnerabilities || '—'}</td>
                  <td className="text-muted text-sm">
                    {scan.created_at ? new Date(scan.created_at).toLocaleString() : '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <div className="empty-state">
            <div className="empty-icon">🔍</div>
            <h3>No previous scans</h3>
            <p className="text-sm">Enter a domain above to start your first scan</p>
          </div>
        )}
      </div>
    </div>
  );
}
