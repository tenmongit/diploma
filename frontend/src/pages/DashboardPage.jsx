import { useState, useEffect } from 'react';
import client from '../api/client';

export default function DashboardPage() {
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchStats();
  }, []);

  const fetchStats = async () => {
    try {
      const res = await client.get('/api/dashboard/stats');
      setStats(res.data);
    } catch (err) {
      console.error('Failed to fetch stats:', err);
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="fade-in">
        <div className="page-header">
          <h2>Dashboard</h2>
          <p>Loading analytics...</p>
        </div>
      </div>
    );
  }

  const s = stats || {
    total_hosts: 0, total_services: 0, total_vulnerabilities: 0,
    critical_count: 0, high_count: 0, medium_count: 0, low_count: 0,
    top_vendors: [], recent_scans: [],
  };

  return (
    <div className="fade-in">
      <div className="page-header">
        <h2>Dashboard</h2>
        <p>Overview of discovered Smart City infrastructure and privacy threats</p>
      </div>

      {/* Stat Cards */}
      <div className="stats-grid">
        <div className="stat-card blue">
          <div className="stat-icon">🖥️</div>
          <div className="stat-value">{s.total_hosts}</div>
          <div className="stat-label">Discovered Hosts</div>
        </div>
        <div className="stat-card green">
          <div className="stat-icon">🔌</div>
          <div className="stat-value">{s.total_services}</div>
          <div className="stat-label">Open Services</div>
        </div>
        <div className="stat-card red">
          <div className="stat-icon">⚠️</div>
          <div className="stat-value">{s.total_vulnerabilities}</div>
          <div className="stat-label">Vulnerabilities</div>
        </div>
        <div className="stat-card amber">
          <div className="stat-icon">🔴</div>
          <div className="stat-value">{s.critical_count}</div>
          <div className="stat-label">Critical Findings</div>
        </div>
      </div>

      <div className="grid-2">
        {/* Severity Breakdown */}
        <div className="card">
          <div className="card-header">
            <h3 className="card-title">Severity Breakdown</h3>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
            {[
              { label: 'Critical', count: s.critical_count, color: 'var(--accent-red)', cls: 'critical' },
              { label: 'High', count: s.high_count, color: '#f97316', cls: 'high' },
              { label: 'Medium', count: s.medium_count, color: 'var(--accent-amber)', cls: 'medium' },
              { label: 'Low', count: s.low_count, color: 'var(--accent-green)', cls: 'low' },
            ].map((sev) => {
              const total = s.total_vulnerabilities || 1;
              const pct = Math.round((sev.count / total) * 100) || 0;
              return (
                <div key={sev.label}>
                  <div className="flex-between" style={{ marginBottom: '4px' }}>
                    <span className="text-sm">
                      <span className={`badge badge-${sev.cls}`}>{sev.label}</span>
                    </span>
                    <span className="text-sm text-muted">{sev.count} ({pct}%)</span>
                  </div>
                  <div className="progress-bar">
                    <div
                      className="progress-fill"
                      style={{
                        width: `${pct}%`,
                        background: sev.color,
                      }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Top Vendors */}
        <div className="card">
          <div className="card-header">
            <h3 className="card-title">Top Vendors</h3>
          </div>
          {s.top_vendors.length > 0 ? (
            <table className="data-table">
              <thead>
                <tr>
                  <th>Vendor</th>
                  <th style={{ textAlign: 'right' }}>Hosts</th>
                </tr>
              </thead>
              <tbody>
                {s.top_vendors.map((v, i) => (
                  <tr key={i}>
                    <td>{v.name}</td>
                    <td style={{ textAlign: 'right' }}>
                      <span className="badge badge-info">{v.count}</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <div className="empty-state">
              <div className="empty-icon">📦</div>
              <h3>No vendors yet</h3>
              <p className="text-sm">Run a scan to discover vendors</p>
            </div>
          )}
        </div>
      </div>

      {/* Recent Scans */}
      <div className="card" style={{ marginTop: '24px' }}>
        <div className="card-header">
          <h3 className="card-title">Recent Scans</h3>
        </div>
        {s.recent_scans.length > 0 ? (
          <table className="data-table">
            <thead>
              <tr>
                <th>ID</th>
                <th>Target</th>
                <th>Status</th>
                <th>Progress</th>
                <th>Date</th>
              </tr>
            </thead>
            <tbody>
              {s.recent_scans.map((scan) => (
                <tr key={scan.id}>
                  <td className="mono">#{scan.id}</td>
                  <td className="mono">{scan.target_domain}</td>
                  <td>
                    <span className={`badge badge-${scan.status}`}>{scan.status}</span>
                  </td>
                  <td>
                    <div className="progress-bar" style={{ width: '100px' }}>
                      <div className="progress-fill" style={{ width: `${scan.progress}%` }} />
                    </div>
                  </td>
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
            <h3>No scans yet</h3>
            <p className="text-sm">Start a new scan to discover infrastructure</p>
          </div>
        )}
      </div>
    </div>
  );
}
