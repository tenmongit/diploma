import { useState, useEffect } from 'react';
import client from '../api/client';

export default function ReportPage() {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [generating, setGenerating] = useState(null);

  useEffect(() => {
    fetchScans();
  }, []);

  const fetchScans = async () => {
    try {
      const res = await client.get('/api/scans');
      setScans(res.data.filter((s) => s.status === 'completed'));
    } catch (err) {
      console.error('Failed to fetch scans:', err);
    } finally {
      setLoading(false);
    }
  };

  const downloadReport = async (scanId, targetDomain) => {
    setGenerating(scanId);
    try {
      const res = await client.get(`/api/reports/${scanId}/pdf`, {
        responseType: 'blob',
      });
      const url = window.URL.createObjectURL(new Blob([res.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `osint_report_${targetDomain}_${scanId}.pdf`);
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
    } catch (err) {
      console.error('Report generation failed:', err);
      alert('Failed to generate report');
    } finally {
      setGenerating(null);
    }
  };

  return (
    <div className="fade-in">
      <div className="page-header">
        <h2>Reports</h2>
        <p>Generate and download PDF security posture reports for completed scans</p>
      </div>

      <div className="card">
        {loading ? (
          <div className="empty-state">
            <div className="empty-icon">⏳</div>
            <h3>Loading...</h3>
          </div>
        ) : scans.length > 0 ? (
          <table className="data-table">
            <thead>
              <tr>
                <th>Scan ID</th>
                <th>Target Domain</th>
                <th>Hosts</th>
                <th>Vulnerabilities</th>
                <th>Date</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {scans.map((scan) => (
                <tr key={scan.id}>
                  <td className="mono">#{scan.id}</td>
                  <td className="mono">{scan.target_domain}</td>
                  <td>{scan.result?.total_hosts || '—'}</td>
                  <td>{scan.result?.total_vulnerabilities || '—'}</td>
                  <td className="text-muted text-sm">
                    {scan.created_at ? new Date(scan.created_at).toLocaleString() : '—'}
                  </td>
                  <td>
                    <button
                      className="btn btn-primary btn-sm"
                      onClick={() => downloadReport(scan.id, scan.target_domain)}
                      disabled={generating === scan.id}
                    >
                      {generating === scan.id ? '⏳ Generating...' : '📄 Download PDF'}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <div className="empty-state">
            <div className="empty-icon">📄</div>
            <h3>No completed scans</h3>
            <p className="text-sm">Complete a scan first to generate reports</p>
          </div>
        )}
      </div>

      {/* Report Format Info */}
      <div className="card" style={{ marginTop: '24px' }}>
        <div className="card-header">
          <h3 className="card-title">Report Contents</h3>
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '16px' }}>
          {[
            { icon: '📊', title: 'Executive Summary', desc: 'High-level findings overview' },
            { icon: '🖥️', title: 'Host Inventory', desc: 'All discovered IPs and domains' },
            { icon: '🔌', title: 'Service Analysis', desc: 'Open ports and software versions' },
            { icon: '⚠️', title: 'Vulnerability Report', desc: 'CVEs and privacy risk scores' },
            { icon: '🔒', title: 'Privacy Assessment', desc: 'LINDDUN threat categories' },
            { icon: '📈', title: 'Severity Stats', desc: 'Critical/High/Medium/Low counts' },
          ].map((item) => (
            <div
              key={item.title}
              style={{
                background: 'var(--bg-card)',
                borderRadius: 'var(--radius-md)',
                padding: '16px',
                border: '1px solid var(--border-subtle)',
              }}
            >
              <div style={{ fontSize: '1.5rem', marginBottom: '8px' }}>{item.icon}</div>
              <div style={{ fontWeight: 600, marginBottom: '4px', fontSize: '0.9rem' }}>{item.title}</div>
              <div className="text-sm text-muted">{item.desc}</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
