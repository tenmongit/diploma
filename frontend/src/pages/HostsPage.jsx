import { useState, useEffect } from 'react';
import client from '../api/client';

export default function HostsPage() {
  const [hosts, setHosts] = useState([]);
  const [vendors, setVendors] = useState([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [vendorFilter, setVendorFilter] = useState('');
  const [expandedHost, setExpandedHost] = useState(null);
  const [hostDetail, setHostDetail] = useState(null);

  useEffect(() => {
    fetchData();
  }, []);

  const fetchData = async () => {
    try {
      const [hostsRes, vendorsRes] = await Promise.all([
        client.get('/api/hosts', { params: { limit: 200 } }),
        client.get('/api/vendors'),
      ]);
      setHosts(hostsRes.data);
      setVendors(vendorsRes.data);
    } catch (err) {
      console.error('Failed to fetch data:', err);
    } finally {
      setLoading(false);
    }
  };

  const fetchHostDetail = async (hostId) => {
    if (expandedHost === hostId) {
      setExpandedHost(null);
      setHostDetail(null);
      return;
    }
    try {
      const res = await client.get(`/api/hosts/${hostId}`);
      setHostDetail(res.data);
      setExpandedHost(hostId);
    } catch (err) {
      console.error('Failed to fetch host detail:', err);
    }
  };

  const applyFilters = async () => {
    setLoading(true);
    try {
      const params = { limit: 200 };
      if (search) params.search = search;
      if (vendorFilter) params.vendor_id = vendorFilter;
      const res = await client.get('/api/hosts', { params });
      setHosts(res.data);
    } catch (err) {
      console.error('Filter error:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    const timer = setTimeout(applyFilters, 400);
    return () => clearTimeout(timer);
  }, [search, vendorFilter]);

  const getSeverityBadge = (score) => {
    if (score >= 9) return <span className="badge badge-critical">Critical</span>;
    if (score >= 7) return <span className="badge badge-high">High</span>;
    if (score >= 4) return <span className="badge badge-medium">Medium</span>;
    return <span className="badge badge-low">Low</span>;
  };

  return (
    <div className="fade-in">
      <div className="page-header">
        <h2>Hosts</h2>
        <p>Browse and filter all discovered hosts, services, and vulnerabilities</p>
      </div>

      {/* Filters */}
      <div className="card" style={{ marginBottom: '24px' }}>
        <div className="filters-bar">
          <input
            type="text"
            className="form-input"
            placeholder="🔍 Search by IP or domain..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
          <select
            className="filter-select"
            value={vendorFilter}
            onChange={(e) => setVendorFilter(e.target.value)}
          >
            <option value="">All Vendors</option>
            {vendors.map((v) => (
              <option key={v.id} value={v.id}>{v.name}</option>
            ))}
          </select>
          <span className="text-sm text-muted">{hosts.length} hosts found</span>
        </div>
      </div>

      {/* Hosts Table */}
      <div className="card">
        {loading ? (
          <div className="empty-state">
            <div className="empty-icon">⏳</div>
            <h3>Loading hosts...</h3>
          </div>
        ) : hosts.length > 0 ? (
          <table className="data-table">
            <thead>
              <tr>
                <th>IP Address</th>
                <th>Domain</th>
                <th>Vendor</th>
                <th>Location</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {hosts.map((host) => (
                <>
                  <tr key={host.id} onClick={() => fetchHostDetail(host.id)} style={{ cursor: 'pointer' }}>
                    <td className="mono">{host.ip_address}</td>
                    <td className="mono">{host.domain || '—'}</td>
                    <td>{host.vendor_name || '—'}</td>
                    <td className="text-sm text-muted">
                      {host.geolocation?.city || '—'}, {host.geolocation?.country || ''}
                    </td>
                    <td>
                      <button className="btn btn-secondary btn-sm">
                        {expandedHost === host.id ? '▲ Close' : '▼ Details'}
                      </button>
                    </td>
                  </tr>
                  {expandedHost === host.id && hostDetail && (
                    <tr key={`${host.id}-detail`}>
                      <td colSpan="5" style={{ padding: '0 16px 16px' }}>
                        <div style={{ background: 'var(--bg-secondary)', borderRadius: 'var(--radius-md)', padding: '16px' }}>
                          {/* Services */}
                          <h4 style={{ marginBottom: '12px', color: 'var(--accent-blue)' }}>
                            🔌 Services ({hostDetail.services?.length || 0})
                          </h4>
                          {hostDetail.services?.length > 0 ? (
                            <table className="data-table" style={{ marginBottom: '16px' }}>
                              <thead>
                                <tr>
                                  <th>Port</th>
                                  <th>Protocol</th>
                                  <th>Service</th>
                                  <th>Classification</th>
                                  <th>Product</th>
                                </tr>
                              </thead>
                              <tbody>
                                {hostDetail.services.map((svc) => (
                                  <tr key={svc.id}>
                                    <td className="mono">{svc.port}</td>
                                    <td>{svc.protocol}</td>
                                    <td>{svc.service_name || '—'}</td>
                                    <td>
                                      <span className="badge badge-info">{svc.classification || '—'}</span>
                                    </td>
                                    <td className="text-sm">{svc.banner_data?.product || '—'}</td>
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                          ) : <p className="text-muted text-sm">No services found</p>}

                          {/* Vulnerabilities */}
                          <h4 style={{ marginBottom: '12px', color: 'var(--accent-red)' }}>
                            ⚠️ Vulnerabilities ({hostDetail.vulnerabilities?.length || 0})
                          </h4>
                          {hostDetail.vulnerabilities?.length > 0 ? (
                            <table className="data-table">
                              <thead>
                                <tr>
                                  <th>Title</th>
                                  <th>CVE</th>
                                  <th>Privacy Risk</th>
                                  <th>Score</th>
                                  <th>Severity</th>
                                </tr>
                              </thead>
                              <tbody>
                                {hostDetail.vulnerabilities.map((v) => (
                                  <tr key={v.id}>
                                    <td className="text-sm">{v.title || '—'}</td>
                                    <td className="mono">{v.cve_id || '—'}</td>
                                    <td className="text-sm">{v.privacy_risk_type || '—'}</td>
                                    <td className="mono">{v.risk_score?.toFixed(1)}</td>
                                    <td>{getSeverityBadge(v.risk_score)}</td>
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                          ) : <p className="text-muted text-sm">No vulnerabilities found</p>}
                        </div>
                      </td>
                    </tr>
                  )}
                </>
              ))}
            </tbody>
          </table>
        ) : (
          <div className="empty-state">
            <div className="empty-icon">🖥️</div>
            <h3>No hosts found</h3>
            <p className="text-sm">
              {search || vendorFilter
                ? 'Try adjusting your filters'
                : 'Run a scan to discover hosts'}
            </p>
          </div>
        )}
      </div>
    </div>
  );
}
