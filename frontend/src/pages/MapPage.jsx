import { useState, useEffect } from 'react';
import { MapContainer, TileLayer, CircleMarker, Popup } from 'react-leaflet';
import client from '../api/client';

const SEVERITY_COLORS = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#f59e0b',
  low: '#10b981',
  default: '#3b82f6',
};

const SEVERITY_RADIUS = {
  critical: 12,
  high: 10,
  medium: 8,
  low: 6,
  default: 7,
};

export default function MapPage() {
  const [hosts, setHosts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [lastUpdated, setLastUpdated] = useState(null);

  useEffect(() => {
    fetchHosts();
    const interval = setInterval(fetchHosts, 10000);
    const handleScanCompleted = () => fetchHosts();
    window.addEventListener('scan-completed', handleScanCompleted);
    return () => {
      clearInterval(interval);
      window.removeEventListener('scan-completed', handleScanCompleted);
    };
  }, []);

  const fetchHosts = async () => {
    try {
      const res = await client.get('/api/hosts', { params: { limit: 500 } });
      setHosts(res.data);
      setLastUpdated(new Date());
    } catch (err) {
      console.error('Failed to fetch hosts:', err);
    } finally {
      setLoading(false);
    }
  };

  // Filter hosts with valid geolocation
  const mappableHosts = hosts.filter(
    (h) => h.geolocation && h.geolocation.lat && h.geolocation.lon
  );

  // Determine map center
  const defaultCenter = [51.1605, 71.4704]; // Astana, Kazakhstan
  const center = mappableHosts.length > 0
    ? [mappableHosts[0].geolocation.lat, mappableHosts[0].geolocation.lon]
    : defaultCenter;

  const formatDateTime = (value) => {
    if (!value) return '—';
    return new Date(value).toLocaleString();
  };

  const severityClass = (severity) => `badge badge-${severity || 'low'}`;

  return (
    <div className="fade-in">
      <div className="page-header">
        <div className="flex-between">
          <div>
            <h2>Threat Map</h2>
            <p>Geographic visualization of discovered Smart City infrastructure</p>
            <p className="text-sm text-muted">
              Auto-refreshes every 10 seconds
              {lastUpdated ? ` • Last updated ${lastUpdated.toLocaleTimeString()}` : ''}
            </p>
          </div>
          <div style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
            {Object.entries(SEVERITY_COLORS).filter(([k]) => k !== 'default').map(([label, color]) => (
              <div key={label} style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                <div style={{
                  width: 10, height: 10, borderRadius: '50%',
                  background: color, boxShadow: `0 0 6px ${color}`,
                }} />
                <span className="text-sm text-muted" style={{ textTransform: 'capitalize' }}>{label}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
        <div className="map-container">
          <MapContainer
            center={center}
            zoom={12}
            scrollWheelZoom={true}
            style={{ width: '100%', height: '100%' }}
          >
            <TileLayer
              url="https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png"
              attribution='&copy; <a href="https://carto.com/">CARTO</a>'
            />
            {mappableHosts.map((host) => {
              const severity = host.max_severity || 'default';
              const color = SEVERITY_COLORS[severity] || SEVERITY_COLORS.default;
              const radius = SEVERITY_RADIUS[severity] || SEVERITY_RADIUS.default;

              return (
                <CircleMarker
                  key={host.id}
                  center={[host.geolocation.lat, host.geolocation.lon]}
                  radius={radius}
                  pathOptions={{
                    color: color,
                    fillColor: color,
                    fillOpacity: 0.6,
                    weight: 2,
                    opacity: 0.8,
                  }}
                >
                  <Popup>
                    <div>
                      <div className="popup-title">
                        {host.ip_address}
                      </div>
                      <div className="popup-row">
                        <span className="label">Domain:</span>
                        <span>{host.domain || '—'}</span>
                      </div>
                      <div className="popup-row">
                        <span className="label">Vendor:</span>
                        <span>{host.vendor_name || '—'}</span>
                      </div>
                      <div className="popup-row">
                        <span className="label">Location:</span>
                        <span>{host.geolocation.city || '—'}, {host.geolocation.country || ''}</span>
                      </div>
                      <div className="popup-row">
                        <span className="label">Scan:</span>
                        <span>#{host.scan_job_id || '—'} {host.scan_target_domain || ''}</span>
                      </div>
                      <div className="popup-row">
                        <span className="label">Appeared:</span>
                        <span>{formatDateTime(host.scan_created_at || host.created_at)}</span>
                      </div>
                      <div className="popup-row">
                        <span className="label">Vulnerabilities:</span>
                        <span>{host.vulnerability_count || 0}</span>
                      </div>
                      {host.vulnerabilities?.length > 0 && (
                        <div style={{ marginTop: '8px' }}>
                          <div className="label" style={{ marginBottom: '4px' }}>Exact findings:</div>
                          {host.vulnerabilities.slice(0, 5).map((v) => (
                            <div key={v.id} className="popup-vuln-row">
                              <span className={severityClass(v.severity)}>{v.severity}</span>
                              <span>{v.title || v.cve_id || 'Privacy risk'}</span>
                            </div>
                          ))}
                          {host.vulnerabilities.length > 5 && (
                            <div className="text-sm text-muted">+{host.vulnerabilities.length - 5} more</div>
                          )}
                        </div>
                      )}
                    </div>
                  </Popup>
                </CircleMarker>
              );
            })}
          </MapContainer>
        </div>
      </div>

      <div className="card" style={{ marginTop: '24px' }}>
        <div className="card-header">
          <h3 className="card-title">Mapped Assets ({mappableHosts.length})</h3>
        </div>
        {mappableHosts.length > 0 ? (
          <table className="data-table">
            <thead>
              <tr>
                <th>IP Address</th>
                <th>Domain</th>
                <th>Vendor</th>
                <th>Scan</th>
                <th>Appeared</th>
                <th>Vulns</th>
                <th>City</th>
                <th>Coordinates</th>
              </tr>
            </thead>
            <tbody>
              {mappableHosts.map((h) => (
                <tr key={h.id}>
                  <td className="mono">{h.ip_address}</td>
                  <td className="mono">{h.domain || '—'}</td>
                  <td>{h.vendor_name || '—'}</td>
                  <td className="mono">#{h.scan_job_id || '—'} {h.scan_target_domain || ''}</td>
                  <td className="text-sm text-muted">{formatDateTime(h.scan_created_at || h.created_at)}</td>
                  <td>
                    <span className={h.vulnerability_count > 0 ? 'badge badge-high' : 'badge badge-low'}>
                      {h.vulnerability_count || 0}
                    </span>
                  </td>
                  <td>{h.geolocation.city || '—'}</td>
                  <td className="text-muted text-sm mono">
                    {h.geolocation.lat?.toFixed(4)}, {h.geolocation.lon?.toFixed(4)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <div className="empty-state">
            <div className="empty-icon">🗺️</div>
            <h3>No geolocated hosts</h3>
            <p className="text-sm">Run a scan to discover geolocated infrastructure</p>
          </div>
        )}
      </div>
    </div>
  );
}
