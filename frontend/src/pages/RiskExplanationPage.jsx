const RISK_CATEGORIES = [
  {
    icon: '🌐',
    title: 'Publicly exposed web services',
    countedBecause: 'A service is reachable from the internet or appears in OSINT records as a public web interface.',
    plainImpact: 'If an internal dashboard, device page, or city service panel is visible online, it may reveal information about city systems or become a target for attackers.',
    example: 'HTTP or HTTPS management pages, dashboards, camera web panels, IoT gateway pages.',
  },
  {
    icon: '🎥',
    title: 'Camera and video stream exposure',
    countedBecause: 'The platform sees service names, ports, or banners commonly connected with cameras, DVR/NVR systems, or video streaming.',
    plainImpact: 'Cameras can affect citizens directly because they may capture faces, license plates, traffic routes, or public-space movement patterns.',
    example: 'RTSP services, Hikvision/Dahua/Axis-like products, video surveillance classifications.',
  },
  {
    icon: '📡',
    title: 'IoT and telemetry systems',
    countedBecause: 'The detected service looks like a broker or gateway used by sensors and connected city devices.',
    plainImpact: 'Telemetry systems can reveal how city infrastructure works, where sensors are located, and when devices send data.',
    example: 'MQTT brokers, IoT gateway interfaces, smart parking or traffic telemetry endpoints.',
  },
  {
    icon: '🔓',
    title: 'Weak or missing encryption',
    countedBecause: 'The record suggests outdated TLS, plaintext protocols, or self-signed certificates.',
    plainImpact: 'Weak encryption can make it easier for someone to read, modify, or impersonate communications between systems.',
    example: 'TLS 1.0, SSL-like banners, FTP, Telnet, unencrypted MQTT.',
  },
  {
    icon: '🏭',
    title: 'Industrial or infrastructure protocols',
    countedBecause: 'The service uses a protocol often associated with automation, sensors, utilities, or control systems.',
    plainImpact: 'Even without proving a direct weakness, these systems are sensitive because they may be connected to real-world infrastructure.',
    example: 'Modbus, OPC-UA, SCADA-like service classifications.',
  },
  {
    icon: '🧩',
    title: 'Known vulnerable products or CVEs',
    countedBecause: 'The detected product name matches software or devices that have public vulnerability records.',
    plainImpact: 'A CVE means security researchers have documented a weakness in that product family. It does not always prove this exact device is vulnerable, but it is a strong reason to investigate.',
    example: 'Known vulnerable camera firmware, embedded web servers, or IoT products.',
  },
];

const LINDDUN_ITEMS = [
  {
    label: 'Linkability',
    meaning: 'Separate pieces of data could be connected together to understand behavior or movement over time.',
  },
  {
    label: 'Identifiability',
    meaning: 'Data could help identify a person, vehicle, location, or user behind an event.',
  },
  {
    label: 'Disclosure of information',
    meaning: 'A system may reveal details that should not be public, such as technology names, locations, or operational metadata.',
  },
  {
    label: 'Non-compliance',
    meaning: 'The system may create privacy or security concerns that require policy, legal, or organizational review.',
  },
];

export default function RiskExplanationPage() {
  return (
    <div className="fade-in">
      <div className="page-header">
        <h2>Risk & Vulnerability Explanation</h2>
        <p>Plain-language explanation of why findings are counted and how they may affect smart-city systems</p>
      </div>

      <div className="card explanation-hero">
        <div>
          <h3>What does "vulnerability" mean in this platform?</h3>
          <p>
            In this platform, a finding can be a technical vulnerability, a privacy risk, or an exposure indicator.
            The system uses passive OSINT records and interprets discovered hosts, services, and banners as
            exposure or risk indicators. It does not actively attack or probe target systems.
          </p>
        </div>
        <div className="explanation-note">
          <strong>Important:</strong> a finding means "needs review", not automatically "confirmed hacked".
          Records are interpreted as exposure and risk indicators for analytical review.
        </div>
      </div>

      <div className="explanation-grid">
        {RISK_CATEGORIES.map((item) => (
          <div key={item.title} className="explanation-card">
            <div className="explanation-icon">{item.icon}</div>
            <h3>{item.title}</h3>
            <div className="explanation-block">
              <span>Why it is counted</span>
              <p>{item.countedBecause}</p>
            </div>
            <div className="explanation-block">
              <span>Possible real-world effect</span>
              <p>{item.plainImpact}</p>
            </div>
            <div className="explanation-example">Example: {item.example}</div>
          </div>
        ))}
      </div>

      <div className="card" style={{ marginTop: '24px' }}>
        <div className="card-header">
          <h3 className="card-title">How severity is interpreted</h3>
        </div>
        <div className="severity-explanation-grid">
          <div className="severity-explanation-item low">
            <span className="badge badge-low">Low</span>
            <p>Information is useful for inventory or monitoring, but immediate impact is limited.</p>
          </div>
          <div className="severity-explanation-item medium">
            <span className="badge badge-medium">Medium</span>
            <p>The service may expose useful operational details or use a risky configuration.</p>
          </div>
          <div className="severity-explanation-item high">
            <span className="badge badge-high">High</span>
            <p>The finding involves sensitive systems, risky protocols, known vulnerable products, or strong privacy impact.</p>
          </div>
          <div className="severity-explanation-item critical">
            <span className="badge badge-critical">Critical</span>
            <p>The finding combines strong exposure with serious privacy or known vulnerability indicators.</p>
          </div>
        </div>
      </div>

      <div className="card" style={{ marginTop: '24px' }}>
        <div className="card-header">
          <h3 className="card-title">Privacy impact in simple words</h3>
        </div>
        <div className="privacy-grid">
          {LINDDUN_ITEMS.map((item) => (
            <div key={item.label} className="privacy-item">
              <strong>{item.label}</strong>
              <p>{item.meaning}</p>
            </div>
          ))}
        </div>
      </div>

      <div className="card" style={{ marginTop: '24px' }}>
        <div className="card-header">
          <h3 className="card-title">Methodology summary</h3>
        </div>
        <div className="defense-script">
          <p>
            The platform uses passive OSINT-style records and interprets discovered hosts, services, and banners as
            exposure or risk indicators. The same pipeline classifies, scores, stores, and visualizes each finding
            through the dashboard.
          </p>
          <p>
            A counted vulnerability does not always mean exploitation is confirmed. It means the service, product,
            protocol, or privacy context matches known risk patterns and should be reviewed by responsible administrators.
          </p>
        </div>
      </div>
    </div>
  );
}
