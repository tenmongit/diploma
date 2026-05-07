import { NavLink, Outlet } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

export default function Layout() {
  const { user, logout } = useAuth();

  const navItems = [
    { to: '/', icon: '📊', label: 'Dashboard', end: true },
    { to: '/map', icon: '🗺️', label: 'Threat Map' },
    { to: '/scan', icon: '🔍', label: 'New Scan' },
    { to: '/hosts', icon: '🖥️', label: 'Hosts' },
    { to: '/risk-explanation', icon: '📘', label: 'Risk Guide' },
    { to: '/reports', icon: '📄', label: 'Reports' },
  ];

  return (
    <div className="app-layout">
      <aside className="sidebar">
        <div className="sidebar-logo">
          <div className="logo-icon">🛡️</div>
          <div>
            <h1>SmartCity<br /><span className="logo-sub">OSINT Platform</span></h1>
          </div>
        </div>

        <nav className="sidebar-nav">
          {navItems.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.end}
              className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}
            >
              <span className="nav-icon">{item.icon}</span>
              {item.label}
            </NavLink>
          ))}
        </nav>

        <div className="sidebar-footer">
          <div className="sidebar-user" onClick={logout} title="Click to logout">
            <div className="user-avatar">
              {user?.username?.charAt(0).toUpperCase()}
            </div>
            <div className="user-info">
              <div className="user-name">{user?.username}</div>
              <div className="user-role">Analyst</div>
            </div>
            <span style={{ fontSize: '0.9rem', opacity: 0.5 }}>⬅️</span>
          </div>
        </div>
      </aside>

      <main className="main-content">
        <Outlet />
      </main>
    </div>
  );
}
