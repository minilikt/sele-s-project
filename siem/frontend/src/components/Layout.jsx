import React, { useState, useEffect } from 'react';
import { fetchHealth } from '../api';

const iconProps = {
  viewBox: '0 0 24 24',
  fill: 'none',
  stroke: 'currentColor',
  strokeWidth: 1.7,
  strokeLinecap: 'round',
  strokeLinejoin: 'round',
  'aria-hidden': true,
};

const ICONS = {
  dashboard: (
    <svg {...iconProps}>
      <rect x="3" y="3" width="7" height="7" rx="1.5" />
      <rect x="14" y="3" width="7" height="7" rx="1.5" />
      <rect x="3" y="14" width="7" height="7" rx="1.5" />
      <rect x="14" y="14" width="7" height="7" rx="1.5" />
    </svg>
  ),
  events: (
    <svg {...iconProps}>
      <path d="M4 6h16M4 12h16M4 18h10" />
      <circle cx="20" cy="18" r="1.6" />
    </svg>
  ),
  alerts: (
    <svg {...iconProps}>
      <path d="M18 9a6 6 0 10-12 0c0 6-2.5 6.5-2.5 8h17C20.5 15.5 18 15 18 9z" />
      <path d="M10 21h4" />
    </svg>
  ),
  incidents: (
    <svg {...iconProps}>
      <path d="M12 3l7.5 2.8v5.7c0 4.8-3.1 8.9-7.5 10.5-4.4-1.6-7.5-5.7-7.5-10.5V5.8L12 3z" />
      <circle cx="11.5" cy="11" r="2.4" />
      <path d="M13.2 12.7l2.6 2.6" />
    </svg>
  ),
  mitre: (
    <svg {...iconProps}>
      <circle cx="12" cy="12" r="8.5" />
      <circle cx="12" cy="12" r="3.2" />
      <path d="M12 1.5v4M12 18.5v4M1.5 12h4M18.5 12h4" />
    </svg>
  ),
  rules: (
    <svg {...iconProps}>
      <path d="M4 7h8M17 7h3M4 17h3M11 17h9" />
      <circle cx="14.5" cy="7" r="2.2" />
      <circle cx="8.5" cy="17" r="2.2" />
    </svg>
  ),
  ingestion: (
    <svg {...iconProps}>
      <path d="M12 3v10" />
      <path d="M8 9.5l4 4 4-4" />
      <path d="M4 15.5V19a1 1 0 001 1h14a1 1 0 001-1v-3.5" />
    </svg>
  ),
  ai: (
    <svg {...iconProps}>
      <path d="M12 3l1.7 4.9L18.5 9.6l-4.8 1.7L12 16l-1.7-4.7L5.5 9.6l4.8-1.7L12 3z" />
      <path d="M18.5 15.5l.8 2.2 2.2.8-2.2.8-.8 2.2-.8-2.2-2.2-.8 2.2-.8.8-2.2z" />
    </svg>
  ),
  ioc: (
    <svg {...iconProps}>
      <path d="M12 2.5l8.2 4.7v9.6L12 21.5l-8.2-4.7V7.2L12 2.5z" />
      <circle cx="12" cy="12" r="2.4" />
      <path d="M12 6.5v3M12 14.5v3M7.5 9.5l2.2 1.3M14.3 13.2l2.2 1.3M7.5 14.5l2.2-1.3M14.3 10.8l2.2-1.3" />
    </svg>
  ),
};

const NAV_ITEMS = [
  { key: 'dashboard', group: 'Observe', label: 'Dashboard' },
  { key: 'events', group: 'Observe', label: 'Events' },
  { key: 'alerts', group: 'Observe', label: 'Alerts' },
  { key: 'incidents', group: 'Observe', label: 'Incidents' },
  { key: 'mitre', group: 'Investigate', label: 'MITRE ATT&CK' },
  { key: 'ai', group: 'Investigate', label: 'AI Assistant' },
  { key: 'ioc', group: 'Investigate', label: 'IoC Enrichment' },
  { key: 'rules', group: 'Configure', label: 'Detection Rules' },
  { key: 'ingestion', group: 'Configure', label: 'Log Ingestion' },
];

export default function Layout({ currentPage, onNavigate, user, onLogout, children }) {
  const [collapsed, setCollapsed] = useState(false);
  const [health, setHealth] = useState(null);

  useEffect(() => {
    const check = () =>
      fetchHealth().then(({ data, error }) => {
        if (error) setHealth({ status: 'offline' });
        else setHealth(data);
      });
    check();
    const id = setInterval(check, 30000);
    return () => clearInterval(id);
  }, []);

  return (
    <div className="layout">
      <aside className={`sidebar ${collapsed ? 'collapsed' : ''}`}>
        <div className="sidebar-header">
          <div className="brand" onClick={() => onNavigate('dashboard')}>
            <span className="brand-mark" aria-hidden="true">
              <svg viewBox="0 0 32 32" fill="none">
                <path
                  d="M16 3.5l10 3.8v8.1c0 6.2-4.1 11.4-10 13.5-5.9-2.1-10-7.3-10-13.5V7.3l10-3.8z"
                  stroke="currentColor"
                  strokeWidth="1.6"
                  strokeLinejoin="round"
                />
                <path
                  d="M10.5 16h3.2l1.9-3.9 2.5 7.8 1.9-3.9h3"
                  stroke="currentColor"
                  strokeWidth="1.8"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                />
              </svg>
            </span>
            {!collapsed && (
              <div className="brand-text">
                <span className="brand-name">SENTINEL</span>
                <span className="brand-sub">SIEM Platform</span>
              </div>
            )}
          </div>
          <button
            className="collapse-btn"
            onClick={() => setCollapsed(!collapsed)}
            title={collapsed ? 'Expand navigation' : 'Collapse navigation'}
            aria-label={collapsed ? 'Expand navigation' : 'Collapse navigation'}
          >
            <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round">
              {collapsed ? <path d="M6 3l5 5-5 5" /> : <path d="M10 3L5 8l5 5" />}
            </svg>
          </button>
        </div>

        <nav className="sidebar-nav" aria-label="Main navigation">
          {NAV_ITEMS.map((item, index) => {
            const showGroup = !collapsed && (index === 0 || NAV_ITEMS[index - 1].group !== item.group);
            return (
              <React.Fragment key={item.key}>
                {showGroup && <span className="nav-group-label">{item.group}</span>}
                <button
                  className={`nav-item ${currentPage === item.key ? 'active' : ''}`}
                  onClick={() => onNavigate(item.key)}
                  title={item.label}
                  aria-current={currentPage === item.key ? 'page' : undefined}
                >
                  <span className="nav-icon">{ICONS[item.key]}</span>
                  {!collapsed && <span className="nav-label">{item.label}</span>}
                </button>
              </React.Fragment>
            );
          })}
        </nav>

        <div className="sidebar-footer">
          {user && (
            <div className="account-chip" title={`${user.username} (${user.role})`}>
              <span className="account-avatar">{user.username.slice(0, 1).toUpperCase()}</span>
              {!collapsed && (
                <div className="account-meta">
                  <span className="account-name">{user.username}</span>
                  <span className={`account-role role-${user.role}`}>{user.role}</span>
                </div>
              )}
              <button className="logout-btn" onClick={onLogout} title="Sign out" aria-label="Sign out">
                <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M6 2.5H3v11h3" />
                  <path d="M10 5l3 3-3 3M13 8H6" />
                </svg>
              </button>
            </div>
          )}
          <div className={`system-status ${health?.status === 'offline' ? 'offline' : 'online'}`}>
            <span className="status-dot" />
            {!collapsed && (
              <span className="status-text">
                {health?.status === 'offline' ? 'API Offline' : 'System Online'}
              </span>
            )}
          </div>
        </div>
      </aside>

      <main className="main-content">
        {user?.role === 'viewer' && (
          <div className="readonly-banner">
            <svg
              viewBox="0 0 24 24"
              width="15"
              height="15"
              fill="none"
              stroke="currentColor"
              strokeWidth="1.7"
              strokeLinecap="round"
              strokeLinejoin="round"
              aria-hidden="true"
            >
              <path d="M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12z" />
              <circle cx="12" cy="12" r="2.8" />
            </svg>
            Read-only viewer account — write actions are disabled by the API.
          </div>
        )}
        {children}
      </main>
    </div>
  );
}
