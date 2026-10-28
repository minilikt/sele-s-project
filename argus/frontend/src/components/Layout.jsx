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
  assets: (
    <svg {...iconProps}>
      <circle cx="12" cy="12" r="8.5" />
      <path d="M3.5 12h17" />
      <path d="M12 3.5c2.4 2.3 3.6 5.2 3.6 8.5s-1.2 6.2-3.6 8.5c-2.4-2.3-3.6-5.2-3.6-8.5S9.6 5.8 12 3.5z" />
    </svg>
  ),
  findings: (
    <svg {...iconProps}>
      <path d="M10.3 4.3L2.7 17.5A1.9 1.9 0 004.3 20.4h15.4a1.9 1.9 0 001.6-2.9L13.7 4.3a1.9 1.9 0 00-3.4 0z" />
      <path d="M12 9v4.5M12 17h.01" />
    </svg>
  ),
  scans: (
    <svg {...iconProps}>
      <circle cx="12" cy="12" r="8.5" opacity="0.45" />
      <circle cx="12" cy="12" r="4.8" opacity="0.75" />
      <path d="M12 12l7.2-5.4" />
      <circle cx="12" cy="12" r="1.5" fill="currentColor" stroke="none" />
      <circle cx="19.2" cy="6.6" r="1.5" fill="currentColor" stroke="none" />
    </svg>
  ),
  ai: (
    <svg {...iconProps}>
      <path d="M12 3l1.7 4.9L18.5 9.6l-4.8 1.7L12 16l-1.7-4.7L5.5 9.6l4.8-1.7L12 3z" />
      <path d="M18.5 15.5l.8 2.2 2.2.8-2.2.8-.8 2.2-.8-2.2-2.2-.8 2.2-.8.8-2.2z" />
    </svg>
  ),
};

const NAV_ITEMS = [
  { key: 'dashboard', group: 'Overview', label: 'Dashboard' },
  { key: 'assets', group: 'Surface', label: 'Assets' },
  { key: 'findings', group: 'Surface', label: 'Findings' },
  { key: 'scans', group: 'Surface', label: 'Scans' },
  { key: 'ai', group: 'Assist', label: 'AI Assistant' },
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
                <circle cx="16" cy="16" r="11.5" stroke="currentColor" strokeWidth="1.4" opacity="0.35" />
                <circle cx="16" cy="16" r="6.5" stroke="currentColor" strokeWidth="1.4" opacity="0.65" />
                <path d="M16 16l9.5-7" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" />
                <circle cx="16" cy="16" r="1.9" fill="currentColor" />
                <circle cx="25.5" cy="9" r="1.8" fill="currentColor" />
              </svg>
            </span>
            {!collapsed && (
              <div className="brand-text">
                <span className="brand-name">ARGUS</span>
                <span className="brand-sub">Attack Surface Intelligence</span>
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
            Read-only viewer account — scans and finding updates are disabled by the API.
          </div>
        )}
        {children}
      </main>
    </div>
  );
}
