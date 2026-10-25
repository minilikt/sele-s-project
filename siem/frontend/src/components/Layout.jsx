import React, { useState, useEffect } from 'react';
import { fetchHealth } from '../api';

const NAV_ITEMS = [
  { key: 'dashboard', icon: '📊', label: 'Dashboard' },
  { key: 'events', icon: '📋', label: 'Events' },
  { key: 'alerts', icon: '🚨', label: 'Alerts' },
  { key: 'incidents', icon: '🔍', label: 'Incidents' },
  { key: 'mitre', icon: '⚔️', label: 'MITRE ATT&CK' },
  { key: 'rules', icon: '⚙️', label: 'Detection Rules' },
  { key: 'ingestion', icon: '📥', label: 'Log Ingestion' },
  { key: 'ai', icon: '🤖', label: 'AI Assistant' },
  { key: 'ioc', icon: '🧬', label: 'IoC Enrichment' },
];

export default function Layout({ currentPage, onNavigate, children }) {
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
            <span className="brand-icon">⛨</span>
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
            title={collapsed ? 'Expand' : 'Collapse'}
          >
            {collapsed ? '»' : '«'}
          </button>
        </div>

        <nav className="sidebar-nav">
          {NAV_ITEMS.map((item) => (
            <button
              key={item.key}
              className={`nav-item ${currentPage === item.key ? 'active' : ''}`}
              onClick={() => onNavigate(item.key)}
              title={item.label}
            >
              <span className="nav-icon">{item.icon}</span>
              {!collapsed && <span className="nav-label">{item.label}</span>}
            </button>
          ))}
        </nav>

        <div className="sidebar-footer">
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

      <main className="main-content">{children}</main>
    </div>
  );
}
