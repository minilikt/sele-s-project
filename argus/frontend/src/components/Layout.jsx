import React, { useState, useEffect } from 'react';
import { fetchHealth } from '../api';

const NAV_ITEMS = [
  { key: 'dashboard', icon: '📊', label: 'Dashboard' },
  { key: 'assets', icon: '🌐', label: 'Assets' },
  { key: 'findings', icon: '🚨', label: 'Findings' },
  { key: 'scans', icon: '🔎', label: 'Scans' },
  { key: 'ai', icon: '🤖', label: 'AI Assistant' },
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
            <span className="brand-icon">🛰️</span>
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
