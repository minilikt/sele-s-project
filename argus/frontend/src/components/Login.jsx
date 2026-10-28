import React, { useState } from 'react';
import { login } from '../api';
import { setSession } from '../session';

export default function Login({ onLogin }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);

  const handleSubmit = async (event) => {
    event.preventDefault();
    setBusy(true);
    setError(null);

    const { data, error: requestError } = await login(username.trim(), password);
    if (requestError || !data?.access_token) {
      setError(requestError || 'Login failed');
      setBusy(false);
      return;
    }

    setSession(data.access_token, data.user);
    onLogin(data.user);
  };

  return (
    <div className="login-screen">
      <aside className="login-aside">
        <div className="login-orbit" aria-hidden="true">
          <span className="orbit-ring orbit-ring-1" />
          <span className="orbit-ring orbit-ring-2" />
          <span className="orbit-ring orbit-ring-3" />
          <span className="orbit-sweep" />
          <span className="orbit-core" />
        </div>

        <div className="login-aside-content">
          <span className="login-kicker">ARGUS // Attack Surface Intelligence</span>
          <h2>
            Know your exposure
            <br />
            <em>before someone else maps it.</em>
          </h2>
          <p>
            Scope-bound discovery, TLS and header assessment, and a finding lifecycle that
            remembers what changed between scans. Every result stays tied to the evidence
            that produced it.
          </p>
          <ul className="login-features">
            <li>
              <span>01</span> Authorised, scope-bound asset inventory
            </li>
            <li>
              <span>02</span> TLS, header and exposure findings
            </li>
            <li>
              <span>03</span> Stable finding identity across scans
            </li>
          </ul>
        </div>
        <div className="login-aside-foot">
          <span className="ping-dot" />
          Authorised use only
        </div>
      </aside>

      <section className="login-panel">
        <form className="login-card" onSubmit={handleSubmit}>
          <div className="login-brand">
            <span className="brand-mark" aria-hidden="true">
              <svg viewBox="0 0 32 32" fill="none">
                <circle cx="16" cy="16" r="11.5" stroke="currentColor" strokeWidth="1.4" opacity="0.35" />
                <circle cx="16" cy="16" r="6.5" stroke="currentColor" strokeWidth="1.4" opacity="0.65" />
                <path d="M16 16l9.5-7" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" />
                <circle cx="16" cy="16" r="1.9" fill="currentColor" />
                <circle cx="25.5" cy="9" r="1.8" fill="currentColor" />
              </svg>
            </span>
            <div>
              <h1>ARGUS</h1>
              <p>Attack Surface Intelligence</p>
            </div>
          </div>

          <span className="login-kicker">Secure access</span>

          <label className="login-label">
            Username
            <input
              className="login-input"
              autoComplete="username"
              autoFocus
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
            />
          </label>

          <label className="login-label">
            Password
            <input
              className="login-input"
              type="password"
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
            />
          </label>

          {error && <div className="login-error">{error}</div>}

          <button className="btn btn-primary login-submit" type="submit" disabled={busy}>
            {busy ? 'Signing in...' : 'Sign in'}
          </button>

          <p className="login-hint">
            Accounts are managed by an administrator. The development bootstrap account is
            <code> admin / admin</code> unless <code>ARGUS_ADMIN_PASSWORD</code> is set.
            Only assess systems you are authorised to test.
          </p>
        </form>
      </section>
    </div>
  );
}
