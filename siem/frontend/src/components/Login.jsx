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
        <div className="login-aside-content">
          <span className="login-kicker">SENTINEL // Security Operations</span>
          <h2>
            Turn raw telemetry into
            <br />
            <em>defensible decisions.</em>
          </h2>
          <p>
            Detection-as-code, ordered correlation and incident context in a single analyst
            workspace. Built to keep every conclusion traceable back to the evidence.
          </p>
          <ul className="login-features">
            <li>
              <span>01</span> Sigma detections with per-rule validation
            </li>
            <li>
              <span>02</span> Entity-aware alert correlation
            </li>
            <li>
              <span>03</span> ATT&amp;CK kill-chain coverage scoring
            </li>
          </ul>
        </div>
        <div className="login-aside-foot">
          <span className="ping-dot" />
          Authorised lab environment
        </div>
      </aside>

      <section className="login-panel">
        <form className="login-card" onSubmit={handleSubmit}>
          <div className="login-brand">
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
            <div>
              <h1>SENTINEL</h1>
              <p>SIEM Platform</p>
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
            <code> admin / admin</code> unless <code>SIEM_ADMIN_PASSWORD</code> is set.
          </p>
        </form>
      </section>
    </div>
  );
}
