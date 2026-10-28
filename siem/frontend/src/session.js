const TOKEN_KEY = 'sentinel.token';
const USER_KEY = 'sentinel.user';

const ROLE_RANK = { viewer: 1, analyst: 2, admin: 3 };

export function getToken() {
  try {
    return localStorage.getItem(TOKEN_KEY);
  } catch {
    return null;
  }
}

export function getUser() {
  try {
    return JSON.parse(localStorage.getItem(USER_KEY) || 'null');
  } catch {
    return null;
  }
}

export function setSession(token, user) {
  try {
    localStorage.setItem(TOKEN_KEY, token);
    localStorage.setItem(USER_KEY, JSON.stringify(user));
  } catch {
    // Private browsing can block storage; the token then lives only in memory
    // via the api module's fallback below.
  }
}

export function clearSession() {
  try {
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(USER_KEY);
  } catch {
    // ignore
  }
}

export function hasRole(minimum) {
  const user = getUser();
  return Boolean(user) && (ROLE_RANK[user.role] || 0) >= (ROLE_RANK[minimum] || 99);
}

export function isViewer() {
  return getUser()?.role === 'viewer';
}

/** Subscribe to forced logouts (expired or revoked token). */
export function onLogout(handler) {
  const listener = () => handler();
  window.addEventListener('sentinel:logout', listener);
  return () => window.removeEventListener('sentinel:logout', listener);
}
