const TOKEN_KEY = 'argus.token';
const USER_KEY = 'argus.user';

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
    // Storage can be blocked in private browsing; the app will simply ask
    // for credentials again on reload.
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

export function onLogout(handler) {
  const listener = () => handler();
  window.addEventListener('argus:logout', listener);
  return () => window.removeEventListener('argus:logout', listener);
}
