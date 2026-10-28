import { useEffect, useState } from 'react';
import './App.css';
import Layout from './components/Layout';
import Login from './components/Login';
import Dashboard from './components/Dashboard';
import Assets from './components/Assets';
import Findings from './components/Findings';
import Scans from './components/Scans';
import AIAssistant from './components/AIAssistant';
import { clearSession, getToken, getUser, onLogout } from './session';

export default function App() {
  const [page, setPage] = useState({ name: 'dashboard' });
  const [user, setUser] = useState(getUser());

  useEffect(() => onLogout(() => setUser(null)), []);

  const handleLogout = () => {
    clearSession();
    setUser(null);
    setPage({ name: 'dashboard' });
  };

  const navigate = (name, param) => {
    if (typeof name === 'object' && name !== null) {
      setPage({ name: name.page || name.name, param: name.param || name.id });
      return;
    }
    setPage({ name, param });
  };

  const render = () => {
    switch (page.name) {
      case 'assets':
        return <Assets />;
      case 'findings':
        return <Findings />;
      case 'scans':
        return <Scans />;
      case 'ai':
        return <AIAssistant />;
      case 'dashboard':
      default:
        return <Dashboard onNavigate={navigate} />;
    }
  };

  if (!getToken() || !user) {
    return (
      <Login
        onLogin={(nextUser) => {
          setUser(nextUser);
          setPage({ name: 'dashboard' });
        }}
      />
    );
  }

  return (
    <Layout
      currentPage={page.name}
      onNavigate={navigate}
      user={user}
      onLogout={handleLogout}
    >
      {render()}
    </Layout>
  );
}
