import { useEffect, useState } from 'react';
import './App.css';
import Layout from './components/Layout';
import Login from './components/Login';
import Dashboard from './components/Dashboard';
import EventsTable from './components/EventsTable';
import AlertsList from './components/AlertsList';
import AlertDetail from './components/AlertDetail';
import IncidentsList from './components/IncidentsList';
import IncidentDetail from './components/IncidentDetail';
import MitreAttackMap from './components/MitreAttackMap';
import DetectionRules from './components/DetectionRules';
import LogIngestion from './components/LogIngestion';
import AIAssistant from './components/AIAssistant';
import IoCEnrichment from './components/IoCEnrichment';
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
      case 'events':
        return <EventsTable />;
      case 'alerts':
        return <AlertsList onNavigate={navigate} />;
      case 'alert-detail':
        return <AlertDetail alertId={page.param} onNavigate={navigate} />;
      case 'incidents':
        return <IncidentsList onNavigate={navigate} />;
      case 'incident-detail':
        return <IncidentDetail incidentId={page.param} onNavigate={navigate} />;
      case 'mitre':
        return <MitreAttackMap />;
      case 'rules':
        return <DetectionRules />;
      case 'ingestion':
        return <LogIngestion />;
      case 'ai':
        return (
          <AIAssistant
            initialContext={
              page.param && page.param.contextType
                ? page.param
                : null
            }
          />
        );
      case 'ioc':
        return <IoCEnrichment />;
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
