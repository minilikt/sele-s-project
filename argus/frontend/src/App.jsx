import { useState } from 'react';
import './App.css';
import Layout from './components/Layout';
import Dashboard from './components/Dashboard';
import Assets from './components/Assets';
import Findings from './components/Findings';
import Scans from './components/Scans';
import AIAssistant from './components/AIAssistant';

export default function App() {
  const [page, setPage] = useState({ name: 'dashboard' });

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

  return (
    <Layout currentPage={page.name} onNavigate={navigate}>
      {render()}
    </Layout>
  );
}
