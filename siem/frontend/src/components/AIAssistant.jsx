import React, { useState, useEffect } from 'react';
import { askAI, fetchAlerts, fetchIncidents } from '../api';

const SUGGESTIONS = [
  'Why did this alert trigger?',
  'What should I investigate next?',
  'Summarize this incident',
  'What containment steps should I take?',
  'Generate an incident report',
];

export default function AIAssistant({ initialContext }) {
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [contextType, setContextType] = useState(initialContext?.contextType || '');
  const [contextId, setContextId] = useState(initialContext?.contextId || '');
  const [alerts, setAlerts] = useState([]);
  const [incidents, setIncidents] = useState([]);

  useEffect(() => {
    fetchAlerts({ limit: 50 }).then(({ data }) => {
      if (data) setAlerts(Array.isArray(data) ? data : data.alerts || []);
    });
    fetchIncidents().then(({ data }) => {
      if (data) setIncidents(Array.isArray(data) ? data : data.incidents || []);
    });
  }, []);

  useEffect(() => {
    if (initialContext?.contextType && initialContext?.contextId) {
      setContextType(initialContext.contextType);
      setContextId(initialContext.contextId);
    }
  }, [initialContext]);

  const sendMessage = async (text) => {
    if (!text.trim()) return;
    const userMsg = { role: 'user', content: text };
    setMessages((prev) => [...prev, userMsg]);
    setInput('');
    setLoading(true);

    const { data, error } = await askAI(text, contextType || undefined, contextId || undefined);
    const assistantMsg = {
      role: 'assistant',
      content: error
        ? `Error: ${error}`
        : data?.response || data?.answer || data?.message || JSON.stringify(data),
      sections: data?.sections || null,
    };
    setMessages((prev) => [...prev, assistantMsg]);
    setLoading(false);
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    sendMessage(input);
  };

  const contextLabel = () => {
    if (contextType === 'alert' && contextId) {
      const a = alerts.find((x) => String(x.id) === String(contextId));
      return a ? `Alert: ${a.rule_name || a.title}` : `Alert #${contextId}`;
    }
    if (contextType === 'incident' && contextId) {
      const inc = incidents.find((x) => String(x.id) === String(contextId));
      return inc ? `Incident: ${inc.title}` : `Incident #${contextId}`;
    }
    return 'No context selected';
  };

  return (
    <div className="page ai-page">
      <h1 className="page-title">AI Investigation Assistant</h1>

      <div className="ai-layout">
        {/* Context Panel */}
        <div className="ai-context-panel card">
          <h2 className="card-title">Context</h2>
          <div className="context-selector">
            <select
              className="filter-select"
              value={contextType}
              onChange={(e) => {
                setContextType(e.target.value);
                setContextId('');
              }}
            >
              <option value="">No Context</option>
              <option value="alert">Alert</option>
              <option value="incident">Incident</option>
            </select>

            {contextType === 'alert' && (
              <select
                className="filter-select"
                value={contextId}
                onChange={(e) => setContextId(e.target.value)}
              >
                <option value="">Select an alert...</option>
                {alerts.map((a) => (
                  <option key={a.id} value={a.id}>
                    #{a.id} — {a.rule_name || a.title || 'Alert'}
                  </option>
                ))}
              </select>
            )}

            {contextType === 'incident' && (
              <select
                className="filter-select"
                value={contextId}
                onChange={(e) => setContextId(e.target.value)}
              >
                <option value="">Select an incident...</option>
                {incidents.map((inc) => (
                  <option key={inc.id} value={inc.id}>
                    #{inc.id} — {inc.title || 'Incident'}
                  </option>
                ))}
              </select>
            )}
          </div>
          <div className="context-info">
            <span className="context-label">{contextLabel()}</span>
          </div>
        </div>

        {/* Chat Panel */}
        <div className="ai-chat-panel card">
          <div className="chat-messages">
            {messages.length === 0 && (
              <div className="chat-empty">
                <span className="chat-empty-icon">🤖</span>
                <p>Ask me anything about your security events, alerts, or incidents.</p>
                <p className="text-muted">Select a context from the left panel for more targeted analysis.</p>
              </div>
            )}
            {messages.map((msg, idx) => (
              <div key={idx} className={`chat-message ${msg.role}`}>
                <div className="chat-message-header">
                  {msg.role === 'user' ? '👤 You' : '🤖 SENTINEL AI'}
                </div>
                <div className="chat-message-content">
                  {msg.sections ? (
                    msg.sections.map((section, si) => (
                      <div key={si} className="ai-section">
                        {section.title && <h4>{section.title}</h4>}
                        <p>{section.content}</p>
                      </div>
                    ))
                  ) : (
                    <p>{msg.content}</p>
                  )}
                </div>
              </div>
            ))}
            {loading && (
              <div className="chat-message assistant">
                <div className="chat-message-header">🤖 SENTINEL AI</div>
                <div className="chat-message-content">
                  <div className="typing-indicator">
                    <span /><span /><span />
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* Suggestions */}
          <div className="chat-suggestions">
            {SUGGESTIONS.map((s, i) => (
              <button key={i} className="suggestion-chip" onClick={() => sendMessage(s)}>
                {s}
              </button>
            ))}
          </div>

          {/* Input */}
          <form className="chat-input-form" onSubmit={handleSubmit}>
            <input
              type="text"
              className="chat-input"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder="Ask a question..."
              disabled={loading}
            />
            <button type="submit" className="btn btn-primary" disabled={loading || !input.trim()}>
              Send
            </button>
          </form>
        </div>
      </div>
    </div>
  );
}
