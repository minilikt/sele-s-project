import React, { useState } from 'react';
import { askAI, generateReport } from '../api';

const SUGGESTIONS = [
  'Summarize the current attack surface',
  'How risky is our posture overall?',
  'What are the critical or high findings?',
  'What should we remediate first?',
  'Are there any new assets?',
];

export default function AIAssistant() {
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [reportLoading, setReportLoading] = useState(false);
  const [report, setReport] = useState(null);

  const sendMessage = async (text) => {
    if (!text.trim()) return;
    const userMsg = { role: 'user', content: text };
    setMessages((prev) => [...prev, userMsg]);
    setInput('');
    setLoading(true);

    const { data, error } = await askAI(text);
    const assistantMsg = {
      role: 'assistant',
      content: error ? `Error: ${error}` : data?.answer || data?.response || JSON.stringify(data),
      sections: data?.sections || null,
    };
    setMessages((prev) => [...prev, assistantMsg]);
    setLoading(false);
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    sendMessage(input);
  };

  const handleReport = async () => {
    setReportLoading(true);
    const { data, error } = await generateReport();
    setReport(data ? (data.report || JSON.stringify(data)) : `Error: ${error}`);
    setReportLoading(false);
  };

  return (
    <div className="page ai-page">
      <h1 className="page-title">AI Assistant</h1>

      <div className="ai-layout">
        <div className="ai-context-panel card">
          <h2 className="card-title">Assistance</h2>
          <p className="card-text">
            Answers are generated deterministically from the assets, findings and
            risk scores in the database — no invented evidence.
          </p>
          <button className="btn btn-primary" onClick={handleReport} disabled={reportLoading}>
            {reportLoading ? 'Generating...' : 'Generate security report'}
          </button>
          {report && (
            <div className="result-card">
              <h3 className="card-title">Generated Report</h3>
              <pre className="report-block">{report}</pre>
            </div>
          )}
        </div>

        <div className="ai-chat-panel card">
          <div className="chat-messages">
            {messages.length === 0 && (
              <div className="chat-empty">
                <p>Ask me about your attack surface, findings, or remediation priorities.</p>
                <p className="text-muted">Run a scan first to populate the analysis.</p>
              </div>
            )}
            {messages.map((msg, idx) => (
              <div key={idx} className={`chat-message ${msg.role}`}>
                <div className="chat-message-header">
                  {msg.role === 'user' ? 'You' : 'ARGUS AI'}
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
                <div className="chat-message-header">ARGUS AI</div>
                <div className="chat-message-content">
                  <div className="typing-indicator"><span /><span /><span /></div>
                </div>
              </div>
            )}
          </div>

          <div className="chat-suggestions">
            {SUGGESTIONS.map((s, i) => (
              <button key={i} className="suggestion-chip" onClick={() => sendMessage(s)}>
                {s}
              </button>
            ))}
          </div>

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
