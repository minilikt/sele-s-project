import React, { useState } from 'react';
import { generateSampleLogs, ingestEvents, runDetection, runCorrelation } from '../api';

export default function LogIngestion() {
  const [generating, setGenerating] = useState(false);
  const [genResult, setGenResult] = useState(null);
  const [manualJson, setManualJson] = useState('');
  const [uploadResult, setUploadResult] = useState(null);
  const [uploading, setUploading] = useState(false);
  const [detectionResult, setDetectionResult] = useState(null);
  const [correlationResult, setCorrelationResult] = useState(null);
  const [runningDetection, setRunningDetection] = useState(false);
  const [runningCorrelation, setRunningCorrelation] = useState(false);

  const handleGenerate = async () => {
    setGenerating(true);
    setGenResult(null);
    const { data, error } = await generateSampleLogs();
    setGenResult(data || { error });
    setGenerating(false);
  };

  const handleUpload = async () => {
    setUploading(true);
    setUploadResult(null);
    try {
      const events = JSON.parse(manualJson);
      const { data, error } = await ingestEvents(events);
      setUploadResult(data || { error });
    } catch (e) {
      setUploadResult({ error: 'Invalid JSON: ' + e.message });
    }
    setUploading(false);
  };

  const handleDetection = async () => {
    setRunningDetection(true);
    const { data, error } = await runDetection();
    setDetectionResult(data || { error });
    setRunningDetection(false);
  };

  const handleCorrelation = async () => {
    setRunningCorrelation(true);
    const { data, error } = await runCorrelation();
    setCorrelationResult(data || { error });
    setRunningCorrelation(false);
  };

  return (
    <div className="page">
      <h1 className="page-title">Log Ingestion</h1>

      {/* Generate Sample Logs */}
      <div className="card">
        <h2 className="card-title">Generate Sample Logs</h2>
        <p className="card-text">
          Generates 200–500 realistic Windows security events including brute force attacks,
          privilege escalation, and suspicious PowerShell execution.
        </p>
        <button className="btn btn-primary btn-large" onClick={handleGenerate} disabled={generating}>
          {generating ? (
            <>
              <span className="spinner-inline" /> Generating...
            </>
          ) : (
            '📥 Generate & Ingest Sample Logs'
          )}
        </button>
        {genResult && (
          <div className="result-card">
            <pre className="json-block">{JSON.stringify(genResult, null, 2)}</pre>
          </div>
        )}
      </div>

      {/* Manual Upload */}
      <div className="card">
        <h2 className="card-title">Manual Upload</h2>
        <p className="card-text">Paste JSON log events to ingest manually.</p>
        <div className="format-guide">
          <details>
            <summary>📋 Expected JSON Format</summary>
            <pre className="json-block">{`[
  {
    "event_id": "4625",
    "event_type": "Authentication",
    "timestamp": "2024-01-15T10:30:00Z",
    "account": "admin",
    "source_ip": "192.168.1.100",
    "computer": "DC01",
    "severity": "medium",
    "description": "Failed logon attempt"
  }
]`}</pre>
          </details>
        </div>
        <textarea
          className="log-textarea"
          value={manualJson}
          onChange={(e) => setManualJson(e.target.value)}
          placeholder="Paste JSON array of events here..."
          rows={8}
        />
        <button
          className="btn btn-primary"
          onClick={handleUpload}
          disabled={uploading || !manualJson.trim()}
        >
          {uploading ? 'Uploading...' : '⬆ Upload Events'}
        </button>
        {uploadResult && (
          <div className="result-card">
            <pre className="json-block">{JSON.stringify(uploadResult, null, 2)}</pre>
          </div>
        )}
      </div>

      {/* Quick Actions */}
      {(genResult || uploadResult) && (
        <div className="card">
          <h2 className="card-title">Quick Actions</h2>
          <p className="card-text">Run analysis on the ingested logs.</p>
          <div className="action-bar">
            <button className="btn btn-primary" onClick={handleDetection} disabled={runningDetection}>
              {runningDetection ? '⏳ Running...' : '🔍 Run Detection Engine'}
            </button>
            <button className="btn btn-primary" onClick={handleCorrelation} disabled={runningCorrelation}>
              {runningCorrelation ? '⏳ Running...' : '🔗 Run Correlation'}
            </button>
          </div>
          {detectionResult && (
            <div className="result-card">
              <h3>Detection Results</h3>
              <pre className="json-block">{JSON.stringify(detectionResult, null, 2)}</pre>
            </div>
          )}
          {correlationResult && (
            <div className="result-card">
              <h3>Correlation Results</h3>
              <pre className="json-block">{JSON.stringify(correlationResult, null, 2)}</pre>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
