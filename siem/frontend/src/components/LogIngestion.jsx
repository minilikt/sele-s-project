import React, { useState } from 'react';
import {
  generateSampleLogs,
  ingestEvents,
  importEventLog,
  runDetection,
  runCorrelation,
} from '../api';
import { hasRole } from '../session';

export default function LogIngestion() {
  const canWrite = hasRole('analyst');
  const isAdmin = hasRole('admin');
  const [generating, setGenerating] = useState(false);
  const [genResult, setGenResult] = useState(null);
  const [manualJson, setManualJson] = useState('');
  const [uploadResult, setUploadResult] = useState(null);
  const [uploading, setUploading] = useState(false);
  const [detectionResult, setDetectionResult] = useState(null);
  const [correlationResult, setCorrelationResult] = useState(null);
  const [runningDetection, setRunningDetection] = useState(false);
  const [runningCorrelation, setRunningCorrelation] = useState(false);
  const [selectedFile, setSelectedFile] = useState(null);
  const [fileResult, setFileResult] = useState(null);
  const [importingFile, setImportingFile] = useState(false);
  const [dryRun, setDryRun] = useState(false);
  const [correlationWindow, setCorrelationWindow] = useState(60);
  const [rebuildIncidents, setRebuildIncidents] = useState(false);

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

  const handleFileUpload = async () => {
    if (!selectedFile) return;
    setImportingFile(true);
    setFileResult(null);
    const { data, error } = await importEventLog(selectedFile, { dryRun });
    setFileResult(data || { error });
    setImportingFile(false);
  };

  const handleDetection = async () => {
    setRunningDetection(true);
    const { data, error } = await runDetection();
    setDetectionResult(data || { error });
    setRunningDetection(false);
  };

  const handleCorrelation = async () => {
    setRunningCorrelation(true);
    const { data, error } = await runCorrelation({
      windowMinutes: Number(correlationWindow) || 60,
      rebuild: rebuildIncidents,
    });
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
        <button
          className="btn btn-primary btn-large"
          onClick={handleGenerate}
          disabled={generating || !canWrite}
          title={canWrite ? '' : 'Analyst role required'}
        >
          {generating ? (
            <>
              <span className="spinner-inline" /> Generating...
            </>
          ) : (
            'Generate & ingest sample logs'
          )}
        </button>
        {genResult && (
          <div className="result-card">
            <pre className="json-block">{JSON.stringify(genResult, null, 2)}</pre>
          </div>
        )}
      </div>

      {/* Windows log file import */}
      <div className="card">
        <h2 className="card-title">Import Windows Log File</h2>
        <p className="card-text">
          Upload a binary <code>.evtx</code> file, an XML export
          (<code>Get-WinEvent | ConvertTo-Xml</code>, or <code>wevtutil</code> output), or a JSON
          event array. Events are normalised, deduplicated and fed through the same detection
          pipeline as live data.
        </p>

        <div className="file-import-row">
          <input
            type="file"
            accept=".evtx,.xml,.json,application/xml,application/json"
            onChange={(e) => {
              setSelectedFile(e.target.files?.[0] || null);
              setFileResult(null);
            }}
          />
          <label className="checkbox-label">
            <input
              type="checkbox"
              checked={dryRun}
              onChange={(e) => setDryRun(e.target.checked)}
            />
            Dry run (parse only, do not persist)
          </label>
          <button
            className="btn btn-primary"
            onClick={handleFileUpload}
            disabled={importingFile || !selectedFile || !canWrite}
            title={canWrite ? '' : 'Analyst role required'}
          >
            {importingFile ? 'Importing...' : 'Import file'}
          </button>
        </div>

        {fileResult && (
          <div className="result-card">
            <pre className="json-block">{JSON.stringify(fileResult, null, 2)}</pre>
          </div>
        )}
      </div>

      {/* Manual Upload */}
      <div className="card">
        <h2 className="card-title">Manual Upload</h2>
        <p className="card-text">Paste JSON log events to ingest manually.</p>
        <div className="format-guide">
          <details>
            <summary>Expected JSON format</summary>
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
          disabled={uploading || !manualJson.trim() || !canWrite}
          title={canWrite ? '' : 'Analyst role required'}
        >
          {uploading ? 'Uploading...' : 'Upload events'}
        </button>
        {uploadResult && (
          <div className="result-card">
            <pre className="json-block">{JSON.stringify(uploadResult, null, 2)}</pre>
          </div>
        )}
      </div>

      {/* Quick Actions */}
      <div className="card">
        <h2 className="card-title">Quick Actions</h2>
        <p className="card-text">
          Re-run detection and correlation on everything stored. Detection is idempotent;
          correlation can optionally be rebuilt from scratch.
        </p>
        <div className="file-import-row">
          <label className="checkbox-label">
            Correlation window (minutes)
            <input
              type="number"
              className="window-input"
              min="1"
              max="1440"
              value={correlationWindow}
              onChange={(e) => setCorrelationWindow(e.target.value)}
            />
          </label>
          <label className="checkbox-label">
            <input
              type="checkbox"
              checked={rebuildIncidents}
              disabled={!isAdmin}
              title={isAdmin ? '' : 'Admin role required'}
              onChange={(e) => setRebuildIncidents(e.target.checked)}
            />
            Rebuild incidents (discards status and notes)
          </label>
        </div>
        <div className="action-bar">
          <button className="btn btn-primary" onClick={handleDetection} disabled={runningDetection || !canWrite} title={canWrite ? '' : 'Analyst role required'}>
            {runningDetection ? 'Running...' : 'Run detection engine'}
          </button>
          <button className="btn btn-primary" onClick={handleCorrelation} disabled={runningCorrelation || !canWrite} title={canWrite ? '' : 'Analyst role required'}>
            {runningCorrelation ? 'Running...' : 'Run correlation'}
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
    </div>
  );
}
