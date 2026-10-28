import React from 'react';
import { downloadFromResult } from '../utils';
import { exportAssetsJSON, exportFindingsJSON, exportReportTxt } from '../api';

export default function ExportButtons({ scope }) {
  const run = async (fn) => {
    const { data, error } = await fn();
    if (error) alert(`Export failed: ${error}`);
    else downloadFromResult(data);
  };

  return (
    <div className="export-bar">
      {scope === 'findings' && (
        <button className="btn btn-secondary btn-small" onClick={() => run(exportFindingsJSON)}>Findings JSON</button>
      )}
      {scope === 'assets' && (
        <button className="btn btn-secondary btn-small" onClick={() => run(exportAssetsJSON)}>Assets JSON</button>
      )}
      {scope === 'report' && (
        <button className="btn btn-secondary btn-small" onClick={() => run(exportReportTxt)}>Report (.txt)</button>
      )}
    </div>
  );
}
