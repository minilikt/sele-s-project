import React from 'react';
import { downloadFromResult } from '../utils';
import { exportEventsCSV, exportEventsJSON, exportAlertsJSON, exportIncidentsJSON } from '../api';

export default function ExportButtons({ scope }) {
  const run = async (fn) => {
    const { data, error } = await fn();
    if (error) alert(`Export failed: ${error}`);
    else downloadFromResult(data);
  };

  return (
    <div className="export-bar">
      {scope === 'events' && (
        <>
          <button className="btn btn-secondary btn-small" onClick={() => run(exportEventsCSV)}>⬇ CSV</button>
          <button className="btn btn-secondary btn-small" onClick={() => run(exportEventsJSON)}>⬇ JSON</button>
        </>
      )}
      {scope === 'alerts' && (
        <button className="btn btn-secondary btn-small" onClick={() => run(exportAlertsJSON)}>⬇ Export JSON</button>
      )}
      {scope === 'incidents' && (
        <button className="btn btn-secondary btn-small" onClick={() => run(exportIncidentsJSON)}>⬇ Export JSON</button>
      )}
    </div>
  );
}
