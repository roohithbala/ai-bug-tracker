import { useState, useEffect } from 'react'
import axios from 'axios'
import './Dashboard.css'

const API_URL = import.meta.env.VITE_API_URL || ''

function Dashboard() {
  const [logs, setLogs] = useState([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetchLogs()
  }, [])

  const fetchLogs = async () => {
    try {
      const response = await axios.get(`${API_URL}/api/logs`)
      setLogs(response.data)
    } catch (error) {
      console.error('Failed to fetch logs:', error)
    } finally {
      setLoading(false)
    }
  }

  const getSeverityClass = (severity) => {
    switch (severity.toLowerCase()) {
      case 'high': return 'severity-high'
      case 'medium': return 'severity-medium'
      case 'low': return 'severity-low'
      default: return 'severity-unknown'
    }
  }

  if (loading) {
    return (
      <div className="loading-message" role="status" aria-live="polite">
        Loading analysis history...
      </div>
    )
  }

  return (
    <div className="dashboard-container">
      <h1 className="dashboard-title">Log Analysis History</h1>
      
      <div className="dashboard-table" role="table" aria-label="Log analysis history">
        <div className="dashboard-header">
          <h2 className="dashboard-header-title">Analysis History</h2>
        </div>
        
        <div className="dashboard-body" role="rowgroup">
          {logs.length === 0 ? (
            <div className="log-item" role="row">
              <div role="cell" style={{ textAlign: 'center', padding: '48px' }}>
                No log analyses found. Upload a log file to get started.
              </div>
            </div>
          ) : (
            logs.map((log) => (
              <article key={log.id} className="log-item" role="row">
                <div className="log-header">
                  <div className="log-title-section">
                    <h3 className="log-filename" role="cell">
                      {log.filename}
                    </h3>
                    <span 
                      className={`severity-badge ${getSeverityClass(log.severity)}`}
                      role="cell"
                      aria-label={`Severity: ${log.severity}`}
                    >
                      {log.severity}
                    </span>
                  </div>
                  <div className="log-timestamp" role="cell">
                    {new Date(log.upload_time).toLocaleString()}
                  </div>
                </div>
                
                <div className="log-details">
                  <div className="log-size" role="cell">
                    Size: {(log.file_size / 1024).toFixed(2)} KB
                  </div>
                  <div className="log-status" role="cell">
                    Status: {log.status}
                  </div>
                </div>
                
                {log.issue_type && (
                  <section className="log-issue" aria-labelledby={`issue-${log.id}`}>
                    <h4 id={`issue-${log.id}`} className="sr-only">Issue details for {log.filename}</h4>
                    <p className="log-issue-text">
                      <strong>Issue:</strong> {log.issue_type}
                    </p>
                    <p className="log-root-cause">
                      <strong>Root Cause:</strong> {log.root_cause}
                    </p>
                    <p className="log-suggested-fix">
                      <strong>Suggested Fix:</strong> {log.suggested_fix}
                    </p>
                  </section>
                )}
              </article>
            ))
          )}
        </div>
      </div>
    </div>
  )
}

export default Dashboard