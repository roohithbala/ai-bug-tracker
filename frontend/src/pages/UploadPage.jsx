import { useState } from 'react'
import axios from 'axios'
import './UploadPage.css'

const API_URL = import.meta.env.VITE_API_URL || (import.meta.env.PROD ? 'https://ai-bug-tracker-lac.vercel.app' : '')

function UploadPage() {
  const [file, setFile] = useState(null)
  const [preview, setPreview] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)
  const [dragActive, setDragActive] = useState(false)

  const handleFileChange = (e) => {
    const selectedFile = e.target.files[0]
    if (selectedFile) {
      processFile(selectedFile)
    }
  }

  const processFile = (selectedFile) => {
    setFile(selectedFile)
    const reader = new FileReader()
    reader.onload = (e) => setPreview(e.target.result)
    reader.readAsText(selectedFile)
  }

  const handleDrag = (e) => {
    e.preventDefault()
    e.stopPropagation()
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true)
    } else if (e.type === 'dragleave') {
      setDragActive(false)
    }
  }

  const handleDrop = (e) => {
    e.preventDefault()
    e.stopPropagation()
    setDragActive(false)
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      processFile(e.dataTransfer.files[0])
    }
  }

  const handleUpload = async () => {
    if (!file) return

    setLoading(true)
    const formData = new FormData()
    formData.append('log_file', file)

    try {
      const response = await axios.post(`${API_URL}/api/upload`, formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
      })
      setResult(response.data)
    } catch (error) {
      console.error('Upload failed:', error)
      setResult({ error: 'Upload failed. Please try again.' })
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="upload-container">
      <h1 className="upload-title">AI Bug Tracker</h1>
      
      <section className="upload-section" aria-labelledby="upload-heading">
        <h2 id="upload-heading" className="upload-section-title">Upload Error Log</h2>
        
        <form className="file-input-section" onSubmit={(e) => { e.preventDefault(); handleUpload(); }}>
          <label htmlFor="file-input" className="file-label">
            Select log file (.log, .txt, .json)
          </label>
          <input
            id="file-input"
            type="file"
            onChange={handleFileChange}
            accept=".log,.txt,.json"
            className="file-input"
            aria-describedby="file-help"
          />
          <div id="file-help" className="sr-only">
            Choose a log file to analyze. Supported formats: .log, .txt, .json. Maximum size: 5MB.
          </div>

          <div 
            onDragEnter={handleDrag}
            onDragLeave={handleDrag}
            onDragOver={handleDrag}
            onDrop={handleDrop}
            className={`drop-zone ${dragActive ? 'drag-active' : ''}`}
            role="button"
            tabIndex={0}
            aria-label="Drag and drop log file here or click to select"
            onKeyDown={(e) => {
              if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault()
                document.getElementById('file-input').click()
              }
            }}
          >
            <p>{dragActive ? 'Drop the file here' : 'Drag and drop or click to select file'}</p>
            <p className="file-size-note">Max size: 5MB</p>
          </div>
        </form>

        {file && (
          <div className="file-info" role="region" aria-labelledby="file-info-heading">
            <h3 id="file-info-heading" className="file-info-title">File Information</h3>
            <p><strong>Name:</strong> {file.name}</p>
            <p><strong>Size:</strong> {(file.size / 1024).toFixed(2)} KB</p>
            <p><strong>Lines:</strong> {preview.split('\n').length}</p>
          </div>
        )}

        {preview && (
          <section className="preview-section" aria-labelledby="preview-heading">
            <h3 id="preview-heading" className="preview-title">File Preview</h3>
            <pre className="preview-content" aria-label="File content preview">
              {preview}
            </pre>
          </section>
        )}

        <button
          onClick={handleUpload}
          disabled={!file || loading}
          className={`upload-button ${loading ? 'loading' : ''}`}
          aria-describedby="upload-status"
        >
          {loading ? 'Analyzing...' : 'Analyze Log'}
        </button>
        <div id="upload-status" className="sr-only">
          {loading ? 'Analysis in progress' : file ? 'Ready to analyze' : 'Please select a file first'}
        </div>
      </section>

      {result && (
        <section className="result-section" aria-labelledby="result-heading">
          <h2 id="result-heading" className="result-title">Analysis Results</h2>
          
          {result.error ? (
            <div className="error-message" role="alert" aria-live="assertive">
              {result.error}
            </div>
          ) : result.duplicate ? (
            <div>
              <div className="duplicate-message" role="status" aria-live="polite">
                {result.message}
              </div>
              <div className="analysis-summary">
                <p><strong>Issue Type:</strong> {result.result?.issue_type}</p>
                <p><strong>Severity:</strong> {result.result?.severity}</p>
                <p><strong>Root Cause:</strong> {result.result?.root_cause}</p>
                <p><strong>Suggested Fix:</strong> {result.result?.suggested_fix}</p>
              </div>
              {result.removal_info && (
                <section className="removal-summary" aria-labelledby="removal-heading">
                  <h3 id="removal-heading" className="removal-title">Data Removal Summary</h3>
                  <p className="removal-count">
                    <strong>Total sensitive items removed:</strong> {result.removal_info.total_removals}
                  </p>
                  <div className="content-comparison">
                    <div className="content-column">
                      <h4 className="content-title">Original Content</h4>
                      <pre className="content-display original-content" aria-label="Original file content">
                        {result.removal_info.original_content || 'No original content available'}
                      </pre>
                    </div>
                    <div className="content-column">
                      <h4 className="content-title">Processed Content</h4>
                      <pre className="content-display redacted-content" aria-label="Content with sensitive data removed">
                        {result.removal_info.removed_content || 'No processed content available'}
                      </pre>
                    </div>
                  </div>
                </section>
              )}
            </div>
          ) : (
            <div>
              <div className="analysis-summary">
                <p><strong>Issue Type:</strong> {result.analysis?.issue_type}</p>
                <p><strong>Severity:</strong> {result.analysis?.severity}</p>
                <p><strong>Root Cause:</strong> {result.analysis?.root_cause}</p>
                <p><strong>Suggested Fix:</strong> {result.analysis?.suggested_fix}</p>
              </div>

              {result.removal_info && (
                <section className="removal-summary" aria-labelledby="removal-heading">
                  <h3 id="removal-heading" className="removal-title">Data Removal Summary</h3>
                  <p className="removal-count">
                    <strong>Total sensitive items removed:</strong> {result.removal_info.total_removals}
                  </p>

                  {result.removal_info.removed_items.length > 0 && (
                    <div className="removed-items">
                      <h4 className="removed-items-title">Sensitive Data Removed</h4>
                      <ul className="removed-list" aria-label="List of removed sensitive items">
                        {result.removal_info.removed_items.map((item, index) => (
                          <li key={index} className="removed-item">
                            {item}
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}

                  <div className="content-comparison">
                    <div className="content-column">
                      <h4 className="content-title">Original Content</h4>
                      <pre className="content-display original-content" aria-label="Original file content">
                        {result.removal_info.original_content || 'No original content available'}
                      </pre>
                    </div>
                    <div className="content-column">
                      <h4 className="content-title">Processed Content</h4>
                      <pre className="content-display redacted-content" aria-label="Content with sensitive data removed">
                        {result.removal_info.removed_content || 'No processed content available'}
                      </pre>
                    </div>
                  </div>
                </section>
              )}
            </div>
          )}
        </section>
      )}
    </div>
  )
}

export default UploadPage