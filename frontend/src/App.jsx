import { useState } from 'react'
import UploadPage from './pages/UploadPage'
import Dashboard from './pages/Dashboard'
import './App.css'

function App() {
  const [currentPage, setCurrentPage] = useState('upload')

  return (
    <div className="app-container">
      <a href="#main-content" className="skip-link">
        Skip to main content
      </a>

      <header>
        <nav className="nav-bar" role="navigation" aria-label="Main navigation">
          <div style={{ maxWidth: '1200px', margin: '0 auto', padding: '0 24px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', height: '64px' }}>
              <div style={{ display: 'flex' }}>
                <div style={{ display: 'flex', alignItems: 'center', flexShrink: 0 }}>
                  <h1 style={{ fontSize: '24px', fontWeight: 'bold', color: '#1f2937' }}>AI Bug Tracker</h1>
                </div>
              </div>
              <div className="nav-tabs" role="tablist" aria-label="Page navigation">
                <button
                  onClick={() => setCurrentPage('upload')}
                  className={`nav-link ${currentPage === 'upload' ? 'active' : ''}`}
                  role="tab"
                  aria-selected={currentPage === 'upload'}
                  aria-controls="upload-panel"
                  id="upload-tab"
                >
                  Upload Log
                </button>
                <button
                  onClick={() => setCurrentPage('dashboard')}
                  className={`nav-link ${currentPage === 'dashboard' ? 'active' : ''}`}
                  role="tab"
                  aria-selected={currentPage === 'dashboard'}
                  aria-controls="dashboard-panel"
                  id="dashboard-tab"
                >
                  Dashboard
                </button>
              </div>
            </div>
          </div>
        </nav>
      </header>

      <main
        className="main-content"
        id="main-content"
        role="main"
        aria-labelledby={currentPage === 'upload' ? 'upload-tab' : 'dashboard-tab'}
      >
        {currentPage === 'upload' ? (
          <div id="upload-panel" role="tabpanel" aria-labelledby="upload-tab">
            <UploadPage />
          </div>
        ) : (
          <div id="dashboard-panel" role="tabpanel" aria-labelledby="dashboard-tab">
            <Dashboard />
          </div>
        )}
      </main>
    </div>
  )
}

export default App