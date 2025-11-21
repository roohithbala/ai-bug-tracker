# AI Bug Tracker

A comprehensive full-stack application that securely analyzes error logs using AI, with intelligent deduplication and sensitive data redaction.

## 🚀 Features

### Core Functionality
- **Secure Log Analysis**: Detects and redacts sensitive information before AI processing
- **AI-Powered Analysis**: Uses Google Gemini AI to categorize issues, explain root causes, suggest fixes, and estimate severity
- **Smart Deduplication**: Two-level caching prevents reprocessing of similar logs
- **Accessible UI**: WCAG-compliant interface with keyboard navigation and screen reader support

### Security & Privacy
- **Comprehensive Data Redaction**: Removes JWT tokens, API keys, passwords, session IDs, emails, IPs, SSNs, and more
- **Privacy-First Design**: Sensitive data never reaches AI services
- **Input Validation**: File type and size restrictions

### Performance & Efficiency
- **Intelligent Caching**: Exact file duplicates and content similarity detection
- **Token Optimization**: AI calls only for truly new error patterns
- **Fast Responses**: Instant results for known error patterns

## 🛠 Technology Stack

### Backend
- **Flask** - Python web framework
- **Google Gemini AI** - Advanced log analysis
- **SQLite** - Lightweight database
- **Regex Patterns** - Comprehensive sensitive data detection

### Frontend
- **React 18** - Modern UI framework
- **Vite** - Fast development server
- **Axios** - HTTP client
- **CSS Modules** - Scoped styling

## 📋 Requirements Evaluation

✅ **Full-Stack Development**: Complete React + Flask implementation
✅ **AI Integration**: Google Gemini AI with structured JSON responses
✅ **Regex Logic**: 25+ patterns for sensitive data detection
✅ **Caching Efficiency**: Two-level deduplication system
✅ **Security Best Practices**: Data redaction, input validation, CORS

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- Node.js 16+
- Google Gemini API key

### Backend Setup
```bash
cd backend
python -m venv venv
venv\Scripts\activate  # Windows
pip install -r requirements.txt
```

### Frontend Setup
```bash
cd frontend
npm install
```

### Configuration
1. Get a [Google Gemini API key](https://makersuite.google.com/app/apikey)
2. Update `backend/.env`:
   ```
   GEMINI_API_KEY=your_actual_api_key_here
   ```

### Running the Application
```bash
# Terminal 1 - Backend
cd backend
venv\Scripts\activate
python app.py

# Terminal 2 - Frontend
cd frontend
npm run dev
```

Open [http://localhost:5173](http://localhost:5173) in your browser.

## 🔧 API Endpoints

### POST /api/upload
Upload and analyze log files
- **Input**: Multipart form with `log_file` (log/txt/json, max 5MB)
- **Output**: Analysis results or duplicate detection

### GET /api/logs
Retrieve analysis history
- **Output**: Array of analyzed logs with metadata

## 🛡️ Security Features

### Data Redaction Patterns
- **Authentication**: JWT tokens, Bearer tokens, session keys
- **Credentials**: Passwords, API keys, secret tokens
- **Personal Data**: Emails, SSNs, phone numbers, IP addresses
- **System Data**: File paths, environment variables, database URIs
- **Security**: Private keys, MAC addresses, cookies

### Duplicate Detection
1. **Exact Match**: SHA-256 hash of original file
2. **Content Similarity**: Hash of redacted content (same errors, different sensitive data)

## 🎨 User Interface

### Upload Page
- Drag-and-drop file upload
- Real-time file preview
- Analysis results display
- Before/after content comparison

### Dashboard
- Analysis history with severity indicators
- Issue categorization and root cause display
- Responsive design for all devices

### Accessibility
- ARIA labels and roles
- Keyboard navigation
- Screen reader support
- High contrast mode compatibility
- Reduced motion support

## 📊 Database Schema

```sql
CREATE TABLE logs (
    id INTEGER PRIMARY KEY,
    filename TEXT,
    file_size INTEGER,
    original_content TEXT,
    redacted_content TEXT,
    redacted_hash TEXT,      -- For content similarity detection
    hash TEXT UNIQUE,        -- For exact duplicate detection
    issue_type TEXT,
    severity TEXT,           -- High/Medium/Low
    root_cause TEXT,
    suggested_fix TEXT,
    upload_time TEXT,
    status TEXT
);
```

## 🔍 AI Analysis Structure

The Gemini AI provides structured JSON responses:

```json
{
  "issue_type": "Database Connection Error",
  "severity": "High",
  "root_cause": "The application failed to establish a connection to the PostgreSQL database due to incorrect connection parameters...",
  "suggested_fix": "Verify database credentials and network connectivity..."
}
```

## 🚦 Error Handling

- **File Validation**: Type, size, and content checks
- **API Resilience**: Graceful degradation when AI unavailable
- **User Feedback**: Clear error messages and status indicators
- **Mock Analysis**: Fallback analysis when API key not configured

## 📈 Performance Optimizations

- **Lazy Loading**: Components load on demand
- **Efficient Queries**: Indexed database lookups
- **Caching Strategy**: Prevents redundant AI calls
- **Response Truncation**: Large content safely displayed

## 🧪 Testing

### Manual Testing Checklist
- [ ] File upload with various formats (.log, .txt, .json)
- [ ] Sensitive data redaction verification
- [ ] Duplicate detection (exact and similar)
- [ ] AI analysis with valid API key
- [ ] Error handling for invalid files
- [ ] Responsive design on different screen sizes
- [ ] Keyboard navigation and accessibility

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Add comprehensive tests
4. Ensure accessibility compliance
5. Submit a pull request

## 📄 License

This project demonstrates full-stack development, AI integration, and security best practices for educational purposes.

---

**Built with ❤️ using React, Flask, and Google Gemini AI**