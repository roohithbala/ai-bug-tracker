import os
import re
import hashlib
import sqlite3
from datetime import datetime
from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
CORS(app)

# OpenRouter AI setup
OPENROUTER_API_KEY = os.getenv('OPENROUTER_API_KEY')
OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"

# Database setup
def init_db():
    conn = sqlite3.connect('logs.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY,
        filename TEXT,
        file_size INTEGER,
        original_content TEXT,
        redacted_content TEXT,
        redacted_hash TEXT,
        hash TEXT UNIQUE,
        issue_type TEXT,
        severity TEXT,
        root_cause TEXT,
        suggested_fix TEXT,
        upload_time TEXT,
        status TEXT
    )''')
    # Create table for individual error analyses
    c.execute('''CREATE TABLE IF NOT EXISTS error_analyses (
        id INTEGER PRIMARY KEY,
        error_hash TEXT UNIQUE,
        error_content TEXT,
        issue_type TEXT,
        severity TEXT,
        root_cause TEXT,
        suggested_fix TEXT,
        created_time TEXT
    )''')
    # Add redacted_hash column if it doesn't exist (for backward compatibility)
    try:
        c.execute('ALTER TABLE logs ADD COLUMN redacted_hash TEXT')
    except sqlite3.OperationalError:
        pass  # Column already exists
    conn.commit()
    conn.close()

init_db()

REMOVAL_PATTERNS = {
    # ===== CREDIT CARD INFORMATION =====
    # Credit Card Numbers - comprehensive patterns
    r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b': '[REMOVED_CC_NUMBER]',  # 16-digit with separators
    r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{3}\b': '[REMOVED_CC_NUMBER]',  # 15-digit (Amex)
    r'\b\d{4}[-\s]?\d{6}[-\s]?\d{4,5}\b': '[REMOVED_CC_NUMBER]',  # Other formats
    # Removed broad 13-19 digit fallback for credit cards to avoid
    # accidental redaction of other numeric identifiers. Rely on
    # explicit field matches and formatted card patterns instead.
    r'\*{4,6}[-\s]?\*{4,6}[-\s]?\*{4,6}[-\s]?\d{4}': '[REMOVED_CC_NUMBER]',  # Masked cards
    r'(?i)"cardNumber"\s*:\s*"[^"]*"': '[REMOVED_CC_NUMBER]',
    r'(?i)"creditCard"\s*:\s*"[^"]*"': '[REMOVED_CC_NUMBER]',

    # CVV/CVC/Security Codes - comprehensive
    r'(?i)(?:cvv|cvc|security code|card verification|verification code)[:=\s]*\d{3,4}\b': '[REMOVED_CVV]',
    r'(?i)"cvv"\s*:\s*"\d{3,4}"': '[REMOVED_CVV]',
    r'(?i)"cvv"\s*:\s*\d{3,4}': '[REMOVED_CVV]',
    r'(?i)"cvc"\s*:\s*"\d{3,4}"': '[REMOVED_CVV]',
    r'(?i)"cvc"\s*:\s*\d{3,4}': '[REMOVED_CVV]',
    r'(?i)"securityCode"\s*:\s*"\d{3,4}"': '[REMOVED_CVV]',
    r'(?i)"securityCode"\s*:\s*\d{3,4}': '[REMOVED_CVV]',

    # Expiry Dates - comprehensive
    # More strict expiry matcher (MM/YY or MM/YYYY) to avoid partial digit matches
    r'(?i)(?:exp|expiry|expiration|exp_date|valid_thru)[:=\s]*(?:0[1-9]|1[0-2])[-/](?:\d{2}|\d{4})': '[REMOVED_EXPIRY]',
    r'(?i)"expiryMonth"\s*:\s*"\d{1,2}"': '[REMOVED_EXPIRY_MONTH]',
    r'(?i)"expiryYear"\s*:\s*"\d{4}"': '[REMOVED_EXPIRY_YEAR]',
    r'(?i)"expMonth"\s*:\s*"\d{1,2}"': '[REMOVED_EXPIRY_MONTH]',
    r'(?i)"expYear"\s*:\s*"\d{4}"': '[REMOVED_EXPIRY_YEAR]',
    r'\b\d{1,2}[-/]\d{2,4}\b': '[REMOVED_EXPIRY]',  # MM/YY or MM/YYYY

    # ===== PERSONAL IDENTIFICATION =====
    # Names - comprehensive
    r'(?i)"firstName"\s*:\s*"[^"]*"': '[REMOVED_FIRST_NAME]',
    r'(?i)"lastName"\s*:\s*"[^"]*"': '[REMOVED_LAST_NAME]',
    r'(?i)"fullName"\s*:\s*"[^"]*"': '[REMOVED_FULL_NAME]',
    r'(?i)"cardholderName"\s*:\s*"[^"]*"': '[REMOVED_CARDHOLDER_NAME]',
    r'(?i)"name"\s*:\s*"[^"]*"': '[REMOVED_NAME]',
    r'(?i)"displayName"\s*:\s*"[^"]*"': '[REMOVED_DISPLAY_NAME]',
    #santhosh
        r'(?i)s[^\s]{0,2}a[^\s]{0,2}n[^\s]{0,2}t[^\s]{0,2}h[^\s]{0,2}o[^\s]{0,2}s[^\s]{0,2}h': '[REMOVED_NAME]',
    r'(?i)"Name"\s*:\s*"[^"]*"': '[REMOVED_FULL_NAME]',


 
    r'(?i)"username"\s*:\s*"[^"]*"': '[REMOVED_USERNAME]',
    r'(?i)"user"\s*:\s*"[^"]*"': '[REMOVED_USERNAME]',
    r'(?i)"login"\s*:\s*"[^"]*"': '[REMOVED_USERNAME]',
    r'\b[a-zA-Z][a-zA-Z0-9._-]{2,30}@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b': '[REMOVED_USERNAME]',  # email-like usernames
    r'\b[a-zA-Z][a-zA-Z0-9._-]{2,30}\.[a-zA-Z][a-zA-Z0-9._-]{2,30}\b': '[REMOVED_USERNAME]',  # first.last format

    # ===== CONTACT INFORMATION =====
    # Email addresses - comprehensive
    r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b': '[REMOVED_EMAIL]',
    r'(?i)"email"\s*:\s*"[^"]*"': '[REMOVED_EMAIL]',
    r'(?i)"emailAddress"\s*:\s*"[^"]*"': '[REMOVED_EMAIL]',

    # Phone numbers - comprehensive international formats
    r'(?i)"phoneNumber"\s*:\s*"[^"]*"': '[REMOVED_PHONE]',
    r'(?i)"phone"\s*:\s*"[^"]*"': '[REMOVED_PHONE]',
    r'(?i)"mobile"\s*:\s*"[^"]*"': '[REMOVED_PHONE]',
    r'(?i)"cell"\s*:\s*"[^"]*"': '[REMOVED_PHONE]',
    r'\b\+?\d{1,4}?[-.\s]?\(?\d{1,4}\)?[-.\s]?\d{1,4}[-.\s]?\d{1,4}[-.\s]?\d{1,4}\b': '[REMOVED_PHONE]',
    r'\b\d{10,15}\b': '[REMOVED_PHONE]',  # 10-15 digit numbers (potential phones)

    # ===== IDENTIFICATION NUMBERS =====
    # Social Security Numbers - various formats
    r'\b\d{3}-\d{2}-\d{4}\b': '[REMOVED_SSN]',
    r'\b\d{9}\b': '[REMOVED_SSN]',  # 9-digit SSN without dashes
    r'(?i)"ssn"\s*:\s*"[^"]*"': '[REMOVED_SSN]',
    r'(?i)"socialSecurity"\s*:\s*"[^"]*"': '[REMOVED_SSN]',

    # Driver's License
    r'(?i)"driverLicense"\s*:\s*"[^"]*"': '[REMOVED_DRIVER_LICENSE]',
    r'(?i)"driversLicense"\s*:\s*"[^"]*"': '[REMOVED_DRIVER_LICENSE]',
    r'(?i)"licenseNumber"\s*:\s*"[^"]*"': '[REMOVED_DRIVER_LICENSE]',
    r'\b[A-Z]\d{6,8}\b': '[REMOVED_DRIVER_LICENSE]',  # State + numbers
    r'\b\d{2,3}[A-Z]\d{5,7}\b': '[REMOVED_DRIVER_LICENSE]',  # Various state formats

    # Passport Numbers
    r'(?i)"passport"\s*:\s*"[^"]*"': '[REMOVED_PASSPORT]',
    r'(?i)"passportNumber"\s*:\s*"[^"]*"': '[REMOVED_PASSPORT]',
    r'\b[A-Z]\d{7,9}\b': '[REMOVED_PASSPORT]',  # Letter + 7-9 digits
    r'\b\d{9}\b': '[REMOVED_PASSPORT]',  # 9-digit passport

    # ===== ADDRESSES =====
    # Address components
    r'(?i)"street"\s*:\s*"[^"]*"': '[REMOVED_STREET]',
    r'(?i)"address"\s*:\s*"[^"]*"': '[REMOVED_ADDRESS]',
    r'(?i)"streetAddress"\s*:\s*"[^"]*"': '[REMOVED_STREET]',
    r'(?i)"city"\s*:\s*"[^"]*"': '[REMOVED_CITY]',
    r'(?i)"state"\s*:\s*"[^"]*"': '[REMOVED_STATE]',
    r'(?i)"province"\s*:\s*"[^"]*"': '[REMOVED_STATE]',
    r'(?i)"zipCode"\s*:\s*"[^"]*"': '[REMOVED_ZIP]',
    r'(?i)"postalCode"\s*:\s*"[^"]*"': '[REMOVED_ZIP]',
    r'(?i)"country"\s*:\s*"[^"]*"': '[REMOVED_COUNTRY]',
    # Full address patterns
    r'\b\d+\s+[A-Z][a-zA-Z\s]+(?:Street|St|Avenue|Ave|Road|Rd|Drive|Dr|Lane|Ln|Way|Place|Pl|Court|Ct|Boulevard|Blvd|Parkway|Pkwy|Circle|Cir|Square|Sq|Apt|Suite|Unit|#)\s*\d*[A-Z]*,?\s*[A-Z]{2}\s*\d{5}': '[REMOVED_ADDRESS]',

    # ===== FINANCIAL INFORMATION =====
    # Bank account and routing numbers
    r'(?i)"accountNumber"\s*:\s*"[^"]*"': '[REMOVED_DATA]',
    r'(?i)"bankAccount"\s*:\s*"[^"]*"': '[REMOVED_DATA]',
    r'(?i)"routingNumber"\s*:\s*"[^"]*"': '[REMOVED_ROUTING_NUMBER]',
    r'\b\d{8,17}\b': '[REMOVED_BANK_ACCOUNT]',  # 8-17 digit account numbers

    # Monetary amounts
    r'(?i)"annualIncome"\s*:\s*\d+': '[REMOVED_INCOME]',
    r'(?i)"salary"\s*:\s*\d+': '[REMOVED_SALARY]',
    r'(?i)"creditScore"\s*:\s*\d+': '[REMOVED_CREDIT_SCORE]',
    r'(?i)"balance"\s*:\s*[\d,]+\.?\d*': '[REMOVED_BALANCE]',
    r'\$[\d,]+\.?\d{0,2}': '[REMOVED_AMOUNT]',  # $1,250.00
    r'\b\d{1,3}(?:,\d{3})*(?:\.\d{2})?\s*(?:USD|EUR|GBP|CAD|AUD|JPY|dollars|euros|pounds)\b': '[REMOVED_AMOUNT]',

    # ===== AUTHENTICATION & TOKENS =====
    # Passwords - comprehensive
    r'(?i)"password"\s*:\s*"[^"]*"': '[REMOVED_PASSWORD]',
    r'(?i)"pwd"\s*:\s*"[^"]*"': '[REMOVED_PASSWORD]',
    r'(?i)"pass"\s*:\s*"[^"]*"': '[REMOVED_PASSWORD]',
    r'(?i)"passwd"\s*:\s*"[^"]*"': '[REMOVED_PASSWORD]',
    r'password[:=\s]*[^\s"&]+': '[REMOVED_PASSWORD]',
    r'(?:pwd|pass|passwd)[:=\s]*[^\s"&]+': '[REMOVED_PASSWORD]',

    # API Keys and Tokens
    r'(?i)"apiKey"\s*:\s*"[^"]*"': '[REMOVED_API_KEY]',
    r'(?i)"accessToken"\s*:\s*"[^"]*"': '[REMOVED_ACCESS_TOKEN]',
    r'(?i)"refreshToken"\s*:\s*"[^"]*"': '[REMOVED_REFRESH_TOKEN]',
    r'(?i)"authToken"\s*:\s*"[^"]*"': '[REMOVED_AUTH_TOKEN]',
    r'(?i)"bearerToken"\s*:\s*"[^"]*"': '[REMOVED_BEARER_TOKEN]',
    r'(?i)"sessionToken"\s*:\s*"[^"]*"': '[REMOVED_SESSION_TOKEN]',
    # Security question/answer fields (JSON double-quoted)
    r'(?i)"securityQuestion"\s*:\s*"[^"]*"': '[REMOVED_SECURITY_QUESTION]',
    r'(?i)"securityAnswer"\s*:\s*"[^"]*"': '[REMOVED_SECURITY_ANSWER]',
    # Security question/answer fields (single-quoted variants commonly found in Python-serialized logs)
    r"(?i)'securityQuestion'\s*:\s*'[^']*'": '[REMOVED_SECURITY_QUESTION]',
    r"(?i)'securityAnswer'\s*:\s*'[^']*'": '[REMOVED_SECURITY_ANSWER]',
    r'\bsk-or-v1-[a-fA-F0-9]+\b': '[REMOVED_API_KEY]',  # OpenRouter API keys
    r'\b(?:sk|pk|api)[_-](?:or|openai|anthropic|claude|gpt|ai)[_-]v?\d*[_-][a-zA-Z0-9_-]{20,}\b': '[REMOVED_API_KEY]',  # Various AI API keys
    r'\b(?:sk|pk|api)[_-][a-zA-Z0-9_-]{10,}\b': '[REMOVED_API_KEY]',

    # JWT Tokens
    r'eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]*\.?[a-zA-Z0-9_-]*': '[REMOVED_JWT]',

    # ===== EMPLOYMENT INFORMATION =====
    r'(?i)"employer"\s*:\s*"[^"]*"': '[REMOVED_EMPLOYER]',
    r'(?i)"company"\s*:\s*"[^"]*"': '[REMOVED_COMPANY]',
    r'(?i)"employeeId"\s*:\s*"[^"]*"': '[REMOVED_EMPLOYEE_ID]',
    r'(?i)"empId"\s*:\s*"[^"]*"': '[REMOVED_EMPLOYEE_ID]',
    r'\b(?:EMP|EMPLOYEE)_[A-Z0-9_]+\b': '[REMOVED_EMPLOYEE_ID]',

    # ===== IDENTIFIERS =====
    r'(?i)"customerId"\s*:\s*"[^"]*"': '[REMOVED_CUSTOMER_ID]',
    r'(?i)"userId"\s*:\s*"[^"]*"': '[REMOVED_USER_ID]',
    r'(?i)"accountId"\s*:\s*"[^"]*"': '[REMOVED_ACCOUNT_ID]',
    r'\b(?:CUST|CUSTOMER|USER|ACCOUNT|CLIENT)_[A-Z0-9_]+\b': '[REMOVED_ID]',

    # ===== DATES & PERSONAL INFO =====
    # Date of Birth
    r'(?i)"dateOfBirth"\s*:\s*"[^"]*"': '[REMOVED_DOB]',
    r'(?i)"dob"\s*:\s*"[^"]*"': '[REMOVED_DOB]',
    r'(?i)"birthDate"\s*:\s*"[^"]*"': '[REMOVED_DOB]',
    r'\b\d{4}-\d{2}-\d{2}\b': '[REMOVED_DOB]',  # YYYY-MM-DD

    # ===== SYSTEM INFORMATION =====
    # IP Addresses
    r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b': '[REMOVED_IP]',

    # MAC Addresses
    r'\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b': '[REMOVED_MAC]',

    # Hostnames and Domains
    r'\b[a-zA-Z0-9-]+\.[a-zA-Z]{2,}(?::\d+)?\b': '[REMOVED_HOSTNAME]',

 
    r'/(?:opt|usr|var|home|app|tmp|etc|srv|production|uploads)[^\s\n]*': '[REMOVED_PATH]',
    # Bracketed content (e.g. [http-nio-8080-exec-10]) but avoid matching
    # our own placeholders (which start with '[REMOVED_') so we don't
    # accidentally replace earlier redaction tokens.
    r'\[(?!REMOVED_)[^\]]*\]': '[REMOVED_PATH]',  # Bracketed paths

    # Database Connection Strings
    r'(?:postgres|mysql|mongodb|redis|oracle|sqlserver)://[^\s]+': '[REMOVED_DB_URI]',
    r'\b[a-zA-Z0-9_-]+:[^\s@]+@[a-zA-Z0-9.-]+(?::\d+)?/[a-zA-Z0-9_-]+\b': '[REMOVED_DB_URI]',

    # User-Agent Strings
    r'User-Agent:\s*[^\n]+': '[REMOVED_USER_AGENT]',

    # Cookies
    r'(?:Set-Cookie|Cookie):\s*[A-Za-z0-9_-]+=.[^; \n]+': '[REMOVED_COOKIE]',

    # Environment Variables
    r'\b[A-Z_]{2,}=(?:[^ \n]+)': '[REMOVED_ENV_VAR]',

    # Timestamps (sometimes sensitive)
    r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?': '[REMOVED_TIMESTAMP]',

    # Private Keys
    r'-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----(.*?)-----END (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----': '[REMOVED_PRIVATE_KEY]',

    # Security Tokens
    r'(?i)(?:csrf|xsrf|jwt_secret|salt|pepper)[=:\s]+[A-Za-z0-9._-]+': '[REMOVED_SECURITY_TOKEN]',

    # Session Keys - comprehensive patterns
    r'(?i)session\s*:\s*sess_[a-zA-Z0-9_-]+': '[REMOVED_SESSION_KEY]',
    r'(?i)"sessionId"\s*:\s*"[^"]*"': '[REMOVED_SESSION_KEY]',
    r'(?i)"sessionToken"\s*:\s*"[^"]*"': '[REMOVED_SESSION_KEY]',
    r'(?i)"session_key"\s*:\s*"[^"]*"': '[REMOVED_SESSION_KEY]',
    r'(?i)(?:admin|user|audit|oauth|ws)_session_[a-zA-Z0-9_-]+': '[REMOVED_SESSION_KEY]',
    r'(?i)session_(?:key|id|token)[:=\s]*[a-zA-Z0-9_-]+': '[REMOVED_SESSION_KEY]',
    r'(?i)session\s*[:=]\s*[a-zA-Z0-9_-]+': '[REMOVED_SESSION_KEY]',

    # Authorization Headers
    r'Authorization:\s*Bearer\s+[A-Za-z0-9._-]+': '[REMOVED_BEARER_TOKEN]',

    # ===== ADDITIONAL SENSITIVE PATTERNS =====
    # Tax IDs and other government identifiers
    r'(?i)"taxId"\s*:\s*"[^"]*"': '[REMOVED_TAX_ID]',
    r'(?i)"tin"\s*:\s*"[^"]*"': '[REMOVED_TAX_ID]',
    r'\b\d{2}-\d{7}\b': '[REMOVED_TAX_ID]',  # EIN format

    # Healthcare identifiers
    r'(?i)"medicalId"\s*:\s*"[^"]*"': '[REMOVED_MEDICAL_ID]',
    r'(?i)"patientId"\s*:\s*"[^"]*"': '[REMOVED_PATIENT_ID]',
    r'(?i)"insuranceId"\s*:\s*"[^"]*"': '[REMOVED_INSURANCE_ID]',

    # Vehicle information
    r'(?i)"vin"\s*:\s*"[^"]*"': '[REMOVED_VIN]',
    r'(?i)"vehicleId"\s*:\s*"[^"]*"': '[REMOVED_VEHICLE_ID]',
    r'\b[A-HJ-NPR-Z0-9]{17}\b': '[REMOVED_VIN]',  # VIN format

    # Biometric data
    r'(?i)"fingerprint"\s*:\s*"[^"]*"': '[REMOVED_BIOMETRIC]',
    r'(?i)"biometric"\s*:\s*"[^"]*"': '[REMOVED_BIOMETRIC]',

    # Device identifiers
    r'(?i)"deviceId"\s*:\s*"[^"]*"': '[REMOVED_DEVICE_ID]',
    r'(?i)"imei"\s*:\s*"[^"]*"': '[REMOVED_IMEI]',
    r'(?i)"uuid"\s*:\s*"[^"]*"': '[REMOVED_UUID]',

    # Location data
    r'(?i)"latitude"\s*:\s*"-?\d+\.?\d*"': '[REMOVED_LATITUDE]',
    r'(?i)"longitude"\s*:\s*"-?\d+\.?\d*"': '[REMOVED_LONGITUDE]',
    r'(?i)"coordinates"\s*:\s*"[^"]*"': '[REMOVED_COORDINATES]',

    # ===== INTERNATIONAL FORMATS =====
    # International phone numbers
    r'\+\d{1,4}\s?\(?\d{1,4}\)?[\s.-]?\d{1,4}[\s.-]?\d{1,4}[\s.-]?\d{1,4}': '[REMOVED_PHONE]',

    # International addresses
    r'(?i)"postalCode"\s*:\s*"[^"]*"': '[REMOVED_POSTAL_CODE]',

    # ===== FALLBACK PATTERNS =====
    # Any remaining long alphanumeric strings that might be sensitive
    # Increase threshold to 64 chars to avoid replacing common shorter tokens
    r'\b[a-zA-Z0-9_-]{64,}\b': '[REMOVED_LONG_TOKEN]',
}

# Priority patterns applied first to avoid partial matches by more general regexes below.
PRIORITY_PATTERNS = [
    # Private keys and long encoded tokens
    (r'-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----(.*?)-----END (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----', '[REMOVED_PRIVATE_KEY]'),
    (r'eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]*\.?[a-zA-Z0-9_-]*', '[REMOVED_JWT]'),
    # API keys (OpenRouter/OpenAI/Anthropic etc.)
    (r'\bsk-or-v1-[a-fA-F0-9]+\b', '[REMOVED_API_KEY]'),
    (r'\b(?:sk|pk|api)[_-](?:or|openai|anthropic|claude|gpt|ai)[_-]v?\d*[_-][a-zA-Z0-9_-]{20,}\b', '[REMOVED_API_KEY]'),
    (r'\b(?:sk|pk|api)[_-][a-zA-Z0-9_-]{20,}\b', '[REMOVED_API_KEY]'),
    # Credit cards and CVV
    (r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b', '[REMOVED_CC_NUMBER]'),
    (r'(?i)(?:cvv|cvc|security code|card verification|verification code)[:=\s]*\d{3,4}\b', '[REMOVED_CVV]'),
    # SSN
    (r'\b\d{3}-\d{2}-\d{4}\b', '[REMOVED_SSN]'),
    # Emails
    (r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b', '[REMOVED_EMAIL]'),
    # Phone numbers (international-ish)
    (r'\+\d{1,4}[\s.-]?\(?\d{1,4}\)?[\s.-]?\d{1,4}[\s.-]?\d{1,4}[\s.-]?\d{0,4}\b', '[REMOVED_PHONE]'),
    # Bank accounts (long digit sequences)
    (r'\b\d{8,17}\b', '[REMOVED_BANK_ACCOUNT]'),
    # DB connection strings
    (r'(?:postgres|mysql|mongodb|redis|oracle|sqlserver)://[^\s]+', '[REMOVED_DB_URI]'),
]

def validate_sanitization(text):
    """Validate that sensitive data has been properly removed"""
    validation_patterns = [
        # High-risk patterns that should never appear
        r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',  # Credit cards
        r'\b\d{3}-\d{2}-\d{4}\b',  # SSN
        r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b',  # Email
        r'eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]*\.?[a-zA-Z0-9_-]*',  # JWT
        r'-----BEGIN.*PRIVATE KEY-----',  # Private keys
        r'(?i)password\s*[:=]\s*[^\s"&]+',  # Passwords
        r'\b[a-zA-Z0-9_-]{50,}\b',  # Long tokens
    ]

    issues_found = []
    for pattern in validation_patterns:
        matches = re.findall(pattern, text, flags=re.IGNORECASE)
        if matches:
            issues_found.extend(matches)

    return issues_found


def extract_names_from_text(text):
    """Heuristically extract explicit name mentions from free text.

    This looks for common phrasings like "my name is X", "Name: X",
    JSON name fields, and simple capitalized name patterns when safe.
    Returns a set of candidate name strings (trimmed).
    """
    names = set()
    if not text:
        return names

    # Common explicit patterns
    patterns = [
        r"\bmy name is\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,2})\b",
        r"\bname is\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,2})\b",
        r"\bI am\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,2})\b",
        r"\bI'm\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,2})\b",
        r'"(?:firstName|lastName|fullName|displayName|name)"\s*:\s*"([^\"]+)"',
        r"'?(?:firstName|lastName|fullName|displayName|name)'?\s*:\s*'([^']+)'",
        r"\bName[:\s]+([A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,2})\b",
        r"\bUser[:\s]+([A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,2})\b",
        
    ]

    for pat in patterns:
        for m in re.findall(pat, text, flags=re.IGNORECASE):
            if isinstance(m, tuple):
                m = m[0]
            name = m.strip()
            # Skip obviously short tokens
            if 1 < len(name) <= 80:
                names.add(name)

    # As a last resort, capture two-word capitalized sequences (First Last)
    # but only if none of the above patterns matched to avoid over-redaction.
    if not names:
        for m in re.findall(r"\b([A-Z][a-z]{1,}\s+[A-Z][a-z]{1,})\b", text):
            if 1 < len(m) <= 80:
                names.add(m.strip())

    return names

def remove_text(text):
    """Enhanced text sanitization with comprehensive pattern matching and JSON handling"""
    removed_items = []

    # Extract any explicit names mentioned in the raw text so we can redact them everywhere
    dynamic_names = extract_names_from_text(text)

    # First pass: Handle JSON structures specifically
    try:
        import json
        # Try to parse as JSON and sanitize individual fields
        if text.strip().startswith('{') and text.strip().endswith('}'):
            data = json.loads(text)
            sanitized_data = sanitize_json_object(data, removed_items, dynamic_names)
            return json.dumps(sanitized_data, indent=2), removed_items
        elif text.strip().startswith('[') and text.strip().endswith(']'):
            data = json.loads(text)
            sanitized_data = sanitize_json_array(data, removed_items, dynamic_names)
            return json.dumps(sanitized_data, indent=2), removed_items
    except (json.JSONDecodeError, TypeError):
        # Not valid JSON, continue with regex patterns
        pass

    # Second pass: Apply regex patterns
    # Apply high-priority patterns first to avoid partial matches by looser patterns
    # First, apply dynamic name redactions discovered earlier
    if dynamic_names:
        for name in dynamic_names:
            try:
                esc = re.escape(name)
                # Match word boundaries and possessive forms
                name_pat = re.compile(rf"\b{esc}(?:'s)?\b", flags=re.IGNORECASE)
                if re.search(name_pat, text):
                    removed_items.append(name)
                    text = re.sub(name_pat, '[REMOVED_NAME]', text)
            except re.error:
                continue
    for pattern, replacement in PRIORITY_PATTERNS:
        matches = re.findall(pattern, text, flags=re.IGNORECASE | re.DOTALL)
        if matches:
            removed_items.extend(matches)
        text = re.sub(pattern, replacement, text, flags=re.IGNORECASE | re.DOTALL)

    # Then apply the rest of the patterns
    for pattern, replacement in REMOVAL_PATTERNS.items():
        # Skip any pattern that is identical to a priority one
        if any(pattern == p for p, _ in PRIORITY_PATTERNS):
            continue
        matches = re.findall(pattern, text, flags=re.IGNORECASE)
        if matches:
            removed_items.extend(matches)
        text = re.sub(pattern, replacement, text, flags=re.IGNORECASE)

    # Third pass: Additional cleanup for edge cases
    # Remove any remaining potential sensitive data patterns
    text = remove_additional_patterns(text, removed_items)

    # Fourth pass: Validation and final cleanup
    issues_found = validate_sanitization(text)
    if issues_found:
        # If validation finds issues, apply more aggressive cleanup
        for issue in issues_found:
            removed_items.append(issue)
            text = text.replace(issue, '[REMOVED_SENSITIVE_DATA]')

    return text, removed_items

def sanitize_json_object(obj, removed_items, dynamic_names=None):
    """Recursively sanitize JSON objects"""
    if isinstance(obj, dict):
        sanitized = {}
        for key, value in obj.items():
            # Check if key itself contains sensitive information
            if any(re.search(pattern, key, re.IGNORECASE) for pattern in [
                r'(?i)(password|secret|token|key|ssn|social|credit|card)',
                r'(?i)(private|auth|bearer|jwt|session)',
                r'(?i)(security|question|answer)'
            ]):
                removed_items.append(f"{key}: {str(value)}")
                sanitized[key] = "[REMOVED_SENSITIVE_DATA]"
            else:
                sanitized[key] = sanitize_json_object(value, removed_items, dynamic_names)
        return sanitized
    elif isinstance(obj, list):
        return sanitize_json_array(obj, removed_items, dynamic_names)
    elif isinstance(obj, str):
        # Apply string sanitization
        # Apply priority patterns first for JSON string fields
        # First, redact any dynamic names we discovered from the raw text
        if dynamic_names:
            for name in dynamic_names:
                try:
                    esc = re.escape(name)
                    name_pat = re.compile(rf"\b{esc}(?:'s)?\b", flags=re.IGNORECASE)
                    if re.search(name_pat, obj):
                        removed_items.append(name)
                        obj = re.sub(name_pat, '[REMOVED_NAME]', obj)
                except re.error:
                    continue

        for pattern, replacement in PRIORITY_PATTERNS:
            matches = re.findall(pattern, obj, flags=re.IGNORECASE | re.DOTALL)
            if matches:
                removed_items.extend(matches)
            obj = re.sub(pattern, replacement, obj, flags=re.IGNORECASE | re.DOTALL)

        for pattern, replacement in REMOVAL_PATTERNS.items():
            if any(pattern == p for p, _ in PRIORITY_PATTERNS):
                continue
            matches = re.findall(pattern, obj, flags=re.IGNORECASE)
            if matches:
                removed_items.extend(matches)
            obj = re.sub(pattern, replacement, obj, flags=re.IGNORECASE)
        return obj
    else:
        return obj

def sanitize_json_array(arr, removed_items, dynamic_names=None):
    """Sanitize JSON arrays"""
    return [sanitize_json_object(item, removed_items, dynamic_names) for item in arr]

def remove_additional_patterns(text, removed_items):
    """Additional pattern removal for edge cases"""
    # Remove potential base64 encoded sensitive data
    base64_pattern = r'\b[A-Za-z0-9+/]{40,}={0,2}\b'
    matches = re.findall(base64_pattern, text)
    if matches:
        for match in matches:
            # Check if it looks like it could be sensitive data
            if len(match) > 50 or any(keyword in match.lower() for keyword in ['eyj', 'jwt', 'token']):
                removed_items.append(match)
                text = text.replace(match, '[REMOVED_ENCODED_DATA]')

    # Remove potential hex-encoded data that might be sensitive
    hex_pattern = r'\b[0-9A-Fa-f]{32,}\b'
    matches = re.findall(hex_pattern, text)
    if matches:
        for match in matches:
            if len(match) > 32:  # Likely a hash or token
                removed_items.append(match)
                text = text.replace(match, '[REMOVED_HEX_DATA]')

    # Remove potential XML/HTML encoded sensitive data
    xml_encoded_pattern = r'&[a-zA-Z0-9#]+;'
    matches = re.findall(xml_encoded_pattern, text)
    if matches:
        for match in matches:
            removed_items.append(match)
            text = text.replace(match, '[REMOVED_XML_ENTITY]')

    return text

def parse_log_errors(content):
    """Parse log content to identify individual error segments"""
    # Common error patterns that indicate separate issues
    error_patterns = [
        r'ERROR[:\s]+[^\n]+',
        r'Exception[:\s]+[^\n]+',
        r'Failed[:\s]+[^\n]+',
        r'Timeout[:\s]+[^\n]+',
        r'Connection refused[^\n]*',
        r'java\.[a-zA-Z]+Exception[^\n]*',
        r'NullPointerException[^\n]*',
        r'SQLException[^\n]*',
        r'IOException[^\n]*',
        r'Authentication failed[^\n]*',
        r'Access denied[^\n]*',
        r'Database connection[^\n]*',
        r'Payment.*failed[^\n]*',
        r'Validation error[^\n]*',
    ]

    errors = []
    lines = content.split('\n')

    for i, line in enumerate(lines):
        line = line.strip()
        if not line:
            continue

        # Check if this line matches any error pattern
        is_error = False
        for pattern in error_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                is_error = True
                break

        if is_error:
            # Collect this error line and a few context lines
            error_segment = [line]
            # Add a few lines before and after for context
            start = max(0, i - 2)
            end = min(len(lines), i + 3)
            error_segment = lines[start:end]
            errors.append('\n'.join(error_segment))

    # If no specific errors found, treat the whole log as one error
    if not errors:
        errors = [content]

    return errors

def analyze_errors_selectively(errors, removed_content):
    """Analyze only new errors, reuse existing analyses for known errors"""
    conn = sqlite3.connect('logs.db')
    c = conn.cursor()

    new_errors = []
    existing_analyses = []

    for error in errors:
        # Create a hash for this specific error
        error_hash = hashlib.sha256(error.encode()).hexdigest()

        # Check if this specific error has been analyzed before
        c.execute('SELECT issue_type, severity, root_cause, suggested_fix FROM error_analyses WHERE error_hash = ?', (error_hash,))
        existing = c.fetchone()

        if existing:
            existing_analyses.append({
                'error': error,
                'issue_type': existing[0],
                'severity': existing[1],
                'root_cause': existing[2],
                'suggested_fix': existing[3]
            })
        else:
            new_errors.append(error)

    # Only call AI for new errors
    new_analyses = []
    if new_errors:
        # Combine new errors into a single prompt for efficiency
        combined_new_errors = '\n\n---\n\n'.join(new_errors)
        ai_result = analyze_log_with_ai(combined_new_errors)

        # Save each new error analysis to the database
        created_time = datetime.now().isoformat()
        for error in new_errors:
            error_hash = hashlib.sha256(error.encode()).hexdigest()
            c.execute('''INSERT INTO error_analyses 
                (error_hash, error_content, issue_type, severity, root_cause, suggested_fix, created_time)
                VALUES (?, ?, ?, ?, ?, ?, ?)''',
                (error_hash, error, ai_result['issue_type'], ai_result['severity'], 
                 ai_result['root_cause'], ai_result['suggested_fix'], created_time))

            new_analyses.append({
                'error': error,
                'issue_type': ai_result['issue_type'],
                'severity': ai_result['severity'],
                'root_cause': ai_result['root_cause'],
                'suggested_fix': ai_result['suggested_fix']
            })

    conn.commit()
    conn.close()

    # Combine all analyses
    all_analyses = existing_analyses + new_analyses

    # Create a summary analysis
    if all_analyses:
        # Determine overall severity (highest severity wins)
        severity_levels = {'Low': 1, 'Medium': 2, 'High': 3, 'Unknown': 0}
        max_severity = max(all_analyses, key=lambda x: severity_levels.get(x['severity'], 0))

        # Combine issue types and root causes
        issue_types = list(set([a['issue_type'] for a in all_analyses]))
        root_causes = [a['root_cause'] for a in all_analyses]
        suggested_fixes = [a['suggested_fix'] for a in all_analyses]

        combined_analysis = {
            'issue_type': 'Multiple Issues' if len(issue_types) > 1 else issue_types[0],
            'severity': max_severity['severity'],
            'root_cause': '\n\n'.join([f"• {cause}" for cause in root_causes]),
            'suggested_fix': '\n\n'.join([f"• {fix}" for fix in suggested_fixes])
        }

        return combined_analysis, all_analyses, len(existing_analyses), len(new_analyses)

    return None, [], 0, 0

def analyze_log_with_ai(redacted_content):
    if not OPENROUTER_API_KEY or OPENROUTER_API_KEY == 'your_openrouter_api_key_here':
        # Determine severity based on log content for mock analysis
        content_lower = redacted_content.lower()
        if 'error' in content_lower or 'exception' in content_lower or 'failed' in content_lower:
            severity = 'High'
        elif 'warning' in content_lower or 'timeout' in content_lower:
            severity = 'Medium'
        else:
            severity = 'Low'

        return {
            "issue_type": "Mock Analysis - API Key Not Configured",
            "severity": severity,
            "root_cause": "This is a mock analysis because no OpenRouter API key is configured. Please set OPENROUTER_API_KEY in your .env file.",
            "suggested_fix": "Configure your OpenRouter API key to enable real AI analysis."
        }

    # Build prompt
    prompt = f"""
Analyze the following error log and provide a structured response in JSON only.

Log content:
{redacted_content}

Return a JSON object with these keys exactly: issue_type, severity, root_cause, suggested_fix.
Severity should be one of: High, Medium, Low.
Return only the JSON object, no commentary.
"""

    def format_as_bullets(text, max_items=5):
        """Convert paragraphs or long texts into concise bullet points.

        - Splits on newlines and sentence endings.
        - Trims and deduplicates short items.
        - Returns a string with each item prefixed by '• '.
        """
        if not text:
            return ''
        # Normalize line breaks
        s = str(text).strip()
        # Split by newlines first
        parts = []
        for line in re.split(r'\r?\n', s):
            line = line.strip()
            if not line:
                continue
            parts.append(line)

        # If no newline-separated parts, split into sentences
        if not parts:
            parts = re.split(r'(?<=[.!?])\s+', s)

        # Further split long lines into sentence pieces
        normalized = []
        for p in parts:
            # If very long, split by sentence-end punctuation
            if len(p) > 200:
                for sub in re.split(r'(?<=[.!?])\s+', p):
                    sub = sub.strip()
                    if sub:
                        normalized.append(sub)
            else:
                normalized.append(p)

        # Deduplicate while preserving order
        seen = set()
        bullets = []
        for item in normalized:
            it = item.strip()
            if not it:
                continue
            if it in seen:
                continue
            seen.add(it)
            bullets.append(it)
            if len(bullets) >= max_items:
                break

        if not bullets:
            return s

        return '\n'.join(['• ' + b for b in bullets])

    try:
        import json
        import ast

        resp = requests.post(
            url=f"{OPENROUTER_BASE_URL}/chat/completions",
            headers={
                "Authorization": f"Bearer {OPENROUTER_API_KEY}",
                "Referer": "https://github.com/your-repo/ai-bug-tracker",
                "X-Title": "AI Bug Tracker",
                "Content-Type": "application/json"
            },
            data=json.dumps({
                "model": "openai/gpt-4o",
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.1,
                "max_tokens": 1000
            }),
            timeout=30
        )

        resp.raise_for_status()
        result = resp.json()

        # Extract the textual content from common response shapes
        content = None
        if isinstance(result, dict):
            # Common OpenRouter / OpenAI Chat shape
            choices = result.get('choices') or []
            if choices:
                first = choices[0]
                # message may be a dict with 'content' or a nested structure
                msg = first.get('message') or {}
                if isinstance(msg, dict):
                    content = msg.get('content') or msg.get('text') or ''
                elif isinstance(first.get('message'), str):
                    content = first.get('message')
                else:
                    # sometimes choice has 'text' or other keys
                    content = first.get('text') or first.get('message') or ''
            else:
                # Fallback to other possible fields
                content = result.get('text') or result.get('output') or str(result)
        else:
            content = str(result)

        if not isinstance(content, str):
            content = str(content or '')

        # Remove code fences and surrounding backticks
        content = content.strip()
        content = re.sub(r"^```json\s*", '', content, flags=re.I)
        content = re.sub(r"^```\s*", '', content, flags=re.I)
        content = re.sub(r"```$", '', content)
        content = content.strip()

        # Try to extract the first JSON object from the text robustly
        def extract_json_object(s: str):
            idx = s.find('{')
            if idx == -1:
                return None
            depth = 0
            in_str = False
            esc = False
            for i in range(idx, len(s)):
                ch = s[i]
                if ch == '"' and not esc:
                    in_str = not in_str
                if ch == '\\' and not esc:
                    esc = True
                    continue
                else:
                    esc = False
                if not in_str:
                    if ch == '{':
                        depth += 1
                    elif ch == '}':
                        depth -= 1
                        if depth == 0:
                            return s[idx:i+1]
            return None

        json_str = extract_json_object(content)
        parsed = None
        if json_str:
            try:
                parsed = json.loads(json_str)
            except Exception:
                # Try ast.literal_eval as a fallback (handles single quotes)
                try:
                    parsed = ast.literal_eval(json_str)
                except Exception:
                    parsed = None

        # If we couldn't extract an object, try to directly parse the whole content
        if parsed is None:
            try:
                parsed = json.loads(content)
            except Exception:
                try:
                    parsed = ast.literal_eval(content)
                except Exception:
                    parsed = None

        # If parsed is still None, try to heuristically find fields
        if not isinstance(parsed, dict):
            # heuristics: find lines like "issue_type": "..." or issue_type: ...
            heur = {}
            def find_field(name):
                m = re.search(rf'"?{re.escape(name)}"?\s*[:=]\s*"([^"]+)"', content, flags=re.IGNORECASE)
                if m:
                    return m.group(1).strip()
                m2 = re.search(rf'{re.escape(name)}\s*[:=]\s*([^\n,]+)', content, flags=re.IGNORECASE)
                if m2:
                    return m2.group(1).strip().strip('\"\'')
                return None

            heur['issue_type'] = find_field('issue_type') or find_field('issue') or 'Unknown'
            heur['severity'] = find_field('severity') or ('High' if re.search(r'error|exception|failed', redacted_content, flags=re.IGNORECASE) else 'Low')
            heur_root = find_field('root_cause') or find_field('rootcause') or ('See log for details.')
            heur_fix = find_field('suggested_fix') or find_field('suggestedfix') or ('Run diagnostics and inspect logs.')
            heur['root_cause'] = format_as_bullets(heur_root)
            heur['suggested_fix'] = format_as_bullets(heur_fix)
            return heur

        # Ensure the parsed object contains required keys and normalize
        def safe_get(d, k):
            v = d.get(k) or d.get(k.lower()) or d.get(k.upper())
            if v is None:
                return ''
            return v

        # Format returned text fields into concise bullets
        issue_type_val = safe_get(parsed, 'issue_type') or safe_get(parsed, 'issue') or 'Unknown'
        severity_val = safe_get(parsed, 'severity') or 'Unknown'
        root_cause_val = safe_get(parsed, 'root_cause') or safe_get(parsed, 'rootcause') or ''
        suggested_fix_val = safe_get(parsed, 'suggested_fix') or safe_get(parsed, 'suggestedfix') or ''

        return {
            'issue_type': issue_type_val,
            'severity': severity_val,
            'root_cause': format_as_bullets(root_cause_val),
            'suggested_fix': format_as_bullets(suggested_fix_val)
        }

    except requests.exceptions.RequestException as e:
        error_msg = f"Failed to connect to OpenRouter API: {str(e)}"
    except Exception as e:
        error_msg = f"Failed to analyze log with OpenRouter: {str(e)}"

    return {
        "issue_type": "Analysis Failed",
        "severity": "Unknown",
        "root_cause": error_msg,
        "suggested_fix": "Please check your OpenRouter API key and try again."
    }


@app.route('/api/upload', methods=['POST'])
def upload_log():
    if 'log_file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['log_file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    allowed_extensions = ['.log', '.txt', '.json']
    if not any(file.filename.lower().endswith(ext) for ext in allowed_extensions):
        return jsonify({'error': 'Invalid file type. Allowed: .log, .txt, .json'}), 400
    
   
    if file.content_length and file.content_length > 5 * 1024 * 1024:
        return jsonify({'error': 'File too large. Max size: 5MB'}), 400
    content = file.read().decode('utf-8', errors='ignore')
    
    file_hash = hashlib.sha256(content.encode()).hexdigest()
    
    # Check for exact duplicate first
    conn = sqlite3.connect('logs.db')
    c = conn.cursor()
    c.execute('SELECT * FROM logs WHERE hash = ?', (file_hash,))
    existing = c.fetchone()
    
    if existing:
        conn.close()
        return jsonify({
            'duplicate': True,
            'message': 'This exact log file has been analyzed before.',
            'result': {
                'issue_type': existing[7],
                'severity': existing[8],
                'root_cause': existing[9],
                'suggested_fix': existing[10]
            },
            'removal_info': {
                'original_content': existing[3],
                'removed_content': existing[4],
                'removed_items': [],  # Can't recover original removed items from stored data
                'total_removals': 0
            }
        })
    
    # Remove sensitive data
    removed, removed_items = remove_text(content)
    redacted_hash = hashlib.sha256(removed.encode()).hexdigest()
    
    # Check for similar content (same errors, different sensitive data)
    c.execute('SELECT * FROM logs WHERE redacted_hash = ? LIMIT 1', (redacted_hash,))
    similar_existing = c.fetchone()
    
    if similar_existing:
        conn.close()
        return jsonify({
            'duplicate': True,
            'message': 'Similar log content has been analyzed before (same errors, different sensitive data).',
            'result': {
                'issue_type': similar_existing[7],
                'severity': similar_existing[8],
                'root_cause': similar_existing[9],
                'suggested_fix': similar_existing[10]
            },
            'removal_info': {
                'original_content': content,
                'removed_content': removed,
                'removed_items': list(set(removed_items)),
                'total_removals': len(removed_items)
            }
        })
 
    # Only call AI if we haven't seen this error pattern before
    # Parse individual errors and analyze selectively
    errors = parse_log_errors(removed)
    ai_result, detailed_analyses, reused_count, new_count = analyze_errors_selectively(errors, removed)
    
    if ai_result is None:
        ai_result = {
            'issue_type': 'No errors detected',
            'severity': 'Low',
            'root_cause': 'The log content does not contain recognizable error patterns.',
            'suggested_fix': 'Review the log content manually or check if the error patterns are properly formatted.'
        }
    
    # Save to database
    upload_time = datetime.now().isoformat()
    c.execute('''INSERT INTO logs 
        (filename, file_size, original_content, redacted_content, redacted_hash, hash, issue_type, severity, root_cause, suggested_fix, upload_time, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
        (file.filename, len(content), content, removed, redacted_hash, file_hash, 
         ai_result['issue_type'], ai_result['severity'], ai_result['root_cause'], ai_result['suggested_fix'], 
         upload_time, 'Completed'))
    conn.commit()
    conn.close()
    
    return jsonify({
        'analysis': ai_result,
        'removal_info': {
            'original_content': content,
            'removed_content': removed,
            'removed_items': list(set(removed_items)),
            'total_removals': len(removed_items)
        },
        'analysis_stats': {
            'total_errors': len(errors),
            'reused_analyses': reused_count,
            'new_analyses': new_count,
            'ai_calls_saved': reused_count
        }
    })

@app.route('/api/logs', methods=['GET'])
def get_logs():
    conn = sqlite3.connect('logs.db')
    c = conn.cursor()
    c.execute('SELECT id, filename, file_size, issue_type, severity, root_cause, suggested_fix, upload_time, status FROM logs ORDER BY upload_time DESC')
    logs = c.fetchall()
    conn.close()
    
    return jsonify([{
        'id': log[0],
        'filename': log[1],
        'file_size': log[2],
        'issue_type': log[3],
        'severity': log[4],
        'root_cause': log[5],
        'suggested_fix': log[6],
        'upload_time': log[7],
        'status': log[8]
    } for log in logs])

if __name__ == '__main__':
    app.run(debug=True, port=5000)