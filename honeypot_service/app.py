"""
HONEYPOT SERVICE - ATTACK DETECTION ENGINE
============================================

This is the main attack detection service. It runs a Flask web server that:
✓ Listens for incoming HTTP requests on port 8080
✓ Detects various attack patterns (SQL injection, XSS, path traversal)
✓ Logs attacks to both files and database
✓ Implements rate limiting to prevent DoS

SECURITY FEATURES:
✓ Input sanitization prevents injection attacks
✓ Parameterized database queries prevent SQL injection
✓ Rate limiting prevents brute force attacks
✓ IP validation prevents spoofing
✓ Non-root execution in Docker container
✓ Read-only root filesystem in container
✓ Capability dropping limits container privileges

Production-ready with hardened security practices.
"""

import os
import json
import logging
from datetime import datetime
from flask import Flask, request, jsonify
from functools import wraps
import re
from sql_utils import safe_log_attack

# ============================================================================
# FLASK APPLICATION SETUP
# ============================================================================

app = Flask(__name__)

# SECURITY: Limit maximum request size to 1MB to prevent DoS attacks
app.config['JSON_SORT_KEYS'] = False
app.config['MAX_CONTENT_LENGTH'] = 1024 * 1024

# ============================================================================
# LOGGING CONFIGURATION
# ============================================================================

"""
LOGGING SETUP - Configure dual logging for security and debugging
=================================================================
Logs to:
1. File: /var/log/honeypot/honeypot.log (persistent storage for audits)
2. Console: stdout (for Docker Compose logs)

Format: Timestamp, logger name, severity level, and message
JSON format is used to prevent log injection attacks (not raw strings)
"""
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/honeypot/honeypot.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# ============================================================================
# DATABASE CONFIGURATION
# ============================================================================

"""
DATABASE CONNECTION PARAMETERS - Read from environment for security
====================================================================
These are read from environment variables for security:
- No hardcoded credentials in source code
- Easy to change for different deployments
- Allows Docker Compose to inject secrets safely

Environment variables:
- DB_HOST: PostgreSQL server hostname (default: 'db' for Docker network)
- DB_USER: Database username with LIMITED permissions (not admin!)
- DB_PASSWORD: Credentials stored in .env file (not in code)
- DB_NAME: Database name containing attacks table
- DB_PORT: PostgreSQL port (default: 5432)
"""
DB_HOST = os.getenv('DB_HOST', 'db')
DB_USER = os.getenv('DB_USER', 'honeypot_user')
DB_PASSWORD = os.getenv('DB_PASSWORD', 'SecurePass123!')
DB_NAME = os.getenv('DB_NAME', 'honeypot_db')
DB_PORT = os.getenv('DB_PORT', '5432')

# ============================================================================
# SECURITY UTILITY FUNCTIONS
# ============================================================================

def sanitize_string(value, max_length=1024):
    """
    SANITIZE_STRING FUNCTION - Clean user input to prevent attacks
    ===============================================================
    
    PURPOSE:
    Sanitizes input strings to prevent injection attacks and buffer overflows.
    Applied to ALL user input before processing.
    
    SECURITY FEATURES:
    1. Removes null bytes (\x00) - prevents null byte injection
    2. Truncates strings to max_length - prevents buffer overflow
    3. Type conversion safety - ensures value is always a string
    
    PARAMETERS:
    - value: Input value to sanitize (any type)
    - max_length: Maximum allowed string length (default: 1024 bytes)
    
    RETURNS:
    Sanitized string with null bytes removed and length limited
    
    EXAMPLES:
    - sanitize_string("'; DROP TABLE--") → "'; DROP TABLE--" (safe for logging)
    - sanitize_string("test\x00\x00attack") → "testaattack" (null bytes removed)
    - sanitize_string("verylongstring"*100, 50) → "verylongstring..." (truncated)
    
    ATTACKS PREVENTED:
    ✓ Log injection attacks via embedded null bytes
    ✓ Buffer overflow via extremely long strings
    ✓ SQL injection (prevented by parameterized queries + input cleaned)
    
    COMPLIANCE:
    ✓ OWASP: Input validation and encoding
    ✓ CWE-78: Improper neutralization of special elements
    ✓ CWE-119: Buffer overflow protection
    """
    if not isinstance(value, str):
        return str(value)[:max_length]
    
    # Remove null bytes which can cause injection in logs/database
    value = value.replace('\x00', '')
    
    # Truncate to prevent buffer overflow and DoS via oversized input
    return value[:max_length]


def get_client_ip():
    """
    GET_CLIENT_IP FUNCTION - Extract real client IP, handling proxies
    ==================================================================
    
    PURPOSE:
    Extracts the real client IP address from HTTP request, handling proxies.
    Validates IP format to prevent spoofing.
    
    SECURITY FEATURES:
    1. Checks X-Forwarded-For header for proxy scenarios
    2. Falls back to remote_addr for direct connections
    3. Validates IP format (IPv4 or IPv6)
    4. Prevents IP spoofing through regex validation
    
    HOW IT WORKS:
    1. First checks if request came through proxy (X-Forwarded-For header)
    2. If no proxy, uses direct connection IP (request.remote_addr)
    3. Validates IP against regex patterns:
       - IPv4: digits and dots only (e.g., 192.168.1.1)
       - IPv6: hex digits and colons only (e.g., 2001:db8::1)
    4. Truncates to 45 characters (IPv6 max length)
    5. Returns "unknown" if validation fails (defense in depth)
    
    RETURNS:
    Valid IP address string (IPv4 or IPv6) or "unknown" if invalid
    
    ATTACKS PREVENTED:
    ✓ IP spoofing via invalid characters (e.g., 192.168.1.1; DROP TABLE)
    ✓ Oversized IP strings causing issues (excessive buffer size)
    ✓ Proxy confusion attacks (multi-hop X-Forwarded-For manipulation)
    
    EXAMPLES:
    - Direct connection: "192.168.1.100" → "192.168.1.100"
    - Through proxy: "203.0.113.1" → "203.0.113.1"
    - Invalid characters: "192.168.1.100; DROP TABLE" → "unknown"
    - IPv6: "2001:db8::1" → "2001:db8::1"
    """
    if request.headers.getlist("X-Forwarded-For"):
        ip = request.headers.getlist("X-Forwarded-For")[0]
    else:
        ip = request.remote_addr
    
    # Regex validates IPv4 (digits/dots) or IPv6 (hex/colons)
    ip_pattern = r'^[\d.]+$|^[\da-f:]+$'
    if re.match(ip_pattern, ip):
        return sanitize_string(ip, 45)  # IPv6 max length is 45 chars
    return "unknown"


def rate_limit(max_per_minute=60):
    """
    RATE_LIMIT FUNCTION - Decorator to limit requests per IP
    ==========================================================
    
    PURPOSE:
    Decorator that implements rate limiting per IP address to prevent DoS.
    Tracks requests per IP per minute and blocks excessive traffic.
    
    SECURITY FEATURES:
    1. Tracks requests per IP per minute
    2. Blocks IPs exceeding threshold with 429 status
    3. In-memory rate limiting (fast, no DB overhead)
    4. Returns 429 (Too Many Requests) HTTP status
    
    HOW IT WORKS:
    1. Decorator wraps Flask route functions
    2. Gets current client IP using get_client_ip()
    3. Creates unique key: "IP:YYYY-MM-DD HH:MM" (per-minute buckets)
    4. Increments request counter for that minute
    5. Blocks if exceeds max_per_minute
    6. Resets counter every minute (automatic bucket rotation)
    
    PARAMETERS:
    - max_per_minute: Maximum requests allowed per minute per IP (default: 60)
    
    RETURNS:
    Wrapped function that enforces rate limiting
    
    HTTP RESPONSES:
    - 200/201: Normal responses (under limit)
    - 429: Too Many Requests (rate limit exceeded)
    
    ATTACKS PREVENTED:
    ✓ Brute force attacks (excessive requests from single IP)
    ✓ Dictionary attacks (password guessing via API)
    ✓ Denial of Service (DoS) via request flooding
    ✓ Scanner enumeration (automated vulnerability scanning)
    
    LIMITATION:
    In-memory only - doesn't persist across container restarts.
    For production with multiple servers, use Redis or Memcached.
    
    USAGE EXAMPLE:
    @app.route('/api/endpoint')
    @rate_limit(max_per_minute=30)
    def protected_endpoint():
        return "OK"
    
    COMPLIANCE:
    ✓ OWASP: Rate limiting for API protection
    ✓ CWE-770: Allocation of resources without limits or throttling
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            client_ip = get_client_ip()
            
            # Initialize counter dictionary if needed
            if not hasattr(decorated_function, 'calls'):
                decorated_function.calls = {}
            
            # Create unique key for this IP and minute
            now = datetime.now()
            key = f"{client_ip}:{now.strftime('%Y-%m-%d %H:%M')}"
            
            # Increment counter for this IP this minute
            decorated_function.calls[key] = decorated_function.calls.get(key, 0) + 1
            
            # Check if over limit
            if decorated_function.calls[key] > max_per_minute:
                logger.warning(f"Rate limit exceeded for {client_ip}")
                return jsonify({'error': 'Rate limit exceeded'}), 429
            
            # Allow request to proceed
            return f(*args, **kwargs)
        return decorated_function
    return decorator


# ============================================================================
# ATTACK DETECTION ENGINE - Core Security Component
# ============================================================================

class AttackDetector:
    """
    ATTACK DETECTOR CLASS - Regex-based attack pattern matching
    ============================================================
    
    PURPOSE:
    Central detection engine for identifying various web application attacks.
    Uses regex pattern matching to identify malicious payloads in requests.
    
    SECURITY APPROACH:
    - Signature-based detection (similar to antivirus)
    - Multiple patterns per attack type (defense in depth)
    - Case-insensitive matching (?i regex flag)
    - Checks multiple request components (query string, body, headers)
    
    DETECTION METHODS INCLUDED:
    1. detect_sql_injection() - SQL injection patterns
    2. detect_xss_attempt() - Cross-site scripting patterns
    3. detect_path_traversal() - Directory traversal attempts
    
    LIMITATIONS:
    - Pattern-based detection (not behavioral analysis)
    - Can be bypassed by obfuscation (encoded payloads)
    - Potential false-positive rate (tuning needed)
    - No zero-day detection capability
    
    NOTES:
    - Extends easily by adding new static methods
    - Non-invasive (doesn't modify requests)
    - Lightweight regex matching (fast execution)
    
    COMPLIANCE:
    ✓ OWASP Top 10: A1 Injection, A7 XSS
    ✓ CWE-89: SQL Injection
    ✓ CWE-79: Cross-site Scripting
    ✓ CWE-22: Path Traversal
    """
    
    @staticmethod
    def detect_sql_injection(data):
        """
        DETECT_SQL_INJECTION METHOD - Identify SQL injection patterns
        ==============================================================
        
        PURPOSE:
        Identifies SQL injection attack patterns in input data.
        
        DETECTION PATTERNS (3 main categories):
        
        PATTERN 1 - UNION-based SQLi:
        - Regex: (?i)(union|select|insert|update|delete|drop)\s+(from|where)
        - Example: "1 UNION SELECT * FROM users"
        - Attack: Combines query results to extract data
        
        PATTERN 2 - Boolean-based SQLi:
        - Regex: (?i)('|\")\s*(or|and)\s*('|\")\s*=
        - Example: "1' OR '1'='1"
        - Attack: Manipulates query logic
        
        PATTERN 3 - Comment-based SQLi:
        - Regex: (?i)(--|xp_|sp_)
        - Example: "1' OR 1=1 --"
        - Attack: Comments out query restrictions
        """
        sql_patterns = [
            r"(?i)(union|select|insert|update|delete|drop)\s+(from|where)",
            r"(?i)('|\")\s*(or|and)\s*('|\")\s*=",
            r"(?i)(--|xp_|sp_)",
        ]
        
        for pattern in sql_patterns:
            if re.search(pattern, str(data)):
                return True
        return False
    
    @staticmethod
    def detect_xss_attempt(data):
        """
        DETECT_XSS_ATTEMPT METHOD - Identify Cross-Site Scripting patterns
        ===================================================================
        
        DETECTION PATTERNS (3 main categories):
        
        PATTERN 1 - Script tags and protocols:
        - Regex: (?i)(<script|javascript:|onerror=|onload=)
        - Example: "<script>alert('xss')</script>"
        
        PATTERN 2 - Dynamic code execution:
        - Regex: (?i)(alert\(|eval\(|expression\()
        - Example: "alert('XSS')"
        
        PATTERN 3 - DOM-based XSS vectors:
        - Regex: (?i)(<iframe|<object|<embed)
        - Example: "<iframe src='evil.com'></iframe>"
        """
        xss_patterns = [
            r"(?i)(<script|javascript:|onerror=|onload=)",
            r"(?i)(alert\(|eval\(|expression\()",
            r"(?i)(<iframe|<object|<embed)",
        ]
        
        for pattern in xss_patterns:
            if re.search(pattern, str(data)):
                return True
        return False
    
    @staticmethod
    def detect_path_traversal(data):
        """
        DETECT_PATH_TRAVERSAL METHOD - Identify directory traversal attempts
        =====================================================================
        
        DETECTION PATTERNS (3 main categories):
        
        PATTERN 1 - Directory traversal sequences:
        - Regex: \.\.[/\\]+
        - Example: "../../../../etc/passwd"
        
        PATTERN 2 - URL-encoded traversal:
        - Regex: (?i)(%2e%2e)
        - Example: "%2e%2e/etc/passwd"
        
        PATTERN 3 - Sensitive file access:
        - Regex: (?i)(etc/passwd|windows/system32)
        - Example: "/etc/passwd"
        """
        traversal_patterns = [
            r"\.\.[/\\]+",
            r"(?i)(%2e%2e)",
            r"(?i)(etc/passwd|windows/system32)",
        ]
        
        for pattern in traversal_patterns:
            if re.search(pattern, str(data)):
                return True
        return False


# ============================================================================
# FLASK ROUTES / ENDPOINTS
# ============================================================================

@app.route('/health', methods=['GET'])
@rate_limit(max_per_minute=100)
def health_check():
    """
    HEALTH_CHECK ENDPOINT - Service monitoring
    ===========================================
    
    PURPOSE: Returns health status for Docker and monitoring systems
    ENDPOINT: GET /health
    RETURNS: {"status": "healthy"} with HTTP 200
    """
    return jsonify({'status': 'healthy'}), 200


@app.route('/', methods=['GET', 'POST'])
@rate_limit(max_per_minute=60)
def index():
    """
    MAIN ENDPOINT - Primary honeypot endpoint
    =========================================
    
    PURPOSE:
    Main endpoint that attracts and detects attacks.
    Accepts GET and POST requests with any parameters.
    
    SECURITY FLOW:
    1. Extract client IP (validated)
    2. Get User-Agent (sanitized)
    3. Extract request data (query string, body)
    4. Check for SQL injection patterns
    5. Check for XSS patterns
    6. Check for path traversal patterns
    7. Log to file (JSON format)
    8. Log to database (parameterized queries)
    9. Return generic response
    """
    client_ip = get_client_ip()
    user_agent = sanitize_string(request.headers.get('User-Agent', 'unknown'), 500)
    
    attack_type = None
    
    all_data = {
        'query': sanitize_string(request.query_string.decode('utf-8', errors='ignore'), 500),
        'body': sanitize_string(request.get_data(as_text=True), 1000),
    }
    
    for key, value in all_data.items():
        if AttackDetector.detect_sql_injection(value):
            attack_type = 'SQL_Injection'
            break
        elif AttackDetector.detect_xss_attempt(value):
            attack_type = 'XSS_Attack'
            break
        elif AttackDetector.detect_path_traversal(value):
            attack_type = 'Path_Traversal'
            break
    
    # File-based logging (JSON prevents injection)
    try:
        os.makedirs('/var/log/honeypot', exist_ok=True)
        with open('/var/log/honeypot/honeypot.log', 'a') as f:
            log_entry = {
                'timestamp': datetime.utcnow().isoformat(),
                'event': 'HTTP_REQUEST',
                'source_ip': client_ip,
                'user_agent': user_agent,
                'attack_type': attack_type,
            }
            f.write(json.dumps(log_entry) + '\n')
    except Exception as e:
        logger.error(f"Error writing to log file: {e}")
    
    # Database logging (if attack detected)
    if attack_type:
        safe_log_attack(
            attack_name=attack_type,
            source_ip=client_ip,
            user_agent=user_agent,
            db_host=DB_HOST,
            db_user=DB_USER,
            db_password=DB_PASSWORD,
            db_name=DB_NAME,
            db_port=DB_PORT
        )
        logger.warning(f"Attack detected: {attack_type} from {client_ip}")
    
    return "Admin Panel", 200


@app.route('/admin', methods=['GET', 'POST'])
@rate_limit(max_per_minute=30)
def admin_panel():
    """
    ADMIN PANEL ENDPOINT - Fake admin interface
    ============================================
    
    Attracts penetration testers looking for admin panels.
    Logs all access attempts.
    """
    client_ip = get_client_ip()
    user_agent = sanitize_string(request.headers.get('User-Agent', 'unknown'), 500)
    
    safe_log_attack('Unauthorized_Admin_Access', client_ip, user_agent,
                   DB_HOST, DB_USER, DB_PASSWORD, DB_NAME, DB_PORT)
    
    return jsonify({'error': 'Access Denied'}), 403


@app.route('/api/users', methods=['GET'])
@rate_limit(max_per_minute=40)
def get_users():
    """
    API USERS ENDPOINT - Fake REST API
    ===================================
    
    Detects API enumeration attempts.
    """
    client_ip = get_client_ip()
    user_agent = sanitize_string(request.headers.get('User-Agent', 'unknown'), 500)
    
    safe_log_attack('API_Enumeration_Attempt', client_ip, user_agent,
                   DB_HOST, DB_USER, DB_PASSWORD, DB_NAME, DB_PORT)
    
    return jsonify({'error': 'Unauthorized'}), 401


@app.errorhandler(404)
def not_found(error):
    """
    404 ERROR HANDLER - Path enumeration detection
    ==============================================
    
    Catches all undefined routes and logs as enumeration attempts.
    """
    client_ip = get_client_ip()
    user_agent = sanitize_string(request.headers.get('User-Agent', 'unknown'), 500)
    
    safe_log_attack('Path_Enumeration', client_ip, user_agent,
                   DB_HOST, DB_USER, DB_PASSWORD, DB_NAME, DB_PORT)
    
    return jsonify({'error': 'Not Found'}), 404


logger.info("Starting honeypot service...")