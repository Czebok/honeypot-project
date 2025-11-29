# Honeypot Lab Project

Complete honeypot system with attack detection, database, and analytics dashboard.

## Services

### Honeypot (Port 8080)
- Detects: SQL Injection, XSS, Path Traversal
- Logs to: file + database
- Rate limited: 60 req/min per IP

### Database (Port 5432)
- PostgreSQL 16
- Parameterized queries
- Limited user permissions

### Analytics (Port 5000)
- Real-time statistics
- Top IPs, user agents
- Recent attacks table

## Testing

**SQL Injection**
***Logiczne obejście OR 1=1***

- curl -X GET "http://localhost/api/search?q=' OR '1'='1" -v

***INSERT/UPDATE/DELETE***

- curl -X GET "http://localhost/api/search?q=drop table users" -v

***Blind SQL Injection (time-based)***

- curl -X GET "http://localhost/api/search?q=1' AND SLEEP(5)--" -v

***Kodowane znaki (URL encoding)***

- curl -X GET "http://localhost/api/search?q=%27%20OR%20%271%27%3D%271" -v

***POST z JSON payload***

- curl -X POST -H "Content-Type: application/json" \
  -d '{"username":"admin\" OR 1=1--","password":""}' \
  "http://localhost/api/login" -v


**XSS**
***Klasyczne XSS***

- curl "http://localhost/?q=<script>alert(1)</script>"

***Event handler***

- curl "http://localhost/?q=<img src=x onerror=alert(1)>"

***JavaScript URL***

- curl "http://localhost/?q=<a href=javascript:alert(1)>click</a>"

***URL encoded***

- url "http://localhost/?q=%3Cscript%3Ealert(1)%3C/script%3E"

***Unicode***

- curl "http://localhost/?q=\u003cscript\u003ealert(1)\u003c/script\u003e"


**Path Traversal**
***Test klasycznego path traversal (../)***

- curl -X GET "http://localhost/api/file?path=../../etc/passwd" -v

***Test wielokrotnego ../ (dot-dot-slash sequences)***

- curl -X GET "http://localhost/api/file?path=../../../etc/passwd" -v

***Test z URL-encoded ../***

- curl -X GET "http://localhost/api/file?path=%2e%2e/%2e%2e/%2e%2e/etc/passwd" -v

***Test próby dostępu do katalogu Windows system32***

- curl -X GET "http://localhost/api/file?path=windows/system32/calc.exe" -v

***Test próby użycia backslash zamiast slash***

- curl -X GET "http://localhost/api/file?path=..\\..\\windows\\system32\\calc.exe" -v

**Admin Access**

- curl http://localhost:8080/admin

**API Enumeration**

- curl http://localhost:8080/api/users


## View Attacks

**Connect to database**

- docker exec -it honeypot_db psql -U honeypot_user -d honeypot_db

**Query**

- SELECT * FROM attacks ORDER BY timestamp DESC LIMIT 10;
- SELECT attack_name, COUNT() FROM attacks GROUP BY attack_name;
- SELECT source_ip, COUNT() FROM attacks GROUP BY source_ip ORDER BY 2 DESC;


## Security

- Parameterized queries prevent SQL injection
- Input sanitization
- Non-root execution
- Network isolation
- OWASP compliant

## Troubleshooting

**Check logs**

docker-compose logs -f

**Restart**

docker-compose restart

**Reset**

docker-compose down -v

docker-compose up -d
