# Honeypot Lab Project

Complete honeypot system with attack detection, database, and analytics dashboard.

## Quick Start

**Extract and navigate**
cd honeypot_project

**Update passwords in .env**
nano .env

**Deploy**
docker-compose up -d

**Wait for initialization**
sleep 30

**Verify**
docker-compose ps

**Test**
curl "http://localhost:8080/?id=1 OR 1=1 --"

**Access dashboard**
Open: http://localhost:5000

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
curl "http://localhost:8080/?id=1 OR 1=1 --"

**XSS**
curl "http://localhost:8080/?q=<script>alert(1)</script>"

**Path Traversal**
curl "http://localhost:8080/../../etc/passwd"

**Admin Access**
curl http://localhost:8080/admin

**API Enumeration**
curl http://localhost:8080/api/users


## View Attacks

**Connect to database**
docker exec -it honeypot_db psql -U honeypot_user -d honeypot_db

**Query**
SELECT * FROM attacks ORDER BY timestamp DESC LIMIT 10;
SELECT attack_name, COUNT() FROM attacks GROUP BY attack_name;
SELECT source_ip, COUNT() FROM attacks GROUP BY source_ip ORDER BY 2 DESC;


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
