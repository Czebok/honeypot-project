# 🛡️ Honeypot Lab Project

**Complete honeypot system** with attack detection, PostgreSQL logging, and analytics dashboard.

![Analytics Dashboard](./analytics.jpg)

---

## 🏗️ Architecture Overview

| Service | Port | Purpose | Status |
|---------|------|---------|--------|
| **Honeypot** | 80 | Attack detection + logging | 🟢 Active |
| **Database** | 5432 | PostgreSQL attack storage | 🟢 Active |
| **Analytics** | 5000 | Real-time dashboard | 🟢 Active |

---

## 🧪 Attack Testing Commands

### 🔪 SQL Injection (3/3 ✅)

| # | Payload | Regex | Command |
|---|---------|-------|---------|
| 1 | UNION SELECT | `regex[0]` | `curl -s "http://localhost/?id=1'+UNION+SELECT+1\,2\,3--"` |
| 2 | OR 1=1 | `regex[1]` | `curl -s "http://localhost/?login=admin'+OR+'1'='1'"` |
| 3 | SLEEP() | `regex[7]` | `curl -s "http://localhost/?id=1;+SLEEP\(5\)--"` |

### 🕷️ XSS Attacks (2/3 ✅)

| # | Payload | Regex | Command |
|---|---------|-------|---------|
| 1 | `<img onerror>` | `regex[1]` | `curl -s "http://localhost/?name=%3Cimg%20src=x%20onerror=alert(1)%3E"` |
| 2 | `<svg onload>` | `regex[9]` | `curl -s "http://localhost/?input=%3Csvg%20onload=alert(1)%3E"` |
| 3 | `%3Cscript` | `regex[4]` | `curl -s "http://localhost/?data=%3Cscript%3Ealert(1)%3C/script%3E"` |

### 📁 Path Traversal (5/5 ✅)

| # | Payload | Regex | Command |
|---|---------|-------|---------|
| 1 | `../` | `regex[0]` | `curl -s "http://localhost/?file=../../../etc/passwd"` |
| 2 | `%2e%2e/` | `regex[1]` | `curl -s "http://localhost/?path=%2e%2e%2f%2e%2e%2fetc%2fpasswd"` |
| 3 | `/etc/passwd` | `regex[6]` | `curl -s "http://localhost/?file=/etc/passwd"` |
| 4 | `/boot.ini` | `regex[6]` | `curl -s "http://localhost/?file=/boot.ini"` |
| 5 | `/win.ini` | `regex[6]` | `curl -s "http://localhost/?file=/win.ini"` |

---

## 🔍 View Attack Logs

1. Connect to database

docker exec -it honeypot_db psql -U honeypot_user -d honeypot_db

2. Top queries (run in psql)

SELECT attack_name, COUNT() as count FROM attacks GROUP BY attack_name ORDER BY count DESC; SELECT source_ip, COUNT() as attacks FROM attacks GROUP BY source_ip ORDER BY attacks DESC LIMIT 10; SELECT * FROM attacks ORDER BY timestamp DESC LIMIT 20;


---

## ⚙️ Additional Endpoints

Admin panel (403 + log)

curl -s “http://localhost/admin”

API enumeration (401 + log)

curl -s “http://localhost/api/users”

Health check

curl -s “http://localhost/health”


---

## 🔧 Management Commands

| Action | Command |
|--------|---------|
| **View logs** | `docker-compose logs -f` |
| **Restart** | `docker-compose restart` |
| **Reset DB** | `docker-compose down -v && docker-compose up -d` |
| **Analytics** | `http://localhost:5000` |

---

## 🛡️ Security Features

- ✅ **Parameterized queries** (no SQLi in DB)
- ✅ **Rate limiting** (60 req/min/IP) 
- ✅ **Input sanitization** (null bytes, length limits)
- ✅ **Non-root container**
- ✅ **Read-only filesystem**
- ✅ **IP validation** (anti-spoofing)