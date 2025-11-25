# Database Service

PostgreSQL database for honeypot attack logging.

## Features
- Parameterized queries prevent SQL injection
- Dedicated user with minimal permissions
- Optimized indexes for analytics
- Automatic backup support

## Connection
- Host: db (internal Docker network)
- Port: 5432
- Database: honeypot_db
- User: honeypot_user
- Password: SecurePass123!