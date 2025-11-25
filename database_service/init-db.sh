#!/bin/bash
# Database initialization script - Creates tables and user permissions

set -e

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
    -- Create limited-privilege user
    CREATE USER honeypot_user WITH PASSWORD 'SecurePass123!';
    ALTER USER honeypot_user WITH PASSWORD 'SecurePass123!';
    
    -- Grant minimal permissions (principle of least privilege)
    GRANT CONNECT ON DATABASE $POSTGRES_DB TO honeypot_user;
    GRANT USAGE ON SCHEMA public TO honeypot_user;
    GRANT CREATE ON SCHEMA public TO honeypot_user;
    
    -- Create attacks table
    CREATE TABLE IF NOT EXISTS attacks (
        id SERIAL PRIMARY KEY,
        attack_name VARCHAR(100) NOT NULL,
        source_ip VARCHAR(45) NOT NULL,
        user_agent VARCHAR(1024),
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    
    -- Create indexes
    CREATE INDEX IF NOT EXISTS idx_attacks_timestamp ON attacks(timestamp DESC);
    CREATE INDEX IF NOT EXISTS idx_attacks_source_ip ON attacks(source_ip);
    CREATE INDEX IF NOT EXISTS idx_attacks_attack_name ON attacks(attack_name);
    
    -- Grant limited permissions (SELECT, INSERT, UPDATE only)
    ALTER TABLE attacks OWNER TO honeypot_user;
    GRANT SELECT, INSERT, UPDATE ON attacks TO honeypot_user;
    GRANT USAGE, SELECT ON SEQUENCE attacks_id_seq TO honeypot_user;
EOSQL

echo "Database initialization complete"