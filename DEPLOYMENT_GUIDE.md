# Production Deployment Guide

## Ubuntu 24.04 LTS Setup

sudo apt update && sudo apt upgrade -y

### Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER
newgrp docker

### Deploy Honeypot
git clone https://github.com/Czebok/honeypot-project.git
cd honeypot-project
nano .env # Change all passwords!
docker-compose up -d

### Firewall Configuration
sudo ufw enable
sudo ufw allow 22/tcp
sudo ufw allow 8080/tcp
sudo ufw allow 5000/tcp
sudo ufw deny 5432/tcp # Database internal only
sudo ufw status

### Backup
docker exec honeypot_db pg_dump -U honeypot_user honeypot_db > backup.sql

### Logs
Check logs:
docker-compose logs <service_name>

**Access dashboard**
Open: http://localhost:5000

### Maintenance
- Daily: Check health, review logs
- Weekly: Verify attacks, check disk
- Monthly: Backups, patching, audits
