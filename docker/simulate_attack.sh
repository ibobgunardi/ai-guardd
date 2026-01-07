#!/bin/sh

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

LOG_DIR="/var/log_sim"
AUTH_LOG="$LOG_DIR/auth.log"
ACCESS_LOG="$LOG_DIR/access.log"

mkdir -p $LOG_DIR
touch $AUTH_LOG $ACCESS_LOG

echo -e "${GREEN}Starting Simulation...${NC}"
echo "Logs located at: $LOG_DIR"

# 1. Simulate SSH Brute Force (Low & Slow)
echo -e "${RED}[ATTACK] Simulating SSH Brute Force (IP: 45.1.1.1)...${NC}"
for i in $(seq 1 6); do
    echo "Dec 10 12:34:$i server sshd[12345]: Failed password for invalid user root from 45.1.1.1 port 22 ssh2" >> $AUTH_LOG
    sleep 1
done

# 2. Simulate HTTP 404 Flood (Web Scanning)
echo -e "${RED}[ATTACK] Simulating Web Scanner (IP: 10.0.0.50)...${NC}"
for i in $(seq 1 25); do
    # Nginx format: IP - - [Time] "METHOD URL PROTO" Status Size "-" "UA"
    echo "10.0.0.50 - - [10/Dec/2026:12:35:$i +0000] \"GET /wp-admin/login.php?id=$i HTTP/1.1\" 404 123 \"-\" \"EvilScanner/1.0\"" >> $ACCESS_LOG
    sleep 0.2
done

echo -e "${GREEN}Simulation Complete. Check agent logs for alerts.${NC}"
# Keep container alive
tail -f $AUTH_LOG
