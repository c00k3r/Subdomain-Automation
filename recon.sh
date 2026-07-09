#!/bin/bash

# ============================================
# Passive Subdomain Recon Script
# Author: Your Name
# Tool Used: Subfinder
# ============================================

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Banner
echo -e "${BLUE}"
echo "=============================================="
echo "      Passive Subdomain Recon Automation"
echo "=============================================="
echo -e "${NC}"

# Check if a domain was provided
if [ -z "$1" ]; then
    echo -e "${RED}[!] Usage:${NC} ./recon.sh <domain>"
    echo "Example:"
    echo "./recon.sh example.com"
    exit 1
fi

DOMAIN=$1

# Check if Subfinder is installed
if ! command -v subfinder &> /dev/null; then
    echo -e "${RED}[!] Subfinder is not installed.${NC}"
    exit 1
fi

# Create output directory
mkdir -p output

echo -e "${YELLOW}[+] Target:${NC} $DOMAIN"
echo -e "${YELLOW}[+] Enumerating subdomains...${NC}"

# Run Subfinder
subfinder -d "$DOMAIN" -silent -o output/subdomains.txt

# Check if output exists
if [ ! -f output/subdomains.txt ]; then
    echo -e "${RED}[!] No output generated.${NC}"
    exit 1
fi

# Remove duplicate entries
sort -u output/subdomains.txt -o output/subdomains.txt

# Count results
TOTAL=$(wc -l < output/subdomains.txt)

echo ""
echo -e "${GREEN}[✓] Enumeration Completed Successfully!${NC}"
echo -e "${GREEN}[✓] Total Unique Subdomains Found:${NC} $TOTAL"
echo -e "${GREEN}[✓] Results Saved To:${NC} output/subdomains.txt"
echo ""

echo "=============================================="
echo "Done!"
echo "=============================================="
