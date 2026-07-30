#!/bin/bash

# ============================================
# Passive Subdomain Recon Automation Tool v2
# Author: Mrityunjay
# ============================================

# ---------- Colors ----------
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# ---------- Banner ----------
echo -e "${BLUE}"
echo "=================================================="
echo "        Passive Subdomain Recon Automation"
echo "=================================================="
echo -e "${NC}"

# ---------- Validate Input ----------
if [ -z "$1" ]; then
    echo -e "${RED}[!] Usage:${NC} ./recon.sh <domain>"
    echo "Example:"
    echo "./recon.sh hackerone.com"
    exit 1
fi

DOMAIN=$1

# ---------- Dependency Check ----------
if ! command -v subfinder &> /dev/null; then
    echo -e "${RED}[!] Subfinder is not installed.${NC}"
    echo "Install it using:"
    echo "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    exit 1
fi

# ---------- Create Output Directory ----------
OUTPUT_DIR="output/$DOMAIN"

mkdir -p "$OUTPUT_DIR"

echo -e "${YELLOW}[+] Target:${NC} $DOMAIN"
echo -e "${YELLOW}[+] Running Subfinder...${NC}"

# ---------- Run Enumeration ----------
subfinder -d "$DOMAIN" -silent -o "$OUTPUT_DIR/subdomains.txt"

# ---------- Validate Output ----------
if [ ! -f "$OUTPUT_DIR/subdomains.txt" ]; then
    echo -e "${RED}[!] No output generated.${NC}"
    exit 1
fi

# ---------- Remove Duplicates ----------
sort -u "$OUTPUT_DIR/subdomains.txt" -o "$OUTPUT_DIR/subdomains.txt"

# ---------- Count ----------
TOTAL=$(wc -l < "$OUTPUT_DIR/subdomains.txt")

echo ""

echo -e "${GREEN}[✓] Enumeration Completed Successfully!${NC}"

echo -e "${GREEN}[✓] Total Unique Subdomains:${NC} $TOTAL"

echo -e "${GREEN}[✓] Results Saved To:${NC}"

echo "    $OUTPUT_DIR/subdomains.txt"

echo ""

echo "=================================================="
echo "Done!"
echo "=================================================="