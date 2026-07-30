#!/bin/bash

# =========================================================
# Passive Subdomain Recon Automation Tool v2
# Author: Mrityunjay
# =========================================================

# ---------------- Colors ----------------
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# ---------------- Banner ----------------
clear

echo -e "${BLUE}"
echo "==========================================================="
echo "      Passive Subdomain Recon Automation Tool v2"
echo "==========================================================="
echo -e "${NC}"

# ---------------- Validate Input ----------------
if [ -z "$1" ]; then
    echo -e "${RED}[!] Usage:${NC} ./recon.sh <domain>"
    echo ""
    echo "Example:"
    echo "./recon.sh hackerone.com"
    exit 1
fi

DOMAIN=$1
OUTPUT_DIR="output/$DOMAIN"

echo -e "${CYAN}Target          :${NC} $DOMAIN"
echo -e "${CYAN}Output Folder   :${NC} $OUTPUT_DIR"
echo ""

echo "-----------------------------------------------------------"

# ---------------- Dependency Check ----------------
printf "[1/4] Checking Dependencies... "

if ! command -v subfinder >/dev/null 2>&1; then
    echo -e "${RED}FAILED${NC}"
    echo ""
    echo "Subfinder is not installed."
    echo ""
    echo "Install using:"
    echo ""
    echo "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    exit 1
fi

echo -e "${GREEN}✓${NC}"

# ---------------- Create Output ----------------
mkdir -p "$OUTPUT_DIR"

# ---------------- Run Subfinder ----------------
printf "[2/4] Running Subfinder......... "

subfinder -d "$DOMAIN" \
-silent \
-o "$OUTPUT_DIR/subdomains.txt"

echo -e "${GREEN}✓${NC}"

# ---------------- Validate ----------------
if [ ! -f "$OUTPUT_DIR/subdomains.txt" ]; then
    echo ""
    echo -e "${RED}[!] No output generated.${NC}"
    exit 1
fi

# ---------------- Remove Duplicates ----------------
printf "[3/4] Removing Duplicates...... "

sort -u \
"$OUTPUT_DIR/subdomains.txt" \
-o "$OUTPUT_DIR/subdomains.txt"

echo -e "${GREEN}✓${NC}"

# ---------------- Count ----------------
TOTAL=$(wc -l < "$OUTPUT_DIR/subdomains.txt")

printf "[4/4] Generating Report......... "

echo -e "${GREEN}✓${NC}"

echo ""
echo "-----------------------------------------------------------"
echo ""

echo -e "${GREEN}Scan Summary${NC}"
echo ""

echo -e "Target Domain      : $DOMAIN"
echo -e "Unique Subdomains  : $TOTAL"
echo -e "Output Directory   : $OUTPUT_DIR"
echo -e "Results File       : subdomains.txt"

echo ""

echo -e "${BLUE}===========================================================${NC}"
echo -e "${GREEN}          Scan Completed Successfully${NC}"
echo -e "${BLUE}===========================================================${NC}"