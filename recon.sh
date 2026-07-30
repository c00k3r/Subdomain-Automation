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

START_TIME=$(date +%s)

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
    echo "Install using:"
    echo "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    exit 1
fi

echo -e "${GREEN}✓${NC}"

# ---------------- Output Directory ----------------
mkdir -p "$OUTPUT_DIR"

# ---------------- Enumeration ----------------
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

sort -u "$OUTPUT_DIR/subdomains.txt" \
-o "$OUTPUT_DIR/subdomains.txt"

echo -e "${GREEN}✓${NC}"

# ---------------- Statistics ----------------
TOTAL=$(wc -l < "$OUTPUT_DIR/subdomains.txt")

END_TIME=$(date +%s)
TIME_TAKEN=$((END_TIME - START_TIME))

printf "[4/4] Generating Report......... "

cat << EOF > "$OUTPUT_DIR/summary.txt"
===================================================
Passive Subdomain Recon Automation Tool v2
===================================================

Target Domain : $DOMAIN

Unique Subdomains : $TOTAL

Execution Time : ${TIME_TAKEN} seconds

Results File :

$OUTPUT_DIR/subdomains.txt

Generated :

$(date)

===================================================
EOF

echo -e "${GREEN}✓${NC}"

echo ""
echo "-----------------------------------------------------------"
echo ""

echo -e "${GREEN}Scan Summary${NC}"

echo ""
echo "Target Domain      : $DOMAIN"
echo "Unique Subdomains  : $TOTAL"
echo "Execution Time     : ${TIME_TAKEN} seconds"
echo "Summary Report     : $OUTPUT_DIR/summary.txt"
echo "Results File       : $OUTPUT_DIR/subdomains.txt"

echo ""
echo -e "${BLUE}===========================================================${NC}"
echo -e "${GREEN}          Scan Completed Successfully${NC}"
echo -e "${BLUE}===========================================================${NC}"