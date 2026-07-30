#!/bin/bash

# ============================================
# Functions
# ============================================

validate_input() {

if [ -z "$1" ]; then

echo -e "${RED}[!] Usage:${NC} ./recon.sh <domain>"

echo ""

echo "./recon.sh hackerone.com"

exit 1

fi

}

check_dependencies() {

printf "[1/5] Checking Dependencies... "

if ! command -v subfinder >/dev/null 2>&1; then

echo -e "${RED}Subfinder Missing${NC}"

exit 1

fi

if ! command -v httpx >/dev/null 2>&1; then

echo -e "${RED}Httpx Missing${NC}"

echo ""
echo "Install with:"
echo ""
echo "go install github.com/projectdiscovery/httpx/cmd/httpx@latest"

exit 1

fi

echo -e "${GREEN}✓${NC}"

}

create_output() {

mkdir -p "$1"

}

run_subfinder() {

printf "[2/4] Running Subfinder......... "

subfinder -d "$2" \
-silent \
-o "$1/subdomains.txt"

echo -e "${GREEN}✓${NC}"

}

remove_duplicates() {

printf "[3/4] Removing Duplicates...... "

sort -u "$1/subdomains.txt" \
-o "$1/subdomains.txt"

echo -e "${GREEN}✓${NC}"

}

count_subdomains() {

wc -l < "$1/subdomains.txt"

}
run_httpx() {

printf "[4/5] Checking Live Hosts........ "

httpx \
-silent \
-l "$1/subdomains.txt" \
-o "$1/alive.txt" >/dev/null 2>&1

echo -e "${GREEN}✓${NC}"

}

count_alive() {

if [ -f "$1/alive.txt" ]; then
    wc -l < "$1/alive.txt"
else
    echo 0
fi

}

generate_summary() {

cat << EOF > "$1/summary.txt"
===================================================
Passive Subdomain Recon Automation Tool v2
===================================================

Target Domain : $2

Unique Subdomains : $3

Live Hosts : $4

Execution Time : $5 seconds

Generated :

$(date)

===================================================
EOF

}

generate_markdown_report() {

REPORT_DIR="reports/$2"

mkdir -p "$REPORT_DIR"

cat << EOF > "$REPORT_DIR/report.md"
# Passive Subdomain Recon Report

## Target

$2

---

## Scan Statistics

| Item | Value |
|------|-------|
| Total Subdomains | $3 |
| Live Hosts | $4 |
| Execution Time | $5 seconds |

---

## Output Files

- output/$2/subdomains.txt
- output/$2/alive.txt
- output/$2/summary.txt

---

Generated:

$(date)
EOF

}

write_log() {

cat << EOF >> logs/recon.log

==================================================

$(date)

Target : $1

Subdomains : $2

Alive Hosts : $3

Execution Time : $4 seconds

Status : SUCCESS

==================================================

EOF

}