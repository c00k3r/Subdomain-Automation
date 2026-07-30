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

printf "[1/4] Checking Dependencies... "

if ! command -v subfinder >/dev/null 2>&1; then

echo -e "${RED}FAILED${NC}"

echo ""

echo "Subfinder is not installed."

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