#!/bin/bash

source config.sh
source functions.sh

START_TIME=$(date +%s)

show_banner

validate_input "$1"

DOMAIN=$1

OUTPUT_DIR="output/$DOMAIN"

echo -e "${CYAN}Target          :${NC} $DOMAIN"

echo -e "${CYAN}Output Folder   :${NC} $OUTPUT_DIR"

echo ""

echo "-----------------------------------------------------------"

check_dependencies

create_output "$OUTPUT_DIR"

run_subfinder "$OUTPUT_DIR" "$DOMAIN"

remove_duplicates "$OUTPUT_DIR"

TOTAL=$(count_subdomains "$OUTPUT_DIR")

END_TIME=$(date +%s)

TIME=$((END_TIME-START_TIME))

echo ""

echo "-----------------------------------------------------------"

echo ""

echo -e "${GREEN}Scan Summary${NC}"

echo ""

echo "Target Domain      : $DOMAIN"

echo "Unique Subdomains  : $TOTAL"

echo "Execution Time     : ${TIME} seconds"

echo ""

echo "==========================================================="

echo "Completed."

echo "==========================================================="