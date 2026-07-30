#!/bin/bash

source config.sh
source functions.sh

START_TIME=$(date +%s)

show_banner

validate_input "$@"

OUTPUT_DIR="output/$DOMAIN"

echo -e "${CYAN}Target          :${NC} $DOMAIN"
echo -e "${CYAN}Output Folder   :${NC} $OUTPUT_DIR"

echo ""

echo "-----------------------------------------------------------"

check_dependencies

create_output "$OUTPUT_DIR"

run_subfinder "$OUTPUT_DIR" "$DOMAIN"

run_assetfinder "$OUTPUT_DIR" "$DOMAIN"

merge_results "$OUTPUT_DIR"

TOTAL=$(count_subdomains "$OUTPUT_DIR")

run_httpx "$OUTPUT_DIR"

ALIVE=$(count_alive "$OUTPUT_DIR")

END_TIME=$(date +%s)

TIME=$((END_TIME-START_TIME))

printf "[6/6] Generating Summary......... "

generate_summary \
"$OUTPUT_DIR" \
"$DOMAIN" \
"$TOTAL" \
"$ALIVE" \
"$TIME"

generate_markdown_report \
"$OUTPUT_DIR" \
"$DOMAIN" \
"$TOTAL" \
"$ALIVE" \
"$TIME"

write_log \
"$DOMAIN" \
"$TOTAL" \
"$ALIVE" \
"$TIME"

echo -e "${GREEN}✓${NC}"

echo ""

echo "-----------------------------------------------------------"

echo ""

echo -e "${GREEN}Scan Summary${NC}"

echo ""

echo "Target Domain      : $DOMAIN"

echo "Unique Subdomains  : $TOTAL"

echo "Live Hosts         : $ALIVE"

echo "Execution Time     : ${TIME} seconds"

echo ""

echo "==========================================================="

echo "Completed."

echo "==========================================================="