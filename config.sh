#!/bin/bash

# ============================================
# Configuration File
# ============================================

# Colors

GREEN='\033[0;32m'

RED='\033[0;31m'

YELLOW='\033[1;33m'

BLUE='\033[0;34m'

CYAN='\033[0;36m'

NC='\033[0m'

# Banner

show_banner() {

clear

echo -e "${BLUE}"

echo "==========================================================="

echo "        Passive Subdomain Recon Automation Tool v2"

echo "==========================================================="

echo -e "${NC}"

}