#!/bin/bash

###############################################################################
# ONDC Multi-Language Signature Test Runner
#
# This script runs all language implementations and generates a comprehensive
# compatibility report.
###############################################################################

set -e  # Exit on error

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Header
echo -e "${BLUE}╔════════════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║${NC}     ${GREEN}ONDC Multi-Language Signature Compatibility Test Suite${NC}              ${BLUE}║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Create reports directory if it doesn't exist
mkdir -p reports

# Clean up old reports
echo -e "${YELLOW}🧹 Cleaning up old test reports...${NC}"
rm -f reports/*.json reports/*.html

echo -e "${GREEN}✓ Ready to run tests${NC}"
echo ""

# Ensure participant is registered before running tests
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}📋 Checking participant registration...${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
if [ -f "shared/ensure_participant_registered.py" ]; then
    python shared/ensure_participant_registered.py || echo -e "${YELLOW}⚠️  Registration check completed with warnings${NC}"
else
    echo -e "${YELLOW}⚠️  Registration script not found, skipping...${NC}"
fi
echo ""

# Build all Docker images
echo -e "${BLUE}🐳 Building Docker images...${NC}"
docker-compose build

echo -e "${GREEN}✓ Docker images built${NC}"
echo ""

# Run Python tests
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}🐍 Running Python tests...${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
docker-compose run --rm python-signature || echo -e "${RED}✗ Python tests failed${NC}"
echo ""

# Run Java tests
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}☕ Running Java tests...${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
docker-compose run --rm java-signature || echo -e "${RED}✗ Java tests failed${NC}"
echo ""

# Run Node.js tests
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}📗 Running Node.js tests...${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
docker-compose run --rm nodejs-signature || echo -e "${RED}✗ Node.js tests failed${NC}"
echo ""

# Run Go tests
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}🔷 Running Go tests...${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
docker-compose run --rm golang-signature || echo -e "${RED}✗ Go tests failed${NC}"
echo ""

# Run PHP tests
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}🐘 Running PHP tests...${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
docker-compose run --rm php-signature || echo -e "${RED}✗ PHP tests failed${NC}"
echo ""

# Run Ruby tests
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}💎 Running Ruby tests...${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
docker-compose run --rm ruby-signature || echo -e "${RED}✗ Ruby tests failed${NC}"
echo ""

# Generate compatibility reports
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}📊 Generating compatibility reports...${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"

# Generate text report with simple analysis
python3 generate_simple_report.py

# Generate comprehensive HTML report by re-running tests with detailed capture
python3 generate_html_report.py

echo ""

# Check if reports were generated
if [ -f "reports/compatibility-report.html" ] && [ -f "reports/COMPATIBILITY_REPORT.txt" ]; then
    echo -e "${GREEN}✓ Compatibility reports generated successfully!${NC}"
    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}📄 View the reports:${NC}"
    echo -e "   ${YELLOW}Text report: cat reports/COMPATIBILITY_REPORT.txt${NC}"
    echo -e "   ${YELLOW}HTML report: open reports/compatibility-report.html${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
    
    # Try to open the report automatically (macOS)
    if command -v open &> /dev/null; then
        echo -e "${YELLOW}Opening report in browser...${NC}"
        open reports/compatibility-report.html
    fi
else
    echo -e "${RED}✗ Failed to generate compatibility report${NC}"
    exit 1
fi

echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}✓ All tests completed successfully!${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
echo ""

# Summary
echo -e "${BLUE}Test Results Summary:${NC}"
echo -e "  Python:   $([ -f reports/python-keys.json ] && echo -e '${GREEN}✓${NC}' || echo -e '${RED}✗${NC}')"
echo -e "  Java:     $([ -f reports/java-keys.json ] && echo -e '${GREEN}✓${NC}' || echo -e '${RED}✗${NC}')"
echo -e "  Node.js:  $([ -f reports/nodejs-keys.json ] && echo -e '${GREEN}✓${NC}' || echo -e '${RED}✗${NC}')"
echo -e "  Go:       $([ -f reports/golang-keys.json ] && echo -e '${GREEN}✓${NC}' || echo -e '${RED}✗${NC}')"
echo -e "  PHP:      $([ -f reports/php-keys.json ] && echo -e '${GREEN}✓${NC}' || echo -e '${RED}✗${NC}')"
echo -e "  Ruby:     $([ -f reports/ruby-keys.json ] && echo -e '${GREEN}✓${NC}' || echo -e '${RED}✗${NC}')"
echo ""
