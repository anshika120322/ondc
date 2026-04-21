#!/bin/bash
# Admin Portal Tests Runner Script
# This script runs both admin portal service test suites with the correct base URLs

echo "=========================================="
echo "Admin Portal Test Suite Runner"
echo "=========================================="
echo ""

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Auth Service Tests
echo -e "${BLUE}[1/2] Running Admin Portal Auth Service Tests...${NC}"
echo "Base URL: https://admin-auth-uat.kynondc.net/api"
echo ""

BASE_URL="https://admin-auth-uat.kynondc.net/api" \
  python run_tests.py run \
  --file config/admin_portal_auth_service_tests.yaml \
  --output-format html

AUTH_RESULT=$?

echo ""
echo "=========================================="
echo ""

# Admin Service Tests  
echo -e "${BLUE}[2/2] Running Admin Portal Service Tests...${NC}"
echo "Base URL: https://admin-service-uat.kynondc.net/api/v1"
echo ""

BASE_URL="https://admin-service-uat.kynondc.net/api/v1" \
  python run_tests.py run \
  --file config/admin_portal_service_tests.yaml \
  --output-format html

SERVICE_RESULT=$?

echo ""
echo "=========================================="
echo "Test Execution Complete"
echo "=========================================="

if [ $AUTH_RESULT -eq 0 ] && [ $SERVICE_RESULT -eq 0 ]; then
    echo -e "${GREEN}✓ All tests completed successfully${NC}"
    exit 0
else
    echo -e "${RED}✗ Some tests failed. Check the HTML reports in the output/ directory${NC}"
    exit 1
fi
